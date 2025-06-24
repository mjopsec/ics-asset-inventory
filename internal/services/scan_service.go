package services

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"ics-asset-inventory/internal/database"
	"ics-asset-inventory/internal/database/models"
	"ics-asset-inventory/internal/scanner"
	"ics-asset-inventory/internal/utils"
	"ics-asset-inventory/internal/websocket"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"strings"
)

// ScanService manages network scanning operations
type ScanService struct {
	db          *gorm.DB
	logger      *utils.Logger
	activeScan  *ActiveScan
	scanHistory map[string]*models.NetworkScan
	mu          sync.RWMutex
}

// ActiveScan represents a currently running scan
type ActiveScan struct {
	ID       string
	Scanner  *scanner.Scanner
	ScanDB   *models.NetworkScan
	Results  []*scanner.DeviceResult
	mu       sync.Mutex
}

// ScanRequest represents a scan configuration request
type ScanRequest struct {
	IPRange       string   `json:"ip_range" binding:"required"`
	ScanType      string   `json:"scan_type" binding:"required,oneof=quick full custom"`
	Timeout       int      `json:"timeout" binding:"min=10,max=300"`
	MaxConcurrent int      `json:"max_concurrent" binding:"min=1,max=100"`
	Protocols     []string `json:"protocols"`
	PortRanges    []struct {
		Start uint16 `json:"start"`
		End   uint16 `json:"end"`
	} `json:"port_ranges"`
}

// ScanResponse represents scan initiation response
type ScanResponse struct {
	ScanID    string    `json:"scan_id"`
	Status    string    `json:"status"`
	Message   string    `json:"message"`
	StartTime time.Time `json:"start_time"`
}

// ScanProgressResponse represents current scan progress
type ScanProgressResponse struct {
	ScanID          string        `json:"scan_id"`
	Status          string        `json:"status"`
	Progress        float64       `json:"progress"`
	TotalHosts      int           `json:"total_hosts"`
	ScannedHosts    int           `json:"scanned_hosts"`
	DiscoveredHosts int           `json:"discovered_hosts"`
	ElapsedTime     string        `json:"elapsed_time"`
	EstimatedTime   string        `json:"estimated_time"`
	Errors          []string      `json:"errors"`
}

// DiscoveredDevice represents a discovered device for UI
type DiscoveredDevice struct {
	ID           string                 `json:"id"`
	IPAddress    string                 `json:"ip_address"`
	MACAddress   string                 `json:"mac_address"`
	Hostname     string                 `json:"hostname"`
	DeviceType   string                 `json:"device_type"`
	Vendor       string                 `json:"vendor"`
	Model        string                 `json:"model"`
	Protocol     string                 `json:"protocol"`
	OpenPorts    []scanner.PortInfo     `json:"open_ports"`
	ResponseTime string                 `json:"response_time"`
	IsNew        bool                   `json:"is_new"`
	ExistingID   string                 `json:"existing_id,omitempty"`
	Fingerprint  map[string]interface{} `json:"fingerprint"`
	InInventory  bool                   `json:"in_inventory"`
	AssetID      string                 `json:"asset_id,omitempty"`
}

// NewScanService creates a new scan service
func NewScanService() *ScanService {
	return &ScanService{
		db:          database.GetDB(),
		logger:      utils.NewLogger(),
		scanHistory: make(map[string]*models.NetworkScan),
	}
}

// StartScan initiates a new network scan - FIXED
func (s *ScanService) StartScan(req *ScanRequest) (*ScanResponse, error) {
	// Clear any previous active scan first
	s.mu.Lock()
	if s.activeScan != nil {
		// Force stop previous scan if still running
		if s.activeScan.Scanner != nil {
			s.activeScan.Scanner.Stop()
		}
		s.activeScan = nil
	}
	s.mu.Unlock()

	// Validate IP range
	if err := s.ValidateIPRange(req.IPRange); err != nil {
		return nil, err
	}

	// Create scan configuration
	config := &scanner.ScanConfig{
		IPRange:       req.IPRange,
		ScanType:      scanner.ScanType(req.ScanType),
		Timeout:       time.Duration(req.Timeout) * time.Second,
		MaxConcurrent: req.MaxConcurrent,
		Protocols:     req.Protocols,
		PortRanges:    make([]scanner.PortRange, len(req.PortRanges)),
	}

	// Convert port ranges
	for i, pr := range req.PortRanges {
		config.PortRanges[i] = scanner.PortRange{
			Start: pr.Start,
			End:   pr.End,
		}
	}

	// Create scanner
	scannerInstance := scanner.NewScanner(config, s.logger)

	// Create database record
	scanDB := &models.NetworkScan{
		ID:        uuid.New(),
		ScanType:  req.ScanType,
		Target:    req.IPRange,
		Status:    string(scanner.StatusRunning),
		StartTime: time.Now(),
	}

	if err := s.db.Create(scanDB).Error; err != nil {
		return nil, fmt.Errorf("failed to create scan record: %w", err)
	}

	// Create active scan
	activeScan := &ActiveScan{
		ID:      scanDB.ID.String(),
		Scanner: scannerInstance,
		ScanDB:  scanDB,
		Results: make([]*scanner.DeviceResult, 0),
	}

	// Store active scan
	s.mu.Lock()
	s.activeScan = activeScan
	s.scanHistory[scanDB.ID.String()] = scanDB
	s.mu.Unlock()

	// Start the scan
	if err := scannerInstance.Start(); err != nil {
		scanDB.Status = string(scanner.StatusFailed)
		scanDB.ErrorMsg = err.Error()
		s.db.Save(scanDB)
		return nil, err
	}

	// Start result processor in background
	go s.processResults(activeScan)

	// Start progress monitor with WebSocket broadcasting
	go s.monitorProgress(activeScan)

	s.logger.Info("Scan started", "scan_id", scanDB.ID.String(), "target", req.IPRange)

	return &ScanResponse{
		ScanID:    scanDB.ID.String(),
		Status:    scanDB.Status,
		Message:   "Scan started successfully",
		StartTime: scanDB.StartTime,
	}, nil
}

// StopScan stops the currently running scan
func (s *ScanService) StopScan(scanID string) error {
	s.mu.RLock()
	activeScan := s.activeScan
	s.mu.RUnlock()

	if activeScan == nil || activeScan.ID != scanID {
		return fmt.Errorf("no active scan with ID %s", scanID)
	}

	activeScan.Scanner.Stop()
	return nil
}

// GetScanProgress returns the progress of a scan
func (s *ScanService) GetScanProgress(scanID string) (*ScanProgressResponse, error) {
	s.mu.RLock()
	activeScan := s.activeScan
	s.mu.RUnlock()

	if activeScan != nil && activeScan.ID == scanID {
		progress := activeScan.Scanner.GetProgress()
		
		// Calculate progress percentage
		var progressPct float64
		if progress.TotalHosts > 0 {
			progressPct = float64(progress.ScannedHosts) / float64(progress.TotalHosts) * 100
		}

		// Estimate remaining time
		var estimatedTime string
		if progress.ScannedHosts > 0 && progressPct < 100 {
			elapsed := progress.ElapsedTime
			rate := float64(progress.ScannedHosts) / elapsed.Seconds()
			remaining := float64(progress.TotalHosts-progress.ScannedHosts) / rate
			estimatedTime = time.Duration(remaining * float64(time.Second)).String()
		}

		return &ScanProgressResponse{
			ScanID:          scanID,
			Status:          string(progress.Status),
			Progress:        progressPct,
			TotalHosts:      progress.TotalHosts,
			ScannedHosts:    progress.ScannedHosts,
			DiscoveredHosts: progress.DiscoveredHosts,
			ElapsedTime:     progress.ElapsedTime.String(),
			EstimatedTime:   estimatedTime,
			Errors:          progress.Errors,
		}, nil
	}

	// Check historical scan
	s.mu.RLock()
	scanDB, exists := s.scanHistory[scanID]
	s.mu.RUnlock()

	if !exists {
		// Try to load from database
		var scan models.NetworkScan
		if err := s.db.First(&scan, "id = ?", scanID).Error; err != nil {
			return nil, fmt.Errorf("scan not found")
		}
		scanDB = &scan
	}

	return &ScanProgressResponse{
		ScanID:          scanID,
		Status:          scanDB.Status,
		Progress:        100,
		TotalHosts:      0,
		ScannedHosts:    0,
		DiscoveredHosts: scanDB.DevicesFound,
		ElapsedTime:     fmt.Sprintf("%d seconds", scanDB.Duration),
		EstimatedTime:   "0",
		Errors:          []string{},
	}, nil
}

// GetScanResults returns discovered devices from a scan - FIXED
func (s *ScanService) GetScanResults(scanID string) ([]DiscoveredDevice, error) {
	var results []DiscoveredDevice

	// Load scan from database
	var scanDB models.NetworkScan
	if err := s.db.First(&scanDB, "id = ?", scanID).Error; err != nil {
		return nil, fmt.Errorf("scan not found")
	}

	// Parse results from JSON
	if scanDB.Results != "" {
		var devices []*scanner.DeviceResult
		if err := json.Unmarshal([]byte(scanDB.Results), &devices); err != nil {
			s.logger.Error("Failed to parse scan results", "error", err, "scan_id", scanID)
			return nil, fmt.Errorf("failed to parse scan results: %w", err)
		}

		s.logger.Info("Loaded scan results", "scan_id", scanID, "device_count", len(devices))

		for _, device := range devices {
			discoveredDevice := s.convertToDiscoveredDevice(device)
			
			// Check if device is already in inventory
			var existingAsset models.Asset
			err := s.db.Where("ip_address = ?", device.IPAddress).First(&existingAsset).Error
			if err == nil {
				discoveredDevice.InInventory = true
				discoveredDevice.AssetID = existingAsset.ID.String()
				discoveredDevice.IsNew = false
			} else {
				discoveredDevice.InInventory = false
				discoveredDevice.IsNew = true
			}
			
			results = append(results, discoveredDevice)
		}
	}

	return results, nil
}

// GetScanHistory returns scan history
func (s *ScanService) GetScanHistory(limit int) ([]models.NetworkScan, error) {
	var scans []models.NetworkScan
	
	query := s.db.Order("created_at DESC")
	if limit > 0 {
		query = query.Limit(limit)
	}
	
	if err := query.Find(&scans).Error; err != nil {
		return nil, err
	}
	
	return scans, nil
}

// AddDeviceToInventory adds a discovered device to the asset inventory
func (s *ScanService) AddDeviceToInventory(scanID string, deviceIP string) (*models.Asset, error) {
	// Find the device in scan results
	devices, err := s.GetScanResults(scanID)
	if err != nil {
		return nil, err
	}

	var targetDevice *DiscoveredDevice
	for _, device := range devices {
		if device.IPAddress == deviceIP {
			targetDevice = &device
			break
		}
	}

	if targetDevice == nil {
		return nil, fmt.Errorf("device not found in scan results")
	}

	// Check if already in inventory
	if targetDevice.InInventory {
		return nil, fmt.Errorf("device already in inventory")
	}

	// Check if asset already exists (double check)
	var existingAsset models.Asset
	err = s.db.Where("ip_address = ?", deviceIP).First(&existingAsset).Error
	if err == nil {
		// Update existing asset
		existingAsset.LastSeen = time.Now()
		existingAsset.Status = "online"
		if targetDevice.Hostname != "" {
			existingAsset.Name = targetDevice.Hostname
		}
		if targetDevice.Vendor != "" {
			existingAsset.Vendor = targetDevice.Vendor
		}
		if targetDevice.Model != "" {
			existingAsset.Model = targetDevice.Model
		}
		if targetDevice.Protocol != "" {
			existingAsset.Protocol = targetDevice.Protocol
		}
		if targetDevice.DeviceType != "" {
			existingAsset.AssetType = targetDevice.DeviceType
		}
		
		if err := s.db.Save(&existingAsset).Error; err != nil {
			return nil, err
		}
		return &existingAsset, nil
	}

	// Create new asset
	asset := &models.Asset{
		ID:          uuid.New(),
		Name:        targetDevice.Hostname,
		AssetType:   targetDevice.DeviceType,
		IPAddress:   targetDevice.IPAddress,
		MACAddress:  targetDevice.MACAddress,
		Protocol:    targetDevice.Protocol,
		Vendor:      targetDevice.Vendor,
		Model:       targetDevice.Model,
		Status:      "online",
		LastSeen:    time.Now(),
		Criticality: "medium",
	}

	if asset.Name == "" {
		asset.Name = fmt.Sprintf("%s Device %s", targetDevice.DeviceType, targetDevice.IPAddress)
	}

	if asset.AssetType == "" {
		asset.AssetType = "Unknown Device"
	}

	// Add port information as attributes
	for _, port := range targetDevice.OpenPorts {
		attribute := &models.AssetAttribute{
			ID:        uuid.New(),
			AssetID:   asset.ID,
			Key:       fmt.Sprintf("port_%d", port.Port),
			Value:     port.Service,
			ValueType: "string",
		}
		asset.Attributes = append(asset.Attributes, *attribute)
	}

	if err := s.db.Create(asset).Error; err != nil {
		return nil, err
	}

	s.logger.Info("Device added to inventory", "ip", deviceIP, "asset_id", asset.ID.String())

	return asset, nil
}

// processResults processes scan results in the background - FIXED
func (s *ScanService) processResults(activeScan *ActiveScan) {
	resultChan := activeScan.Scanner.GetResults()
	
	for result := range resultChan {
		activeScan.mu.Lock()
		activeScan.Results = append(activeScan.Results, result)
		currentResultCount := len(activeScan.Results)
		activeScan.mu.Unlock()

		// Check if device already exists in inventory
		s.checkExistingDevice(result)

		// Send WebSocket notification for discovered device
		websocket.BroadcastDeviceFound(
			activeScan.ID,
			result.IPAddress,
			result.DeviceType,
			result.Protocol,
			result.Vendor,
		)

		// Log discovery
		s.logger.Info("Device discovered",
			"scan_id", activeScan.ID,
			"ip", result.IPAddress,
			"type", result.DeviceType,
			"protocol", result.Protocol,
			"result_count", currentResultCount)
	}
}

// monitorProgress monitors scan progress and updates database - FIXED
func (s *ScanService) monitorProgress(activeScan *ActiveScan) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			progress := activeScan.Scanner.GetProgress()
			
			// Calculate progress percentage
			var progressPct float64
			if progress.TotalHosts > 0 {
				progressPct = float64(progress.ScannedHosts) / float64(progress.TotalHosts) * 100
			}
			
			// Broadcast progress via WebSocket
			websocket.BroadcastScanProgress(
				activeScan.ID,
				progressPct,
				progress.TotalHosts,
				progress.ScannedHosts,
				progress.DiscoveredHosts,
				progress.ElapsedTime.String(),
			)
			
			// Update database
			activeScan.ScanDB.Status = string(progress.Status)
			activeScan.ScanDB.DevicesFound = progress.DiscoveredHosts
			
			if progress.Status == scanner.StatusCompleted || 
			   progress.Status == scanner.StatusFailed || 
			   progress.Status == scanner.StatusCancelled {
				
				// Final update
				endTime := time.Now()
				activeScan.ScanDB.EndTime = &endTime
				activeScan.ScanDB.Duration = int64(progress.ElapsedTime.Seconds())
				
				// Save results - IMPORTANT: Lock before accessing Results
				activeScan.mu.Lock()
				resultsJSON, err := json.Marshal(activeScan.Results)
				if err != nil {
					s.logger.Error("Failed to marshal scan results", "error", err)
				} else {
					activeScan.ScanDB.Results = string(resultsJSON)
					s.logger.Info("Saving scan results", 
						"scan_id", activeScan.ID, 
						"device_count", len(activeScan.Results),
						"status", progress.Status)
				}
				activeScan.mu.Unlock()
				
				if progress.Status == scanner.StatusFailed && len(progress.Errors) > 0 {
					activeScan.ScanDB.ErrorMsg = progress.Errors[0]
				}
				
				// Save to database
				if err := s.db.Save(activeScan.ScanDB).Error; err != nil {
					s.logger.Error("Failed to save scan results", "error", err)
				} else {
					s.logger.Info("Scan completed and saved", 
						"scan_id", activeScan.ID,
						"devices_found", activeScan.ScanDB.DevicesFound)
				}
				
				// Send completion notification
				if progress.Status == scanner.StatusCompleted {
					websocket.BroadcastScanComplete(activeScan.ID, progress.DiscoveredHosts)
				} else if progress.Status == scanner.StatusFailed {
					websocket.BroadcastScanError(activeScan.ID, activeScan.ScanDB.ErrorMsg)
				}
				
				// Clear active scan
				s.mu.Lock()
				if s.activeScan != nil && s.activeScan.ID == activeScan.ID {
					s.activeScan = nil
				}
				s.mu.Unlock()
				
				return
			}
			
			// Save progress to database
			if err := s.db.Save(activeScan.ScanDB).Error; err != nil {
				s.logger.Error("Failed to update scan progress", "error", err)
			}
		}
	}
}

// checkExistingDevice checks if device already exists in inventory
func (s *ScanService) checkExistingDevice(device *scanner.DeviceResult) {
	var existingAsset models.Asset
	err := s.db.Where("ip_address = ?", device.IPAddress).First(&existingAsset).Error
	if err == nil {
		device.IsNew = false
		device.Fingerprint["existing_asset_id"] = existingAsset.ID.String()
	} else {
		device.IsNew = true
	}
}

// convertToDiscoveredDevice converts scanner result to UI model
func (s *ScanService) convertToDiscoveredDevice(result *scanner.DeviceResult) DiscoveredDevice {
	device := DiscoveredDevice{
		ID:           uuid.New().String(),
		IPAddress:    result.IPAddress,
		MACAddress:   result.MACAddress,
		Hostname:     result.Hostname,
		DeviceType:   result.DeviceType,
		Vendor:       result.Vendor,
		Model:        result.Model,
		Protocol:     result.Protocol,
		OpenPorts:    result.OpenPorts,
		ResponseTime: result.ResponseTime.String(),
		IsNew:        result.IsNew,
		Fingerprint:  result.Fingerprint,
	}

	if existingID, ok := result.Fingerprint["existing_asset_id"].(string); ok {
		device.ExistingID = existingID
	}

	return device
}

// GetActiveScan returns the currently active scan if any
func (s *ScanService) GetActiveScan() *ActiveScan {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.activeScan
}

// CleanupOldScans removes old scan records from history
func (s *ScanService) CleanupOldScans(daysToKeep int) error {
	cutoffDate := time.Now().AddDate(0, 0, -daysToKeep)
	
	// Delete old scan records
	if err := s.db.Where("created_at < ?", cutoffDate).Delete(&models.NetworkScan{}).Error; err != nil {
		return fmt.Errorf("failed to cleanup old scans: %w", err)
	}
	
	// Clean up in-memory history
	s.mu.Lock()
	defer s.mu.Unlock()
	
	for id, scan := range s.scanHistory {
		if scan.CreatedAt.Before(cutoffDate) {
			delete(s.scanHistory, id)
		}
	}
	
	return nil
}

// GetScanStatistics returns overall scan statistics
func (s *ScanService) GetScanStatistics() (map[string]interface{}, error) {
	stats := make(map[string]interface{})
	
	// Total scans
	var totalScans int64
	s.db.Model(&models.NetworkScan{}).Count(&totalScans)
	stats["total_scans"] = totalScans
	
	// Successful scans
	var successfulScans int64
	s.db.Model(&models.NetworkScan{}).Where("status = ?", "completed").Count(&successfulScans)
	stats["successful_scans"] = successfulScans
	
	// Failed scans
	var failedScans int64
	s.db.Model(&models.NetworkScan{}).Where("status = ?", "failed").Count(&failedScans)
	stats["failed_scans"] = failedScans
	
	// Total devices discovered
	var totalDevices int64
	s.db.Model(&models.NetworkScan{}).Select("SUM(devices_found)").Scan(&totalDevices)
	stats["total_devices_discovered"] = totalDevices
	
	// Average scan duration
	var avgDuration float64
	s.db.Model(&models.NetworkScan{}).Where("duration > 0").Select("AVG(duration)").Scan(&avgDuration)
	stats["average_scan_duration"] = avgDuration
	
	// Most common protocols
	var protocols []struct {
		Protocol string
		Count    int64
	}
	s.db.Model(&models.Asset{}).
		Select("protocol, count(*) as count").
		Where("protocol != ''").
		Group("protocol").
		Order("count DESC").
		Limit(5).
		Scan(&protocols)
	stats["top_protocols"] = protocols
	
	return stats, nil
}

// ValidateIPRange validates if the IP range is valid and accessible
func (s *ScanService) ValidateIPRange(ipRange string) error {
	// Parse and validate IP range
	hosts, err := s.parseIPRange(ipRange)
	if err != nil {
		return fmt.Errorf("invalid IP range: %w", err)
	}
	
	if len(hosts) == 0 {
		return fmt.Errorf("no valid hosts in IP range")
	}
	
	if len(hosts) > 65536 {
		return fmt.Errorf("IP range too large (max 65536 hosts)")
	}
	
	s.logger.Info("Validated IP range", "input", ipRange, "host_count", len(hosts))
	
	return nil
}

// parseIPRange is a helper method to parse IP ranges
func (s *ScanService) parseIPRange(ipRange string) ([]string, error) {
	var hosts []string
	hostMap := make(map[string]bool) // To avoid duplicates

	// Split by comma for multiple entries
	entries := strings.Split(ipRange, ",")
	
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		// Check if it's a range (e.g., 192.168.1.1-192.168.1.10)
		if strings.Contains(entry, "-") {
			parts := strings.Split(entry, "-")
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid range format: %s", entry)
			}
			
			startIP := net.ParseIP(strings.TrimSpace(parts[0]))
			endIP := net.ParseIP(strings.TrimSpace(parts[1]))
			
			if startIP == nil || endIP == nil {
				return nil, fmt.Errorf("invalid IP in range: %s", entry)
			}
			
			// Convert IPs to uint32 for comparison
			start := ipToUint32(startIP.To4())
			end := ipToUint32(endIP.To4())
			
			if start > end {
				return nil, fmt.Errorf("invalid range: start IP is greater than end IP")
			}
			
			// Generate all IPs in range
			for i := start; i <= end; i++ {
				ip := uint32ToIP(i).String()
				if !hostMap[ip] {
					hostMap[ip] = true
					hosts = append(hosts, ip)
				}
			}
			
		} else if _, ipNet, err := net.ParseCIDR(entry); err == nil {
			// CIDR notation (e.g., 192.168.1.0/24)
			for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
				// Skip network and broadcast addresses for /24 and smaller
				ones, _ := ipNet.Mask.Size()
				if ones >= 24 && (ip[3] == 0 || ip[3] == 255) {
					continue
				}
				ipStr := ip.String()
				if !hostMap[ipStr] {
					hostMap[ipStr] = true
					hosts = append(hosts, ipStr)
				}
			}
			
		} else if ip := net.ParseIP(entry); ip != nil {
			// Single IP (e.g., 192.168.1.100)
			ipStr := ip.String()
			if !hostMap[ipStr] {
				hostMap[ipStr] = true
				hosts = append(hosts, ipStr)
			}
			
		} else {
			return nil, fmt.Errorf("invalid IP format: %s", entry)
		}
	}

	if len(hosts) == 0 {
		return nil, fmt.Errorf("no valid hosts found in input")
	}

	return hosts, nil
}

// Helper functions for IP range parsing
func ipToUint32(ip net.IP) uint32 {
	if len(ip) == 4 {
		return uint32(ip[0])<<24 + uint32(ip[1])<<16 + uint32(ip[2])<<8 + uint32(ip[3])
	}
	return 0
}

func uint32ToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

// incrementIP increments an IP address
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}