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
	stopped  bool
}

// ScanRequest represents a scan configuration request - FIXED VALIDATION
type ScanRequest struct {
	IPRange       string   `json:"ip_range" binding:"required"`
	ScanType      string   `json:"scan_type" binding:"required,oneof=industrial network custom"`
	ScanMode      string   `json:"scan_mode"`
	Timeout       int      `json:"timeout"`            // Removed min validation
	MaxConcurrent int      `json:"max_concurrent"`     // Removed min validation
	Protocols     []string `json:"protocols"`          // Removed all validation
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
	ScannedPorts    int           `json:"scanned_ports"`
	TotalPorts      int           `json:"total_ports"`
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

// StartScan initiates a new network scan - COMPLETELY REMOVED PROTOCOL VALIDATION
func (s *ScanService) StartScan(req *ScanRequest) (*ScanResponse, error) {
	// Log the incoming request for debugging
	s.logger.Info("Received scan request",
		"ip_range", req.IPRange,
		"scan_type", req.ScanType,
		"protocols", req.Protocols,
		"port_ranges", len(req.PortRanges))

	// Check and stop any existing scan
	s.mu.Lock()
	if s.activeScan != nil {
		s.logger.Info("Stopping previous active scan", "scan_id", s.activeScan.ID)
		s.activeScan.stopped = true
		if s.activeScan.Scanner != nil {
			s.activeScan.Scanner.Stop()
		}
		
		// Mark the previous scan as cancelled in database
		if s.activeScan.ScanDB != nil {
			s.activeScan.ScanDB.Status = string(scanner.StatusCancelled)
			endTime := time.Now()
			s.activeScan.ScanDB.EndTime = &endTime
			s.activeScan.ScanDB.Duration = int64(time.Since(s.activeScan.ScanDB.StartTime).Seconds())
			s.db.Save(s.activeScan.ScanDB)
		}
		
		// Clear the active scan
		s.activeScan = nil
		
		// Small delay to ensure cleanup
		time.Sleep(500 * time.Millisecond)
	}
	s.mu.Unlock()

	// Validate IP range
	if err := s.ValidateIPRange(req.IPRange); err != nil {
		return nil, err
	}

	// Set default scan mode if not provided
	if req.ScanMode == "" {
		req.ScanMode = "active"
	}

	// Set default timeout if not provided or too low
	if req.Timeout <= 0 || req.Timeout < 10 {
		req.Timeout = 30
	}

	// Set default max concurrent if not provided
	if req.MaxConcurrent <= 0 {
		req.MaxConcurrent = 20
	}

	// Create scan configuration
	config := &scanner.ScanConfig{
		IPRange:       req.IPRange,
		ScanType:      scanner.ScanType(req.ScanType),
		ScanMode:      scanner.ScanMode(req.ScanMode),
		Timeout:       time.Duration(req.Timeout) * time.Second,
		MaxConcurrent: req.MaxConcurrent,
		RetryAttempts: 2,
	}

	// NO PROTOCOL VALIDATION - protocols are completely optional
	
	// Port ranges handling
	if len(req.PortRanges) > 0 {
		config.PortRanges = make([]scanner.PortRange, len(req.PortRanges))
		for i, pr := range req.PortRanges {
			config.PortRanges[i] = scanner.PortRange{
				Start: pr.Start,
				End:   pr.End,
			}
		}
	} else {
		// If no port ranges provided, use defaults based on scan type
		switch req.ScanType {
		case "industrial":
			config.PortRanges = []scanner.PortRange{
				{Start: 102, End: 102},     // S7
				{Start: 502, End: 502},     // Modbus
				{Start: 1911, End: 1911},   // Niagara Fox
				{Start: 2222, End: 2222},   // EtherNet/IP Alt
				{Start: 2404, End: 2404},   // IEC-104
				{Start: 4840, End: 4840},   // OPC UA
				{Start: 20000, End: 20000}, // DNP3
				{Start: 20547, End: 20547}, // DNP3 Alt
				{Start: 44818, End: 44818}, // EtherNet/IP
				{Start: 47808, End: 47808}, // BACnet
			}
		case "network":
			config.PortRanges = []scanner.PortRange{
				// Common network ports
				{Start: 22, End: 23},       // SSH, Telnet
				{Start: 80, End: 80},       // HTTP
				{Start: 161, End: 162},     // SNMP
				{Start: 443, End: 443},     // HTTPS
				{Start: 3389, End: 3389},   // RDP
				// Industrial ports
				{Start: 102, End: 102},     // S7
				{Start: 502, End: 502},     // Modbus
				{Start: 1911, End: 1911},   // Niagara Fox
				{Start: 2222, End: 2222},   // EtherNet/IP Alt
				{Start: 2404, End: 2404},   // IEC-104
				{Start: 20000, End: 20000}, // DNP3
				{Start: 44818, End: 44818}, // EtherNet/IP
				{Start: 47808, End: 47808}, // BACnet
			}
		case "custom":
			// For custom, we expect port ranges to be provided
			if len(config.PortRanges) == 0 {
				return nil, fmt.Errorf("custom scan requires port ranges to be specified")
			}
		}
	}

	// Set protocols for passive scanning filter (optional)
	if len(req.Protocols) > 0 {
		config.Protocols = req.Protocols
	}

	// Log total ports to scan
	totalPorts := s.calculateTotalPorts(config.PortRanges)
	s.logger.Info("Scan configuration finalized",
		"ip_range", req.IPRange,
		"scan_type", req.ScanType,
		"scan_mode", req.ScanMode,
		"timeout", req.Timeout,
		"port_ranges", len(config.PortRanges),
		"total_ports", totalPorts)

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
		stopped: false,
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
		
		s.mu.Lock()
		s.activeScan = nil
		s.mu.Unlock()
		
		return nil, err
	}

	// Start result processor in background
	go s.processResults(activeScan)

	// Start progress monitor with WebSocket broadcasting
	go s.monitorProgress(activeScan)

	s.logger.Info("Scan started successfully", "scan_id", scanDB.ID.String(), "target", req.IPRange)

	return &ScanResponse{
		ScanID:    scanDB.ID.String(),
		Status:    scanDB.Status,
		Message:   "Scan started successfully",
		StartTime: scanDB.StartTime,
	}, nil
}

// calculateTotalPorts calculates total ports from port ranges
func (s *ScanService) calculateTotalPorts(portRanges []scanner.PortRange) int {
	total := 0
	for _, pr := range portRanges {
		total += int(pr.End - pr.Start + 1)
	}
	return total
}

// processResults processes scan results in the background
func (s *ScanService) processResults(activeScan *ActiveScan) {
	resultChan := activeScan.Scanner.GetResults()
	deviceCount := 0
	
	// Create a local map to track processed devices
	processedDevices := make(map[string]bool)
	
	for result := range resultChan {
		// Check if scan was stopped
		activeScan.mu.Lock()
		if activeScan.stopped {
			activeScan.mu.Unlock()
			s.logger.Info("Scan was stopped, ignoring remaining results", "scan_id", activeScan.ID)
			break
		}
		activeScan.mu.Unlock()

		// Skip if already processed (duplicate check)
		if processedDevices[result.IPAddress] {
			s.logger.Debug("Skipping duplicate device", "ip", result.IPAddress)
			continue
		}
		processedDevices[result.IPAddress] = true

		deviceCount++
		
		// Store the result with proper locking
		activeScan.mu.Lock()
		activeScan.Results = append(activeScan.Results, result)
		currentResultCount := len(activeScan.Results)
		activeScan.mu.Unlock()

		// Check if device already exists in inventory
		s.checkExistingDevice(result)

		// Update asset status if device exists in inventory
		if !result.IsNew && result.IPAddress != "" {
			s.updateAssetOnlineStatus(result.IPAddress, true)
		}

		// Log device discovery details
		s.logger.Info("Device discovered",
			"scan_id", activeScan.ID,
			"device_number", deviceCount,
			"ip", result.IPAddress,
			"type", result.DeviceType,
			"protocol", result.Protocol,
			"vendor", result.Vendor,
			"open_ports", len(result.OpenPorts),
			"is_new", result.IsNew,
			"result_count", currentResultCount)

		// Send WebSocket notification for discovered device
		websocket.BroadcastDeviceFound(
			activeScan.ID,
			result.IPAddress,
			result.DeviceType,
			result.Protocol,
			result.Vendor,
		)
		
		// Small delay to avoid overwhelming the system
		time.Sleep(10 * time.Millisecond)
	}
	
	s.logger.Info("Result processing completed", 
		"scan_id", activeScan.ID,
		"total_devices", deviceCount)
		
	// Ensure results are saved to database
	s.saveResultsToDatabase(activeScan)
}

// monitorProgress monitors scan progress and updates database
func (s *ScanService) monitorProgress(activeScan *ActiveScan) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	
	lastProgressLog := time.Now()
	lastSaveTime := time.Now()
	completionBroadcast := false

	for {
		select {
		case <-ticker.C:
			// Check if scan was stopped
			activeScan.mu.Lock()
			if activeScan.stopped {
				activeScan.mu.Unlock()
				s.logger.Info("Progress monitoring stopped for scan", "scan_id", activeScan.ID)
				return
			}
			activeScan.mu.Unlock()

			progress := activeScan.Scanner.GetProgress()
			
			// Calculate progress percentage based on ports scanned
			var progressPct float64
			if progress.TotalPorts > 0 {
				progressPct = float64(progress.ScannedPorts) / float64(progress.TotalPorts) * 100
			} else if progress.TotalHosts > 0 {
				progressPct = float64(progress.ScannedHosts) / float64(progress.TotalHosts) * 100
			}
			
			// Update discovered hosts count from actual results
			activeScan.mu.Lock()
			actualDiscoveredCount := len(activeScan.Results)
			activeScan.mu.Unlock()
			
			// Log progress every 10 seconds
			if time.Since(lastProgressLog) > 10*time.Second {
				s.logger.Info("Scan progress update",
					"scan_id", activeScan.ID,
					"progress", fmt.Sprintf("%.1f%%", progressPct),
					"scanned_hosts", progress.ScannedHosts,
					"total_hosts", progress.TotalHosts,
					"scanned_ports", progress.ScannedPorts,
					"total_ports", progress.TotalPorts,
					"discovered_hosts", actualDiscoveredCount,
					"open_ports", progress.OpenPorts,
					"elapsed", progress.ElapsedTime.String())
				lastProgressLog = time.Now()
			}
			
			// Broadcast enhanced progress via WebSocket
			s.broadcastEnhancedProgress(
				activeScan.ID,
				progressPct,
				progress.TotalHosts,
				progress.ScannedHosts,
				actualDiscoveredCount,
				progress.ScannedPorts,
				progress.TotalPorts,
				progress.ElapsedTime.String(),
			)
			
			// Update database
			activeScan.ScanDB.Status = string(progress.Status)
			activeScan.ScanDB.DevicesFound = actualDiscoveredCount
			
			// Save intermediate results every 30 seconds
			if time.Since(lastSaveTime) > 30*time.Second {
				s.saveResultsToDatabase(activeScan)
				lastSaveTime = time.Now()
			}
			
			// Check if scan is complete
			if progress.Status == scanner.StatusCompleted || 
			   progress.Status == scanner.StatusFailed || 
			   progress.Status == scanner.StatusCancelled {
				
				// Prevent multiple completion broadcasts
				if completionBroadcast {
					return
				}
				completionBroadcast = true
				
				// Final update
				endTime := time.Now()
				activeScan.ScanDB.EndTime = &endTime
				activeScan.ScanDB.Duration = int64(progress.ElapsedTime.Seconds())
				
				// Save final results
				s.saveResultsToDatabase(activeScan)
				
				if progress.Status == scanner.StatusFailed && len(progress.Errors) > 0 {
					activeScan.ScanDB.ErrorMsg = strings.Join(progress.Errors, "; ")
				}
				
				// Final save to database with retry
				saved := false
				for i := 0; i < 3; i++ {
					if err := s.db.Save(activeScan.ScanDB).Error; err != nil {
						s.logger.Error("Failed to save final scan results (attempt %d)", i+1, "error", err)
						time.Sleep(time.Second)
						continue
					}
					s.logger.Info("Scan completed and saved", 
						"scan_id", activeScan.ID,
						"devices_found", activeScan.ScanDB.DevicesFound,
						"status", progress.Status)
					saved = true
					break
				}
				
				// Send completion notification with delay to ensure data is saved
				if saved {
					time.Sleep(1 * time.Second)
					
					if progress.Status == scanner.StatusCompleted {
						// Send scan complete with results included
						s.broadcastScanCompleteWithResults(activeScan)
					} else if progress.Status == scanner.StatusFailed {
						websocket.BroadcastScanError(activeScan.ID, activeScan.ScanDB.ErrorMsg)
					}
				}
				
				// Update offline status for assets not found in scan
				s.updateOfflineAssets(activeScan)
				
				// Clear active scan
				s.mu.Lock()
				if s.activeScan != nil && s.activeScan.ID == activeScan.ID {
					s.logger.Info("Clearing active scan", "scan_id", activeScan.ID)
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

// broadcastEnhancedProgress broadcasts enhanced progress with port information
func (s *ScanService) broadcastEnhancedProgress(scanID string, progress float64, totalHosts, scannedHosts, discoveredHosts, scannedPorts, totalPorts int, elapsedTime string) {
	hub := websocket.GetHub()
	hub.BroadcastMessage("scan_progress", map[string]interface{}{
		"scan_id":          scanID,
		"progress":         progress,
		"total_hosts":      totalHosts,
		"scanned_hosts":    scannedHosts,
		"discovered_hosts": discoveredHosts,
		"scanned_ports":    scannedPorts,
		"total_ports":      totalPorts,
		"elapsed_time":     elapsedTime,
	})
}

// GetScanProgress returns the progress of a scan
func (s *ScanService) GetScanProgress(scanID string) (*ScanProgressResponse, error) {
	s.mu.RLock()
	activeScan := s.activeScan
	s.mu.RUnlock()

	if activeScan != nil && activeScan.ID == scanID {
		progress := activeScan.Scanner.GetProgress()
		
		// Get actual discovered count from results
		activeScan.mu.Lock()
		actualDiscoveredCount := len(activeScan.Results)
		activeScan.mu.Unlock()
		
		// Calculate progress percentage based on ports
		var progressPct float64
		if progress.TotalPorts > 0 {
			progressPct = float64(progress.ScannedPorts) / float64(progress.TotalPorts) * 100
		} else if progress.TotalHosts > 0 {
			progressPct = float64(progress.ScannedHosts) / float64(progress.TotalHosts) * 100
		}

		// Estimate remaining time
		var estimatedTime string
		if progress.ScannedPorts > 0 && progressPct < 100 {
			elapsed := progress.ElapsedTime
			rate := float64(progress.ScannedPorts) / elapsed.Seconds()
			remaining := float64(progress.TotalPorts-progress.ScannedPorts) / rate
			estimatedTime = time.Duration(remaining * float64(time.Second)).String()
		}

		return &ScanProgressResponse{
			ScanID:          scanID,
			Status:          string(progress.Status),
			Progress:        progressPct,
			TotalHosts:      progress.TotalHosts,
			ScannedHosts:    progress.ScannedHosts,
			DiscoveredHosts: actualDiscoveredCount,
			ScannedPorts:    progress.ScannedPorts,
			TotalPorts:      progress.TotalPorts,
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
		ScannedPorts:    0,
		TotalPorts:      0,
		ElapsedTime:     fmt.Sprintf("%d seconds", scanDB.Duration),
		EstimatedTime:   "0",
		Errors:          []string{},
	}, nil
}

// saveResultsToDatabase saves scan results to database
func (s *ScanService) saveResultsToDatabase(activeScan *ActiveScan) {
	activeScan.mu.Lock()
	defer activeScan.mu.Unlock()
	
	if len(activeScan.Results) > 0 {
		resultsJSON, err := json.Marshal(activeScan.Results)
		if err != nil {
			s.logger.Error("Failed to marshal scan results", "error", err)
			return
		}
		
		activeScan.ScanDB.Results = string(resultsJSON)
		activeScan.ScanDB.DevicesFound = len(activeScan.Results)
		
		if err := s.db.Save(activeScan.ScanDB).Error; err != nil {
			s.logger.Error("Failed to save scan results to database", "error", err)
		} else {
			s.logger.Info("Scan results saved to database", 
				"scan_id", activeScan.ID,
				"device_count", len(activeScan.Results))
		}
	}
}

// broadcastScanCompleteWithResults broadcasts scan completion with results
func (s *ScanService) broadcastScanCompleteWithResults(activeScan *ActiveScan) {
	// Convert results to discovered devices format
	devices := make([]DiscoveredDevice, 0)
	
	activeScan.mu.Lock()
	for _, result := range activeScan.Results {
		device := s.convertToDiscoveredDevice(result)
		
		// Check inventory status
		var existingAsset models.Asset
		err := s.db.Where("ip_address = ?", result.IPAddress).First(&existingAsset).Error
		if err == nil {
			device.InInventory = true
			device.AssetID = existingAsset.ID.String()
			device.IsNew = false
		} else {
			device.InInventory = false
			device.IsNew = true
		}
		
		devices = append(devices, device)
	}
	activeScan.mu.Unlock()
	
	s.logger.Info("Broadcasting scan complete with results", 
		"scan_id", activeScan.ID, 
		"device_count", len(devices))
	
	// Create enhanced completion message
	hub := websocket.GetHub()
	hub.BroadcastMessage("scan_complete_with_results", map[string]interface{}{
		"scan_id":       activeScan.ID,
		"devices_found": len(devices),
		"devices":       devices,
		"timestamp":     time.Now(),
	})
}

// checkExistingDevice checks if device already exists in inventory
func (s *ScanService) checkExistingDevice(device *scanner.DeviceResult) {
	if device.IPAddress == "" {
		return
	}
	
	var existingAsset models.Asset
	err := s.db.Where("ip_address = ?", device.IPAddress).First(&existingAsset).Error
	if err == nil {
		device.IsNew = false
		device.Fingerprint["existing_asset_id"] = existingAsset.ID.String()
		
		// Update last seen time
		updates := map[string]interface{}{
			"last_seen": time.Now(),
			"status": "online",
		}
		s.db.Model(&existingAsset).Updates(updates)
		
		s.logger.Debug("Device already exists in inventory", 
			"ip", device.IPAddress, 
			"asset_id", existingAsset.ID.String())
	} else {
		device.IsNew = true
		s.logger.Debug("New device discovered", "ip", device.IPAddress)
	}
}

// updateAssetOnlineStatus updates asset online/offline status
func (s *ScanService) updateAssetOnlineStatus(ipAddress string, isOnline bool) {
	if ipAddress == "" {
		return
	}
	
	var asset models.Asset
	if err := s.db.Where("ip_address = ?", ipAddress).First(&asset).Error; err != nil {
		s.logger.Debug("Asset not found for status update", "ip", ipAddress)
		return
	}
	
	updates := map[string]interface{}{
		"last_seen": time.Now(),
	}
	
	if isOnline {
		updates["status"] = "online"
	} else {
		updates["status"] = "offline"
	}
	
	if err := s.db.Model(&asset).Updates(updates).Error; err != nil {
		s.logger.Error("Failed to update asset status", "ip", ipAddress, "error", err)
	} else {
		s.logger.Debug("Asset status updated", "ip", ipAddress, "status", updates["status"])
	}
}

// StopScan stops the currently running scan
func (s *ScanService) StopScan(scanID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.activeScan == nil || s.activeScan.ID != scanID {
		return fmt.Errorf("no active scan with ID %s", scanID)
	}

	// Mark as stopped first
	s.activeScan.stopped = true
	
	// Stop the scanner
	s.activeScan.Scanner.Stop()
	
	// Update database status
	s.activeScan.ScanDB.Status = string(scanner.StatusCancelled)
	endTime := time.Now()
	s.activeScan.ScanDB.EndTime = &endTime
	
	// Save current results
	s.saveResultsToDatabase(s.activeScan)
	
	s.db.Save(s.activeScan.ScanDB)
	
	// Broadcast cancellation
	websocket.BroadcastScanError(scanID, "Scan cancelled by user")
	
	// Clear active scan
	s.activeScan = nil
	
	s.logger.Info("Scan stopped by user", "scan_id", scanID)
	
	return nil
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
	
	s.logger.Info("Loaded scan history", "count", len(scans))
	
	return scans, nil
}

// GetActiveScan returns the currently active scan if any
func (s *ScanService) GetActiveScan() *ActiveScan {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.activeScan
}

// GetScanResults returns the results of a scan
func (s *ScanService) GetScanResults(scanID string) ([]DiscoveredDevice, error) {
	// Check if this is the active scan
	s.mu.RLock()
	activeScan := s.activeScan
	s.mu.RUnlock()

	var devices []DiscoveredDevice

	if activeScan != nil && activeScan.ID == scanID {
		// Get results from active scan
		activeScan.mu.Lock()
		for _, result := range activeScan.Results {
			device := s.convertToDiscoveredDevice(result)
			
			// Check inventory status
			var existingAsset models.Asset
			err := s.db.Where("ip_address = ?", result.IPAddress).First(&existingAsset).Error
			if err == nil {
				device.InInventory = true
				device.AssetID = existingAsset.ID.String()
			} else {
				device.InInventory = false
			}
			
			devices = append(devices, device)
		}
		activeScan.mu.Unlock()
	} else {
		// Load from database
		var scanDB models.NetworkScan
		if err := s.db.First(&scanDB, "id = ?", scanID).Error; err != nil {
			return nil, fmt.Errorf("scan not found")
		}

		// Parse results from JSON
		if scanDB.Results != "" {
			var results []*scanner.DeviceResult
			if err := json.Unmarshal([]byte(scanDB.Results), &results); err != nil {
				return nil, fmt.Errorf("failed to parse scan results: %w", err)
			}

			for _, result := range results {
				device := s.convertToDiscoveredDevice(result)
				
				// Check inventory status
				var existingAsset models.Asset
				err := s.db.Where("ip_address = ?", result.IPAddress).First(&existingAsset).Error
				if err == nil {
					device.InInventory = true
					device.AssetID = existingAsset.ID.String()
				} else {
					device.InInventory = false
				}
				
				devices = append(devices, device)
			}
		}
	}

	return devices, nil
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

// updateOfflineAssets marks assets as offline if not found in scan
func (s *ScanService) updateOfflineAssets(activeScan *ActiveScan) {
	// Get all IPs from scan results
	foundIPs := make(map[string]bool)
	activeScan.mu.Lock()
	for _, result := range activeScan.Results {
		if result.IPAddress != "" {
			foundIPs[result.IPAddress] = true
		}
	}
	activeScan.mu.Unlock()
	
	// Parse target IP range to get expected IPs
	targetIPs, _ := s.parseIPRange(activeScan.ScanDB.Target)
	
	// Update assets in the scanned range that were not found
	for _, targetIP := range targetIPs {
		if !foundIPs[targetIP] {
			s.updateAssetOnlineStatus(targetIP, false)
		}
	}
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