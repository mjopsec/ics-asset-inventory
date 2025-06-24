// internal/services/monitoring_service.go
package services

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"ics-asset-inventory/internal/database"
	"ics-asset-inventory/internal/database/models"
	"ics-asset-inventory/internal/utils"
	"ics-asset-inventory/internal/websocket"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// MonitoringService handles real-time asset status monitoring
type MonitoringService struct {
	db              *gorm.DB
	logger          *utils.Logger
	monitoringTasks map[string]*MonitoringTask
	mu              sync.RWMutex
	config          *MonitoringConfig
}

// MonitoringConfig contains monitoring configuration
type MonitoringConfig struct {
	// Monitoring intervals based on asset criticality
	CriticalInterval time.Duration // 5 minutes for critical assets
	HighInterval     time.Duration // 10 minutes for high priority
	MediumInterval   time.Duration // 15 minutes for medium priority
	LowInterval      time.Duration // 30 minutes for low priority
	
	// Monitoring settings
	EnablePassive    bool          // Enable passive monitoring
	MaxRetries       int           // Max retries for connection
	ConnectionTimeout time.Duration // Connection timeout
	
	// ICS/OT Safety settings
	UseReadOnly      bool          // Only read operations
	RespectQuietHours bool         // Respect operational quiet hours
	MaxConcurrent    int           // Max concurrent checks
}

// MonitoringTask represents a monitoring task for an asset
type MonitoringTask struct {
	AssetID      string
	Asset        *models.Asset
	Interval     time.Duration
	LastCheck    time.Time
	NextCheck    time.Time
	IsActive     bool
	CheckMethod  string // "active" or "passive"
	ticker       *time.Ticker
	stopChan     chan bool
}

// AssetStatusUpdate represents a status update for an asset
type AssetStatusUpdate struct {
	AssetID      string    `json:"asset_id"`
	AssetName    string    `json:"asset_name"`
	IPAddress    string    `json:"ip_address"`
	OldStatus    string    `json:"old_status"`
	NewStatus    string    `json:"new_status"`
	ResponseTime int64     `json:"response_time"` // in milliseconds
	Timestamp    time.Time `json:"timestamp"`
	CheckMethod  string    `json:"check_method"`
}

// NewMonitoringService creates a new monitoring service
func NewMonitoringService() *MonitoringService {
	// ICS/OT safe default configuration
	config := &MonitoringConfig{
		CriticalInterval:  5 * time.Minute,
		HighInterval:      10 * time.Minute,
		MediumInterval:    15 * time.Minute,
		LowInterval:       30 * time.Minute,
		EnablePassive:     true,
		MaxRetries:        2,
		ConnectionTimeout: 5 * time.Second,
		UseReadOnly:       true,
		RespectQuietHours: true,
		MaxConcurrent:     10,
	}
	
	return &MonitoringService{
		db:              database.GetDB(),
		logger:          utils.NewLogger(),
		monitoringTasks: make(map[string]*MonitoringTask),
		config:          config,
	}
}

// StartMonitoring starts monitoring for all active assets
func (s *MonitoringService) StartMonitoring() error {
	s.logger.Info("Starting asset monitoring service")
	
	// Load all assets that need monitoring
	var assets []models.Asset
	err := s.db.Where("status != ?", "decommissioned").Find(&assets).Error
	if err != nil {
		return fmt.Errorf("failed to load assets: %w", err)
	}
	
	// Start monitoring for each asset
	for _, asset := range assets {
		s.StartAssetMonitoring(&asset)
	}
	
	// Start the monitoring scheduler
	go s.runScheduler()
	
	s.logger.Info("Asset monitoring service started", "assets_count", len(assets))
	
	return nil
}

// StartAssetMonitoring starts monitoring for a specific asset
func (s *MonitoringService) StartAssetMonitoring(asset *models.Asset) {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	// Skip if already monitoring
	if _, exists := s.monitoringTasks[asset.ID.String()]; exists {
		return
	}
	
	// Determine monitoring interval based on criticality
	interval := s.getMonitoringInterval(asset.Criticality)
	
	// Determine check method based on asset type and settings
	checkMethod := "active"
	if s.config.EnablePassive && s.isPassiveCompatible(asset) {
		checkMethod = "passive"
	}
	
	task := &MonitoringTask{
		AssetID:     asset.ID.String(),
		Asset:       asset,
		Interval:    interval,
		LastCheck:   time.Now(),
		NextCheck:   time.Now().Add(interval),
		IsActive:    true,
		CheckMethod: checkMethod,
		stopChan:    make(chan bool),
	}
	
	s.monitoringTasks[asset.ID.String()] = task
	
	// Start individual monitoring goroutine
	go s.monitorAsset(task)
	
	s.logger.Info("Started monitoring for asset",
		"asset_id", asset.ID,
		"asset_name", asset.Name,
		"interval", interval,
		"method", checkMethod)
}

// StopAssetMonitoring stops monitoring for a specific asset
func (s *MonitoringService) StopAssetMonitoring(assetID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if task, exists := s.monitoringTasks[assetID]; exists {
		task.IsActive = false
		close(task.stopChan)
		delete(s.monitoringTasks, assetID)
		
		s.logger.Info("Stopped monitoring for asset", "asset_id", assetID)
	}
}

// monitorAsset monitors a single asset
func (s *MonitoringService) monitorAsset(task *MonitoringTask) {
	// Use ticker for regular checks
	ticker := time.NewTicker(task.Interval)
	defer ticker.Stop()
	
	// Perform initial check
	s.checkAssetStatus(task)
	
	for {
		select {
		case <-ticker.C:
			// Check if we should respect quiet hours
			if s.config.RespectQuietHours && s.isQuietHours() {
				s.logger.Debug("Skipping check during quiet hours", "asset_id", task.AssetID)
				continue
			}
			
			// Perform status check
			s.checkAssetStatus(task)
			
		case <-task.stopChan:
			s.logger.Debug("Stopping monitor for asset", "asset_id", task.AssetID)
			return
		}
	}
}

// checkAssetStatus performs the actual status check
func (s *MonitoringService) checkAssetStatus(task *MonitoringTask) {
	startTime := time.Now()
	
	// Get current status from database
	var asset models.Asset
	if err := s.db.First(&asset, "id = ?", task.AssetID).Error; err != nil {
		s.logger.Error("Failed to fetch asset", "asset_id", task.AssetID, "error", err)
		return
	}
	
	oldStatus := asset.Status
	newStatus := "offline"
	responseTime := int64(0)
	
	// Perform the appropriate check based on method
	if task.CheckMethod == "passive" {
		// For passive monitoring, check last seen time
		// If device hasn't been seen in 2x the interval, consider it offline
		if time.Since(asset.LastSeen) < task.Interval*2 {
			newStatus = "online"
		}
	} else {
		// Active check - try to connect to the device
		if s.isAssetReachable(&asset) {
			newStatus = "online"
			responseTime = time.Since(startTime).Milliseconds()
		}
	}
	
	// Update status if changed
	if oldStatus != newStatus {
		// Update database
		updates := map[string]interface{}{
			"status": newStatus,
		}
		
		if newStatus == "online" {
			updates["last_seen"] = time.Now()
			updates["uptime"] = time.Since(asset.LastSeen).Seconds()
		}
		
		if err := s.db.Model(&asset).Updates(updates).Error; err != nil {
			s.logger.Error("Failed to update asset status", "asset_id", task.AssetID, "error", err)
			return
		}
		
		// Create status update event
		statusUpdate := AssetStatusUpdate{
			AssetID:      asset.ID.String(),
			AssetName:    asset.Name,
			IPAddress:    asset.IPAddress,
			OldStatus:    oldStatus,
			NewStatus:    newStatus,
			ResponseTime: responseTime,
			Timestamp:    time.Now(),
			CheckMethod:  task.CheckMethod,
		}
		
		// Broadcast status change via WebSocket
		s.broadcastStatusUpdate(statusUpdate)
		
		// Log status change
		s.logger.Info("Asset status changed",
			"asset_id", asset.ID,
			"asset_name", asset.Name,
			"old_status", oldStatus,
			"new_status", newStatus,
			"response_time", responseTime)
		
		// Create alert if asset went offline and is critical
		if newStatus == "offline" && asset.Criticality == "critical" {
			s.createCriticalAssetAlert(&asset)
		}
	}
	
	// Update last check time
	task.LastCheck = time.Now()
	task.NextCheck = time.Now().Add(task.Interval)
}

// isAssetReachable checks if an asset is reachable
func (s *MonitoringService) isAssetReachable(asset *models.Asset) bool {
	if asset.IPAddress == "" {
		return false
	}
	
	// For ICS/OT safety, use appropriate check based on protocol
	switch asset.Protocol {
	case "Modbus TCP":
		return s.checkModbusTCP(asset.IPAddress, 502)
	case "DNP3":
		return s.checkTCPPort(asset.IPAddress, 20000)
	case "EtherNet/IP":
		return s.checkTCPPort(asset.IPAddress, 44818)
	case "BACnet":
		return s.checkUDPPort(asset.IPAddress, 47808)
	case "Siemens S7":
		return s.checkTCPPort(asset.IPAddress, 102)
	case "SNMP":
		return s.checkSNMP(asset.IPAddress)
	default:
		// Default to simple TCP check on known port or ICMP
		if asset.Port > 0 {
			return s.checkTCPPort(asset.IPAddress, uint16(asset.Port))
		}
		return s.checkICMP(asset.IPAddress)
	}
}

// checkTCPPort performs a simple TCP port check
func (s *MonitoringService) checkTCPPort(ip string, port uint16) bool {
	address := fmt.Sprintf("%s:%d", ip, port)
	
	conn, err := net.DialTimeout("tcp", address, s.config.ConnectionTimeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	
	return true
}

// checkUDPPort performs a simple UDP port check
func (s *MonitoringService) checkUDPPort(ip string, port uint16) bool {
	address := fmt.Sprintf("%s:%d", ip, port)
	
	conn, err := net.DialTimeout("udp", address, s.config.ConnectionTimeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	
	// For UDP, we might need to send a protocol-specific packet
	// For now, just return true if connection succeeded
	return true
}

// checkModbusTCP performs a Modbus-specific check (read-only)
func (s *MonitoringService) checkModbusTCP(ip string, port uint16) bool {
	// For ICS safety, we only establish connection, not send commands
	return s.checkTCPPort(ip, port)
}

// checkSNMP performs SNMP availability check
func (s *MonitoringService) checkSNMP(ip string) bool {
	// Simple SNMP check - just verify port is open
	return s.checkUDPPort(ip, 161)
}

// checkICMP performs ICMP ping check
func (s *MonitoringService) checkICMP(ip string) bool {
	// For simplicity, using TCP check on common port
	// In production, implement proper ICMP
	return s.checkTCPPort(ip, 80) || s.checkTCPPort(ip, 443)
}

// getMonitoringInterval returns interval based on criticality
func (s *MonitoringService) getMonitoringInterval(criticality string) time.Duration {
	switch criticality {
	case "critical":
		return s.config.CriticalInterval
	case "high":
		return s.config.HighInterval
	case "medium":
		return s.config.MediumInterval
	case "low":
		return s.config.LowInterval
	default:
		return s.config.MediumInterval
	}
}

// isPassiveCompatible checks if asset supports passive monitoring
func (s *MonitoringService) isPassiveCompatible(asset *models.Asset) bool {
	// Assets that generate regular traffic are good for passive monitoring
	passiveProtocols := []string{"SNMP", "Modbus TCP", "EtherNet/IP"}
	
	for _, protocol := range passiveProtocols {
		if asset.Protocol == protocol {
			return true
		}
	}
	
	return false
}

// isQuietHours checks if current time is in quiet hours
func (s *MonitoringService) isQuietHours() bool {
	now := time.Now()
	hour := now.Hour()
	
	// Define quiet hours (e.g., 2 AM - 5 AM)
	// This should be configurable in production
	return hour >= 2 && hour < 5
}

// broadcastStatusUpdate sends status update via WebSocket
func (s *MonitoringService) broadcastStatusUpdate(update AssetStatusUpdate) {
	hub := websocket.GetHub()
	
	// Create WebSocket message
	message := map[string]interface{}{
		"type": "asset_status_update",
		"data": update,
	}
	
	jsonData, err := json.Marshal(message)
	if err != nil {
		s.logger.Error("Failed to marshal status update", "error", err)
		return
	}
	
	hub.BroadcastMessage("asset_status_update", jsonData)
}

// createCriticalAssetAlert creates an alert for critical asset going offline
func (s *MonitoringService) createCriticalAssetAlert(asset *models.Asset) {
	alert := &models.SecurityAssessment{
		ID:          uuid.New(),
		AssetID:     asset.ID,
		ScanDate:    time.Now(),
		ScanType:    "monitoring",
		Severity:    "critical",
		Title:       fmt.Sprintf("Critical Asset Offline: %s", asset.Name),
		Description: fmt.Sprintf("Critical asset %s (%s) is not responding to monitoring checks", asset.Name, asset.IPAddress),
		Status:      "open",
		Remediation: "Investigate network connectivity and device status immediately",
	}
	
	if err := s.db.Create(alert).Error; err != nil {
		s.logger.Error("Failed to create critical asset alert", "error", err)
	}
}

// runScheduler runs the monitoring scheduler
func (s *MonitoringService) runScheduler() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		s.mu.RLock()
		activeCount := 0
		for _, task := range s.monitoringTasks {
			if task.IsActive {
				activeCount++
			}
		}
		s.mu.RUnlock()
		
		s.logger.Debug("Monitoring scheduler status", "active_tasks", activeCount)
	}
}

// GetMonitoringStatus returns current monitoring status
func (s *MonitoringService) GetMonitoringStatus() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	status := map[string]interface{}{
		"active_monitors":    len(s.monitoringTasks),
		"monitoring_enabled": true,
		"passive_enabled":    s.config.EnablePassive,
		"intervals": map[string]string{
			"critical": s.config.CriticalInterval.String(),
			"high":     s.config.HighInterval.String(),
			"medium":   s.config.MediumInterval.String(),
			"low":      s.config.LowInterval.String(),
		},
	}
	
	// Count by criticality
	criticalityCount := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
	}
	
	for _, task := range s.monitoringTasks {
		if task.Asset != nil {
			criticalityCount[task.Asset.Criticality]++
		}
	}
	
	status["monitors_by_criticality"] = criticalityCount
	
	return status
}

// UpdateMonitoringConfig updates monitoring configuration
func (s *MonitoringService) UpdateMonitoringConfig(config *MonitoringConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	s.config = config
	
	// Restart monitoring tasks with new intervals
	for _, task := range s.monitoringTasks {
		task.Interval = s.getMonitoringInterval(task.Asset.Criticality)
	}
	
	s.logger.Info("Monitoring configuration updated")
}
