package services

import (
	"fmt"
	"net"
	"sync"
	"time"

	"ics-asset-inventory/internal/database"
	"ics-asset-inventory/internal/database/models"
	"ics-asset-inventory/internal/utils"
	"ics-asset-inventory/internal/websocket"

	"gorm.io/gorm"
)

// MonitoringService handles real-time asset monitoring
type MonitoringService struct {
	db              *gorm.DB
	logger          *utils.Logger
	monitorInterval time.Duration
	stopChan        chan bool
	wg              sync.WaitGroup
	mu              sync.RWMutex
	isRunning       bool
}

// MonitoringConfig contains monitoring configuration
type MonitoringConfig struct {
	Interval        time.Duration
	Timeout         time.Duration
	MaxConcurrent   int
	EnableRealtime  bool
	SafeMode        bool // For ICS/OT environments
}

// AssetStatus represents current asset status
type AssetStatus struct {
	AssetID      string    `json:"asset_id"`
	IPAddress    string    `json:"ip_address"`
	Status       string    `json:"status"`
	ResponseTime int64     `json:"response_time_ms"`
	LastChecked  time.Time `json:"last_checked"`
	Protocol     string    `json:"protocol"`
	Port         int       `json:"port"`
}

// NewMonitoringService creates a new monitoring service
func NewMonitoringService(config *MonitoringConfig) *MonitoringService {
	if config == nil {
		config = &MonitoringConfig{
			Interval:      5 * time.Minute, // Default 5 minutes for ICS safety
			Timeout:       5 * time.Second,
			MaxConcurrent: 10,
			EnableRealtime: true,
			SafeMode:      true, // Default to safe mode for ICS
		}
	}

	return &MonitoringService{
		db:              database.GetDB(),
		logger:          utils.NewLogger(),
		monitorInterval: config.Interval,
		stopChan:        make(chan bool),
		isRunning:       false,
	}
}

// Start begins the monitoring service
func (s *MonitoringService) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isRunning {
		return fmt.Errorf("monitoring service is already running")
	}

	s.isRunning = true
	s.wg.Add(1)
	go s.monitoringLoop()

	s.logger.Info("Asset monitoring service started", "interval", s.monitorInterval)
	return nil
}

// Stop stops the monitoring service
func (s *MonitoringService) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isRunning {
		return fmt.Errorf("monitoring service is not running")
	}

	s.stopChan <- true
	s.wg.Wait()
	s.isRunning = false

	s.logger.Info("Asset monitoring service stopped")
	return nil
}

// monitoringLoop is the main monitoring loop
func (s *MonitoringService) monitoringLoop() {
	defer s.wg.Done()

	// Initial check
	s.checkAllAssets()

	ticker := time.NewTicker(s.monitorInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.checkAllAssets()
		case <-s.stopChan:
			return
		}
	}
}

// checkAllAssets checks the status of all assets
func (s *MonitoringService) checkAllAssets() {
	s.logger.Debug("Starting asset status check")
	startTime := time.Now()

	// Get all active assets with IP addresses
	var assets []models.Asset
	if err := s.db.Where("ip_address != ? AND ip_address IS NOT NULL", "").Find(&assets).Error; err != nil {
		s.logger.Error("Failed to fetch assets for monitoring", "error", err)
		return
	}

	// Use worker pool for concurrent checking
	workerCount := 10
	assetChan := make(chan models.Asset, len(assets))
	resultChan := make(chan AssetStatus, len(assets))

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go s.checkWorker(&wg, assetChan, resultChan)
	}

	// Send assets to workers
	for _, asset := range assets {
		assetChan <- asset
	}
	close(assetChan)

	// Wait for workers to finish
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect and process results
	updatedCount := 0
	for status := range resultChan {
		s.updateAssetStatus(status)
		updatedCount++
	}

	duration := time.Since(startTime)
	s.logger.Info("Asset status check completed", 
		"assets_checked", len(assets),
		"assets_updated", updatedCount,
		"duration", duration)
}

// checkWorker is a worker that checks asset status
func (s *MonitoringService) checkWorker(wg *sync.WaitGroup, assetChan <-chan models.Asset, resultChan chan<- AssetStatus) {
	defer wg.Done()

	for asset := range assetChan {
		status := s.checkAssetStatus(asset)
		resultChan <- status
	}
}

// checkAssetStatus checks the status of a single asset
func (s *MonitoringService) checkAssetStatus(asset models.Asset) AssetStatus {
	status := AssetStatus{
		AssetID:     asset.ID.String(),
		IPAddress:   asset.IPAddress,
		Protocol:    asset.Protocol,
		Port:        asset.Port,
		LastChecked: time.Now(),
	}

	// Determine port to check
	port := asset.Port
	if port == 0 {
		// Use default port based on protocol
		port = s.getDefaultPort(asset.Protocol)
	}

	// Perform connectivity check
	startTime := time.Now()
	if s.isReachable(asset.IPAddress, port) {
		status.Status = "online"
		status.ResponseTime = time.Since(startTime).Milliseconds()
	} else {
		status.Status = "offline"
		status.ResponseTime = -1
	}

	return status
}

// isReachable checks if an asset is reachable
func (s *MonitoringService) isReachable(ipAddress string, port int) bool {
	if port == 0 {
		// If no port specified, try ICMP ping first (requires root)
		// For now, default to common port
		port = 80
	}

	address := fmt.Sprintf("%s:%d", ipAddress, port)
	timeout := 5 * time.Second

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	return true
}

// updateAssetStatus updates asset status in database and broadcasts update
func (s *MonitoringService) updateAssetStatus(status AssetStatus) {
	// Update database
	updates := map[string]interface{}{
		"status":    status.Status,
		"last_seen": status.LastChecked,
	}

	if err := s.db.Model(&models.Asset{}).Where("id = ?", status.AssetID).Updates(updates).Error; err != nil {
		s.logger.Error("Failed to update asset status", "asset_id", status.AssetID, "error", err)
		return
	}

	// Broadcast status update via WebSocket
	websocket.BroadcastAssetStatusUpdate(
		status.AssetID,
		status.IPAddress,
		status.Status,
		status.LastChecked,
	)
}

// getDefaultPort returns default port for a protocol
func (s *MonitoringService) getDefaultPort(protocol string) int {
	portMap := map[string]int{
		"Modbus TCP":    502,
		"DNP3":          20000,
		"EtherNet/IP":   44818,
		"BACnet":        47808,
		"Siemens S7":    102,
		"SNMP":          161,
	}

	if port, ok := portMap[protocol]; ok {
		return port
	}

	// Default to HTTP port
	return 80
}

// CheckSingleAsset checks a single asset on demand
func (s *MonitoringService) CheckSingleAsset(assetID string) (*AssetStatus, error) {
	var asset models.Asset
	if err := s.db.First(&asset, "id = ?", assetID).Error; err != nil {
		return nil, fmt.Errorf("asset not found: %w", err)
	}

	status := s.checkAssetStatus(asset)
	s.updateAssetStatus(status)

	return &status, nil
}

// GetMonitoringStats returns monitoring statistics
func (s *MonitoringService) GetMonitoringStats() map[string]interface{} {
	stats := make(map[string]interface{})

	// Count assets by status
	var onlineCount, offlineCount, totalCount int64
	s.db.Model(&models.Asset{}).Where("status = ?", "online").Count(&onlineCount)
	s.db.Model(&models.Asset{}).Where("status = ?", "offline").Count(&offlineCount)
	s.db.Model(&models.Asset{}).Count(&totalCount)

	// Get last check time
	var lastCheck time.Time
	s.db.Model(&models.Asset{}).Select("MAX(last_seen)").Scan(&lastCheck)

	stats["online_assets"] = onlineCount
	stats["offline_assets"] = offlineCount
	stats["total_assets"] = totalCount
	stats["monitoring_enabled"] = s.isRunning
	stats["monitoring_interval"] = s.monitorInterval.String()
	stats["last_check"] = lastCheck

	return stats
}

// SetMonitoringInterval updates the monitoring interval
func (s *MonitoringService) SetMonitoringInterval(interval time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Minimum interval for ICS safety
	if interval < 1*time.Minute {
		return fmt.Errorf("monitoring interval must be at least 1 minute for ICS safety")
	}

	s.monitorInterval = interval

	// Restart monitoring if running
	if s.isRunning {
		s.mu.Unlock()
		s.Stop()
		s.Start()
		s.mu.Lock()
	}

	return nil
}

// BulkCheckAssets performs bulk status check for specific assets
func (s *MonitoringService) BulkCheckAssets(assetIDs []string) ([]AssetStatus, error) {
	var assets []models.Asset
	if err := s.db.Where("id IN ?", assetIDs).Find(&assets).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch assets: %w", err)
	}

	results := make([]AssetStatus, len(assets))
	var wg sync.WaitGroup

	for i, asset := range assets {
		wg.Add(1)
		go func(idx int, a models.Asset) {
			defer wg.Done()
			results[idx] = s.checkAssetStatus(a)
			s.updateAssetStatus(results[idx])
		}(i, asset)
	}

	wg.Wait()
	return results, nil
}

// GetAssetHistory returns status history for an asset
func (s *MonitoringService) GetAssetHistory(assetID string, hours int) ([]AssetStatus, error) {
	// This would require a separate status history table
	// For now, return current status only
	var asset models.Asset
	if err := s.db.First(&asset, "id = ?", assetID).Error; err != nil {
		return nil, fmt.Errorf("asset not found: %w", err)
	}

	current := AssetStatus{
		AssetID:     asset.ID.String(),
		IPAddress:   asset.IPAddress,
		Status:      asset.Status,
		LastChecked: asset.LastSeen,
		Protocol:    asset.Protocol,
		Port:        asset.Port,
	}

	return []AssetStatus{current}, nil
}