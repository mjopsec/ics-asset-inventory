package handlers

import (
	"net/http"
	"strconv"
	"time"

	"ics-asset-inventory/internal/services"

	"github.com/gin-gonic/gin"
)

// MonitoringHandler handles asset monitoring operations
type MonitoringHandler struct {
	service *services.MonitoringService
}

// Global monitoring service instance
var globalMonitoringService *services.MonitoringService

// InitMonitoringService initializes the global monitoring service
func InitMonitoringService() {
	config := &services.MonitoringConfig{
		Interval:      5 * time.Minute, // 5 minutes for ICS safety
		Timeout:       5 * time.Second,
		MaxConcurrent: 10,
		EnableRealtime: true,
		SafeMode:      true,
	}
	
	globalMonitoringService = services.NewMonitoringService(config)
	
	// Auto-start monitoring service
	if err := globalMonitoringService.Start(); err != nil {
		// Log error but don't fail initialization
		println("Warning: Failed to start monitoring service:", err.Error())
	}
}

// NewMonitoringHandler creates a new monitoring handler
func NewMonitoringHandler() *MonitoringHandler {
	if globalMonitoringService == nil {
		InitMonitoringService()
	}
	
	return &MonitoringHandler{
		service: globalMonitoringService,
	}
}

// GetMonitoringStatus returns current monitoring status
// @Summary Get monitoring status
// @Description Get current asset monitoring service status and statistics
// @Tags monitoring
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/monitoring/status [get]
func (h *MonitoringHandler) GetMonitoringStatus(c *gin.Context) {
	stats := h.service.GetMonitoringStats()
	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
		"data":   stats,
	})
}

// StartMonitoring starts the monitoring service
// @Summary Start monitoring
// @Description Start the asset monitoring service
// @Tags monitoring
// @Accept json
// @Produce json
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Router /api/monitoring/start [post]
func (h *MonitoringHandler) StartMonitoring(c *gin.Context) {
	if err := h.service.Start(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Monitoring service started successfully",
	})
}

// StopMonitoring stops the monitoring service
// @Summary Stop monitoring
// @Description Stop the asset monitoring service
// @Tags monitoring
// @Accept json
// @Produce json
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Router /api/monitoring/stop [post]
func (h *MonitoringHandler) StopMonitoring(c *gin.Context) {
	if err := h.service.Stop(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Monitoring service stopped successfully",
	})
}

// UpdateMonitoringInterval updates the monitoring interval
// @Summary Update monitoring interval
// @Description Update the interval between monitoring checks
// @Tags monitoring
// @Accept json
// @Produce json
// @Param interval body map[string]int true "Monitoring interval in minutes"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Router /api/monitoring/interval [put]
func (h *MonitoringHandler) UpdateMonitoringInterval(c *gin.Context) {
	var req struct {
		Interval int `json:"interval" binding:"required,min=1"` // Minutes
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
			"details": err.Error(),
		})
		return
	}
	
	// Convert minutes to duration
	interval := time.Duration(req.Interval) * time.Minute
	
	if err := h.service.SetMonitoringInterval(interval); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Monitoring interval updated successfully",
		"interval_minutes": req.Interval,
	})
}

// CheckAsset performs on-demand status check for a single asset
// @Summary Check asset status
// @Description Perform immediate status check for a specific asset
// @Tags monitoring
// @Accept json
// @Produce json
// @Param id path string true "Asset ID"
// @Success 200 {object} services.AssetStatus
// @Failure 404 {object} map[string]string
// @Router /api/monitoring/check/{id} [post]
func (h *MonitoringHandler) CheckAsset(c *gin.Context) {
	assetID := c.Param("id")
	
	status, err := h.service.CheckSingleAsset(assetID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": err.Error(),
		})
		return
	}
	
	c.JSON(http.StatusOK, status)
}

// BulkCheckAssets performs on-demand status check for multiple assets
// @Summary Bulk check assets
// @Description Perform immediate status check for multiple assets
// @Tags monitoring
// @Accept json
// @Produce json
// @Param assets body map[string][]string true "Asset IDs to check"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Router /api/monitoring/bulk-check [post]
func (h *MonitoringHandler) BulkCheckAssets(c *gin.Context) {
	var req struct {
		AssetIDs []string `json:"asset_ids" binding:"required,min=1"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
			"details": err.Error(),
		})
		return
	}
	
	results, err := h.service.BulkCheckAssets(req.AssetIDs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"checked": len(results),
		"results": results,
	})
}

// GetAssetHistory returns status history for an asset
// @Summary Get asset status history
// @Description Get historical status data for a specific asset
// @Tags monitoring
// @Accept json
// @Produce json
// @Param id path string true "Asset ID"
// @Param hours query int false "Number of hours of history" default(24)
// @Success 200 {object} map[string]interface{}
// @Failure 404 {object} map[string]string
// @Router /api/monitoring/history/{id} [get]
func (h *MonitoringHandler) GetAssetHistory(c *gin.Context) {
	assetID := c.Param("id")
	
	// Get hours parameter
	hours := 24
	if h := c.Query("hours"); h != "" {
		if parsed, err := strconv.Atoi(h); err == nil && parsed > 0 {
			hours = parsed
		}
	}
	
	history, err := h.service.GetAssetHistory(assetID, hours)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": err.Error(),
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"asset_id": assetID,
		"hours": hours,
		"history": history,
	})
}

// GetMonitoringConfig returns current monitoring configuration
// @Summary Get monitoring configuration
// @Description Get current monitoring service configuration
// @Tags monitoring
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/monitoring/config [get]
func (h *MonitoringHandler) GetMonitoringConfig(c *gin.Context) {
	stats := h.service.GetMonitoringStats()
	
	config := gin.H{
		"monitoring_enabled": stats["monitoring_enabled"],
		"monitoring_interval": stats["monitoring_interval"],
		"last_check": stats["last_check"],
		"safe_mode": true, // Always true for ICS environments
		"features": gin.H{
			"real_time_updates": true,
			"bulk_checking": true,
			"history_tracking": false, // Would require additional implementation
		},
	}
	
	c.JSON(http.StatusOK, config)
}