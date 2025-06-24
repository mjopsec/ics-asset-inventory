// internal/api/handlers/monitoring.go
package handlers

import (
	"net/http"

	"ics-asset-inventory/internal/services"

	"github.com/gin-gonic/gin"
)

// MonitoringHandler handles monitoring-related endpoints
type MonitoringHandler struct {
	monitoringService *services.MonitoringService
}

// NewMonitoringHandler creates a new monitoring handler
func NewMonitoringHandler() *MonitoringHandler {
	return &MonitoringHandler{
		monitoringService: services.NewMonitoringService(),
	}
}

// GetMonitoringStatus returns current monitoring status
// @Summary Get monitoring status
// @Description Get current status of the monitoring service
// @Tags monitoring
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/monitoring/status [get]
func (h *MonitoringHandler) GetMonitoringStatus(c *gin.Context) {
	status := h.monitoringService.GetMonitoringStatus()
	c.JSON(http.StatusOK, status)
}

// StartMonitoring starts the monitoring service
// @Summary Start monitoring
// @Description Start the asset monitoring service
// @Tags monitoring
// @Accept json
// @Produce json
// @Success 200 {object} map[string]string
// @Router /api/monitoring/start [post]
func (h *MonitoringHandler) StartMonitoring(c *gin.Context) {
	if err := h.monitoringService.StartMonitoring(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to start monitoring",
			"details": err.Error(),
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Monitoring service started successfully",
	})
}

// StartAssetMonitoring starts monitoring for a specific asset
// @Summary Start asset monitoring
// @Description Start monitoring for a specific asset
// @Tags monitoring
// @Accept json
// @Produce json
// @Param id path string true "Asset ID"
// @Success 200 {object} map[string]string
// @Router /api/monitoring/assets/{id}/start [post]
func (h *MonitoringHandler) StartAssetMonitoring(c *gin.Context) {
	assetID := c.Param("id")
	
	// Fetch asset from database
	assetService := services.NewAssetService()
	asset, err := assetService.GetAssetByID(assetID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Asset not found",
		})
		return
	}
	
	h.monitoringService.StartAssetMonitoring(asset)
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Started monitoring for asset",
		"asset_id": assetID,
		"asset_name": asset.Name,
	})
}

// StopAssetMonitoring stops monitoring for a specific asset
// @Summary Stop asset monitoring
// @Description Stop monitoring for a specific asset
// @Tags monitoring
// @Accept json
// @Produce json
// @Param id path string true "Asset ID"
// @Success 200 {object} map[string]string
// @Router /api/monitoring/assets/{id}/stop [post]
func (h *MonitoringHandler) StopAssetMonitoring(c *gin.Context) {
	assetID := c.Param("id")
	
	h.monitoringService.StopAssetMonitoring(assetID)
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Stopped monitoring for asset",
		"asset_id": assetID,
	})
}

// UpdateMonitoringConfig updates monitoring configuration
// @Summary Update monitoring config
// @Description Update the monitoring service configuration
// @Tags monitoring
// @Accept json
// @Produce json
// @Param config body services.MonitoringConfig true "Monitoring configuration"
// @Success 200 {object} map[string]string
// @Router /api/monitoring/config [put]
func (h *MonitoringHandler) UpdateMonitoringConfig(c *gin.Context) {
	var config services.MonitoringConfig
	if err := c.ShouldBindJSON(&config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid configuration",
			"details": err.Error(),
		})
		return
	}
	
	h.monitoringService.UpdateMonitoringConfig(&config)
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Monitoring configuration updated successfully",
	})
}