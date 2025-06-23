package handlers

import (
	"net/http"
	"strconv"
	"time"
	
	"ics-asset-inventory/internal/database"
	"ics-asset-inventory/internal/database/models"
	"ics-asset-inventory/internal/services"
	
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// GroupHandler handles asset group operations
type GroupHandler struct {
	db *gorm.DB
}

func NewGroupHandler() *GroupHandler {
	return &GroupHandler{
		db: database.GetDB(),
	}
}

// GetGroups returns all asset groups
// @Summary Get asset groups
// @Description Get all asset groups with asset count
// @Tags groups
// @Accept json
// @Produce json
// @Success 200 {array} models.AssetGroup
// @Router /api/groups [get]
func (h *GroupHandler) GetGroups(c *gin.Context) {
	var groups []models.AssetGroup
	err := h.db.Preload("Assets").Find(&groups).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch groups"})
		return
	}
	c.JSON(http.StatusOK, groups)
}

// GetGroup returns a single group by ID
// @Summary Get group by ID
// @Description Get detailed information about a specific group
// @Tags groups
// @Accept json
// @Produce json
// @Param id path string true "Group ID"
// @Success 200 {object} models.AssetGroup
// @Failure 404 {object} map[string]string
// @Router /api/groups/{id} [get]
func (h *GroupHandler) GetGroup(c *gin.Context) {
	id := c.Param("id")
	var group models.AssetGroup
	err := h.db.Preload("Assets").First(&group, "id = ?", id).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch group"})
		return
	}
	c.JSON(http.StatusOK, group)
}

// CreateGroup creates a new asset group
// @Summary Create new group
// @Description Create a new asset group
// @Tags groups
// @Accept json
// @Produce json
// @Param group body models.AssetGroup true "Group data"
// @Success 201 {object} models.AssetGroup
// @Failure 400 {object} map[string]string
// @Router /api/groups [post]
func (h *GroupHandler) CreateGroup(c *gin.Context) {
	var group models.AssetGroup
	if err := c.ShouldBindJSON(&group); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	group.ID = uuid.New()
	if err := h.db.Create(&group).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create group"})
		return
	}

	c.JSON(http.StatusCreated, group)
}

// UpdateGroup updates an existing group
// @Summary Update group
// @Description Update an existing asset group
// @Tags groups
// @Accept json
// @Produce json
// @Param id path string true "Group ID"
// @Param group body models.AssetGroup true "Updated group data"
// @Success 200 {object} models.AssetGroup
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/groups/{id} [put]
func (h *GroupHandler) UpdateGroup(c *gin.Context) {
	id := c.Param("id")
	var group models.AssetGroup
	if err := h.db.First(&group, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch group"})
		return
	}

	var updateData models.AssetGroup
	if err := c.ShouldBindJSON(&updateData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.db.Model(&group).Updates(updateData).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update group"})
		return
	}

	c.JSON(http.StatusOK, group)
}

// DeleteGroup deletes a group
// @Summary Delete group
// @Description Delete an asset group
// @Tags groups
// @Accept json
// @Produce json
// @Param id path string true "Group ID"
// @Success 204
// @Failure 404 {object} map[string]string
// @Router /api/groups/{id} [delete]
func (h *GroupHandler) DeleteGroup(c *gin.Context) {
	id := c.Param("id")
	result := h.db.Delete(&models.AssetGroup{}, "id = ?", id)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete group"})
		return
	}

	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
		return
	}

	c.Status(http.StatusNoContent)
}

// DashboardHandler handles dashboard-specific operations
type DashboardHandler struct {
	service *services.DashboardService
}

func NewDashboardHandler() *DashboardHandler {
	return &DashboardHandler{
		service: services.NewDashboardService(),
	}
}

// GetOverview returns dashboard overview statistics
// @Summary Get dashboard overview
// @Description Get overview statistics for the dashboard
// @Tags dashboard
// @Accept json
// @Produce json
// @Success 200 {object} services.DashboardOverview
// @Router /api/dashboard/overview [get]
func (h *DashboardHandler) GetOverview(c *gin.Context) {
	overview, err := h.service.GetOverview()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, overview)
}

// GetMetrics returns detailed dashboard metrics
// @Summary Get dashboard metrics
// @Description Get detailed metrics for charts and visualizations
// @Tags dashboard
// @Accept json
// @Produce json
// @Success 200 {object} services.DashboardMetrics
// @Router /api/dashboard/metrics [get]
func (h *DashboardHandler) GetMetrics(c *gin.Context) {
	metrics, err := h.service.GetMetrics()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, metrics)
}

// GetAlerts returns dashboard alerts
// @Summary Get dashboard alerts
// @Description Get recent security alerts for the dashboard
// @Tags dashboard
// @Accept json
// @Produce json
// @Param limit query int false "Number of alerts to return" default(10)
// @Success 200 {object} map[string]interface{}
// @Router /api/dashboard/alerts [get]
func (h *DashboardHandler) GetAlerts(c *gin.Context) {
	limit := 10
	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 50 {
			limit = parsed
		}
	}

	alerts, err := h.service.GetAlerts(limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"alerts": alerts,
		"count":  len(alerts),
	})
}

// GetOverviewOld returns dashboard overview statistics (OLD VERSION - FOR FALLBACK)
// This is the old implementation that directly queries the database
// Keep this temporarily for backward compatibility
func (h *DashboardHandler) GetOverviewOld(c *gin.Context) {
	db := database.GetDB()
	
	overview := gin.H{
		"total_assets": 0,
		"online_assets": 0,
		"offline_assets": 0,
		"critical_alerts": 0,
		"recent_scans": 0,
	}

	// Get total assets
	var totalAssets int64
	db.Model(&models.Asset{}).Count(&totalAssets)
	overview["total_assets"] = totalAssets

	// Get online/offline counts
	var onlineAssets int64
	db.Model(&models.Asset{}).Where("status = ?", "online").Count(&onlineAssets)
	overview["online_assets"] = onlineAssets

	var offlineAssets int64
	db.Model(&models.Asset{}).Where("status = ?", "offline").Count(&offlineAssets)
	overview["offline_assets"] = offlineAssets

	// Get critical alerts
	var criticalAlerts int64
	db.Model(&models.SecurityAssessment{}).Where("severity = ? AND status = ?", "critical", "open").Count(&criticalAlerts)
	overview["critical_alerts"] = criticalAlerts

	// Get recent scans (fixed for SQLite compatibility)
	// Calculate time 24 hours ago
	twentyFourHoursAgo := time.Now().Add(-24 * time.Hour)
	var recentScans int64
	db.Model(&models.NetworkScan{}).Where("created_at > ?", twentyFourHoursAgo).Count(&recentScans)
	overview["recent_scans"] = recentScans

	c.JSON(http.StatusOK, overview)
}

// GetMetricsOld returns detailed dashboard metrics (OLD VERSION - FOR FALLBACK)
func (h *DashboardHandler) GetMetricsOld(c *gin.Context) {
	db := database.GetDB()
	
	metrics := gin.H{
		"asset_distribution": map[string]int64{},
		"status_distribution": map[string]int64{},
		"criticality_distribution": map[string]int64{},
		"protocol_distribution": map[string]int64{},
	}

	// Asset type distribution
	var assetTypes []struct {
		AssetType string `json:"asset_type"`
		Count     int64  `json:"count"`
	}
	db.Model(&models.Asset{}).Select("asset_type, count(*) as count").Group("asset_type").Scan(&assetTypes)
	assetDist := make(map[string]int64)
	for _, at := range assetTypes {
		assetDist[at.AssetType] = at.Count
	}
	metrics["asset_distribution"] = assetDist

	// Status distribution
	var statusTypes []struct {
		Status string `json:"status"`
		Count  int64  `json:"count"`
	}
	db.Model(&models.Asset{}).Select("status, count(*) as count").Group("status").Scan(&statusTypes)
	statusDist := make(map[string]int64)
	for _, st := range statusTypes {
		statusDist[st.Status] = st.Count
	}
	metrics["status_distribution"] = statusDist

	// Criticality distribution
	var criticalityTypes []struct {
		Criticality string `json:"criticality"`
		Count       int64  `json:"count"`
	}
	db.Model(&models.Asset{}).Select("criticality, count(*) as count").Group("criticality").Scan(&criticalityTypes)
	critDist := make(map[string]int64)
	for _, ct := range criticalityTypes {
		critDist[ct.Criticality] = ct.Count
	}
	metrics["criticality_distribution"] = critDist

	// Protocol distribution
	var protocolTypes []struct {
		Protocol string `json:"protocol"`
		Count    int64  `json:"count"`
	}
	db.Model(&models.Asset{}).Select("protocol, count(*) as count").Where("protocol != ''").Group("protocol").Scan(&protocolTypes)
	protocolDist := make(map[string]int64)
	for _, pt := range protocolTypes {
		protocolDist[pt.Protocol] = pt.Count
	}
	metrics["protocol_distribution"] = protocolDist

	c.JSON(http.StatusOK, metrics)
}

// GetAlertsOld returns dashboard alerts (OLD VERSION - FOR FALLBACK)
func (h *DashboardHandler) GetAlertsOld(c *gin.Context) {
	db := database.GetDB()
	
	var alerts []models.SecurityAssessment
	err := db.Preload("Asset").Where("status = ?", "open").Order("created_at DESC").Limit(10).Find(&alerts).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch alerts"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"alerts": alerts,
		"count": len(alerts),
	})
}