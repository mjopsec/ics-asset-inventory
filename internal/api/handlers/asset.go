package handlers

import (
	"net/http"
	"strconv"

	"ics-asset-inventory/internal/database/models"
	"ics-asset-inventory/internal/services"

	"github.com/gin-gonic/gin"
)

type AssetHandler struct {
	service *services.AssetService
}

func NewAssetHandler() *AssetHandler {
	return &AssetHandler{
		service: services.NewAssetService(),
	}
}

// GetAssets returns paginated list of assets
// @Summary Get assets
// @Description Get paginated list of assets with optional filtering
// @Tags assets
// @Accept json
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page" default(20)
// @Param search query string false "Search term"
// @Param asset_type query string false "Filter by asset type"
// @Param status query string false "Filter by status"
// @Param criticality query string false "Filter by criticality"
// @Param group_id query string false "Filter by group ID"
// @Param protocol query string false "Filter by protocol"
// @Param zone query string false "Filter by zone"
// @Param sort_by query string false "Sort field" default(created_at)
// @Param sort_order query string false "Sort order (ASC/DESC)" default(DESC)
// @Success 200 {object} services.PaginatedResult
// @Router /api/assets [get]
func (h *AssetHandler) GetAssets(c *gin.Context) {
	filter := services.AssetFilter{
		Search:      c.Query("search"),
		AssetType:   c.Query("asset_type"),
		Status:      c.Query("status"),
		Criticality: c.Query("criticality"),
		GroupID:     c.Query("group_id"),
		Protocol:    c.Query("protocol"),
		Zone:        c.Query("zone"),
		SortBy:      c.Query("sort_by"),
		SortOrder:   c.Query("sort_order"),
	}

	// Parse pagination
	page := 1
	limit := 20
	if p := c.Query("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}
	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}
	filter.Page = page
	filter.Limit = limit

	result, err := h.service.GetAssets(filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

// GetAsset returns a single asset by ID
// @Summary Get asset by ID
// @Description Get detailed information about a specific asset
// @Tags assets
// @Accept json
// @Produce json
// @Param id path string true "Asset ID"
// @Success 200 {object} models.Asset
// @Failure 404 {object} map[string]string
// @Router /api/assets/{id} [get]
func (h *AssetHandler) GetAsset(c *gin.Context) {
	id := c.Param("id")
	
	asset, err := h.service.GetAssetByID(id)
	if err != nil {
		if err.Error() == "asset not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Asset not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, asset)
}

// CreateAsset creates a new asset
// @Summary Create new asset
// @Description Create a new asset in the inventory
// @Tags assets
// @Accept json
// @Produce json
// @Param asset body models.Asset true "Asset data"
// @Success 201 {object} models.Asset
// @Failure 400 {object} map[string]string
// @Router /api/assets [post]
func (h *AssetHandler) CreateAsset(c *gin.Context) {
	var asset models.Asset
	if err := c.ShouldBindJSON(&asset); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.service.CreateAsset(&asset); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, asset)
}

// UpdateAsset updates an existing asset
// @Summary Update asset
// @Description Update an existing asset in the inventory
// @Tags assets
// @Accept json
// @Produce json
// @Param id path string true "Asset ID"
// @Param asset body models.Asset true "Updated asset data"
// @Success 200 {object} models.Asset
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/assets/{id} [put]
func (h *AssetHandler) UpdateAsset(c *gin.Context) {
	id := c.Param("id")
	
	var updateData models.Asset
	if err := c.ShouldBindJSON(&updateData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	asset, err := h.service.UpdateAsset(id, &updateData)
	if err != nil {
		if err.Error() == "asset not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Asset not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, asset)
}

// DeleteAsset deletes an asset
// @Summary Delete asset
// @Description Delete an asset from the inventory
// @Tags assets
// @Accept json
// @Produce json
// @Param id path string true "Asset ID"
// @Success 204
// @Failure 404 {object} map[string]string
// @Router /api/assets/{id} [delete]
func (h *AssetHandler) DeleteAsset(c *gin.Context) {
	id := c.Param("id")
	
	if err := h.service.DeleteAsset(id); err != nil {
		if err.Error() == "asset not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Asset not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Status(http.StatusNoContent)
}

// GetAssetStats returns statistics about assets
// @Summary Get asset statistics
// @Description Get statistics and metrics about assets in the inventory
// @Tags assets
// @Accept json
// @Produce json
// @Success 200 {object} services.AssetStats
// @Router /api/assets/stats [get]
func (h *AssetHandler) GetAssetStats(c *gin.Context) {
	stats, err := h.service.GetAssetStats()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, stats)
}

// UpdateAssetStatus updates asset status
// @Summary Update asset status
// @Description Update the operational status of an asset
// @Tags assets
// @Accept json
// @Produce json
// @Param id path string true "Asset ID"
// @Param status body map[string]string true "Status update"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Router /api/assets/{id}/status [patch]
func (h *AssetHandler) UpdateAssetStatus(c *gin.Context) {
	id := c.Param("id")
	
	var statusUpdate struct {
		Status string `json:"status" binding:"required,oneof=online offline unknown error"`
	}
	
	if err := c.ShouldBindJSON(&statusUpdate); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.service.UpdateAssetStatus(id, statusUpdate.Status); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Status updated successfully"})
}

// BulkUpdateAssets updates multiple assets
// @Summary Bulk update assets
// @Description Update multiple assets at once
// @Tags assets
// @Accept json
// @Produce json
// @Param updates body map[string]interface{} true "Bulk update data"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Router /api/assets/bulk [patch]
func (h *AssetHandler) BulkUpdateAssets(c *gin.Context) {
	var bulkUpdate struct {
		IDs     []string               `json:"ids" binding:"required,min=1"`
		Updates map[string]interface{} `json:"updates" binding:"required"`
	}
	
	if err := c.ShouldBindJSON(&bulkUpdate); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.service.BulkUpdateAssets(bulkUpdate.IDs, bulkUpdate.Updates); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Assets updated successfully"})
}

// AddAssetTag adds a tag to an asset
// @Summary Add tag to asset
// @Description Add a tag to an asset
// @Tags assets
// @Accept json
// @Produce json
// @Param id path string true "Asset ID"
// @Param tag_id path string true "Tag ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Router /api/assets/{id}/tags/{tag_id} [post]
func (h *AssetHandler) AddAssetTag(c *gin.Context) {
	assetID := c.Param("id")
	tagID := c.Param("tag_id")
	
	if err := h.service.AddAssetTag(assetID, tagID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Tag added successfully"})
}

// RemoveAssetTag removes a tag from an asset
// @Summary Remove tag from asset
// @Description Remove a tag from an asset
// @Tags assets
// @Accept json
// @Produce json
// @Param id path string true "Asset ID"
// @Param tag_id path string true "Tag ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Router /api/assets/{id}/tags/{tag_id} [delete]
func (h *AssetHandler) RemoveAssetTag(c *gin.Context) {
	assetID := c.Param("id")
	tagID := c.Param("tag_id")
	
	if err := h.service.RemoveAssetTag(assetID, tagID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Tag removed successfully"})
}