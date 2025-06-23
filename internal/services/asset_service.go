package services

import (
	"errors"
	"fmt"
	"time"

	"ics-asset-inventory/internal/database"
	"ics-asset-inventory/internal/database/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// AssetService handles business logic for assets
type AssetService struct {
	db           *gorm.DB
	queryBuilder *database.QueryBuilder
}

// NewAssetService creates a new asset service
func NewAssetService() *AssetService {
	return &AssetService{
		db:           database.GetDB(),
		queryBuilder: database.GetQueryBuilder(),
	}
}

// AssetFilter contains filtering options
type AssetFilter struct {
	Search      string
	AssetType   string
	Status      string
	Criticality string
	GroupID     string
	Protocol    string
	Zone        string
	Page        int
	Limit       int
	SortBy      string
	SortOrder   string
}

// AssetStats contains asset statistics
type AssetStats struct {
	Total         int64            `json:"total"`
	ByType        map[string]int64 `json:"by_type"`
	ByStatus      map[string]int64 `json:"by_status"`
	ByCriticality map[string]int64 `json:"by_criticality"`
	ByProtocol    map[string]int64 `json:"by_protocol"`
	OnlineCount   int64            `json:"online_count"`
	OfflineCount  int64            `json:"offline_count"`
	CriticalCount int64            `json:"critical_count"`
}

// PaginatedResult contains paginated data
type PaginatedResult struct {
	Data       interface{} `json:"data"`
	Pagination Pagination  `json:"pagination"`
}

// Pagination contains pagination info
type Pagination struct {
	Page       int   `json:"page"`
	Limit      int   `json:"limit"`
	Total      int64 `json:"total"`
	TotalPages int   `json:"total_pages"`
}

// GetAssets retrieves assets with filtering and pagination
func (s *AssetService) GetAssets(filter AssetFilter) (*PaginatedResult, error) {
	// Default values
	if filter.Page < 1 {
		filter.Page = 1
	}
	if filter.Limit < 1 || filter.Limit > 100 {
		filter.Limit = 20
	}
	if filter.SortBy == "" {
		filter.SortBy = "created_at"
	}
	if filter.SortOrder == "" {
		filter.SortOrder = "DESC"
	}

	offset := (filter.Page - 1) * filter.Limit

	// Build query
	query := s.db.Model(&models.Asset{}).Preload("Group").Preload("Tags")

	// Apply filters
	if filter.Search != "" {
		searchPattern := "%" + filter.Search + "%"
		searchFields := []string{"name", "description", "ip_address", "vendor", "model"}
		searchQuery := s.queryBuilder.BuildSearchQuery(searchFields, len(searchFields))
		
		// Create search parameters
		params := make([]interface{}, len(searchFields))
		for i := range params {
			params[i] = searchPattern
		}
		
		query = query.Where(searchQuery, params...)
	}

	if filter.AssetType != "" {
		query = query.Where("asset_type = ?", filter.AssetType)
	}

	if filter.Status != "" {
		query = query.Where("status = ?", filter.Status)
	}

	if filter.Criticality != "" {
		query = query.Where("criticality = ?", filter.Criticality)
	}

	if filter.GroupID != "" {
		query = query.Where("group_id = ?", filter.GroupID)
	}

	if filter.Protocol != "" {
		query = query.Where("protocol = ?", filter.Protocol)
	}

	if filter.Zone != "" {
		query = query.Where("zone = ?", filter.Zone)
	}

	// Count total
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, fmt.Errorf("failed to count assets: %w", err)
	}

	// Get assets with pagination
	var assets []models.Asset
	orderClause := s.queryBuilder.BuildOrderBy(filter.SortBy, filter.SortOrder)
	err := query.Offset(offset).Limit(filter.Limit).Order(orderClause).Find(&assets).Error
	if err != nil {
		return nil, fmt.Errorf("failed to fetch assets: %w", err)
	}

	// Calculate total pages
	totalPages := int(total) / filter.Limit
	if int(total)%filter.Limit > 0 {
		totalPages++
	}

	result := &PaginatedResult{
		Data: assets,
		Pagination: Pagination{
			Page:       filter.Page,
			Limit:      filter.Limit,
			Total:      total,
			TotalPages: totalPages,
		},
	}

	return result, nil
}

// GetAssetByID retrieves a single asset by ID
func (s *AssetService) GetAssetByID(id string) (*models.Asset, error) {
	assetID, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("invalid asset ID: %w", err)
	}

	var asset models.Asset
	err = s.db.Preload("Group").Preload("Tags").Preload("Attributes").
		First(&asset, "id = ?", assetID).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("asset not found")
		}
		return nil, fmt.Errorf("failed to fetch asset: %w", err)
	}

	return &asset, nil
}

// CreateAsset creates a new asset
func (s *AssetService) CreateAsset(asset *models.Asset) error {
	// Validate required fields
	if asset.Name == "" {
		return errors.New("asset name is required")
	}
	if asset.AssetType == "" {
		return errors.New("asset type is required")
	}

	// Set defaults
	asset.ID = uuid.New()
	if asset.Status == "" {
		asset.Status = "unknown"
	}
	if asset.Criticality == "" {
		asset.Criticality = "medium"
	}
	asset.LastSeen = time.Now()

	// Create asset in transaction
	err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(asset).Error; err != nil {
			return fmt.Errorf("failed to create asset: %w", err)
		}

		// Create initial attribute for creation date
		attribute := &models.AssetAttribute{
			ID:        uuid.New(),
			AssetID:   asset.ID,
			Key:       "created_by",
			Value:     "system", // TODO: Get from auth context
			ValueType: "string",
		}
		if err := tx.Create(attribute).Error; err != nil {
			return fmt.Errorf("failed to create asset attribute: %w", err)
		}

		return nil
	})

	if err != nil {
		return err
	}

	// Reload asset with relationships
	s.db.Preload("Group").Preload("Tags").First(asset, "id = ?", asset.ID)

	return nil
}

// UpdateAsset updates an existing asset
func (s *AssetService) UpdateAsset(id string, updates *models.Asset) (*models.Asset, error) {
	assetID, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("invalid asset ID: %w", err)
	}

	var asset models.Asset
	if err := s.db.First(&asset, "id = ?", assetID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("asset not found")
		}
		return nil, fmt.Errorf("failed to fetch asset: %w", err)
	}

	// Update fields (exclude system fields)
	updateMap := map[string]interface{}{
		"name":          updates.Name,
		"description":   updates.Description,
		"asset_type":    updates.AssetType,
		"ip_address":    updates.IPAddress,
		"mac_address":   updates.MACAddress,
		"port":          updates.Port,
		"protocol":      updates.Protocol,
		"vendor":        updates.Vendor,
		"model":         updates.Model,
		"version":       updates.Version,
		"serial_number": updates.SerialNumber,
		"location":      updates.Location,
		"zone":          updates.Zone,
		"site":          updates.Site,
		"department":    updates.Department,
		"criticality":   updates.Criticality,
		"group_id":      updates.GroupID,
	}

	// Remove empty values
	cleanedMap := make(map[string]interface{})
	for k, v := range updateMap {
		if v != nil && v != "" && v != 0 {
			cleanedMap[k] = v
		}
	}

	if err := s.db.Model(&asset).Updates(cleanedMap).Error; err != nil {
		return nil, fmt.Errorf("failed to update asset: %w", err)
	}

	// Reload asset with relationships
	s.db.Preload("Group").Preload("Tags").Preload("Attributes").First(&asset, "id = ?", asset.ID)

	return &asset, nil
}

// DeleteAsset deletes an asset
func (s *AssetService) DeleteAsset(id string) error {
	assetID, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("invalid asset ID: %w", err)
	}

	// Delete in transaction
	err = s.db.Transaction(func(tx *gorm.DB) error {
		// Delete attributes
		if err := tx.Where("asset_id = ?", assetID).Delete(&models.AssetAttribute{}).Error; err != nil {
			return fmt.Errorf("failed to delete asset attributes: %w", err)
		}

		// Delete asset-tag associations
		if err := tx.Exec("DELETE FROM asset_tags WHERE asset_id = ?", assetID).Error; err != nil {
			// This might fail on SQLite, ignore for now
			// return fmt.Errorf("failed to delete asset tags: %w", err)
		}

		// Delete asset
		result := tx.Delete(&models.Asset{}, "id = ?", assetID)
		if result.Error != nil {
			return fmt.Errorf("failed to delete asset: %w", result.Error)
		}

		if result.RowsAffected == 0 {
			return fmt.Errorf("asset not found")
		}

		return nil
	})

	return err
}

// GetAssetStats returns asset statistics
func (s *AssetService) GetAssetStats() (*AssetStats, error) {
	stats := &AssetStats{
		ByType:        make(map[string]int64),
		ByStatus:      make(map[string]int64),
		ByCriticality: make(map[string]int64),
		ByProtocol:    make(map[string]int64),
	}

	// Total assets
	s.db.Model(&models.Asset{}).Count(&stats.Total)

	// By type
	var typeStats []struct {
		AssetType string
		Count     int64
	}
	s.db.Model(&models.Asset{}).
		Select("asset_type, count(*) as count").
		Group("asset_type").
		Scan(&typeStats)
	for _, ts := range typeStats {
		stats.ByType[ts.AssetType] = ts.Count
	}

	// By status
	var statusStats []struct {
		Status string
		Count  int64
	}
	s.db.Model(&models.Asset{}).
		Select("status, count(*) as count").
		Group("status").
		Scan(&statusStats)
	for _, ss := range statusStats {
		stats.ByStatus[ss.Status] = ss.Count
	}

	// By criticality
	var critStats []struct {
		Criticality string
		Count       int64
	}
	s.db.Model(&models.Asset{}).
		Select("criticality, count(*) as count").
		Group("criticality").
		Scan(&critStats)
	for _, cs := range critStats {
		stats.ByCriticality[cs.Criticality] = cs.Count
	}

	// By protocol
	var protocolStats []struct {
		Protocol string
		Count    int64
	}
	s.db.Model(&models.Asset{}).
		Select("protocol, count(*) as count").
		Where("protocol != ''").
		Group("protocol").
		Scan(&protocolStats)
	for _, ps := range protocolStats {
		stats.ByProtocol[ps.Protocol] = ps.Count
	}

	// Online/Offline counts
	s.db.Model(&models.Asset{}).Where("status = ?", "online").Count(&stats.OnlineCount)
	s.db.Model(&models.Asset{}).Where("status = ?", "offline").Count(&stats.OfflineCount)
	s.db.Model(&models.Asset{}).Where("criticality = ?", "critical").Count(&stats.CriticalCount)

	return stats, nil
}

// UpdateAssetStatus updates asset status and last seen time
func (s *AssetService) UpdateAssetStatus(id string, status string) error {
	assetID, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("invalid asset ID: %w", err)
	}

	updates := map[string]interface{}{
		"status":    status,
		"last_seen": time.Now(),
	}

	if status == "online" {
		// Update uptime calculation if needed
		var asset models.Asset
		if err := s.db.First(&asset, "id = ?", assetID).Error; err == nil {
			// Calculate uptime based on last offline time
			// This is simplified - in production, track state changes properly
			updates["uptime"] = time.Since(asset.LastSeen).Seconds()
		}
	}

	if err := s.db.Model(&models.Asset{}).Where("id = ?", assetID).Updates(updates).Error; err != nil {
		return fmt.Errorf("failed to update asset status: %w", err)
	}

	return nil
}

// BulkUpdateAssets updates multiple assets
func (s *AssetService) BulkUpdateAssets(ids []string, updates map[string]interface{}) error {
	// Convert string IDs to UUIDs
	var assetIDs []uuid.UUID
	for _, id := range ids {
		assetID, err := uuid.Parse(id)
		if err != nil {
			return fmt.Errorf("invalid asset ID %s: %w", id, err)
		}
		assetIDs = append(assetIDs, assetID)
	}

	// Perform bulk update
	if err := s.db.Model(&models.Asset{}).Where("id IN ?", assetIDs).Updates(updates).Error; err != nil {
		return fmt.Errorf("failed to bulk update assets: %w", err)
	}

	return nil
}

// AddAssetTag adds a tag to an asset
func (s *AssetService) AddAssetTag(assetID, tagID string) error {
	aid, err := uuid.Parse(assetID)
	if err != nil {
		return fmt.Errorf("invalid asset ID: %w", err)
	}

	tid, err := uuid.Parse(tagID)
	if err != nil {
		return fmt.Errorf("invalid tag ID: %w", err)
	}

	// Check if asset exists
	var asset models.Asset
	if err := s.db.First(&asset, "id = ?", aid).Error; err != nil {
		return fmt.Errorf("asset not found")
	}

	// Check if tag exists
	var tag models.AssetTag
	if err := s.db.First(&tag, "id = ?", tid).Error; err != nil {
		return fmt.Errorf("tag not found")
	}

	// Add association
	if err := s.db.Model(&asset).Association("Tags").Append(&tag); err != nil {
		return fmt.Errorf("failed to add tag: %w", err)
	}

	return nil
}

// RemoveAssetTag removes a tag from an asset
func (s *AssetService) RemoveAssetTag(assetID, tagID string) error {
	aid, err := uuid.Parse(assetID)
	if err != nil {
		return fmt.Errorf("invalid asset ID: %w", err)
	}

	tid, err := uuid.Parse(tagID)
	if err != nil {
		return fmt.Errorf("invalid tag ID: %w", err)
	}

	// Check if asset exists
	var asset models.Asset
	if err := s.db.First(&asset, "id = ?", aid).Error; err != nil {
		return fmt.Errorf("asset not found")
	}

	// Check if tag exists
	var tag models.AssetTag
	if err := s.db.First(&tag, "id = ?", tid).Error; err != nil {
		return fmt.Errorf("tag not found")
	}

	// Remove association
	if err := s.db.Model(&asset).Association("Tags").Delete(&tag); err != nil {
		return fmt.Errorf("failed to remove tag: %w", err)
	}

	return nil
}