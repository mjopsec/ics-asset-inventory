package services

import (
	"fmt"
	"time"

	"ics-asset-inventory/internal/database"
	"ics-asset-inventory/internal/database/models"

	"gorm.io/gorm"
)

// DashboardService handles dashboard business logic
type DashboardService struct {
	db *gorm.DB
}

// NewDashboardService creates a new dashboard service
func NewDashboardService() *DashboardService {
	return &DashboardService{
		db: database.GetDB(),
	}
}

// DashboardOverview contains overview statistics
type DashboardOverview struct {
	TotalAssets     int64 `json:"total_assets"`
	OnlineAssets    int64 `json:"online_assets"`
	OfflineAssets   int64 `json:"offline_assets"`
	CriticalAlerts  int64 `json:"critical_alerts"`
	RecentScans     int64 `json:"recent_scans"`
	NewAssetsToday  int64 `json:"new_assets_today"`
	SecurityScore   int   `json:"security_score"`
	ComplianceScore int   `json:"compliance_score"`
}

// DashboardMetrics contains detailed metrics for charts
type DashboardMetrics struct {
	AssetDistribution      map[string]int64   `json:"asset_distribution"`
	StatusDistribution     map[string]int64   `json:"status_distribution"`
	CriticalityDistribution map[string]int64   `json:"criticality_distribution"`
	ProtocolDistribution   map[string]int64   `json:"protocol_distribution"`
	AssetTrend             []TrendData        `json:"asset_trend"`
	AlertTrend             []TrendData        `json:"alert_trend"`
	TopVulnerableAssets    []VulnerableAsset  `json:"top_vulnerable_assets"`
	RecentActivities       []Activity         `json:"recent_activities"`
}

// TrendData represents trend data point
type TrendData struct {
	Date  string `json:"date"`
	Value int64  `json:"value"`
}

// VulnerableAsset represents an asset with vulnerabilities
type VulnerableAsset struct {
	AssetID          string `json:"asset_id"`
	AssetName        string `json:"asset_name"`
	AssetType        string `json:"asset_type"`
	VulnCount        int    `json:"vuln_count"`
	CriticalVulnCount int    `json:"critical_vuln_count"`
	RiskScore        int    `json:"risk_score"`
}

// Activity represents a system activity
type Activity struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	AssetID     string    `json:"asset_id,omitempty"`
	AssetName   string    `json:"asset_name,omitempty"`
	UserID      string    `json:"user_id,omitempty"`
	UserName    string    `json:"user_name,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

// Alert represents a security alert
type Alert struct {
	ID          string    `json:"id"`
	AssetID     string    `json:"asset_id"`
	AssetName   string    `json:"asset_name"`
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
}

// GetOverview returns dashboard overview statistics
func (s *DashboardService) GetOverview() (*DashboardOverview, error) {
	overview := &DashboardOverview{}

	// Total assets
	if err := s.db.Model(&models.Asset{}).Count(&overview.TotalAssets).Error; err != nil {
		return nil, fmt.Errorf("failed to count total assets: %w", err)
	}

	// Online/Offline assets
	if err := s.db.Model(&models.Asset{}).Where("status = ?", "online").Count(&overview.OnlineAssets).Error; err != nil {
		return nil, fmt.Errorf("failed to count online assets: %w", err)
	}
	if err := s.db.Model(&models.Asset{}).Where("status = ?", "offline").Count(&overview.OfflineAssets).Error; err != nil {
		return nil, fmt.Errorf("failed to count offline assets: %w", err)
	}

	// Critical alerts (open security assessments with critical severity)
	if err := s.db.Model(&models.SecurityAssessment{}).
		Where("severity = ? AND status = ?", "critical", "open").
		Count(&overview.CriticalAlerts).Error; err != nil {
		return nil, fmt.Errorf("failed to count critical alerts: %w", err)
	}

	// Recent scans (last 24 hours)
	twentyFourHoursAgo := time.Now().Add(-24 * time.Hour)
	if err := s.db.Model(&models.NetworkScan{}).
		Where("created_at > ?", twentyFourHoursAgo).
		Count(&overview.RecentScans).Error; err != nil {
		return nil, fmt.Errorf("failed to count recent scans: %w", err)
	}

	// New assets today
	startOfDay := time.Now().Truncate(24 * time.Hour)
	if err := s.db.Model(&models.Asset{}).
		Where("created_at >= ?", startOfDay).
		Count(&overview.NewAssetsToday).Error; err != nil {
		return nil, fmt.Errorf("failed to count new assets today: %w", err)
	}

	// Calculate security score (simplified)
	overview.SecurityScore = s.calculateSecurityScore()
	
	// Calculate compliance score (simplified)
	overview.ComplianceScore = s.calculateComplianceScore()

	return overview, nil
}

// GetMetrics returns detailed dashboard metrics
func (s *DashboardService) GetMetrics() (*DashboardMetrics, error) {
	metrics := &DashboardMetrics{
		AssetDistribution:       make(map[string]int64),
		StatusDistribution:      make(map[string]int64),
		CriticalityDistribution: make(map[string]int64),
		ProtocolDistribution:    make(map[string]int64),
	}

	// Asset distribution by type
	var assetTypes []struct {
		AssetType string
		Count     int64
	}
	if err := s.db.Model(&models.Asset{}).
		Select("asset_type, count(*) as count").
		Group("asset_type").
		Scan(&assetTypes).Error; err != nil {
		return nil, fmt.Errorf("failed to get asset distribution: %w", err)
	}
	for _, at := range assetTypes {
		metrics.AssetDistribution[at.AssetType] = at.Count
	}

	// Status distribution
	var statusTypes []struct {
		Status string
		Count  int64
	}
	if err := s.db.Model(&models.Asset{}).
		Select("status, count(*) as count").
		Group("status").
		Scan(&statusTypes).Error; err != nil {
		return nil, fmt.Errorf("failed to get status distribution: %w", err)
	}
	for _, st := range statusTypes {
		metrics.StatusDistribution[st.Status] = st.Count
	}

	// Criticality distribution
	var criticalityTypes []struct {
		Criticality string
		Count       int64
	}
	if err := s.db.Model(&models.Asset{}).
		Select("criticality, count(*) as count").
		Group("criticality").
		Scan(&criticalityTypes).Error; err != nil {
		return nil, fmt.Errorf("failed to get criticality distribution: %w", err)
	}
	for _, ct := range criticalityTypes {
		metrics.CriticalityDistribution[ct.Criticality] = ct.Count
	}

	// Protocol distribution
	var protocolTypes []struct {
		Protocol string
		Count    int64
	}
	if err := s.db.Model(&models.Asset{}).
		Select("protocol, count(*) as count").
		Where("protocol != ''").
		Group("protocol").
		Scan(&protocolTypes).Error; err != nil {
		return nil, fmt.Errorf("failed to get protocol distribution: %w", err)
	}
	for _, pt := range protocolTypes {
		metrics.ProtocolDistribution[pt.Protocol] = pt.Count
	}

	// Get trends
	metrics.AssetTrend = s.getAssetTrend(7) // Last 7 days
	metrics.AlertTrend = s.getAlertTrend(7) // Last 7 days

	// Get top vulnerable assets
	metrics.TopVulnerableAssets = s.getTopVulnerableAssets(5)

	// Get recent activities
	metrics.RecentActivities = s.getRecentActivities(10)

	return metrics, nil
}

// GetAlerts returns dashboard alerts
func (s *DashboardService) GetAlerts(limit int) ([]Alert, error) {
	var assessments []models.SecurityAssessment
	
	query := s.db.Preload("Asset").
		Where("status = ?", "open").
		Order("created_at DESC")
	
	if limit > 0 {
		query = query.Limit(limit)
	}
	
	if err := query.Find(&assessments).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch alerts: %w", err)
	}

	alerts := make([]Alert, len(assessments))
	for i, assessment := range assessments {
		alerts[i] = Alert{
			ID:          assessment.ID.String(),
			AssetID:     assessment.AssetID.String(),
			AssetName:   assessment.Asset.Name,
			Type:        assessment.ScanType,
			Severity:    assessment.Severity,
			Title:       assessment.Title,
			Description: assessment.Description,
			Status:      assessment.Status,
			CreatedAt:   assessment.CreatedAt,
		}
	}

	return alerts, nil
}

// calculateSecurityScore calculates overall security score
func (s *DashboardService) calculateSecurityScore() int {
	// Simplified security score calculation
	// In production, this would be more sophisticated
	
	var totalAssets, criticalVulns, highVulns int64
	
	s.db.Model(&models.Asset{}).Count(&totalAssets)
	s.db.Model(&models.SecurityAssessment{}).
		Where("severity = ? AND status = ?", "critical", "open").
		Count(&criticalVulns)
	s.db.Model(&models.SecurityAssessment{}).
		Where("severity = ? AND status = ?", "high", "open").
		Count(&highVulns)
	
	if totalAssets == 0 {
		return 100
	}
	
	// Basic scoring: deduct points for vulnerabilities
	score := 100
	score -= int(criticalVulns * 10) // -10 points per critical vuln
	score -= int(highVulns * 5)      // -5 points per high vuln
	
	if score < 0 {
		score = 0
	}
	
	return score
}

// calculateComplianceScore calculates compliance score
func (s *DashboardService) calculateComplianceScore() int {
	// Simplified compliance score calculation
	// In production, this would check actual compliance rules
	
	score := 100
	
	// Check for assets without criticality set
	var uncategorized int64
	s.db.Model(&models.Asset{}).
		Where("criticality = '' OR criticality IS NULL").
		Count(&uncategorized)
	
	// Check for assets not scanned recently
	thirtyDaysAgo := time.Now().AddDate(0, 0, -30)
	var unscanned int64
	s.db.Model(&models.Asset{}).
		Where("last_seen < ? OR last_seen IS NULL", thirtyDaysAgo).
		Count(&unscanned)
	
	score -= int(uncategorized * 2) // -2 points per uncategorized asset
	score -= int(unscanned * 3)      // -3 points per unscanned asset
	
	if score < 0 {
		score = 0
	}
	
	return score
}

// getAssetTrend returns asset count trend for the last N days
func (s *DashboardService) getAssetTrend(days int) []TrendData {
	trend := make([]TrendData, days)
	
	for i := 0; i < days; i++ {
		date := time.Now().AddDate(0, 0, -i)
		startOfDay := date.Truncate(24 * time.Hour)
		endOfDay := startOfDay.Add(24 * time.Hour)
		
		var count int64
		s.db.Model(&models.Asset{}).
			Where("created_at >= ? AND created_at < ?", startOfDay, endOfDay).
			Count(&count)
		
		trend[days-1-i] = TrendData{
			Date:  startOfDay.Format("2006-01-02"),
			Value: count,
		}
	}
	
	return trend
}

// getAlertTrend returns alert count trend for the last N days
func (s *DashboardService) getAlertTrend(days int) []TrendData {
	trend := make([]TrendData, days)
	
	for i := 0; i < days; i++ {
		date := time.Now().AddDate(0, 0, -i)
		startOfDay := date.Truncate(24 * time.Hour)
		endOfDay := startOfDay.Add(24 * time.Hour)
		
		var count int64
		s.db.Model(&models.SecurityAssessment{}).
			Where("created_at >= ? AND created_at < ?", startOfDay, endOfDay).
			Count(&count)
		
		trend[days-1-i] = TrendData{
			Date:  startOfDay.Format("2006-01-02"),
			Value: count,
		}
	}
	
	return trend
}

// getTopVulnerableAssets returns assets with most vulnerabilities
func (s *DashboardService) getTopVulnerableAssets(limit int) []VulnerableAsset {
	var results []struct {
		AssetID           string
		AssetName         string
		AssetType         string
		VulnCount         int
		CriticalVulnCount int
	}
	
	// Query to get top vulnerable assets
	query := `
		SELECT 
			a.id as asset_id,
			a.name as asset_name,
			a.asset_type,
			COUNT(sa.id) as vuln_count,
			COUNT(CASE WHEN sa.severity = 'critical' THEN 1 END) as critical_vuln_count
		FROM assets a
		LEFT JOIN security_assessments sa ON a.id = sa.asset_id AND sa.status = 'open'
		WHERE a.deleted_at IS NULL
		GROUP BY a.id, a.name, a.asset_type
		HAVING COUNT(sa.id) > 0
		ORDER BY critical_vuln_count DESC, vuln_count DESC
		LIMIT ?
	`
	
	s.db.Raw(query, limit).Scan(&results)
	
	vulnerable := make([]VulnerableAsset, len(results))
	for i, r := range results {
		// Calculate risk score (simplified)
		riskScore := r.CriticalVulnCount*10 + (r.VulnCount-r.CriticalVulnCount)*5
		if riskScore > 100 {
			riskScore = 100
		}
		
		vulnerable[i] = VulnerableAsset{
			AssetID:           r.AssetID,
			AssetName:         r.AssetName,
			AssetType:         r.AssetType,
			VulnCount:         r.VulnCount,
			CriticalVulnCount: r.CriticalVulnCount,
			RiskScore:         riskScore,
		}
	}
	
	return vulnerable
}

// getRecentActivities returns recent system activities
func (s *DashboardService) getRecentActivities(limit int) []Activity {
	activities := []Activity{}
	
	// Get recent asset creations
	var recentAssets []models.Asset
	s.db.Order("created_at DESC").Limit(limit/2).Find(&recentAssets)
	
	for _, asset := range recentAssets {
		activities = append(activities, Activity{
			ID:          asset.ID.String(),
			Type:        "asset_created",
			Title:       "New Asset Added",
			Description: fmt.Sprintf("Asset '%s' was added to inventory", asset.Name),
			AssetID:     asset.ID.String(),
			AssetName:   asset.Name,
			Timestamp:   asset.CreatedAt,
		})
	}
	
	// Get recent scans
	var recentScans []models.NetworkScan
	s.db.Order("created_at DESC").Limit(limit/2).Find(&recentScans)
	
	for _, scan := range recentScans {
		activities = append(activities, Activity{
			ID:          scan.ID.String(),
			Type:        "network_scan",
			Title:       "Network Scan Completed",
			Description: fmt.Sprintf("Scan of %s discovered %d devices", scan.Target, scan.DevicesFound),
			Timestamp:   scan.CreatedAt,
		})
	}
	
	// Sort by timestamp
	// In a real implementation, you would use a proper activity log table
	
	return activities
}
