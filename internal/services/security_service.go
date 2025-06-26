// internal/services/security_service.go
package services

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"

	"ics-asset-inventory/internal/database"
	"ics-asset-inventory/internal/database/models"
	"ics-asset-inventory/internal/utils"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// SecurityService handles security assessments in a SAFE manner for ICS
type SecurityService struct {
	db           *gorm.DB
	logger       *utils.Logger
	cveDatabase  *CVEDatabase
	safeMode     bool // Always true for ICS environments
	mu           sync.RWMutex
}

// CVEDatabase stores vulnerability data offline
type CVEDatabase struct {
	LastUpdated time.Time
	CVEs        map[string]*CVEEntry
	mu          sync.RWMutex
}

// CVEEntry represents a CVE record
type CVEEntry struct {
	ID          string    `json:"id"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	CVSS        float64   `json:"cvss_score"`
	Published   time.Time `json:"published"`
	Modified    time.Time `json:"modified"`
	Products    []Product `json:"products"`
	References  []string  `json:"references"`
	Solution    string    `json:"solution"`
}

// Product affected by CVE
type Product struct {
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
	Version string `json:"version"`
}

// SecurityAssessmentRequest for passive assessment
type SecurityAssessmentRequest struct {
	AssetIDs    []string `json:"asset_ids" binding:"required"`
	CheckTypes  []string `json:"check_types"` // vulnerability, compliance, configuration
	UseCache    bool     `json:"use_cache"`
	GenerateReport bool  `json:"generate_report"`
}

// SecurityAssessmentResult contains assessment results
type SecurityAssessmentResult struct {
	ID               string                 `json:"id"`
	AssetID          string                 `json:"asset_id"`
	AssetName        string                 `json:"asset_name"`
	AssessmentDate   time.Time             `json:"assessment_date"`
	Vulnerabilities  []VulnerabilityMatch  `json:"vulnerabilities"`
	ComplianceChecks []SecurityComplianceCheck `json:"compliance_checks"`
	RiskScore        int                   `json:"risk_score"`
	RiskLevel        string                `json:"risk_level"`
	Recommendations  []string              `json:"recommendations"`
}

// VulnerabilityMatch represents a matched vulnerability
type VulnerabilityMatch struct {
	CVE         string    `json:"cve"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	CVSS        float64   `json:"cvss_score"`
	Matched     bool      `json:"matched"`
	MatchReason string    `json:"match_reason"`
	Solution    string    `json:"solution"`
	References  []string  `json:"references"`
}

// ComplianceCheck represents a compliance verification
type SecurityComplianceCheck struct {
	Standard    string `json:"standard"` // IEC-62443, NIST, etc.
	Category    string `json:"category"`
	Requirement string `json:"requirement"`
	Status      string `json:"status"` // pass, fail, not_applicable
	Details     string `json:"details"`
	Evidence    string `json:"evidence"`
}


// RiskMatrix for risk calculation
type RiskMatrix struct {
	AssetCriticality string  `json:"asset_criticality"`
	ThreatLevel      string  `json:"threat_level"`
	Vulnerabilities  int     `json:"vulnerabilities"`
	ExposureLevel    string  `json:"exposure_level"`
	RiskScore        int     `json:"risk_score"`
	RiskLevel        string  `json:"risk_level"`
}

// NewSecurityService creates a new security service
func NewSecurityService() *SecurityService {
	return &SecurityService{
		db:       database.GetDB(),
		logger:   utils.NewLogger(),
		safeMode: true, // Always true for ICS
		cveDatabase: &CVEDatabase{
			CVEs:        make(map[string]*CVEEntry),
			LastUpdated: time.Now(),
		},
	}
}

// RunPassiveAssessment performs SAFE security assessment - FIXED
func (s *SecurityService) RunPassiveAssessment(req *SecurityAssessmentRequest) ([]SecurityAssessmentResult, error) {
	// IMPORTANT: This assessment is PASSIVE only - no active scanning
	s.logger.Info("Starting PASSIVE security assessment", "assets", len(req.AssetIDs))
	
	// Validate request
	if len(req.AssetIDs) == 0 {
		return nil, fmt.Errorf("no assets provided for assessment")
	}
	
	// Set default check types if not specified
	if len(req.CheckTypes) == 0 {
		req.CheckTypes = []string{"vulnerability", "compliance", "configuration"}
	}
	
	// Default to using cache for safety
	if !req.UseCache {
		req.UseCache = true
	}
	
	results := []SecurityAssessmentResult{}
	
	for _, assetID := range req.AssetIDs {
		// Get asset from database
		var asset models.Asset
		if err := s.db.Preload("Tags").Preload("Group").First(&asset, "id = ?", assetID).Error; err != nil {
			s.logger.Error("Asset not found", "id", assetID, "error", err)
			continue
		}
		
		result := SecurityAssessmentResult{
			ID:             uuid.New().String(),
			AssetID:        asset.ID.String(),
			AssetName:      asset.Name,
			AssessmentDate: time.Now(),
			Vulnerabilities: []VulnerabilityMatch{},
			ComplianceChecks: []SecurityComplianceCheck{}, // CHANGED: Updated to use SecurityComplianceCheck
			Recommendations: []string{},
		}
		
		// 1. Check for known vulnerabilities (PASSIVE - database lookup only)
		if contains(req.CheckTypes, "vulnerability") {
			vulns := s.checkVulnerabilities(&asset)
			result.Vulnerabilities = vulns
		}
		
		// 2. Check compliance (PASSIVE - based on existing data)
		if contains(req.CheckTypes, "compliance") {
			checks := s.checkCompliance(&asset)
			result.ComplianceChecks = checks
		}
		
		// 3. Check configuration (PASSIVE - analyze stored config only)
		if contains(req.CheckTypes, "configuration") {
			s.checkConfiguration(&asset, &result)
		}
		
		// 4. Calculate risk score
		result.RiskScore, result.RiskLevel = s.calculateRiskScore(&asset, &result)
		
		// 5. Generate recommendations
		result.Recommendations = s.generateRecommendations(&result)
		
		// 6. Save assessment to database
		s.saveAssessment(&asset, &result)
		
		results = append(results, result)
	}
	
	s.logger.Info("Security assessment completed", 
		"total_assets", len(req.AssetIDs),
		"assessed", len(results))
	
	return results, nil
}

// checkVulnerabilities performs PASSIVE vulnerability matching
func (s *SecurityService) checkVulnerabilities(asset *models.Asset) []VulnerabilityMatch {
	matches := []VulnerabilityMatch{}
	
	// Only match based on vendor, product, and version - NO ACTIVE SCANNING
	s.cveDatabase.mu.RLock()
	defer s.cveDatabase.mu.RUnlock()
	
	for cveID, cve := range s.cveDatabase.CVEs {
		for _, product := range cve.Products {
			if s.isVulnerable(asset, product) {
				match := VulnerabilityMatch{
					CVE:         cveID,
					Title:       cve.Description,
					Description: cve.Description,
					Severity:    cve.Severity,
					CVSS:        cve.CVSS,
					Matched:     true,
					MatchReason: fmt.Sprintf("Vendor: %s, Model: %s, Version: %s", 
						asset.Vendor, asset.Model, asset.Version),
					Solution:   cve.Solution,
					References: cve.References,
				}
				matches = append(matches, match)
			}
		}
	}
	
	return matches
}

// isVulnerable checks if asset matches vulnerability criteria
func (s *SecurityService) isVulnerable(asset *models.Asset, product Product) bool {
	// Simple vendor/product/version matching
	vendorMatch := strings.ToLower(asset.Vendor) == strings.ToLower(product.Vendor)
	productMatch := strings.Contains(strings.ToLower(asset.Model), strings.ToLower(product.Product))
	
	// Version comparison (simplified)
	versionMatch := false
	if asset.Version != "" && product.Version != "" {
		versionMatch = strings.HasPrefix(asset.Version, product.Version)
	}
	
	return vendorMatch && productMatch && versionMatch
}

// checkCompliance performs PASSIVE compliance checking
func (s *SecurityService) checkCompliance(asset *models.Asset) []SecurityComplianceCheck {
	checks := []SecurityComplianceCheck{}
	
	// IEC 62443 Basic Checks (based on stored data only)
	checks = append(checks, s.checkIEC62443Compliance(asset)...)
	
	// NIST Framework Checks
	checks = append(checks, s.checkNISTCompliance(asset)...)
	
	// Custom Policy Checks
	checks = append(checks, s.checkCustomPolicies(asset)...)
	
	return checks
}

// checkIEC62443Compliance checks IEC 62443 requirements passively
func (s *SecurityService) checkIEC62443Compliance(asset *models.Asset) []SecurityComplianceCheck {
	checks := []SecurityComplianceCheck{}
	
	// FR 1: Identification and Authentication Control
	authCheck := SecurityComplianceCheck{
		Standard:    "IEC-62443",
		Category:    "FR 1",
		Requirement: "Identification and Authentication Control",
	}
	
	// Check based on stored configuration only
	if asset.Protocol == "Modbus TCP" {
		authCheck.Status = "fail"
		authCheck.Details = "Modbus TCP does not support authentication"
		authCheck.Evidence = "Protocol: Modbus TCP"
	} else if asset.Protocol == "DNP3" || asset.Protocol == "IEC-104" {
		authCheck.Status = "pass"
		authCheck.Details = "Protocol supports authentication"
		authCheck.Evidence = fmt.Sprintf("Protocol: %s", asset.Protocol)
	} else {
		authCheck.Status = "not_applicable"
		authCheck.Details = "Unable to determine authentication support"
	}
	checks = append(checks, authCheck)
	
	// FR 2: Use Control (based on criticality)
	useControl := SecurityComplianceCheck{
		Standard:    "IEC-62443",
		Category:    "FR 2",
		Requirement: "Use Control",
	}
	
	if asset.Criticality == "critical" || asset.Criticality == "high" {
		useControl.Status = "pass"
		useControl.Details = "Asset marked with appropriate criticality"
		useControl.Evidence = fmt.Sprintf("Criticality: %s", asset.Criticality)
	} else if asset.Criticality == "" {
		useControl.Status = "fail"
		useControl.Details = "Asset criticality not defined"
	}
	checks = append(checks, useControl)
	
	// FR 3: System Integrity (check last update)
	integrityCheck := SecurityComplianceCheck{
		Standard:    "IEC-62443",
		Category:    "FR 3",
		Requirement: "System Integrity",
	}
	
	daysSinceUpdate := time.Since(asset.UpdatedAt).Hours() / 24
	if daysSinceUpdate > 90 {
		integrityCheck.Status = "fail"
		integrityCheck.Details = fmt.Sprintf("Asset not updated in %.0f days", daysSinceUpdate)
	} else {
		integrityCheck.Status = "pass"
		integrityCheck.Details = "Asset recently verified"
	}
	checks = append(checks, integrityCheck)
	
	// FR 7: Resource Availability (based on status)
	availabilityCheck := SecurityComplianceCheck{
		Standard:    "IEC-62443",
		Category:    "FR 7",
		Requirement: "Resource Availability",
	}
	
	if asset.Status == "online" {
		availabilityCheck.Status = "pass"
		availabilityCheck.Details = "Asset is online and available"
	} else {
		availabilityCheck.Status = "fail"
		availabilityCheck.Details = fmt.Sprintf("Asset status: %s", asset.Status)
	}
	checks = append(checks, availabilityCheck)
	
	return checks
}

// checkNISTCompliance checks NIST framework requirements
func (s *SecurityService) checkNISTCompliance(asset *models.Asset) []SecurityComplianceCheck {
	checks := []SecurityComplianceCheck{}
	
	// Identify - Asset Management
	identifyCheck := SecurityComplianceCheck{
		Standard:    "NIST",
		Category:    "ID.AM",
		Requirement: "Asset Management",
		Status:      "pass",
		Details:     "Asset is properly inventoried",
		Evidence:    fmt.Sprintf("Asset ID: %s, Type: %s", asset.ID, asset.AssetType),
	}
	checks = append(checks, identifyCheck)
	
	// Protect - Access Control
	if asset.Zone == "DMZ" || asset.Zone == "Control Network" {
		protectCheck := SecurityComplianceCheck{
			Standard:    "NIST",
			Category:    "PR.AC",
			Requirement: "Access Control",
			Status:      "pass",
			Details:     "Asset is in segregated network zone",
			Evidence:    fmt.Sprintf("Zone: %s", asset.Zone),
		}
		checks = append(checks, protectCheck)
	}
	
	return checks
}

// checkCustomPolicies checks organization-specific policies
func (s *SecurityService) checkCustomPolicies(asset *models.Asset) []SecurityComplianceCheck {
	checks := []SecurityComplianceCheck{}
	
	// Example: Check if critical assets have redundancy
	if asset.Criticality == "critical" {
		redundancyCheck := SecurityComplianceCheck{
			Standard:    "Corporate Policy",
			Category:    "Availability",
			Requirement: "Critical Asset Redundancy",
		}
		
		// Check if asset has backup (simplified check based on naming)
		if strings.Contains(strings.ToLower(asset.Name), "primary") ||
		   strings.Contains(strings.ToLower(asset.Name), "backup") {
			redundancyCheck.Status = "pass"
			redundancyCheck.Details = "Asset appears to have redundancy"
		} else {
			redundancyCheck.Status = "fail"
			redundancyCheck.Details = "No redundancy detected for critical asset"
		}
		checks = append(checks, redundancyCheck)
	}
	
	return checks
}

// checkConfiguration analyzes stored configuration
func (s *SecurityService) checkConfiguration(asset *models.Asset, result *SecurityAssessmentResult) {
	// Check for insecure configurations based on asset type and protocol
	
	if asset.Protocol == "Modbus TCP" && asset.Port == 502 {
		result.Recommendations = append(result.Recommendations,
			"Consider using Modbus/TCP Security Protocol (Modbus/TLS) for encrypted communication")
	}
	
	if asset.Protocol == "SNMP" {
		result.Recommendations = append(result.Recommendations,
			"Ensure SNMPv3 is used instead of SNMPv1/v2 for authentication and encryption")
	}
	
	if asset.Zone == "" {
		result.Recommendations = append(result.Recommendations,
			"Define network zone for proper segmentation")
	}
}

// calculateRiskScore calculates risk based on multiple factors
func (s *SecurityService) calculateRiskScore(asset *models.Asset, result *SecurityAssessmentResult) (int, string) {
	riskScore := 0
	
	// Factor 1: Asset Criticality (0-25 points)
	switch asset.Criticality {
	case "critical":
		riskScore += 25
	case "high":
		riskScore += 20
	case "medium":
		riskScore += 10
	case "low":
		riskScore += 5
	default:
		riskScore += 15 // Unknown criticality is risky
	}
	
	// Factor 2: Vulnerabilities (0-40 points)
	criticalVulns := 0
	highVulns := 0
	for _, vuln := range result.Vulnerabilities {
		if vuln.Severity == "critical" {
			criticalVulns++
		} else if vuln.Severity == "high" {
			highVulns++
		}
	}
	riskScore += (criticalVulns * 10) + (highVulns * 5)
	if riskScore > 65 {
		riskScore = 65 // Cap vulnerability score
	}
	
	// Factor 3: Compliance (0-20 points)
	failedChecks := 0
	totalChecks := len(result.ComplianceChecks)
	for _, check := range result.ComplianceChecks {
		if check.Status == "fail" {
			failedChecks++
		}
	}
	if totalChecks > 0 {
		complianceScore := float64(failedChecks) / float64(totalChecks) * 20
		riskScore += int(complianceScore)
	}
	
	// Factor 4: Network Exposure (0-15 points)
	switch asset.Zone {
	case "DMZ":
		riskScore += 15
	case "Corporate Network":
		riskScore += 10
	case "Control Network":
		riskScore += 5
	case "Isolated":
		riskScore += 0
	default:
		riskScore += 10
	}
	
	// Determine risk level
	var riskLevel string
	switch {
	case riskScore >= 80:
		riskLevel = "critical"
	case riskScore >= 60:
		riskLevel = "high"
	case riskScore >= 40:
		riskLevel = "medium"
	case riskScore >= 20:
		riskLevel = "low"
	default:
		riskLevel = "very_low"
	}
	
	return riskScore, riskLevel
}

// generateRecommendations creates actionable recommendations
func (s *SecurityService) generateRecommendations(result *SecurityAssessmentResult) []string {
	recommendations := result.Recommendations // Start with existing ones
	
	// Based on vulnerabilities
	if len(result.Vulnerabilities) > 0 {
		criticalCount := 0
		for _, vuln := range result.Vulnerabilities {
			if vuln.Severity == "critical" {
				criticalCount++
			}
		}
		
		if criticalCount > 0 {
			recommendations = append(recommendations,
				fmt.Sprintf("URGENT: Address %d critical vulnerabilities immediately", criticalCount))
		}
		
		recommendations = append(recommendations,
			"Create a patch management plan for identified vulnerabilities",
			"Consider network segmentation to limit exposure")
	}
	
	// Based on compliance
	failedCompliance := []string{}
	for _, check := range result.ComplianceChecks {
		if check.Status == "fail" {
			failedCompliance = append(failedCompliance, check.Requirement)
		}
	}
	
	if len(failedCompliance) > 0 {
		recommendations = append(recommendations,
			fmt.Sprintf("Address %d failed compliance checks", len(failedCompliance)))
	}
	
	// Based on risk level
	switch result.RiskLevel {
	case "critical", "high":
		recommendations = append(recommendations,
			"Implement additional monitoring for this high-risk asset",
			"Consider implementing defense-in-depth strategies")
	case "medium":
		recommendations = append(recommendations,
			"Schedule regular security reviews for this asset")
	}
	
	return recommendations
}

// saveAssessment saves assessment results to database
func (s *SecurityService) saveAssessment(asset *models.Asset, result *SecurityAssessmentResult) error {
	// Save vulnerabilities
	for _, vuln := range result.Vulnerabilities {
		assessment := &models.SecurityAssessment{
			ID:          uuid.New(),
			AssetID:     asset.ID,
			ScanDate:    result.AssessmentDate,
			ScanType:    "vulnerability",
			Severity:    vuln.Severity,
			Title:       vuln.Title,
			Description: vuln.Description,
			CVE:         vuln.CVE,
			CVSS:        vuln.CVSS,
			Status:      "open",
			Remediation: vuln.Solution,
		}
		
		if err := s.db.Create(assessment).Error; err != nil {
			s.logger.Error("Failed to save assessment", "error", err)
		}
	}
	
	// Update asset vulnerability count
	s.db.Model(asset).Update("vuln_count", len(result.Vulnerabilities))
	s.db.Model(asset).Update("last_sec_scan", result.AssessmentDate)
	
	return nil
}

// LoadCVEDatabase loads CVE data from file or API (offline preferred)
func (s *SecurityService) LoadCVEDatabase(source string) error {
	s.logger.Info("Loading CVE database", "source", source)
	
	// For ICS safety, prefer offline database
	if source == "offline" {
		return s.loadOfflineCVEs()
	}
	
	// If online update is specifically requested (with caution)
	if source == "online" {
		s.logger.Warn("Online CVE update requested - ensure this doesn't impact ICS network")
		return s.updateCVEsFromNVD()
	}
	
	return fmt.Errorf("invalid CVE source: %s", source)
}

// loadOfflineCVEs loads CVEs from local file
func (s *SecurityService) loadOfflineCVEs() error {
	// Load from local JSON file
	data, err := ioutil.ReadFile("data/cve_database.json")
	if err != nil {
		// If file doesn't exist, create empty database
		s.logger.Warn("CVE database file not found, using empty database")
		return nil
	}
	
	var cves []CVEEntry
	if err := json.Unmarshal(data, &cves); err != nil {
		return fmt.Errorf("failed to parse CVE data: %w", err)
	}
	
	s.cveDatabase.mu.Lock()
	defer s.cveDatabase.mu.Unlock()
	
	for _, cve := range cves {
		s.cveDatabase.CVEs[cve.ID] = &cve
	}
	
	s.cveDatabase.LastUpdated = time.Now()
	s.logger.Info("CVE database loaded", "count", len(s.cveDatabase.CVEs))
	
	return nil
}

// updateCVEsFromNVD updates from NVD API (use with caution in ICS)
func (s *SecurityService) updateCVEsFromNVD() error {
	// This should be done from a separate management network
	// Never directly from ICS network
	
	client := &http.Client{Timeout: 30 * time.Second}
	
	// NVD API endpoint (example)
	url := "https://services.nvd.nist.gov/rest/json/cves/1.0"
	
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("failed to fetch CVEs: %w", err)
	}
	defer resp.Body.Close()
	
	// Parse and update database
	// Implementation depends on NVD API response format
	
	return nil
}

// GetSecurityDashboard returns security metrics for dashboard
func (s *SecurityService) GetSecurityDashboard() (map[string]interface{}, error) {
	dashboard := make(map[string]interface{})
	
	// Count vulnerabilities by severity
	var severityCounts []struct {
		Severity string
		Count    int64
	}
	
	s.db.Model(&models.SecurityAssessment{}).
		Select("severity, count(*) as count").
		Where("status = ? AND scan_type = ?", "open", "vulnerability").
		Group("severity").
		Scan(&severityCounts)
	
	severityMap := make(map[string]int64)
	for _, sc := range severityCounts {
		severityMap[sc.Severity] = sc.Count
	}
	
	dashboard["vulnerabilities"] = severityMap
	
	// Get compliance statistics
	var totalAssets, compliantAssets int64
	s.db.Model(&models.Asset{}).Count(&totalAssets)
	s.db.Model(&models.Asset{}).Where("vuln_count = 0").Count(&compliantAssets)
	
	complianceRate := float64(0)
	if totalAssets > 0 {
		complianceRate = float64(compliantAssets) / float64(totalAssets) * 100
	}
	
	dashboard["compliance_rate"] = complianceRate
	dashboard["total_assets"] = totalAssets
	
	// Get recent assessments
	var recentAssessments []models.SecurityAssessment
	s.db.Order("created_at DESC").Limit(10).Find(&recentAssessments)
	dashboard["recent_assessments"] = recentAssessments
	
	// Calculate overall security score
	securityScore := s.calculateOverallSecurityScore()
	dashboard["security_score"] = securityScore
	
	return dashboard, nil
}

// calculateOverallSecurityScore calculates organization-wide security score
func (s *SecurityService) calculateOverallSecurityScore() int {
	score := 100
	
	// Deduct points for open vulnerabilities
	var criticalVulns, highVulns int64
	s.db.Model(&models.SecurityAssessment{}).
		Where("severity = ? AND status = ?", "critical", "open").
		Count(&criticalVulns)
	s.db.Model(&models.SecurityAssessment{}).
		Where("severity = ? AND status = ?", "high", "open").
		Count(&highVulns)
	
	score -= int(criticalVulns * 10)
	score -= int(highVulns * 5)
	
	// Ensure score doesn't go below 0
	if score < 0 {
		score = 0
	}
	
	return score
}

// GetDB returns the database instance
func (s *SecurityService) GetDB() *gorm.DB {
	return s.db
}

// Helper function
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}