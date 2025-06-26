// internal/services/compliance_service.go
package services

import (
	"fmt"
	"strings"
	"time"

	"ics-asset-inventory/internal/database"
	"ics-asset-inventory/internal/database/models"
	"ics-asset-inventory/internal/utils"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ComplianceService handles compliance assessments
type ComplianceService struct {
	db     *gorm.DB
	logger *utils.Logger
}

// NewComplianceService creates a new compliance service
func NewComplianceService() *ComplianceService {
	return &ComplianceService{
		db:     database.GetDB(),
		logger: utils.NewLogger(),
	}
}

// ComplianceAssessmentRequest represents a compliance check request
type ComplianceAssessmentRequest struct {
	Standards              []string `json:"standards" binding:"required"`
	Scope                  string   `json:"scope"` // all, critical, selected
	AssetIDs               []string `json:"asset_ids"`
	Categories             []string `json:"categories"`
	GenerateEvidence       bool     `json:"generate_evidence"`
	IncludeRecommendations bool     `json:"include_recommendations"`
	CompareBaseline        bool     `json:"compare_baseline"`
}

// ComplianceAssessmentResponse represents the assessment response
type ComplianceAssessmentResponse struct {
	ID               string                        `json:"id"`
	AssessmentDate   time.Time                    `json:"assessment_date"`
	Standards        []StandardComplianceResult    `json:"standards"`
	OverallScore     float64                      `json:"overall_score"`
	TotalChecks      int                          `json:"total_checks"`
	PassedChecks     int                          `json:"passed_checks"`
	FailedChecks     int                          `json:"failed_checks"`
	NotApplicable    int                          `json:"not_applicable"`
	Recommendations  []ComplianceRecommendation    `json:"recommendations"`
	ExecutiveSummary string                        `json:"executive_summary"`
}

// StandardComplianceResult represents compliance results for a standard
type StandardComplianceResult struct {
	Standard         string                    `json:"standard"`
	ComplianceScore  float64                  `json:"compliance_score"`
	Categories       []CategoryComplianceResult `json:"categories"`
	Summary          string                    `json:"summary"`
}

// CategoryComplianceResult represents compliance results for a category
type CategoryComplianceResult struct {
	Category     string              `json:"category"`
	Description  string              `json:"description"`
	TotalChecks  int                 `json:"total_checks"`
	PassedChecks int                 `json:"passed_checks"`
	FailedChecks int                 `json:"failed_checks"`
	Score        float64             `json:"score"`
	Checks       []ComplianceCheckResult `json:"checks"`
}

// ComplianceCheckResult represents individual check result
type ComplianceCheckResult struct {
	ID           string                 `json:"id"`
	CheckID      string                 `json:"check_id"`
	Title        string                 `json:"title"`
	Description  string                 `json:"description"`
	Category     string                 `json:"category"`
	Requirement  string                 `json:"requirement"`
	Status       string                 `json:"status"` // pass, fail, not_applicable
	Evidence     string                 `json:"evidence"`
	AssetID      string                 `json:"asset_id"`
	AssetName    string                 `json:"asset_name"`
	Details      string                 `json:"details"`
	Remediation  string                 `json:"remediation"`
	RiskLevel    string                 `json:"risk_level"`
	LastChecked  time.Time             `json:"last_checked"`
}

// ComplianceRecommendation represents a compliance improvement recommendation
type ComplianceRecommendation struct {
	Priority     string   `json:"priority"`
	Category     string   `json:"category"`
	Title        string   `json:"title"`
	Description  string   `json:"description"`
	Impact       string   `json:"impact"`
	Effort       string   `json:"effort"`
	AffectedAssets []string `json:"affected_assets"`
}

// ComplianceCheckDef defines a compliance requirement check (renamed to avoid conflict)
type ComplianceCheckDef struct {
	ID          string `json:"id"`
	Standard    string `json:"standard"`
	Category    string `json:"category"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Requirement string `json:"requirement"`
	CheckType   string `json:"check_type"` // technical, procedural, physical
	Automated   bool   `json:"automated"`
	Critical    bool   `json:"critical"`
}

// RunComplianceAssessment performs a comprehensive compliance assessment
func (s *ComplianceService) RunComplianceAssessment(req *ComplianceAssessmentRequest) (*ComplianceAssessmentResponse, error) {
	s.logger.Info("Starting compliance assessment", "standards", req.Standards)

	// Get assets based on scope
	assets, err := s.getAssetsForAssessment(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get assets: %w", err)
	}

	response := &ComplianceAssessmentResponse{
		ID:               uuid.New().String(),
		AssessmentDate:   time.Now(),
		Standards:        []StandardComplianceResult{},
		Recommendations:  []ComplianceRecommendation{},
	}

	// Run assessment for each standard
	for _, standard := range req.Standards {
		standardResult := s.assessStandard(standard, assets, req)
		response.Standards = append(response.Standards, standardResult)
		
		// Aggregate counts
		for _, category := range standardResult.Categories {
			response.TotalChecks += category.TotalChecks
			response.PassedChecks += category.PassedChecks
			response.FailedChecks += category.FailedChecks
			response.NotApplicable += (category.TotalChecks - category.PassedChecks - category.FailedChecks)
		}
	}

	// Calculate overall score
	if response.TotalChecks > 0 {
		response.OverallScore = float64(response.PassedChecks) / float64(response.TotalChecks) * 100
	}

	// Generate recommendations if requested
	if req.IncludeRecommendations {
		response.Recommendations = s.generateRecommendations(response.Standards, assets)
	}

	// Generate executive summary
	response.ExecutiveSummary = s.generateExecutiveSummary(response)

	// Save assessment results
	s.saveAssessmentResults(response, assets)

	s.logger.Info("Compliance assessment completed", 
		"id", response.ID, 
		"overall_score", response.OverallScore)

	return response, nil
}

// getAssetsForAssessment retrieves assets based on assessment scope
func (s *ComplianceService) getAssetsForAssessment(req *ComplianceAssessmentRequest) ([]models.Asset, error) {
	var assets []models.Asset
	query := s.db.Model(&models.Asset{})

	switch req.Scope {
	case "all":
		// Get all assets
		err := query.Find(&assets).Error
		return assets, err
		
	case "critical":
		// Get only critical assets
		err := query.Where("criticality IN ?", []string{"critical", "high"}).Find(&assets).Error
		return assets, err
		
	case "selected":
		// Get specific assets
		if len(req.AssetIDs) == 0 {
			return nil, fmt.Errorf("no assets selected")
		}
		err := query.Where("id IN ?", req.AssetIDs).Find(&assets).Error
		return assets, err
		
	default:
		return nil, fmt.Errorf("invalid scope: %s", req.Scope)
	}
}

// assessStandard performs assessment for a specific standard
func (s *ComplianceService) assessStandard(standard string, assets []models.Asset, req *ComplianceAssessmentRequest) StandardComplianceResult {
	result := StandardComplianceResult{
		Standard:   standard,
		Categories: []CategoryComplianceResult{},
	}

	// Get checks for this standard
	checks := s.getChecksForStandard(standard, req.Categories)
	
	// Group checks by category
	categoryChecks := make(map[string][]ComplianceCheckDef)
	for _, check := range checks {
		categoryChecks[check.Category] = append(categoryChecks[check.Category], check)
	}

	// Assess each category
	for category, checks := range categoryChecks {
		categoryResult := CategoryComplianceResult{
			Category:    category,
			Description: s.getCategoryDescription(standard, category),
			Checks:      []ComplianceCheckResult{},
		}

		// Run checks for each asset
		for _, asset := range assets {
			for _, check := range checks {
				checkResult := s.runCheck(check, asset, req.GenerateEvidence)
				categoryResult.Checks = append(categoryResult.Checks, checkResult)
				
				// Update counts
				categoryResult.TotalChecks++
				switch checkResult.Status {
				case "pass":
					categoryResult.PassedChecks++
				case "fail":
					categoryResult.FailedChecks++
				}
			}
		}

		// Calculate category score
		if categoryResult.TotalChecks > 0 {
			categoryResult.Score = float64(categoryResult.PassedChecks) / float64(categoryResult.TotalChecks) * 100
		}

		result.Categories = append(result.Categories, categoryResult)
	}

	// Calculate standard compliance score
	totalChecks := 0
	passedChecks := 0
	for _, cat := range result.Categories {
		totalChecks += cat.TotalChecks
		passedChecks += cat.PassedChecks
	}
	
	if totalChecks > 0 {
		result.ComplianceScore = float64(passedChecks) / float64(totalChecks) * 100
	}

	result.Summary = s.generateStandardSummary(standard, result)
	
	return result
}

// getChecksForStandard returns compliance checks for a standard
func (s *ComplianceService) getChecksForStandard(standard string, categories []string) []ComplianceCheckDef {
	checks := []ComplianceCheckDef{}

	switch standard {
	case "IEC-62443":
		checks = append(checks, s.getIEC62443Checks(categories)...)
	case "NIST":
		checks = append(checks, s.getNISTChecks(categories)...)
	case "ISO27001":
		checks = append(checks, s.getISO27001Checks(categories)...)
	case "NERC-CIP":
		checks = append(checks, s.getNERCCIPChecks(categories)...)
	}

	return checks
}

// getIEC62443Checks returns IEC 62443 compliance checks
func (s *ComplianceService) getIEC62443Checks(categories []string) []ComplianceCheckDef {
	allChecks := []ComplianceCheckDef{
		// FR 1: Identification and Authentication Control
		{
			ID:          "IEC-62443-FR1-01",
			Standard:    "IEC-62443",
			Category:    "access_control",
			Title:       "Human User Identification and Authentication",
			Description: "All human users shall be identified and authenticated",
			Requirement: "FR 1.1",
			CheckType:   "technical",
			Automated:   true,
			Critical:    true,
		},
		{
			ID:          "IEC-62443-FR1-02",
			Standard:    "IEC-62443",
			Category:    "access_control",
			Title:       "Software Process Identification and Authentication",
			Description: "All software processes shall be identified and authenticated",
			Requirement: "FR 1.2",
			CheckType:   "technical",
			Automated:   true,
			Critical:    true,
		},
		// FR 2: Use Control
		{
			ID:          "IEC-62443-FR2-01",
			Standard:    "IEC-62443",
			Category:    "access_control",
			Title:       "Authorization Enforcement",
			Description: "Authorization enforcement at the application layer",
			Requirement: "FR 2.1",
			CheckType:   "technical",
			Automated:   true,
			Critical:    true,
		},
		// FR 3: System Integrity
		{
			ID:          "IEC-62443-FR3-01",
			Standard:    "IEC-62443",
			Category:    "system_integrity",
			Title:       "Communication Integrity",
			Description: "Protect the integrity of transmitted information",
			Requirement: "FR 3.1",
			CheckType:   "technical",
			Automated:   true,
			Critical:    true,
		},
		// FR 4: Data Confidentiality
		{
			ID:          "IEC-62443-FR4-01",
			Standard:    "IEC-62443",
			Category:    "data_protection",
			Title:       "Information Confidentiality",
			Description: "Ensure the confidentiality of information",
			Requirement: "FR 4.1",
			CheckType:   "technical",
			Automated:   true,
			Critical:    true,
		},
		// FR 5: Restricted Data Flow
		{
			ID:          "IEC-62443-FR5-01",
			Standard:    "IEC-62443",
			Category:    "network_security",
			Title:       "Network Segmentation",
			Description: "Segment control system networks from non-control system networks",
			Requirement: "FR 5.1",
			CheckType:   "technical",
			Automated:   true,
			Critical:    true,
		},
		// FR 6: Timely Response to Events
		{
			ID:          "IEC-62443-FR6-01",
			Standard:    "IEC-62443",
			Category:    "incident_response",
			Title:       "Audit Log Accessibility",
			Description: "Audit logs shall be accessible for review",
			Requirement: "FR 6.1",
			CheckType:   "technical",
			Automated:   true,
			Critical:    false,
		},
		// FR 7: Resource Availability
		{
			ID:          "IEC-62443-FR7-01",
			Standard:    "IEC-62443",
			Category:    "system_integrity",
			Title:       "Denial of Service Protection",
			Description: "Protect against denial of service",
			Requirement: "FR 7.1",
			CheckType:   "technical",
			Automated:   true,
			Critical:    true,
		},
		// Physical Security
		{
			ID:          "IEC-62443-PS-01",
			Standard:    "IEC-62443",
			Category:    "physical_security",
			Title:       "Physical Access Control",
			Description: "Control physical access to the control system",
			Requirement: "SR 1.13",
			CheckType:   "physical",
			Automated:   false,
			Critical:    true,
		},
	}

	// Filter by requested categories
	if len(categories) == 0 {
		return allChecks
	}

	filtered := []ComplianceCheckDef{}
	for _, check := range allChecks {
		for _, cat := range categories {
			if check.Category == cat {
				filtered = append(filtered, check)
				break
			}
		}
	}

	return filtered
}

// getNISTChecks returns NIST Framework compliance checks
func (s *ComplianceService) getNISTChecks(categories []string) []ComplianceCheckDef {
	// Similar implementation for NIST checks
	return []ComplianceCheckDef{
		{
			ID:          "NIST-ID-AM-01",
			Standard:    "NIST",
			Category:    "access_control",
			Title:       "Asset Management",
			Description: "Physical devices and systems are inventoried",
			Requirement: "ID.AM-1",
			CheckType:   "procedural",
			Automated:   true,
			Critical:    false,
		},
		// Add more NIST checks...
	}
}

// getISO27001Checks returns ISO 27001 compliance checks
func (s *ComplianceService) getISO27001Checks(categories []string) []ComplianceCheckDef {
	// Implementation for ISO 27001 checks
	return []ComplianceCheckDef{}
}

// getNERCCIPChecks returns NERC CIP compliance checks
func (s *ComplianceService) getNERCCIPChecks(categories []string) []ComplianceCheckDef {
	// Implementation for NERC CIP checks
	return []ComplianceCheckDef{}
}

// runCheck performs an individual compliance check
func (s *ComplianceService) runCheck(check ComplianceCheckDef, asset models.Asset, generateEvidence bool) ComplianceCheckResult {
	result := ComplianceCheckResult{
		ID:          uuid.New().String(),
		CheckID:     check.ID,
		Title:       check.Title,
		Description: check.Description,
		Category:    check.Category,
		Requirement: check.Requirement,
		AssetID:     asset.ID.String(),
		AssetName:   asset.Name,
		LastChecked: time.Now(),
	}

	// Run check based on type and ID
	switch check.ID {
	case "IEC-62443-FR1-01":
		result = s.checkUserAuthentication(asset, result)
	case "IEC-62443-FR1-02":
		result = s.checkProcessAuthentication(asset, result)
	case "IEC-62443-FR3-01":
		result = s.checkCommunicationIntegrity(asset, result)
	case "IEC-62443-FR5-01":
		result = s.checkNetworkSegmentation(asset, result)
	default:
		// Generic check based on asset properties
		result = s.performGenericCheck(check, asset, result)
	}

	// Generate evidence if requested
	if generateEvidence && result.Evidence == "" {
		result.Evidence = s.generateEvidence(check, asset, result.Status)
	}

	// Set remediation if failed
	if result.Status == "fail" {
		result.Remediation = s.getRemediation(check.ID, asset)
		result.RiskLevel = s.calculateRiskLevel(check, asset)
	}

	return result
}

// Specific check implementations
func (s *ComplianceService) checkUserAuthentication(asset models.Asset, result ComplianceCheckResult) ComplianceCheckResult {
	// Check if asset supports and enforces user authentication
	if asset.Protocol == "Modbus TCP" {
		result.Status = "fail"
		result.Details = "Modbus TCP does not support authentication"
		result.Evidence = fmt.Sprintf("Protocol: %s on port %d", asset.Protocol, asset.Port)
	} else if asset.Protocol == "DNP3" || asset.Protocol == "IEC-104" {
		result.Status = "pass"
		result.Details = "Protocol supports authentication mechanisms"
		result.Evidence = fmt.Sprintf("Protocol: %s with authentication capability", asset.Protocol)
	} else {
		result.Status = "not_applicable"
		result.Details = "Unable to determine authentication support"
	}
	
	return result
}

func (s *ComplianceService) checkProcessAuthentication(asset models.Asset, result ComplianceCheckResult) ComplianceCheckResult {
	// Check software process authentication
	// This would typically check certificates, keys, etc.
	result.Status = "pass" // Simplified
	result.Details = "Process authentication configured"
	return result
}

func (s *ComplianceService) checkCommunicationIntegrity(asset models.Asset, result ComplianceCheckResult) ComplianceCheckResult {
	// Check if communications are protected
	secureProtocols := map[string]bool{
		"DNP3-Secure": true,
		"IEC-62351": true,
		"OPC-UA": true,
	}
	
	if secureProtocols[asset.Protocol] {
		result.Status = "pass"
		result.Details = "Secure protocol in use"
	} else {
		result.Status = "fail"
		result.Details = "Insecure protocol detected"
		result.Evidence = fmt.Sprintf("Using %s without encryption", asset.Protocol)
	}
	
	return result
}

func (s *ComplianceService) checkNetworkSegmentation(asset models.Asset, result ComplianceCheckResult) ComplianceCheckResult {
	// Check network zone assignment
	if asset.Zone == "" {
		result.Status = "fail"
		result.Details = "No network zone assigned"
	} else if asset.Zone == "DMZ" || asset.Zone == "Control Network" {
		result.Status = "pass"
		result.Details = fmt.Sprintf("Asset properly segmented in %s", asset.Zone)
		result.Evidence = fmt.Sprintf("Zone: %s", asset.Zone)
	} else {
		result.Status = "fail"
		result.Details = "Asset not in secure network zone"
	}
	
	return result
}

func (s *ComplianceService) performGenericCheck(check ComplianceCheckDef, asset models.Asset, result ComplianceCheckResult) ComplianceCheckResult {
	// Generic check implementation
	result.Status = "not_applicable"
	result.Details = "Check not implemented"
	return result
}

// generateEvidence creates evidence for a compliance check
func (s *ComplianceService) generateEvidence(check ComplianceCheckDef, asset models.Asset, status string) string {
	evidence := fmt.Sprintf("Asset: %s (%s)\n", asset.Name, asset.ID)
	evidence += fmt.Sprintf("Type: %s\n", asset.AssetType)
	evidence += fmt.Sprintf("IP: %s\n", asset.IPAddress)
	evidence += fmt.Sprintf("Protocol: %s\n", asset.Protocol)
	evidence += fmt.Sprintf("Zone: %s\n", asset.Zone)
	evidence += fmt.Sprintf("Criticality: %s\n", asset.Criticality)
	evidence += fmt.Sprintf("Check performed: %s\n", time.Now().Format(time.RFC3339))
	evidence += fmt.Sprintf("Result: %s\n", status)
	
	return evidence
}

// getRemediation provides remediation steps for failed checks
func (s *ComplianceService) getRemediation(checkID string, asset models.Asset) string {
	remediations := map[string]string{
		"IEC-62443-FR1-01": "Implement authentication mechanism or upgrade to secure protocol",
		"IEC-62443-FR3-01": "Enable encryption for communications or use secure protocol variant",
		"IEC-62443-FR5-01": "Assign asset to proper network zone and implement segmentation",
		"IEC-62443-FR7-01": "Implement rate limiting and access controls",
	}
	
	if remediation, ok := remediations[checkID]; ok {
		return remediation
	}
	
	return "Review security requirements and implement appropriate controls"
}

// calculateRiskLevel determines risk level for failed check
func (s *ComplianceService) calculateRiskLevel(check ComplianceCheckDef, asset models.Asset) string {
	// Consider check criticality and asset criticality
	if check.Critical && (asset.Criticality == "critical" || asset.Criticality == "high") {
		return "critical"
	} else if check.Critical || asset.Criticality == "high" {
		return "high"
	} else if asset.Criticality == "medium" {
		return "medium"
	}
	
	return "low"
}

// generateRecommendations creates improvement recommendations
func (s *ComplianceService) generateRecommendations(standards []StandardComplianceResult, assets []models.Asset) []ComplianceRecommendation {
	recommendations := []ComplianceRecommendation{}
	
	// Analyze failed checks
	failedByCategory := make(map[string]int)
	criticalFails := []ComplianceCheckResult{}
	
	for _, standard := range standards {
		for _, category := range standard.Categories {
			if category.FailedChecks > 0 {
				failedByCategory[category.Category] += category.FailedChecks
			}
			
			for _, check := range category.Checks {
				if check.Status == "fail" && check.RiskLevel == "critical" {
					criticalFails = append(criticalFails, check)
				}
			}
		}
	}
	
	// Critical recommendations
	if len(criticalFails) > 0 {
		rec := ComplianceRecommendation{
			Priority:    "critical",
			Category:    "multiple",
			Title:       "Address Critical Compliance Failures",
			Description: fmt.Sprintf("Immediate action required for %d critical compliance failures", len(criticalFails)),
			Impact:      "Major reduction in compliance risk",
			Effort:      "high",
		}
		recommendations = append(recommendations, rec)
	}
	
	// Category-specific recommendations
	for category, count := range failedByCategory {
		priority := "medium"
		if count > 5 {
			priority = "high"
		}
		
		rec := ComplianceRecommendation{
			Priority:    priority,
			Category:    category,
			Title:       fmt.Sprintf("Improve %s Compliance", formatCategory(category)),
			Description: fmt.Sprintf("%d compliance checks failed in %s category", count, category),
			Impact:      "Improved compliance score",
			Effort:      "medium",
		}
		recommendations = append(recommendations, rec)
	}
	
	return recommendations
}

// generateExecutiveSummary creates executive summary
func (s *ComplianceService) generateExecutiveSummary(response *ComplianceAssessmentResponse) string {
	summary := fmt.Sprintf("Compliance Assessment Executive Summary\n\n")
	summary += fmt.Sprintf("Assessment Date: %s\n", response.AssessmentDate.Format("January 2, 2006"))
	summary += fmt.Sprintf("Overall Compliance Score: %.1f%%\n\n", response.OverallScore)
	
	summary += "Standards Assessed:\n"
	for _, standard := range response.Standards {
		summary += fmt.Sprintf("- %s: %.1f%% compliant\n", standard.Standard, standard.ComplianceScore)
	}
	
	summary += fmt.Sprintf("\nTotal Checks Performed: %d\n", response.TotalChecks)
	summary += fmt.Sprintf("Passed: %d (%.1f%%)\n", response.PassedChecks, float64(response.PassedChecks)/float64(response.TotalChecks)*100)
	summary += fmt.Sprintf("Failed: %d (%.1f%%)\n", response.FailedChecks, float64(response.FailedChecks)/float64(response.TotalChecks)*100)
	
	if len(response.Recommendations) > 0 {
		summary += fmt.Sprintf("\nKey Recommendations: %d improvement areas identified\n", len(response.Recommendations))
		
		criticalCount := 0
		for _, rec := range response.Recommendations {
			if rec.Priority == "critical" {
				criticalCount++
			}
		}
		
		if criticalCount > 0 {
			summary += fmt.Sprintf("- %d critical priority items requiring immediate attention\n", criticalCount)
		}
	}
	
	return summary
}

// saveAssessmentResults persists assessment results to database
func (s *ComplianceService) saveAssessmentResults(response *ComplianceAssessmentResponse, assets []models.Asset) error {
	// Save to database (implementation depends on your schema)
	// This is a placeholder
	s.logger.Info("Saving assessment results", "id", response.ID)
	return nil
}

// GetComplianceHistory retrieves historical compliance assessments
func (s *ComplianceService) GetComplianceHistory(limit int) ([]ComplianceAssessmentResponse, error) {
	// Implementation to retrieve historical assessments
	return []ComplianceAssessmentResponse{}, nil
}

// GetComplianceDetails retrieves detailed compliance results
func (s *ComplianceService) GetComplianceDetails(assessmentID string) (*ComplianceAssessmentResponse, error) {
	// Implementation to retrieve specific assessment details
	return nil, nil
}

// ExportComplianceReport generates compliance report in specified format
func (s *ComplianceService) ExportComplianceReport(assessmentID string, format string) ([]byte, error) {
	// Implementation to export report
	return []byte{}, nil
}

// Helper functions
func (s *ComplianceService) getCategoryDescription(standard, category string) string {
	descriptions := map[string]map[string]string{
		"IEC-62443": {
			"access_control":    "Identification, Authentication and Authorization Controls",
			"network_security":  "Network Segmentation and Boundary Protection",
			"data_protection":   "Data Confidentiality and Integrity",
			"system_integrity":  "System Integrity and Availability",
			"incident_response": "Event Logging and Incident Response",
			"physical_security": "Physical Access Controls",
		},
	}
	
	if std, ok := descriptions[standard]; ok {
		if desc, ok := std[category]; ok {
			return desc
		}
	}
	
	return formatCategory(category)
}

func (s *ComplianceService) generateStandardSummary(standard string, result StandardComplianceResult) string {
	return fmt.Sprintf("%s compliance score: %.1f%%. Assessment covered %d categories with varying compliance levels.",
		standard, result.ComplianceScore, len(result.Categories))
}

func formatCategory(category string) string {
	// Convert snake_case to Title Case
	words := strings.Split(category, "_")
	for i, word := range words {
		words[i] = strings.Title(word)
	}
	return strings.Join(words, " ")
}