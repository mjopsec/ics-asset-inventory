// internal/api/handlers/security.go
package handlers

import (
	"net/http"
	"strconv"
	"time"

	"ics-asset-inventory/internal/database"
	"ics-asset-inventory/internal/database/models"
	"ics-asset-inventory/internal/services"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// SecurityHandler handles security-related endpoints
type SecurityHandler struct {
	service *services.SecurityService
	db      *gorm.DB
}

// NewSecurityHandler creates a new security handler
func NewSecurityHandler() *SecurityHandler {
	service := services.NewSecurityService()
	
	// Load offline CVE database on startup
	if err := service.LoadCVEDatabase("offline"); err != nil {
		// Log error but don't fail - can work without CVE DB
		println("Warning: Failed to load CVE database:", err.Error())
	}
	
	return &SecurityHandler{
		service: service,
		db:      database.GetDB(),
	}
}

// RunSecurityAssessment performs passive security assessment
// @Summary Run security assessment
// @Description Perform passive security assessment on selected assets (SAFE for ICS)
// @Tags security
// @Accept json
// @Produce json
// @Param request body services.SecurityAssessmentRequest true "Assessment request"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Router /api/security/assessment [post]
func (h *SecurityHandler) RunSecurityAssessment(c *gin.Context) {
	var req services.SecurityAssessmentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
			"details": err.Error(),
		})
		return
	}
	
	// Validate request
	if len(req.AssetIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "No assets selected for assessment",
		})
		return
	}
	
	// Set default check types if not specified
	if len(req.CheckTypes) == 0 {
		req.CheckTypes = []string{"vulnerability", "compliance", "configuration"}
	}
	
	// Default to using cache for safety
	if !req.UseCache {
		req.UseCache = true
	}
	
	// Run passive assessment
	results, err := h.service.RunPassiveAssessment(&req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to run assessment",
			"details": err.Error(),
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Security assessment completed",
		"mode": "passive",
		"assets_assessed": len(results),
		"results": results,
		"timestamp": time.Now(),
		"safe_mode": true, // Always true for ICS
	})
}

// GetVulnerabilities returns vulnerability list
// @Summary Get vulnerabilities
// @Description Get list of vulnerabilities with filtering
// @Tags security
// @Accept json
// @Produce json
// @Param severity query string false "Filter by severity"
// @Param status query string false "Filter by status"
// @Param asset_id query string false "Filter by asset ID"
// @Param limit query int false "Limit results" default(50)
// @Success 200 {object} map[string]interface{}
// @Router /api/security/vulnerabilities [get]
func (h *SecurityHandler) GetVulnerabilities(c *gin.Context) {
	// Build query
	query := h.db.Model(&models.SecurityAssessment{}).
		Where("scan_type = ?", "vulnerability").
		Preload("Asset")
	
	// Apply filters
	if severity := c.Query("severity"); severity != "" {
		query = query.Where("severity = ?", severity)
	}
	
	if status := c.Query("status"); status != "" {
		query = query.Where("status = ?", status)
	}
	
	if assetID := c.Query("asset_id"); assetID != "" {
		query = query.Where("asset_id = ?", assetID)
	}
	
	// Get limit
	limit := 50
	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}
	
	// Execute query
	var vulnerabilities []models.SecurityAssessment
	if err := query.Order("created_at DESC").Limit(limit).Find(&vulnerabilities).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to fetch vulnerabilities",
		})
		return
	}
	
	// Count by severity
	var severityCounts []struct {
		Severity string
		Count    int64
	}
	h.db.Model(&models.SecurityAssessment{}).
		Select("severity, count(*) as count").
		Where("status = ? AND scan_type = ?", "open", "vulnerability").
		Group("severity").
		Scan(&severityCounts)
	
	c.JSON(http.StatusOK, gin.H{
		"vulnerabilities": vulnerabilities,
		"count": len(vulnerabilities),
		"severity_distribution": severityCounts,
	})
}

// GetSecurityDashboard returns security dashboard data
// @Summary Get security dashboard
// @Description Get security metrics and statistics
// @Tags security
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/security/dashboard [get]
func (h *SecurityHandler) GetSecurityDashboard(c *gin.Context) {
	dashboard, err := h.service.GetSecurityDashboard()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get dashboard data",
		})
		return
	}
	
	c.JSON(http.StatusOK, dashboard)
}

// UpdateVulnerabilityStatus updates vulnerability status
// @Summary Update vulnerability status
// @Description Update the status of a vulnerability (open, acknowledged, resolved)
// @Tags security
// @Accept json
// @Produce json
// @Param id path string true "Vulnerability ID"
// @Param status body map[string]string true "Status update"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Router /api/security/vulnerabilities/{id}/status [patch]
func (h *SecurityHandler) UpdateVulnerabilityStatus(c *gin.Context) {
	vulnID := c.Param("id")
	
	var req struct {
		Status      string `json:"status" binding:"required,oneof=open acknowledged resolved false_positive"`
		Notes       string `json:"notes"`
		Remediation string `json:"remediation"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
			"details": err.Error(),
		})
		return
	}
	
	// Update vulnerability
	updates := map[string]interface{}{
		"status": req.Status,
		"updated_at": time.Now(),
	}
	
	if req.Notes != "" {
		updates["description"] = req.Notes
	}
	
	if req.Remediation != "" {
		updates["remediation"] = req.Remediation
	}
	
	result := h.db.Model(&models.SecurityAssessment{}).
		Where("id = ?", vulnID).
		Updates(updates)
	
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to update vulnerability",
		})
		return
	}
	
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Vulnerability not found",
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Vulnerability status updated",
		"id": vulnID,
		"status": req.Status,
	})
}

// GetComplianceStatus returns compliance status
// @Summary Get compliance status
// @Description Get compliance status for different standards
// @Tags security
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/security/compliance [get]
func (h *SecurityHandler) GetComplianceStatus(c *gin.Context) {
	// This is a simplified implementation
	// In production, this would aggregate compliance check results
	
	compliance := map[string]interface{}{
		"standards": []map[string]interface{}{
			{
				"name": "IEC 62443",
				"compliance_rate": 78.5,
				"last_assessed": time.Now().Add(-24 * time.Hour),
				"categories": map[string]string{
					"FR1_IAC": "pass",
					"FR2_UC": "pass",
					"FR3_SI": "fail",
					"FR4_DC": "pass",
					"FR5_RDF": "not_assessed",
					"FR6_TRE": "pass",
					"FR7_RA": "fail",
				},
			},
			{
				"name": "NIST Cybersecurity Framework",
				"compliance_rate": 92.0,
				"last_assessed": time.Now().Add(-48 * time.Hour),
				"categories": map[string]string{
					"Identify": "pass",
					"Protect": "pass",
					"Detect": "pass",
					"Respond": "pass",
					"Recover": "fail",
				},
			},
			{
				"name": "Corporate Security Policy",
				"compliance_rate": 65.0,
				"last_assessed": time.Now().Add(-72 * time.Hour),
				"categories": map[string]string{
					"Password Policy": "pass",
					"Encryption Standards": "fail",
					"Backup Procedures": "fail",
					"Incident Response": "pass",
					"Security Training": "fail",
				},
			},
		},
		"overall_compliance": 78.5,
		"trend": "improving",
		"next_assessment": time.Now().Add(7 * 24 * time.Hour),
	}
	
	c.JSON(http.StatusOK, compliance)
}

// GetRiskMatrix returns risk assessment matrix
// @Summary Get risk matrix
// @Description Get risk assessment matrix and scores
// @Tags security
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/security/risk-matrix [get]
func (h *SecurityHandler) GetRiskMatrix(c *gin.Context) {
	// Get assets with risk scores
	type AssetRisk struct {
		AssetID      string `json:"asset_id"`
		AssetName    string `json:"asset_name"`
		AssetType    string `json:"asset_type"`
		Criticality  string `json:"criticality"`
		VulnCount    int    `json:"vuln_count"`
		RiskScore    int    `json:"risk_score"`
		RiskLevel    string `json:"risk_level"`
		Likelihood   string `json:"likelihood"`
		Impact       string `json:"impact"`
	}
	
	var assetRisks []AssetRisk
	
	// In production, this would calculate actual risk scores
	// For now, return sample data
	assetRisks = []AssetRisk{
		{
			AssetID:     "uuid-1",
			AssetName:   "Main PLC Controller",
			AssetType:   "PLC",
			Criticality: "critical",
			VulnCount:   3,
			RiskScore:   85,
			RiskLevel:   "critical",
			Likelihood:  "high",
			Impact:      "critical",
		},
		{
			AssetID:     "uuid-2",
			AssetName:   "HMI Panel Line 1",
			AssetType:   "HMI",
			Criticality: "high",
			VulnCount:   1,
			RiskScore:   60,
			RiskLevel:   "high",
			Likelihood:  "medium",
			Impact:      "high",
		},
	}
	
	// Risk matrix definition
	riskMatrix := map[string]interface{}{
		"matrix": [][]int{
			{5, 10, 15, 20, 25},  // Very High likelihood
			{4, 8, 12, 16, 20},   // High likelihood
			{3, 6, 9, 12, 15},    // Medium likelihood
			{2, 4, 6, 8, 10},     // Low likelihood
			{1, 2, 3, 4, 5},      // Very Low likelihood
		},
		"likelihood_levels": []string{"Very Low", "Low", "Medium", "High", "Very High"},
		"impact_levels": []string{"Very Low", "Low", "Medium", "High", "Very High"},
		"risk_levels": map[string]string{
			"1-5":   "low",
			"6-10":  "medium",
			"11-15": "high",
			"16-25": "critical",
		},
		"assets_at_risk": assetRisks,
		"summary": map[string]int{
			"critical_risks": 1,
			"high_risks": 2,
			"medium_risks": 5,
			"low_risks": 8,
		},
	}
	
	c.JSON(http.StatusOK, riskMatrix)
}

// ExportSecurityReport generates security report
// @Summary Export security report
// @Description Generate and export security assessment report
// @Tags security
// @Accept json
// @Produce json
// @Param format query string false "Export format (pdf, csv, json)" default(json)
// @Success 200 {object} map[string]interface{}
// @Router /api/security/report/export [get]
func (h *SecurityHandler) ExportSecurityReport(c *gin.Context) {
	format := c.DefaultQuery("format", "json")
	
	// For now, return JSON format
	// In production, this would generate PDF/CSV reports
	
	report := map[string]interface{}{
		"report_id": "SEC-2024-001",
		"generated_at": time.Now(),
		"format": format,
		"summary": map[string]interface{}{
			"total_assets": 156,
			"assets_assessed": 145,
			"vulnerabilities_found": 43,
			"critical_vulnerabilities": 3,
			"compliance_rate": 78.5,
			"overall_risk": "high",
		},
		"recommendations": []string{
			"Address 3 critical vulnerabilities immediately",
			"Implement network segmentation for 12 exposed assets",
			"Update firmware on 23 devices",
			"Enable authentication on Modbus devices",
			"Complete security training for operations staff",
		},
	}
	
	c.JSON(http.StatusOK, report)
}

// LoadCVEDatabase loads/updates CVE database
// @Summary Load CVE database
// @Description Load or update CVE database (offline mode for ICS safety)
// @Tags security
// @Accept json
// @Produce json
// @Param source query string false "Source (offline, online)" default(offline)
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Router /api/security/cve/load [post]
func (h *SecurityHandler) LoadCVEDatabase(c *gin.Context) {
	source := c.DefaultQuery("source", "offline")
	
	// For ICS safety, default to offline
	if source != "offline" && source != "online" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid source. Use 'offline' or 'online'",
			"recommended": "offline",
		})
		return
	}
	
	if source == "online" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Online CVE updates are disabled for ICS safety",
			"recommendation": "Use offline CVE database updates only",
		})
		return
	}
	
	// Load offline CVE database
	if err := h.service.LoadCVEDatabase(source); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to load CVE database",
			"details": err.Error(),
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"message": "CVE database loaded successfully",
		"source": source,
		"mode": "safe",
	})
}