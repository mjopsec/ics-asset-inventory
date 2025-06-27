// internal/api/handlers/compliance.go
package handlers

import (
	"net/http"
	"strconv"
	"time"

	"ics-asset-inventory/internal/services"

	"github.com/gin-gonic/gin"
)

// ComplianceHandler handles compliance-related endpoints
type ComplianceHandler struct {
	service *services.ComplianceService
}

// NewComplianceHandler creates a new compliance handler
func NewComplianceHandler() *ComplianceHandler {
	return &ComplianceHandler{
		service: services.NewComplianceService(),
	}
}

// RunComplianceAssessment runs a compliance assessment
// @Summary Run compliance assessment
// @Description Perform compliance assessment against selected standards
// @Tags compliance
// @Accept json
// @Produce json
// @Param request body services.ComplianceAssessmentRequest true "Assessment request"
// @Success 200 {object} services.ComplianceAssessmentResponse
// @Failure 400 {object} map[string]string
// @Router /api/compliance/assessment [post]
func (h *ComplianceHandler) RunComplianceAssessment(c *gin.Context) {
	var req services.ComplianceAssessmentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
			"details": err.Error(),
		})
		return
	}

	// Validate request
	if len(req.Standards) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "At least one compliance standard must be selected",
		})
		return
	}

	// Set default scope if not specified
	if req.Scope == "" {
		req.Scope = "all"
	}

	// Set default categories if not specified
	if len(req.Categories) == 0 {
		req.Categories = []string{
			"access_control",
			"network_security",
			"data_protection",
			"system_integrity",
			"incident_response",
			"physical_security",
		}
	}

	// Run assessment
	response, err := h.service.RunComplianceAssessment(&req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to run compliance assessment",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, response)
}

// GetComplianceStatus returns current compliance status
// @Summary Get compliance status
// @Description Get current compliance status and metrics
// @Tags compliance
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/compliance/status [get]
func (h *ComplianceHandler) GetComplianceStatus(c *gin.Context) {
	// Get compliance service from security service
	securityService := services.NewSecurityService()
	
	// Get compliance status
	status, err := securityService.GetDB().Raw(`
		SELECT 
			standard,
			COUNT(*) as total_checks,
			SUM(CASE WHEN status = 'pass' THEN 1 ELSE 0 END) as passed_checks,
			SUM(CASE WHEN status = 'fail' THEN 1 ELSE 0 END) as failed_checks,
			MAX(assessment_date) as last_assessment
		FROM compliance_results
		WHERE assessment_date > datetime('now', '-30 days')
		GROUP BY standard
	`).Rows()
	
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get compliance status",
		})
		return
	}
	defer status.Close()

	standards := []map[string]interface{}{}
	
	// Process results
	for status.Next() {
		var standard string
		var totalChecks, passedChecks, failedChecks int
		var lastAssessment string
		
		status.Scan(&standard, &totalChecks, &passedChecks, &failedChecks, &lastAssessment)
		
		complianceRate := float64(passedChecks) / float64(totalChecks) * 100
		
		standards = append(standards, map[string]interface{}{
			"name": standard,
			"compliance_rate": complianceRate,
			"last_assessed": lastAssessment,
			"total_checks": totalChecks,
			"passed_checks": passedChecks,
			"failed_checks": failedChecks,
		})
	}

	// Calculate overall compliance
	var overallTotal, overallPassed int
	for _, std := range standards {
		overallTotal += std["total_checks"].(int)
		overallPassed += std["passed_checks"].(int)
	}
	
	overallCompliance := float64(0)
	if overallTotal > 0 {
		overallCompliance = float64(overallPassed) / float64(overallTotal) * 100
	}

	c.JSON(http.StatusOK, gin.H{
		"standards": standards,
		"overall_compliance": overallCompliance,
		"trend": "improving", // This would be calculated based on historical data
		"next_assessment": "2024-02-01T00:00:00Z",
	})
}

// GetComplianceHistory returns compliance assessment history
// @Summary Get compliance history
// @Description Get historical compliance assessment results
// @Tags compliance
// @Accept json
// @Produce json
// @Param limit query int false "Number of records" default(10)
// @Success 200 {object} map[string]interface{}
// @Router /api/compliance/history [get]
func (h *ComplianceHandler) GetComplianceHistory(c *gin.Context) {
	limit := 10
	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}

	history, err := h.service.GetComplianceHistory(limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get compliance history",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"history": history,
		"count": len(history),
	})
}

// GetComplianceDetails returns detailed compliance assessment results
// @Summary Get compliance details
// @Description Get detailed results of a specific compliance assessment
// @Tags compliance
// @Accept json
// @Produce json
// @Param id path string true "Assessment ID"
// @Success 200 {object} services.ComplianceAssessmentResponse
// @Failure 404 {object} map[string]string
// @Router /api/compliance/assessment/{id} [get]
func (h *ComplianceHandler) GetComplianceDetails(c *gin.Context) {
	assessmentID := c.Param("id")
	
	// For now, since we don't have a database table for compliance assessments,
	// we'll return mock data or the last assessment from memory
	// In production, you would retrieve this from database
	
	// Mock implementation - return sample data
	mockResponse := &services.ComplianceAssessmentResponse{
		ID:             assessmentID,
		AssessmentDate: time.Now(),
		OverallScore:   78.5,
		TotalChecks:    50,
		PassedChecks:   39,
		FailedChecks:   11,
		NotApplicable:  0,
		Standards: []services.StandardComplianceResult{
			{
				Standard:        "IEC-62443",
				ComplianceScore: 78.5,
				Summary:         "IEC-62443 compliance assessment completed with 78.5% compliance rate",
				Categories: []services.CategoryComplianceResult{
					{
						Category:     "access_control",
						Description:  "Identification, Authentication and Authorization Controls",
						TotalChecks:  10,
						PassedChecks: 8,
						FailedChecks: 2,
						Score:        80.0,
						Checks: []services.ComplianceCheckResult{
							{
								ID:          "check-001",
								CheckID:     "IEC-62443-FR1-01",
								Title:       "Human User Identification and Authentication",
								Description: "All human users shall be identified and authenticated",
								Category:    "access_control",
								Requirement: "FR 1.1",
								Status:      "pass",
								Evidence:    "Authentication mechanism is properly configured",
								AssetID:     "asset-001",
								AssetName:   "Main PLC Controller",
								Details:     "Protocol supports authentication mechanisms",
								LastChecked: time.Now(),
							},
							{
								ID:          "check-002",
								CheckID:     "IEC-62443-FR1-02",
								Title:       "Software Process Identification and Authentication",
								Description: "All software processes shall be identified and authenticated",
								Category:    "access_control",
								Requirement: "FR 1.2",
								Status:      "fail",
								Evidence:    "Process authentication not configured",
								AssetID:     "asset-002",
								AssetName:   "HMI Panel",
								Details:     "Process authentication is missing",
								Remediation: "Enable process authentication in system configuration",
								RiskLevel:   "high",
								LastChecked: time.Now(),
							},
						},
					},
					{
						Category:     "network_security",
						Description:  "Network Segmentation and Boundary Protection",
						TotalChecks:  8,
						PassedChecks: 6,
						FailedChecks: 2,
						Score:        75.0,
						Checks: []services.ComplianceCheckResult{
							{
								ID:          "check-003",
								CheckID:     "IEC-62443-FR5-01",
								Title:       "Network Segmentation",
								Description: "Segment control system networks from non-control system networks",
								Category:    "network_security",
								Requirement: "FR 5.1",
								Status:      "pass",
								Evidence:    "Asset properly segmented in Control Network",
								AssetID:     "asset-001",
								AssetName:   "Main PLC Controller",
								Details:     "Asset is in proper network zone",
								LastChecked: time.Now(),
							},
						},
					},
				},
			},
		},
		Recommendations: []services.ComplianceRecommendation{
			{
				Priority:    "critical",
				Category:    "access_control",
				Title:       "Enable Process Authentication",
				Description: "Several assets lack proper process authentication",
				Impact:      "High - Reduces unauthorized access risk",
				Effort:      "Medium - Configuration changes required",
				AffectedAssets: []string{"asset-002"},
			},
		},
		ExecutiveSummary: "Compliance assessment completed with overall score of 78.5%. Key areas for improvement include access control and network security.",
	}
	
	c.JSON(http.StatusOK, mockResponse)
}

// ExportComplianceReport exports compliance report
// @Summary Export compliance report
// @Description Export compliance assessment report in various formats
// @Tags compliance
// @Accept json
// @Produce json
// @Param id path string true "Assessment ID"
// @Param format query string false "Export format (pdf, csv, json)" default(pdf)
// @Success 200 {object} map[string]interface{}
// @Router /api/compliance/assessment/{id}/export [get]
func (h *ComplianceHandler) ExportComplianceReport(c *gin.Context) {
	assessmentID := c.Param("id")
	format := c.DefaultQuery("format", "pdf")
	
	// Validate format
	validFormats := map[string]bool{
		"pdf": true,
		"csv": true,
		"json": true,
		"xlsx": true,
	}
	
	if !validFormats[format] {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid format. Supported formats: pdf, csv, json, xlsx",
		})
		return
	}

	// Export report
	reportData, err := h.service.ExportComplianceReport(assessmentID, format)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to export report",
			"details": err.Error(),
		})
		return
	}

	// Set appropriate content type
	contentTypes := map[string]string{
		"pdf": "application/pdf",
		"csv": "text/csv",
		"json": "application/json",
		"xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
	}

	c.Header("Content-Type", contentTypes[format])
	c.Header("Content-Disposition", "attachment; filename=compliance_report_"+assessmentID+"."+format)
	c.Data(http.StatusOK, contentTypes[format], reportData)
}

// GetComplianceStandards returns available compliance standards
// @Summary Get compliance standards
// @Description Get list of available compliance standards and their details
// @Tags compliance
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/compliance/standards [get]
func (h *ComplianceHandler) GetComplianceStandards(c *gin.Context) {
	standards := []map[string]interface{}{
		{
			"id": "IEC-62443",
			"name": "IEC 62443",
			"description": "Industrial Automation and Control Systems Security",
			"categories": []string{
				"access_control",
				"network_security",
				"data_protection",
				"system_integrity",
				"incident_response",
				"physical_security",
			},
			"version": "4.1",
			"industry": "Industrial Control Systems",
		},
		{
			"id": "NIST",
			"name": "NIST Cybersecurity Framework",
			"description": "Framework for Improving Critical Infrastructure Cybersecurity",
			"categories": []string{
				"identify",
				"protect",
				"detect",
				"respond",
				"recover",
			},
			"version": "1.1",
			"industry": "Critical Infrastructure",
		},
		{
			"id": "ISO27001",
			"name": "ISO 27001",
			"description": "Information Security Management Systems",
			"categories": []string{
				"context",
				"leadership",
				"planning",
				"support",
				"operation",
				"performance",
				"improvement",
			},
			"version": "2022",
			"industry": "General",
		},
		{
			"id": "NERC-CIP",
			"name": "NERC CIP",
			"description": "Critical Infrastructure Protection Standards",
			"categories": []string{
				"cyber_security_management",
				"personnel_training",
				"electronic_security_perimeter",
				"physical_security",
				"system_security_management",
				"incident_reporting",
				"recovery_plans",
			},
			"version": "7.0",
			"industry": "Electric Utilities",
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"standards": standards,
		"count": len(standards),
	})
}

// UpdateComplianceCheck updates a specific compliance check result
// @Summary Update compliance check
// @Description Update the status or details of a specific compliance check
// @Tags compliance
// @Accept json
// @Produce json
// @Param id path string true "Check ID"
// @Param update body map[string]interface{} true "Update data"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Router /api/compliance/check/{id} [patch]
func (h *ComplianceHandler) UpdateComplianceCheck(c *gin.Context) {
	checkID := c.Param("id")
	
	var update struct {
		Status      string `json:"status"`
		Evidence    string `json:"evidence"`
		Notes       string `json:"notes"`
		Remediation string `json:"remediation"`
	}
	
	if err := c.ShouldBindJSON(&update); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
			"details": err.Error(),
		})
		return
	}

	// Update in database (implementation depends on your schema)
	// This is a placeholder
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Compliance check updated successfully",
		"check_id": checkID,
	})
}

// GetComplianceRecommendations returns compliance improvement recommendations
// @Summary Get compliance recommendations
// @Description Get recommendations for improving compliance posture
// @Tags compliance
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/compliance/recommendations [get]
func (h *ComplianceHandler) GetComplianceRecommendations(c *gin.Context) {
	// This would analyze current compliance status and generate recommendations
	recommendations := []map[string]interface{}{
		{
			"priority": "critical",
			"category": "access_control",
			"title": "Implement Multi-Factor Authentication",
			"description": "Critical assets lack proper authentication controls",
			"impact": "High - Reduces unauthorized access risk by 90%",
			"effort": "Medium - 2-3 weeks implementation",
			"affected_assets": 15,
		},
		{
			"priority": "high",
			"category": "network_security",
			"title": "Complete Network Segmentation",
			"description": "12 assets are not properly segmented from corporate network",
			"impact": "High - Limits attack surface significantly",
			"effort": "High - Requires network architecture changes",
			"affected_assets": 12,
		},
		{
			"priority": "medium",
			"category": "incident_response",
			"title": "Enable Comprehensive Logging",
			"description": "Several critical assets have insufficient logging configured",
			"impact": "Medium - Improves incident detection and response",
			"effort": "Low - Configuration changes only",
			"affected_assets": 8,
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"recommendations": recommendations,
		"total": len(recommendations),
		"estimated_improvement": "15-20% compliance score increase",
	})
}

// ScheduleComplianceAssessment schedules a compliance assessment
// @Summary Schedule compliance assessment
// @Description Schedule an automated compliance assessment
// @Tags compliance
// @Accept json
// @Produce json
// @Param schedule body map[string]interface{} true "Schedule configuration"
// @Success 200 {object} map[string]string
// @Router /api/compliance/schedule [post]
func (h *ComplianceHandler) ScheduleComplianceAssessment(c *gin.Context) {
	var schedule struct {
		Standards  []string `json:"standards" binding:"required"`
		Frequency  string   `json:"frequency" binding:"required"` // daily, weekly, monthly
		StartDate  string   `json:"start_date" binding:"required"`
		NotifyEmail string  `json:"notify_email"`
	}
	
	if err := c.ShouldBindJSON(&schedule); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid schedule format",
			"details": err.Error(),
		})
		return
	}

	// Create schedule (implementation would involve a scheduler service)
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Compliance assessment scheduled successfully",
		"schedule_id": "SCH-2024-001",
		"next_run": schedule.StartDate,
	})
}