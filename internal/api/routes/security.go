// internal/api/routes/security.go
package routes

import (
	"ics-asset-inventory/internal/api/handlers"
	"ics-asset-inventory/internal/api/middleware"
	
	"github.com/gin-gonic/gin"
)

// SetupSecurityRoutes configures security-related routes
func SetupSecurityRoutes(router *gin.Engine, securityHandler *handlers.SecurityHandler) {
	// All security routes require authentication
	api := router.Group("/api")
	api.Use(middleware.AuthRequired())
	{
		security := api.Group("/security")
		{
			// Dashboard and overview
			security.GET("/dashboard", securityHandler.GetSecurityDashboard)
			
			// Passive security assessment (SAFE for ICS)
			security.POST("/assessment", securityHandler.RunSecurityAssessment)
			
			// Vulnerability management
			security.GET("/vulnerabilities", securityHandler.GetVulnerabilities)
			security.PATCH("/vulnerabilities/:id/status", securityHandler.UpdateVulnerabilityStatus)
			
			// Compliance
			security.GET("/compliance", securityHandler.GetComplianceStatus)
			
			// Risk assessment
			security.GET("/risk-matrix", securityHandler.GetRiskMatrix)
			
			// Reporting
			security.GET("/report/export", securityHandler.ExportSecurityReport)
			
			// CVE database management (offline only for ICS)
			security.POST("/cve/load", middleware.AdminRequired(), securityHandler.LoadCVEDatabase)
		}
	}
}