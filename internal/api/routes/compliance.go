// internal/api/routes/compliance.go
package routes

import (
	"ics-asset-inventory/internal/api/handlers"
	"ics-asset-inventory/internal/api/middleware"
	
	"github.com/gin-gonic/gin"
)

// SetupComplianceRoutes configures compliance-related routes
func SetupComplianceRoutes(router *gin.Engine, complianceHandler *handlers.ComplianceHandler) {
	// All compliance routes require authentication
	api := router.Group("/api")
	api.Use(middleware.AuthRequired())
	{
		compliance := api.Group("/compliance")
		{
			// Assessment operations
			compliance.POST("/assessment", complianceHandler.RunComplianceAssessment)
			compliance.GET("/assessment/:id", complianceHandler.GetComplianceDetails)
			compliance.GET("/assessment/:id/export", complianceHandler.ExportComplianceReport)
			
			// Status and monitoring
			compliance.GET("/status", complianceHandler.GetComplianceStatus)
			compliance.GET("/history", complianceHandler.GetComplianceHistory)
			
			// Standards and recommendations
			compliance.GET("/standards", complianceHandler.GetComplianceStandards)
			compliance.GET("/recommendations", complianceHandler.GetComplianceRecommendations)
			
			// Check management
			compliance.PATCH("/check/:id", complianceHandler.UpdateComplianceCheck)
			
			// Scheduling
			compliance.POST("/schedule", complianceHandler.ScheduleComplianceAssessment)
		}
	}
}