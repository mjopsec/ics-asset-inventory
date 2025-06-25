package routes

import (
	"ics-asset-inventory/internal/api/handlers"
	"ics-asset-inventory/internal/api/middleware"
	
	"github.com/gin-gonic/gin"
)

// SetupMonitoringRoutes configures monitoring-related routes
func SetupMonitoringRoutes(router *gin.Engine, monitoringHandler *handlers.MonitoringHandler) {
	// All monitoring routes require authentication
	api := router.Group("/api")
	api.Use(middleware.AuthRequired())
	{
		monitoring := api.Group("/monitoring")
		{
			// Status and control
			monitoring.GET("/status", monitoringHandler.GetMonitoringStatus)
			monitoring.POST("/start", monitoringHandler.StartMonitoring)
			monitoring.POST("/stop", monitoringHandler.StopMonitoring)
			
			// Configuration
			monitoring.GET("/config", monitoringHandler.GetMonitoringConfig)
			monitoring.PUT("/interval", monitoringHandler.UpdateMonitoringInterval)
			
			// Asset checking
			monitoring.POST("/check/:id", monitoringHandler.CheckAsset)
			monitoring.POST("/bulk-check", monitoringHandler.BulkCheckAssets)
			
			// History
			monitoring.GET("/history/:id", monitoringHandler.GetAssetHistory)
		}
	}
}