package routes

import (
	"ics-asset-inventory/internal/api/handlers"
	"ics-asset-inventory/internal/api/middleware"
	
	"github.com/gin-gonic/gin"
)

// SetupDiscoveryRoutes configures discovery-related routes
func SetupDiscoveryRoutes(router *gin.Engine, discoveryHandler *handlers.DiscoveryHandler) {
	// All discovery routes require authentication
	api := router.Group("/api")
	api.Use(middleware.AuthRequired())
	{
		discovery := api.Group("/discovery")
		{
			// Scan management
			discovery.POST("/scan", discoveryHandler.StartScan)
			discovery.POST("/scan/:id/stop", discoveryHandler.StopScan)
			discovery.GET("/scan/:id/progress", discoveryHandler.GetScanProgress)
			discovery.GET("/scan/:id/results", discoveryHandler.GetScanResults)
			
			// Device management
			discovery.POST("/scan/:id/add-device", discoveryHandler.AddDeviceToInventory)
			discovery.POST("/scan/:id/add-all-devices", discoveryHandler.AddAllDevicesToInventory)
			
			// History and info
			discovery.GET("/history", discoveryHandler.GetScanHistory)
			discovery.GET("/protocol-ports", discoveryHandler.GetProtocolPorts)
		}
	}
}
