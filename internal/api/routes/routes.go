// internal/api/routes/routes.go
package routes

import (
	"net/http"
	
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
			// Monitoring control
			monitoring.GET("/status", monitoringHandler.GetMonitoringStatus)
			monitoring.POST("/start", monitoringHandler.StartMonitoring)
			
			// Asset monitoring control
			monitoring.POST("/assets/:id/start", monitoringHandler.StartAssetMonitoring)
			monitoring.POST("/assets/:id/stop", monitoringHandler.StopAssetMonitoring)
			
			// Configuration
			monitoring.PUT("/config", middleware.AdminRequired(), monitoringHandler.UpdateMonitoringConfig)
		}
	}
}

// SetupAllRoutes configures all routes with proper authentication - UPDATED
func SetupAllRoutes(
	router *gin.Engine,
	authHandler *handlers.AuthHandler,
	assetHandler *handlers.AssetHandler,
	groupHandler *handlers.GroupHandler,
	dashboardHandler *handlers.DashboardHandler,
	discoveryHandler *handlers.DiscoveryHandler,
	monitoringHandler *handlers.MonitoringHandler, // Add monitoring handler
) {
	// Setup static routes first (public)
	SetupStaticRoutes(router)
	
	// Setup auth routes (mixed public/protected)
	SetupAuthRoutes(router, authHandler)
	
	// Setup health routes (public)
	SetupHealthRoutes(router)
	
	// Setup protected system routes
	SetupProtectedSystemRoutes(router)
	
	// Setup API info (public)
	SetupAPIInfoRoutes(router)
	
	// Setup web routes (protected)
	SetupWebRoutes(router)
	
	// Setup API routes (all protected)
	SetupAssetRoutes(router, assetHandler)
	SetupGroupRoutes(router, groupHandler)
	SetupDashboardRoutes(router, dashboardHandler)
	SetupDiscoveryRoutes(router, discoveryHandler)
	SetupMonitoringRoutes(router, monitoringHandler) // Add monitoring routes
	SetupTagRoutes(router)
	
	// Setup WebSocket route (protected)
	SetupWebSocketRoute(router)
	
	// Catch-all route - redirect to login
	router.NoRoute(func(c *gin.Context) {
		// For API routes, return 404
		if len(c.Request.URL.Path) > 4 && c.Request.URL.Path[:5] == "/api/" {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "Endpoint not found",
				"path": c.Request.URL.Path,
			})
			return
		}
		
		// For web routes, redirect to login
		c.Redirect(http.StatusTemporaryRedirect, "/login")
	})
}

// SetupAuthRoutes configures authentication routes
func SetupAuthRoutes(router *gin.Engine, authHandler *handlers.AuthHandler) {
	// Public routes (no auth required)
	auth := router.Group("/api/auth")
	{
		auth.POST("/login", authHandler.Login)
		auth.POST("/register", authHandler.Register)
		auth.POST("/logout", authHandler.Logout)
	}
	
	// Protected auth routes
	authProtected := router.Group("/api/auth")
	authProtected.Use(middleware.AuthRequired())
	{
		authProtected.GET("/me", authHandler.Me)
		authProtected.POST("/refresh", authHandler.RefreshToken)
	}
}

// SetupAssetRoutes configures asset-related routes
func SetupAssetRoutes(router *gin.Engine, assetHandler *handlers.AssetHandler) {
	// All asset routes require authentication
	api := router.Group("/api")
	api.Use(middleware.AuthRequired())
	{
		assets := api.Group("/assets")
		{
			assets.GET("", assetHandler.GetAssets)
			assets.POST("", assetHandler.CreateAsset)
			assets.GET("/stats", assetHandler.GetAssetStats)
			assets.GET("/:id", assetHandler.GetAsset)
			assets.PUT("/:id", assetHandler.UpdateAsset)
			assets.DELETE("/:id", assetHandler.DeleteAsset)
			
			// Additional asset routes
			assets.PATCH("/:id/status", assetHandler.UpdateAssetStatus)
			assets.PATCH("/bulk", assetHandler.BulkUpdateAssets)
			assets.POST("/:id/tags/:tag_id", assetHandler.AddAssetTag)
			assets.DELETE("/:id/tags/:tag_id", assetHandler.RemoveAssetTag)
		}
	}
}

// SetupGroupRoutes configures group-related routes
func SetupGroupRoutes(router *gin.Engine, groupHandler *handlers.GroupHandler) {
	// All group routes require authentication
	api := router.Group("/api")
	api.Use(middleware.AuthRequired())
	{
		groups := api.Group("/groups")
		{
			groups.GET("", groupHandler.GetGroups)
			groups.POST("", groupHandler.CreateGroup)
			groups.GET("/:id", groupHandler.GetGroup)
			groups.PUT("/:id", groupHandler.UpdateGroup)
			groups.DELETE("/:id", groupHandler.DeleteGroup)
		}
	}
}

// SetupDashboardRoutes configures dashboard-related routes
func SetupDashboardRoutes(router *gin.Engine, dashboardHandler *handlers.DashboardHandler) {
	// All dashboard routes require authentication
	api := router.Group("/api")
	api.Use(middleware.AuthRequired())
	{
		dashboard := api.Group("/dashboard")
		{
			dashboard.GET("/overview", dashboardHandler.GetOverview)
			dashboard.GET("/metrics", dashboardHandler.GetMetrics)
			dashboard.GET("/alerts", dashboardHandler.GetAlerts)
		}
	}
}

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
			discovery.GET("/active-scans", discoveryHandler.GetActiveScans)
		}
	}
}

// SetupWebRoutes configures web UI routes
func SetupWebRoutes(router *gin.Engine) {
	// Public route - Login page
	router.GET("/login", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", gin.H{
			"title": "ICS Asset Inventory - Login",
		})
	})

	// Add register page route
	router.GET("/register", func(c *gin.Context) {
		c.HTML(http.StatusOK, "register.html", gin.H{
			"title": "ICS Asset Inventory - Register",
		})
	})

	// Protected routes - All web pages require authentication
	protected := router.Group("/")
	protected.Use(middleware.WebAuthRequired())
	{
		// Main dashboard page
		protected.GET("/", func(c *gin.Context) {
			c.HTML(http.StatusOK, "dashboard.html", gin.H{
				"title": "ICS Asset Inventory - Dashboard",
			})
		})

		// Assets page
		protected.GET("/assets", func(c *gin.Context) {
			c.HTML(http.StatusOK, "assets.html", gin.H{
				"title": "ICS Asset Inventory - Assets",
			})
		})

		// Asset detail page
		protected.GET("/assets/:id", func(c *gin.Context) {
			c.HTML(http.StatusOK, "asset-detail.html", gin.H{
				"title": "ICS Asset Inventory - Asset Details",
				"assetId": c.Param("id"),
			})
		})

		// Network discovery page
		protected.GET("/discovery", func(c *gin.Context) {
			c.HTML(http.StatusOK, "discovery.html", gin.H{
				"title": "ICS Asset Inventory - Network Discovery",
			})
		})

		// Security assessment page
		protected.GET("/security", func(c *gin.Context) {
			c.HTML(http.StatusOK, "security.html", gin.H{
				"title": "ICS Asset Inventory - Security Assessment",
			})
		})

		// Reports page
		protected.GET("/reports", func(c *gin.Context) {
			c.HTML(http.StatusOK, "reports.html", gin.H{
				"title": "ICS Asset Inventory - Reports",
			})
		})

		// Settings page
		protected.GET("/settings", func(c *gin.Context) {
			c.HTML(http.StatusOK, "settings.html", gin.H{
				"title": "ICS Asset Inventory - Settings",
			})
		})
	}
}

// SetupHealthRoutes configures health check routes
func SetupHealthRoutes(router *gin.Engine) {
	// Public health check endpoints
	router.GET("/health", healthCheck)
	router.GET("/api/health", healthCheck)
	
	// Public readiness check endpoints
	router.GET("/ready", readinessCheck)
	router.GET("/api/ready", readinessCheck)
}

// SetupProtectedSystemRoutes configures protected system routes
func SetupProtectedSystemRoutes(router *gin.Engine) {
	// System info requires authentication
	api := router.Group("/api")
	api.Use(middleware.AuthRequired())
	{
		api.GET("/system/info", systemInfo)
		api.GET("/system/database", databaseStatus)
	}
}

// SetupAPIInfoRoutes configures API information routes
func SetupAPIInfoRoutes(router *gin.Engine) {
	// Public API info
	router.GET("/api", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"name":        "ICS Asset Inventory API",
			"version":     "1.0.0",
			"description": "Industrial Control Systems Asset Management API with Real-time Monitoring",
			"endpoints": gin.H{
				"auth":       "/api/auth",
				"assets":     "/api/assets (requires auth)",
				"groups":     "/api/groups (requires auth)", 
				"dashboard":  "/api/dashboard (requires auth)",
				"discovery":  "/api/discovery (requires auth)",
				"monitoring": "/api/monitoring (requires auth)",
				"health":     "/health",
				"system":     "/api/system (requires auth)",
			},
			"authentication": gin.H{
				"type":   "Bearer Token",
				"login":  "POST /api/auth/login",
				"logout": "POST /api/auth/logout",
			},
			"web_interfaces": gin.H{
				"login":     "/login",
				"dashboard": "/ (requires auth)",
				"assets":    "/assets (requires auth)",
				"discovery": "/discovery (requires auth)",
				"security":  "/security (requires auth)",
				"reports":   "/reports (requires auth)",
				"settings":  "/settings (requires auth)",
			},
		})
	})
}

// SetupTagRoutes configures tag-related routes
func SetupTagRoutes(router *gin.Engine) {
	// All tag routes require authentication
	api := router.Group("/api")
	api.Use(middleware.AuthRequired())
	{
		tags := api.Group("/tags")
		{
			tags.GET("", getTagsHandler)
			tags.POST("", createTagHandler)
			tags.GET("/:id", getTagHandler)
			tags.PUT("/:id", updateTagHandler)
			tags.DELETE("/:id", deleteTagHandler)
		}
	}
}

// SetupStaticRoutes configures static file serving
func SetupStaticRoutes(router *gin.Engine) {
	// Static files are public
	router.Static("/static", "./web/static")
	
	// Favicon
	router.StaticFile("/favicon.ico", "./web/static/images/favicon.ico")
}

// SetupWebSocketRoute configures WebSocket route
func SetupWebSocketRoute(router *gin.Engine) {
	// WebSocket endpoint requires authentication
	ws := router.Group("/ws")
	ws.Use(middleware.AuthRequired())
	{
		ws.GET("/events", handlers.HandleWebSocket)
	}
}

// Health check handlers (implementations)
func healthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":     "healthy",
		"timestamp":  time.Now().Unix(),
		"version":    "1.0.0",
		"service":    "ICS Asset Inventory",
	})
}

func readinessCheck(c *gin.Context) {
	// Check database connection
	if err := database.TestConnection(); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status": "not ready",
			"reason": "database connection failed",
			"error":  err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":    "ready",
		"timestamp": time.Now().Unix(),
		"checks": gin.H{
			"database": "connected",
		},
	})
}

func systemInfo(c *gin.Context) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	c.JSON(http.StatusOK, gin.H{
		"service": gin.H{
			"name":    "ICS Asset Inventory",
			"version": "1.0.0",
			"uptime":  time.Since(startTime).String(),
		},
		"system": gin.H{
			"go_version":   runtime.Version(),
			"goroutines":   runtime.NumGoroutine(),
			"memory": gin.H{
				"allocated":     bToMb(m.Alloc),
				"total_alloc":   bToMb(m.TotalAlloc),
				"sys":          bToMb(m.Sys),
				"gc_runs":      m.NumGC,
			},
		},
		"timestamp": time.Now().Unix(),
	})
}

func databaseStatus(c *gin.Context) {
	// Test database connection
	if err := database.TestConnection(); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status": "disconnected",
			"error":  err.Error(),
		})
		return
	}

	// Get database statistics
	stats := database.GetStats()

	c.JSON(http.StatusOK, gin.H{
		"status":     "connected",
		"statistics": stats,
		"timestamp":  time.Now().Unix(),
	})
}

func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}

// Basic tag handlers (placeholder implementations)
func getTagsHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"tags": []gin.H{},
		"message": "Tags endpoint - implementation pending",
	})
}

func createTagHandler(c *gin.Context) {
	c.JSON(http.StatusCreated, gin.H{
		"message": "Tag creation endpoint - implementation pending",
	})
}

func getTagHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "Tag detail endpoint - implementation pending",
		"id": c.Param("id"),
	})
}

func updateTagHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "Tag update endpoint - implementation pending",
		"id": c.Param("id"),
	})
}

func deleteTagHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "Tag deletion endpoint - implementation pending",
		"id": c.Param("id"),
	})
}