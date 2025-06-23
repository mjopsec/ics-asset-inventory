package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ics-asset-inventory/internal/api/handlers"
	"ics-asset-inventory/internal/api/middleware"
	"ics-asset-inventory/internal/api/routes"
	"ics-asset-inventory/internal/config"
	"ics-asset-inventory/internal/database"
	"ics-asset-inventory/internal/utils"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

// @title ICS Asset Inventory API
// @version 1.0
// @description A comprehensive asset inventory system for Industrial Control Systems (ICS/OT)
// @contact.name API Support
// @contact.url https://github.com/your-org/ics-asset-inventory
// @contact.email support@example.com
// @license.name MIT
// @license.url https://opensource.org/licenses/MIT
// @host localhost:8080
// @BasePath /api
func main() {
	// Initialize logger
	logger := utils.NewLogger()
	logger.Info("🚀 Starting ICS Asset Inventory...")

	// Load .env file if exists
	if err := godotenv.Load(); err != nil {
		logger.Warn("No .env file found, using environment variables")
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		logger.Fatal("Failed to load configuration", "error", err)
	}
	logger.Info("✅ Configuration loaded successfully")

	// Initialize database
	logger.Info("🔗 Initializing database...")
	if err := database.Initialize(cfg); err != nil {
		logger.Fatal("Failed to initialize database", "error", err)
	}
	logger.Info("✅ Database connected successfully")

	// Run migrations
	logger.Info("📊 Running database migrations...")
	if err := database.AutoMigrate(); err != nil {
		logger.Fatal("Failed to run migrations", "error", err)
	}
	logger.Info("✅ Database migrations completed")

	// Seed initial data
	logger.Info("🌱 Seeding initial data...")
	if err := database.SeedData(); err != nil {
		logger.Fatal("Failed to seed data", "error", err)
	}
	logger.Info("✅ Initial data seeded successfully")

	// Test database connection
	if err := database.TestConnection(); err != nil {
		logger.Fatal("Database connection test failed", "error", err)
	}
	logger.Info("✅ Database connection test passed")

	// Set Gin mode
	gin.SetMode(cfg.Server.Mode)
	if cfg.Server.Mode == "release" {
		gin.DisableConsoleColor()
	}

	// Initialize router
	router := setupRouter(cfg, logger)

	// Create HTTP server
	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:      router,
		ReadTimeout:  time.Duration(cfg.Server.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(cfg.Server.WriteTimeout) * time.Second,
	}

	// Start server in goroutine
	go func() {
		logger.Info("🌐 Starting HTTP server",
			"host", cfg.Server.Host,
			"port", cfg.Server.Port,
			"mode", cfg.Server.Mode)
		logger.Info("📊 Dashboard available at", "url", fmt.Sprintf("http://%s:%d", cfg.Server.Host, cfg.Server.Port))
		logger.Info("🔧 API available at", "url", fmt.Sprintf("http://%s:%d/api", cfg.Server.Host, cfg.Server.Port))
		
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Failed to start server", "error", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	logger.Info("🛑 Received shutdown signal", "signal", sig.String())

	// Graceful shutdown
	logger.Info("🔄 Starting graceful shutdown...")
	ctx, cancel := context.WithTimeout(context.Background(), 
		time.Duration(cfg.Server.ShutdownTimeout)*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Fatal("Server forced to shutdown", "error", err)
	}

	// Close database connection
	if err := database.Close(); err != nil {
		logger.Error("Error closing database", "error", err)
	} else {
		logger.Info("✅ Database connection closed")
	}

	logger.Info("✅ Server shutdown completed gracefully")
}

func setupRouter(cfg *config.Config, logger *utils.Logger) *gin.Engine {
	router := gin.New()

	// Add custom middleware
	router.Use(middleware.LoggerWithConfig(logger))
	router.Use(gin.Recovery())
	router.Use(middleware.CORS(cfg))
	router.Use(middleware.Security())
	router.Use(middleware.RateLimit(cfg))
	router.Use(middleware.RequestID())
	router.Use(middleware.ErrorHandler())

	// Load HTML templates with proper pattern
	// Only load actual HTML files, not directories
	router.LoadHTMLGlob("web/templates/*.html")

	// Serve static files
	router.Static("/static", "./web/static")
	router.StaticFile("/favicon.ico", "./web/static/favicon.ico")

	// Initialize handlers
	authHandler := handlers.NewAuthHandler()
	assetHandler := handlers.NewAssetHandler()
	groupHandler := handlers.NewGroupHandler()
	dashboardHandler := handlers.NewDashboardHandler()

	// Setup all routes with authentication
	routes.SetupAllRoutes(
		router,
		authHandler,
		assetHandler,
		groupHandler,
		dashboardHandler,
	)

	// Add web page routes directly here (since we're not using layout system yet)
	setupWebPageRoutes(router)

	return router
}

// setupWebPageRoutes handles web page rendering
func setupWebPageRoutes(router *gin.Engine) {
	// Public routes
	router.GET("/login", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", gin.H{
			"title": "ICS Asset Inventory - Login",
		})
	})

	router.GET("/register", func(c *gin.Context) {
		c.HTML(http.StatusOK, "register.html", gin.H{
			"title": "ICS Asset Inventory - Register",
		})
	})

	// Protected routes - using middleware for auth
	protected := router.Group("/")
	protected.Use(middleware.WebAuthRequired())
	{
		// Dashboard
		protected.GET("/", func(c *gin.Context) {
			c.HTML(http.StatusOK, "dashboard.html", gin.H{
				"title": "ICS Asset Inventory - Dashboard",
			})
		})

		// Assets
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

		// Discovery
		protected.GET("/discovery", func(c *gin.Context) {
			c.File("web/templates/discovery.html")
		})

		// Security
		protected.GET("/security", func(c *gin.Context) {
			c.File("web/templates/security.html")
		})

		// Reports
		protected.GET("/reports", func(c *gin.Context) {
			c.File("web/templates/reports.html")
		})

		// Settings
		protected.GET("/settings", func(c *gin.Context) {
			c.File("web/templates/settings.html")
		})
	}

	// Catch-all route for 404
	router.NoRoute(func(c *gin.Context) {
		// For API routes, return JSON 404
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