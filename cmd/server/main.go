// cmd/server/main.go
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
	"ics-asset-inventory/internal/services"
	"ics-asset-inventory/internal/utils"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

// @title ICS Asset Inventory API
// @version 1.0
// @description A comprehensive asset inventory system for Industrial Control Systems (ICS/OT) with real-time monitoring
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

	// Initialize monitoring service
	logger.Info("📡 Initializing monitoring service...")
	monitoringService := services.NewMonitoringService()
	go func() {
		// Wait a bit for server to start
		time.Sleep(5 * time.Second)
		if err := monitoringService.StartMonitoring(); err != nil {
			logger.Error("Failed to start monitoring service", "error", err)
		} else {
			logger.Info("✅ Monitoring service started successfully")
		}
	}()

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

	// Load HTML templates
	router.LoadHTMLGlob("web/templates/*")

	// Initialize handlers
	authHandler := handlers.NewAuthHandler()
	assetHandler := handlers.NewAssetHandler()
	groupHandler := handlers.NewGroupHandler()
	dashboardHandler := handlers.NewDashboardHandler()
	discoveryHandler := handlers.NewDiscoveryHandler()
	monitoringHandler := handlers.NewMonitoringHandler()

	// Setup all routes with authentication
	routes.SetupAllRoutes(
		router,
		authHandler,
		assetHandler,
		groupHandler,
		dashboardHandler,
		discoveryHandler,
		monitoringHandler,
	)

	return router
}