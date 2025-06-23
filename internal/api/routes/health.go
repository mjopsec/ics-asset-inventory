package routes

import (
	"net/http"
	"runtime"
	"time"

	"ics-asset-inventory/internal/database"

	"github.com/gin-gonic/gin"
)

var startTime = time.Now()

// SetupHealthRoutes configures health check routes (public endpoints only)
func SetupHealthRoutes(router *gin.Engine) {
	// Public health check endpoints
	router.GET("/health", healthCheck)
	router.GET("/api/health", healthCheck)
	
	// Public readiness check endpoints
	router.GET("/ready", readinessCheck)
	router.GET("/api/ready", readinessCheck)
	
	// Protected system info endpoints are handled in SetupProtectedSystemRoutes
}

func healthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":     "healthy",
		"timestamp":  time.Now().Unix(),
		"version":    "1.0.0",
		"uptime":     time.Since(startTime).String(),
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