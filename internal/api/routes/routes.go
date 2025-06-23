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
	router.GET("/health", HealthCheck)
	router.GET("/api/health", HealthCheck)
	
	// Public readiness check endpoints
	router.GET("/ready", ReadinessCheck)
	router.GET("/api/ready", ReadinessCheck)
}

func HealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":     "healthy",
		"timestamp":  time.Now().Unix(),
		"version":    "1.0.0",
		"uptime":     time.Since(startTime).String(),
		"service":    "ICS Asset Inventory",
	})
}

func ReadinessCheck(c *gin.Context) {
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

func SystemInfo(c *gin.Context) {
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

func DatabaseStatus(c *gin.Context) {
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
func GetTagsHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"tags": []gin.H{},
		"message": "Tags endpoint - implementation pending",
	})
}

func CreateTagHandler(c *gin.Context) {
	c.JSON(http.StatusCreated, gin.H{
		"message": "Tag creation endpoint - implementation pending",
	})
}

func GetTagHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "Tag detail endpoint - implementation pending",
		"id": c.Param("id"),
	})
}

func UpdateTagHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "Tag update endpoint - implementation pending",
		"id": c.Param("id"),
	})
}

func DeleteTagHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "Tag deletion endpoint - implementation pending",
		"id": c.Param("id"),
	})
}