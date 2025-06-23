package utils

import (
	"log/slog"
	"os"
	"time"

	"github.com/gin-gonic/gin"
)

type Logger struct {
	*slog.Logger
}

func NewLogger() *Logger {
	// Create a JSON handler for structured logging
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Customize timestamp format
			if a.Key == slog.TimeKey {
				a.Value = slog.StringValue(time.Now().Format("2006-01-02 15:04:05"))
			}
			return a
		},
	})

	logger := slog.New(handler)
	
	return &Logger{
		Logger: logger,
	}
}

func (l *Logger) Fatal(msg string, args ...interface{}) {
	l.Error(msg, args...)
	os.Exit(1)
}

func (l *Logger) GinLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Process request
		c.Next()

		// Calculate latency
		latency := time.Since(start)

		// Get client IP
		clientIP := c.ClientIP()

		// Get method and status
		method := c.Request.Method
		statusCode := c.Writer.Status()

		// Build full path
		if raw != "" {
			path = path + "?" + raw
		}

		// Log the request
		l.Info("HTTP Request",
			"method", method,
			"path", path,
			"status", statusCode,
			"latency", latency.String(),
			"ip", clientIP,
			"user_agent", c.Request.UserAgent(),
		)
	}
}
