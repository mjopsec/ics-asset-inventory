package middleware

import (
	"net/http"
	"strings"
	"time"

	"ics-asset-inventory/internal/auth"
	"ics-asset-inventory/internal/config"
	"ics-asset-inventory/internal/utils"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/time/rate"
)

// LoggerWithConfig returns a gin logger middleware with custom logger
func LoggerWithConfig(logger *utils.Logger) gin.HandlerFunc {
	return logger.GinLogger()
}

// CORS middleware configuration
func CORS(cfg *config.Config) gin.HandlerFunc {
	if !cfg.Server.EnableCORS {
		return gin.HandlerFunc(func(c *gin.Context) {
			c.Next()
		})
	}

	corsConfig := cors.Config{
		AllowOrigins:     []string{"*"}, // Configure as needed in production
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Requested-With", "X-Request-ID"},
		ExposeHeaders:    []string{"Content-Length", "X-Request-ID"},
		AllowCredentials: true,
		MaxAge:          12 * time.Hour,
	}

	return cors.New(corsConfig)
}

// Security middleware adds security headers
func Security() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; font-src 'self' https://cdnjs.cloudflare.com; img-src 'self' data:;")
		c.Next()
	})
}

// Rate limiting middleware
func RateLimit(cfg *config.Config) gin.HandlerFunc {
	limiter := rate.NewLimiter(rate.Limit(cfg.Security.RateLimit), cfg.Security.RateLimit*2)

	return gin.HandlerFunc(func(c *gin.Context) {
		if !limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Rate limit exceeded",
				"message": "Too many requests, please try again later",
			})
			c.Abort()
			return
		}
		c.Next()
	})
}

// RequestID middleware adds unique request ID
func RequestID() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}
		c.Header("X-Request-ID", requestID)
		c.Set("request_id", requestID)
		c.Next()
	})
}

// AuthRequired middleware for protected routes
func AuthRequired() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		token := extractToken(c)
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization token required",
				"code": "UNAUTHORIZED",
			})
			c.Abort()
			return
		}

		// Validate session
		session, err := auth.ValidateSession(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": err.Error(),
				"code": "INVALID_SESSION",
			})
			c.Abort()
			return
		}

		// Set user context
		c.Set("user_id", session.UserID)
		c.Set("username", session.Username)
		c.Set("user_email", session.Email)
		c.Set("user_role", session.Role)
		c.Set("session_token", token)
		
		c.Next()
	})
}

// AdminRequired middleware for admin-only routes
func AdminRequired() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		userRole, exists := c.Get("user_role")
		if !exists || userRole != "admin" {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Admin access required",
				"code": "FORBIDDEN",
			})
			c.Abort()
			return
		}
		c.Next()
	})
}

// OptionalAuth middleware for routes that work with or without auth
func OptionalAuth() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		token := extractToken(c)
		if token != "" {
			// Try to validate session, but don't fail if invalid
			if session, err := auth.ValidateSession(token); err == nil {
				c.Set("user_id", session.UserID)
				c.Set("username", session.Username)
				c.Set("user_email", session.Email)
				c.Set("user_role", session.Role)
				c.Set("authenticated", true)
			} else {
				c.Set("authenticated", false)
			}
		} else {
			c.Set("authenticated", false)
		}
		c.Next()
	})
}

// ErrorHandler middleware for centralized error handling
func ErrorHandler() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		c.Next()

		// Handle any errors that occurred during request processing
		if len(c.Errors) > 0 {
			err := c.Errors.Last()
			
			switch err.Type {
			case gin.ErrorTypeBind:
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "Invalid request format",
					"details": err.Error(),
					"code": "VALIDATION_ERROR",
				})
			case gin.ErrorTypePublic:
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": err.Error(),
					"code": "PUBLIC_ERROR",
				})
			default:
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Internal server error",
					"code": "INTERNAL_ERROR",
				})
			}
		}
	})
}

// Validation middleware for request validation
func ValidateJSON() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		if c.Request.Method == "POST" || c.Request.Method == "PUT" || c.Request.Method == "PATCH" {
			contentType := c.GetHeader("Content-Type")
			if contentType != "" && !strings.Contains(contentType, "application/json") {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "Content-Type must be application/json",
					"code": "INVALID_CONTENT_TYPE",
				})
				c.Abort()
				return
			}
		}
		c.Next()
	})
}

// Recovery middleware with structured logging
func RecoveryWithLogger(logger *utils.Logger) gin.HandlerFunc {
	return gin.RecoveryWithWriter(nil, func(c *gin.Context, recovered interface{}) {
		logger.Error("Panic recovered",
			"error", recovered,
			"path", c.Request.URL.Path,
			"method", c.Request.Method,
			"ip", c.ClientIP(),
		)
		
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Internal server error",
			"code": "PANIC_RECOVERED",
		})
	})
}

// extractToken extracts the token from the Authorization header
func extractToken(c *gin.Context) string {
	bearerToken := c.GetHeader("Authorization")
	if strings.HasPrefix(bearerToken, "Bearer ") {
		return strings.TrimPrefix(bearerToken, "Bearer ")
	}
	return bearerToken
}

// Add this function to middleware.go

// WebAuthRequired middleware for web routes (redirects to login)
func WebAuthRequired() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		// Check for token in cookie first (for web pages)
		token, err := c.Cookie("auth_token")
		if err != nil || token == "" {
			// Check Authorization header as fallback
			token = extractToken(c)
		}
		
		if token == "" {
			// For AJAX requests, return 401
			if c.GetHeader("X-Requested-With") == "XMLHttpRequest" {
				c.JSON(http.StatusUnauthorized, gin.H{
					"error": "Authentication required",
					"code": "UNAUTHORIZED",
				})
				c.Abort()
				return
			}
			
			// For regular web requests, redirect to login
			c.Redirect(http.StatusTemporaryRedirect, "/login")
			c.Abort()
			return
		}

		// Validate session
		session, err := auth.ValidateSession(token)
		if err != nil {
			// Clear invalid cookie
			c.SetCookie("auth_token", "", -1, "/", "", false, true)
			
			// For AJAX requests, return 401
			if c.GetHeader("X-Requested-With") == "XMLHttpRequest" {
				c.JSON(http.StatusUnauthorized, gin.H{
					"error": err.Error(),
					"code": "INVALID_SESSION",
				})
				c.Abort()
				return
			}
			
			// For regular web requests, redirect to login
			c.Redirect(http.StatusTemporaryRedirect, "/login")
			c.Abort()
			return
		}

		// Set user context
		c.Set("user_id", session.UserID)
		c.Set("username", session.Username)
		c.Set("user_email", session.Email)
		c.Set("user_role", session.Role)
		c.Set("session_token", token)
		
		c.Next()
	})
}