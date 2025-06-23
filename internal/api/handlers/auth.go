package handlers

import (
	"net/http"
	"strings"
	"time"

	"ics-asset-inventory/internal/auth"
	"ics-asset-inventory/internal/database"
	"ics-asset-inventory/internal/database/models"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// AuthHandler handles authentication endpoints
type AuthHandler struct {
	db *gorm.DB
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler() *AuthHandler {
	return &AuthHandler{
		db: database.GetDB(),
	}
}

// LoginRequest represents login credentials
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// LoginResponse represents successful login response
type LoginResponse struct {
	Token string `json:"token"`
	User  struct {
		ID       string `json:"id"`
		Username string `json:"username"`
		Email    string `json:"email"`
		Role     string `json:"role"`
	} `json:"user"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Login handles user authentication
// @Summary User login
// @Description Authenticate user and get access token
// @Tags auth
// @Accept json
// @Produce json
// @Param credentials body LoginRequest true "Login credentials"
// @Success 200 {object} LoginResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/auth/login [post]
func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
			"details": err.Error(),
		})
		return
	}

	// Find user by username
	var user models.User
	err := h.db.Where("username = ? AND active = ?", req.Username, true).First(&user).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	// Check password
	if !auth.CheckPassword(req.Password, user.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Create session
	sessionDuration := 24 * time.Hour
	session, err := auth.CreateSession(
		user.ID.String(),
		user.Username,
		user.Email,
		user.Role,
		sessionDuration,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
		return
	}

	// Update last login
	h.db.Model(&user).Update("last_login", time.Now())

	// Set cookie for web authentication
	c.SetCookie(
		"auth_token",           // name
		session.Token,          // value
		int(sessionDuration.Seconds()), // maxAge
		"/",                    // path
		"",                     // domain
		false,                  // secure (set to true in production with HTTPS)
		true,                   // httpOnly
	)

	// Build response
	response := LoginResponse{
		Token:     session.Token,
		ExpiresAt: session.ExpiresAt,
	}
	response.User.ID = user.ID.String()
	response.User.Username = user.Username
	response.User.Email = user.Email
	response.User.Role = user.Role

	c.JSON(http.StatusOK, response)
}

// Logout handles user logout
// @Summary User logout
// @Description Invalidate user session
// @Tags auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/auth/logout [post]
func (h *AuthHandler) Logout(c *gin.Context) {
	token := extractToken(c)
	if token == "" {
		// Check cookie
		token, _ = c.Cookie("auth_token")
	}
	
	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No token provided"})
		return
	}

	err := auth.InvalidateSession(token)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid session"})
		return
	}

	// Clear cookie
	c.SetCookie("auth_token", "", -1, "/", "", false, true)

	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

// Me returns current user information
// @Summary Get current user
// @Description Get information about the authenticated user
// @Tags auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} map[string]string
// @Router /api/auth/me [get]
func (h *AuthHandler) Me(c *gin.Context) {
	// Get user info from context (set by auth middleware)
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found in context"})
		return
	}

	var user models.User
	err := h.db.First(&user, "id = ?", userID).Error
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":         user.ID.String(),
		"username":   user.Username,
		"email":      user.Email,
		"role":       user.Role,
		"active":     user.Active,
		"last_login": user.LastLogin,
		"created_at": user.CreatedAt,
	})
}

// RefreshToken refreshes the authentication token
// @Summary Refresh token
// @Description Extend session expiration
// @Tags auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} map[string]string
// @Router /api/auth/refresh [post]
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	token := extractToken(c)
	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No token provided"})
		return
	}

	// Validate current session
	session, err := auth.ValidateSession(token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid session"})
		return
	}

	// Extend session
	newDuration := 24 * time.Hour
	err = auth.RefreshSession(token, newDuration)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to refresh session"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":    "Session refreshed successfully",
		"expires_at": session.ExpiresAt.Add(newDuration),
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

// RegisterRequest represents registration data
type RegisterRequest struct {
	Username string `json:"username" binding:"required,min=3,max=20"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
	Role     string `json:"role" binding:"required,oneof=admin operator viewer"`
}

// RegisterResponse represents successful registration response
type RegisterResponse struct {
	Message string `json:"message"`
	User    struct {
		ID       string `json:"id"`
		Username string `json:"username"`
		Email    string `json:"email"`
		Role     string `json:"role"`
	} `json:"user"`
}

// Register handles user registration
// @Summary User registration
// @Description Register a new user account
// @Tags auth
// @Accept json
// @Produce json
// @Param user body RegisterRequest true "Registration data"
// @Success 201 {object} RegisterResponse
// @Failure 400 {object} map[string]string
// @Failure 409 {object} map[string]string
// @Router /api/auth/register [post]
func (h *AuthHandler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
			"details": err.Error(),
		})
		return
	}

	// Check if username already exists
	var existingUser models.User
	if err := h.db.Where("username = ?", req.Username).First(&existingUser).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{
			"error": "Username already taken",
			"field": "username",
		})
		return
	}

	// Check if email already exists
	if err := h.db.Where("email = ?", req.Email).First(&existingUser).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{
			"error": "Email already registered",
			"field": "email",
		})
		return
	}

	// Create new user
	newUser := models.User{
		Username: req.Username,
		Email:    req.Email,
		Password: auth.HashPassword(req.Password),
		Role:     req.Role,
		Active:   true, // You might want to implement email verification
	}

	// Save to database
	if err := h.db.Create(&newUser).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create user",
		})
		return
	}

	// Build response
	response := RegisterResponse{
		Message: "Registration successful",
	}
	response.User.ID = newUser.ID.String()
	response.User.Username = newUser.Username
	response.User.Email = newUser.Email
	response.User.Role = newUser.Role

	c.JSON(http.StatusCreated, response)
}