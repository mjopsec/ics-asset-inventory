package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Session represents a user session
type Session struct {
	Token     string    `json:"token"`
	UserID    string    `json:"user_id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
}

// SessionStore manages active sessions
type SessionStore struct {
	sessions map[string]*Session
	mu       sync.RWMutex
}

// Global session store
var store = &SessionStore{
	sessions: make(map[string]*Session),
}

// HashPassword creates a SHA256 hash of the password
func HashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

// CheckPassword verifies if the provided password matches the hash
func CheckPassword(password, hash string) bool {
	return HashPassword(password) == hash
}

// GenerateToken creates a secure random token
func GenerateToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// CreateSession creates a new session for the user
func CreateSession(userID, username, email, role string, duration time.Duration) (*Session, error) {
	token, err := GenerateToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	session := &Session{
		Token:     token,
		UserID:    userID,
		Username:  username,
		Email:     email,
		Role:      role,
		ExpiresAt: time.Now().Add(duration),
	}

	store.mu.Lock()
	store.sessions[token] = session
	store.mu.Unlock()

	// Clean up expired sessions periodically
	go cleanupExpiredSessions()

	return session, nil
}

// ValidateSession checks if a session token is valid
func ValidateSession(token string) (*Session, error) {
	if token == "" {
		return nil, errors.New("empty token")
	}

	store.mu.RLock()
	session, exists := store.sessions[token]
	store.mu.RUnlock()

	if !exists {
		return nil, errors.New("invalid session")
	}

	if time.Now().After(session.ExpiresAt) {
		// Remove expired session
		store.mu.Lock()
		delete(store.sessions, token)
		store.mu.Unlock()
		return nil, errors.New("session expired")
	}

	return session, nil
}

// RefreshSession extends the expiration time of a session
func RefreshSession(token string, duration time.Duration) error {
	store.mu.Lock()
	defer store.mu.Unlock()

	session, exists := store.sessions[token]
	if !exists {
		return errors.New("session not found")
	}

	session.ExpiresAt = time.Now().Add(duration)
	return nil
}

// InvalidateSession removes a session
func InvalidateSession(token string) error {
	store.mu.Lock()
	defer store.mu.Unlock()

	if _, exists := store.sessions[token]; !exists {
		return errors.New("session not found")
	}

	delete(store.sessions, token)
	return nil
}

// GetActiveSessionsCount returns the number of active sessions
func GetActiveSessionsCount() int {
	store.mu.RLock()
	defer store.mu.RUnlock()
	return len(store.sessions)
}

// GetUserSessions returns all active sessions for a user
func GetUserSessions(userID string) []*Session {
	store.mu.RLock()
	defer store.mu.RUnlock()

	var userSessions []*Session
	for _, session := range store.sessions {
		if session.UserID == userID {
			userSessions = append(userSessions, session)
		}
	}
	return userSessions
}

// cleanupExpiredSessions removes expired sessions from memory
func cleanupExpiredSessions() {
	store.mu.Lock()
	defer store.mu.Unlock()

	now := time.Now()
	for token, session := range store.sessions {
		if now.After(session.ExpiresAt) {
			delete(store.sessions, token)
		}
	}
}

// InitCleanupTask starts a background task to clean up expired sessions
func InitCleanupTask() {
	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		for range ticker.C {
			cleanupExpiredSessions()
		}
	}()
}