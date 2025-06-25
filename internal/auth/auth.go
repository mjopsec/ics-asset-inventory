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
	CreatedAt time.Time `json:"created_at"`
	LastUsed  time.Time `json:"last_used"`
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

// Initialize cleanup task on startup
func init() {
	InitCleanupTask()
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

	now := time.Now()
	session := &Session{
		Token:     token,
		UserID:    userID,
		Username:  username,
		Email:     email,
		Role:      role,
		ExpiresAt: now.Add(duration),
		CreatedAt: now,
		LastUsed:  now,
	}

	store.mu.Lock()
	store.sessions[token] = session
	store.mu.Unlock()

	return session, nil
}

// ValidateSession checks if a session token is valid - ENHANCED VERSION
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

	// Check if session has expired
	if time.Now().After(session.ExpiresAt) {
		// Remove expired session
		store.mu.Lock()
		delete(store.sessions, token)
		store.mu.Unlock()
		return nil, errors.New("session expired")
	}

	// Update last used time (but don't do it on every request to avoid lock contention)
	// Only update if last used is more than 1 minute ago
	if time.Since(session.LastUsed) > time.Minute {
		store.mu.Lock()
		session.LastUsed = time.Now()
		store.mu.Unlock()
	}

	// Return a copy to avoid race conditions
	sessionCopy := *session
	return &sessionCopy, nil
}

// RefreshSession extends the expiration time of a session
func RefreshSession(token string, duration time.Duration) error {
	store.mu.Lock()
	defer store.mu.Unlock()

	session, exists := store.sessions[token]
	if !exists {
		return errors.New("session not found")
	}

	// Only extend if session is valid
	if time.Now().After(session.ExpiresAt) {
		return errors.New("cannot refresh expired session")
	}

	session.ExpiresAt = time.Now().Add(duration)
	session.LastUsed = time.Now()
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
			// Return a copy
			sessionCopy := *session
			userSessions = append(userSessions, &sessionCopy)
		}
	}
	return userSessions
}

// cleanupExpiredSessions removes expired sessions from memory
func cleanupExpiredSessions() {
	store.mu.Lock()
	defer store.mu.Unlock()

	now := time.Now()
	expiredTokens := []string{}
	
	for token, session := range store.sessions {
		if now.After(session.ExpiresAt) {
			expiredTokens = append(expiredTokens, token)
		}
	}
	
	for _, token := range expiredTokens {
		delete(store.sessions, token)
	}
	
	if len(expiredTokens) > 0 {
		fmt.Printf("Cleaned up %d expired sessions\n", len(expiredTokens))
	}
}

// InitCleanupTask starts a background task to clean up expired sessions
func InitCleanupTask() {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		
		for range ticker.C {
			cleanupExpiredSessions()
		}
	}()
}

// InvalidateAllUserSessions removes all sessions for a specific user
func InvalidateAllUserSessions(userID string) error {
	store.mu.Lock()
	defer store.mu.Unlock()

	tokensToDelete := []string{}
	for token, session := range store.sessions {
		if session.UserID == userID {
			tokensToDelete = append(tokensToDelete, token)
		}
	}

	if len(tokensToDelete) == 0 {
		return errors.New("no sessions found for user")
	}

	for _, token := range tokensToDelete {
		delete(store.sessions, token)
	}

	return nil
}

// GetSessionInfo returns information about a session without validating it
func GetSessionInfo(token string) (*Session, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()

	session, exists := store.sessions[token]
	if !exists {
		return nil, errors.New("session not found")
	}

	// Return a copy
	sessionCopy := *session
	return &sessionCopy, nil
}