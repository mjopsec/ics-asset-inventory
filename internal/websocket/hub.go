package websocket

import (
	"encoding/json"
	"log"
	"sync"
	"time"
)

// Message types for WebSocket communication
const (
	MessageTypeScanProgress = "scan_progress"
	MessageTypeDeviceFound  = "device_found"
	MessageTypeScanComplete = "scan_complete"
	MessageTypeScanError    = "scan_error"
)

// WebSocketMessage represents a message sent over WebSocket
type WebSocketMessage struct {
	Type      string      `json:"type"`
	Timestamp time.Time   `json:"timestamp"`
	Data      interface{} `json:"data"`
}

// Hub maintains the set of active clients and broadcasts messages
type Hub struct {
	// Registered clients
	clients map[*Client]bool

	// Inbound messages from clients
	broadcast chan []byte

	// Register requests from clients
	register chan *Client

	// Unregister requests from clients
	unregister chan *Client

	mu sync.RWMutex
}

// Client is a middleman between the websocket connection and the hub
type Client struct {
	hub *Hub

	// The websocket connection
	conn ClientConnection

	// Buffered channel of outbound messages
	send chan []byte

	// User ID for authentication
	userID string
}

// ClientConnection interface to avoid importing gorilla/websocket here
type ClientConnection interface {
	WriteMessage(messageType int, data []byte) error
	Close() error
}

var (
	defaultHub *Hub
	once       sync.Once
)

// GetHub returns the WebSocket hub instance (singleton)
func GetHub() *Hub {
	once.Do(func() {
		defaultHub = &Hub{
			broadcast:  make(chan []byte),
			register:   make(chan *Client),
			unregister: make(chan *Client),
			clients:    make(map[*Client]bool),
		}
		go defaultHub.run()
	})
	return defaultHub
}

// NewClient creates a new client
func NewClient(hub *Hub, conn ClientConnection, userID string) *Client {
	return &Client{
		hub:    hub,
		conn:   conn,
		send:   make(chan []byte, 256),
		userID: userID,
	}
}

func (h *Hub) run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()
			log.Printf("Client connected: %s", client.userID)

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			h.mu.Unlock()
			log.Printf("Client disconnected: %s", client.userID)

		case message := <-h.broadcast:
			h.mu.RLock()
			clients := make([]*Client, 0, len(h.clients))
			for client := range h.clients {
				clients = append(clients, client)
			}
			h.mu.RUnlock()

			for _, client := range clients {
				select {
				case client.send <- message:
				default:
					h.mu.Lock()
					delete(h.clients, client)
					h.mu.Unlock()
					close(client.send)
				}
			}
		}
	}
}

// RegisterClient registers a new client
func (h *Hub) RegisterClient(client *Client) {
	h.register <- client
}

// UnregisterClient unregisters a client
func (h *Hub) UnregisterClient(client *Client) {
	h.unregister <- client
}

// BroadcastMessage sends a message to all connected clients
func (h *Hub) BroadcastMessage(msgType string, data interface{}) {
	msg := WebSocketMessage{
		Type:      msgType,
		Timestamp: time.Now(),
		Data:      data,
	}

	jsonData, err := json.Marshal(msg)
	if err != nil {
		log.Printf("Error marshaling WebSocket message: %v", err)
		return
	}

	h.broadcast <- jsonData
}

// GetClient returns the client channel for sending messages
func (c *Client) GetSendChannel() chan []byte {
	return c.send
}

// GetUserID returns the user ID of the client
func (c *Client) GetUserID() string {
	return c.userID
}

// Broadcast helper functions

// BroadcastScanProgress sends scan progress update to all clients
func BroadcastScanProgress(scanID string, progress float64, totalHosts, scannedHosts, discoveredHosts int, elapsedTime string) {
	hub := GetHub()
	hub.BroadcastMessage(MessageTypeScanProgress, map[string]interface{}{
		"scan_id":          scanID,
		"progress":         progress,
		"total_hosts":      totalHosts,
		"scanned_hosts":    scannedHosts,
		"discovered_hosts": discoveredHosts,
		"elapsed_time":     elapsedTime,
	})
}

// BroadcastDeviceFound sends device discovery notification
func BroadcastDeviceFound(scanID, ipAddress, deviceType, protocol, vendor string) {
	hub := GetHub()
	hub.BroadcastMessage(MessageTypeDeviceFound, map[string]interface{}{
		"scan_id":     scanID,
		"ip_address":  ipAddress,
		"device_type": deviceType,
		"protocol":    protocol,
		"vendor":      vendor,
	})
}

// BroadcastScanComplete sends scan completion notification
func BroadcastScanComplete(scanID string, devicesFound int) {
	hub := GetHub()
	hub.BroadcastMessage(MessageTypeScanComplete, map[string]interface{}{
		"scan_id":       scanID,
		"devices_found": devicesFound,
	})
}

// BroadcastScanError sends scan error notification
func BroadcastScanError(scanID string, error string) {
	hub := GetHub()
	hub.BroadcastMessage(MessageTypeScanError, map[string]interface{}{
		"scan_id": scanID,
		"error":   error,
	})
}