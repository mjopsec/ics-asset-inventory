package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		// In production, implement proper origin checking
		return true
	},
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
}

// Client is a middleman between the websocket connection and the hub
type Client struct {
	hub *Hub

	// The websocket connection
	conn *websocket.Conn

	// Buffered channel of outbound messages
	send chan []byte

	// User ID for authentication
	userID string
}

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

var wsHub *Hub

func init() {
	wsHub = &Hub{
		broadcast:  make(chan []byte),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		clients:    make(map[*Client]bool),
	}
	go wsHub.run()
}

// GetHub returns the WebSocket hub instance
func GetHub() *Hub {
	return wsHub
}

func (h *Hub) run() {
	for {
		select {
		case client := <-h.register:
			h.clients[client] = true
			log.Printf("Client connected: %s", client.userID)

		case client := <-h.unregister:
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
				log.Printf("Client disconnected: %s", client.userID)
			}

		case message := <-h.broadcast:
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					close(client.send)
					delete(h.clients, client)
				}
			}
		}
	}
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

// HandleWebSocket handles WebSocket connections
func HandleWebSocket(c *gin.Context) {
	// Get user ID from context (set by auth middleware)
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}

	client := &Client{
		hub:    wsHub,
		conn:   conn,
		send:   make(chan []byte, 256),
		userID: userID.(string),
	}

	client.hub.register <- client

	// Allow collection of memory referenced by the caller by doing all work in
	// new goroutines.
	go client.writePump()
	go client.readPump()
}

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer.
	maxMessageSize = 512
)

func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %v", err)
			}
			break
		}

		// Handle incoming messages from client if needed
		log.Printf("Received message from client %s: %s", c.userID, message)
	}
}

func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				// The hub closed the channel.
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			// Add queued chat messages to the current websocket message.
			n := len(c.send)
			for i := 0; i < n; i++ {
				w.Write([]byte{'\n'})
				w.Write(<-c.send)
			}

			if err := w.Close(); err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// ScanProgressUpdate represents a scan progress update
type ScanProgressUpdate struct {
	ScanID          string  `json:"scan_id"`
	Progress        float64 `json:"progress"`
	TotalHosts      int     `json:"total_hosts"`
	ScannedHosts    int     `json:"scanned_hosts"`
	DiscoveredHosts int     `json:"discovered_hosts"`
	ElapsedTime     string  `json:"elapsed_time"`
}

// DeviceFoundUpdate represents a newly discovered device
type DeviceFoundUpdate struct {
	ScanID     string `json:"scan_id"`
	IPAddress  string `json:"ip_address"`
	DeviceType string `json:"device_type"`
	Protocol   string `json:"protocol"`
	Vendor     string `json:"vendor"`
}

// Helper functions to send specific message types

// SendScanProgress sends scan progress update to all clients
func SendScanProgress(scanID string, progress float64, totalHosts, scannedHosts, discoveredHosts int, elapsedTime string) {
	update := ScanProgressUpdate{
		ScanID:          scanID,
		Progress:        progress,
		TotalHosts:      totalHosts,
		ScannedHosts:    scannedHosts,
		DiscoveredHosts: discoveredHosts,
		ElapsedTime:     elapsedTime,
	}
	wsHub.BroadcastMessage(MessageTypeScanProgress, update)
}

// SendDeviceFound sends device discovery notification
func SendDeviceFound(scanID, ipAddress, deviceType, protocol, vendor string) {
	update := DeviceFoundUpdate{
		ScanID:     scanID,
		IPAddress:  ipAddress,
		DeviceType: deviceType,
		Protocol:   protocol,
		Vendor:     vendor,
	}
	wsHub.BroadcastMessage(MessageTypeDeviceFound, update)
}

// SendScanComplete sends scan completion notification
func SendScanComplete(scanID string, devicesFound int) {
	wsHub.BroadcastMessage(MessageTypeScanComplete, map[string]interface{}{
		"scan_id":       scanID,
		"devices_found": devicesFound,
	})
}

// SendScanError sends scan error notification
func SendScanError(scanID string, error string) {
	wsHub.BroadcastMessage(MessageTypeScanError, map[string]interface{}{
		"scan_id": scanID,
		"error":   error,
	})
}