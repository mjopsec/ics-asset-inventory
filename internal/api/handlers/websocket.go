package handlers

import (
	"log"
	"net/http"
	"time"

	"ics-asset-inventory/internal/auth"
	"ics-asset-inventory/internal/websocket"

	"github.com/gin-gonic/gin"
	gorilla "github.com/gorilla/websocket"
)

var upgrader = gorilla.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		// In production, implement proper origin checking
		return true
	},
}

// WebSocketConnection wraps gorilla websocket to implement the interface
type WebSocketConnection struct {
	*gorilla.Conn
}

func (w *WebSocketConnection) WriteMessage(messageType int, data []byte) error {
	return w.Conn.WriteMessage(messageType, data)
}

func (w *WebSocketConnection) Close() error {
	return w.Conn.Close()
}

// HandleWebSocket handles WebSocket connections with authentication
func HandleWebSocket(c *gin.Context) {
	// Try to authenticate from query parameter first (for WebSocket)
	token := c.Query("token")
	
	// If no query token, check context (set by auth middleware)
	var userID string
	if token != "" {
		// Validate token
		session, err := auth.ValidateSession(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}
		userID = session.UserID
	} else {
		// Get user ID from context (set by auth middleware)
		uid, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}
		userID = uid.(string)
	}

	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}

	// Wrap the connection
	wsConn := &WebSocketConnection{Conn: conn}
	
	// Get the hub
	hub := websocket.GetHub()
	
	// Create client
	client := websocket.NewClient(hub, wsConn, userID)
	
	// Register client
	hub.RegisterClient(client)

	// Start goroutines
	go handleWritePump(client, conn)
	go handleReadPump(client, conn, hub)
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

func handleReadPump(client *websocket.Client, conn *gorilla.Conn, hub *websocket.Hub) {
	defer func() {
		hub.UnregisterClient(client)
		conn.Close()
	}()

	conn.SetReadLimit(maxMessageSize)
	conn.SetReadDeadline(time.Now().Add(pongWait))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			if gorilla.IsUnexpectedCloseError(err, gorilla.CloseGoingAway, gorilla.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %v", err)
			}
			break
		}

		// Handle incoming messages from client if needed
		log.Printf("Received message from client %s: %s", client.GetUserID(), message)
	}
}

func handleWritePump(client *websocket.Client, conn *gorilla.Conn) {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		conn.Close()
	}()

	sendChan := client.GetSendChannel()

	for {
		select {
		case message, ok := <-sendChan:
			conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				// The hub closed the channel.
				conn.WriteMessage(gorilla.CloseMessage, []byte{})
				return
			}

			w, err := conn.NextWriter(gorilla.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			// Add queued messages to the current websocket message.
			n := len(sendChan)
			for i := 0; i < n; i++ {
				w.Write([]byte{'\n'})
				w.Write(<-sendChan)
			}

			if err := w.Close(); err != nil {
				return
			}

		case <-ticker.C:
			conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := conn.WriteMessage(gorilla.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// GetHub returns the WebSocket hub instance (for backward compatibility)
func GetHub() *websocket.Hub {
	return websocket.GetHub()
}