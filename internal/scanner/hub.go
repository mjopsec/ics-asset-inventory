package scanner

import (
	"sync"
)

// Hub maintains the set of active scanner clients
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

// Client represents a scanner client
type Client struct {
	hub *Hub

	// Buffered channel of outbound messages
	send chan []byte

	// Scanner ID for identification
	scannerID string
}

// Run runs the hub's main loop
func (h *Hub) run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			h.mu.Unlock()

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