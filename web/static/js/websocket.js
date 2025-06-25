// WebSocket Client for Real-time Updates

class WebSocketClient {
    constructor() {
        this.ws = null;
        this.reconnectInterval = 5000;
        this.shouldReconnect = true;
        this.messageHandlers = new Map();
        this.connectionListeners = [];
        this.isConnected = false;
    }

    // Connect to WebSocket server
    connect() {
        const token = this.getAuthToken();
        if (!token) {
            console.error('No authentication token found');
            return;
        }

        // Construct WebSocket URL
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/events`;

        try {
            // Create WebSocket connection with auth token in header
            this.ws = new WebSocket(wsUrl, [], {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            // If headers are not supported, fall back to query parameter
            if (!this.ws.readyState) {
                this.ws = new WebSocket(`${wsUrl}?token=${token}`);
            }

            this.setupEventHandlers();
        } catch (error) {
            console.error('WebSocket connection error:', error);
            this.scheduleReconnect();
        }
    }

    // Setup WebSocket event handlers
    setupEventHandlers() {
        this.ws.onopen = () => {
            console.log('WebSocket connected');
            this.isConnected = true;
            this.notifyConnectionListeners('connected');
        };

        this.ws.onmessage = (event) => {
            try {
                const message = JSON.parse(event.data);
                this.handleMessage(message);
            } catch (error) {
                console.error('Error parsing WebSocket message:', error);
            }
        };

        this.ws.onclose = (event) => {
            console.log('WebSocket disconnected:', event.code, event.reason);
            this.isConnected = false;
            this.notifyConnectionListeners('disconnected');
            
            if (this.shouldReconnect) {
                this.scheduleReconnect();
            }
        };

        this.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
            this.notifyConnectionListeners('error');
        };
    }

    // Handle incoming messages
    handleMessage(message) {
        const { type, timestamp, data } = message;
        
        // Call registered handlers for this message type
        const handlers = this.messageHandlers.get(type) || [];
        handlers.forEach(handler => {
            try {
                handler(data, timestamp);
            } catch (error) {
                console.error(`Error in message handler for ${type}:`, error);
            }
        });

        // Also emit a general message event
        const generalHandlers = this.messageHandlers.get('*') || [];
        generalHandlers.forEach(handler => {
            try {
                handler(message);
            } catch (error) {
                console.error('Error in general message handler:', error);
            }
        });
    }

    // Register a message handler
    on(messageType, handler) {
        if