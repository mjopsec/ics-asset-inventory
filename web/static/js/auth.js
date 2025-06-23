// web/static/js/auth.js

class AuthManager {
    constructor() {
        this.tokenKey = 'token';
        this.userKey = 'user';
        this.cookieTokenKey = 'auth_token';
    }

    // Get authentication token
    getToken() {
        return this.getCookie(this.cookieTokenKey) || localStorage.getItem(this.tokenKey);
    }

    // Set authentication token
    setToken(token, remember = false) {
        localStorage.setItem(this.tokenKey, token);
        
        if (remember) {
            // Set cookie for 30 days
            const expires = new Date();
            expires.setTime(expires.getTime() + (30 * 24 * 60 * 60 * 1000));
            document.cookie = `${this.cookieTokenKey}=${token}; expires=${expires.toUTCString()}; path=/; SameSite=Strict`;
        }
    }

    // Get user data
    getUser() {
        const userData = localStorage.getItem(this.userKey);
        return userData ? JSON.parse(userData) : null;
    }

    // Set user data
    setUser(user) {
        localStorage.setItem(this.userKey, JSON.stringify(user));
    }

    // Clear authentication data
    clearAuth() {
        localStorage.removeItem(this.tokenKey);
        localStorage.removeItem(this.userKey);
        document.cookie = `${this.cookieTokenKey}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;`;
    }

    // Check if user is authenticated
    isAuthenticated() {
        return !!this.getToken();
    }

    // Get cookie value
    getCookie(name) {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) return parts.pop().split(';').shift();
        return null;
    }

    // Make authenticated API request
    async apiRequest(url, options = {}) {
        const token = this.getToken();
        
        if (!token) {
            throw new Error('No authentication token available');
        }

        const defaultOptions = {
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            credentials: 'include'
        };

        // Merge options
        const requestOptions = {
            ...defaultOptions,
            ...options,
            headers: {
                ...defaultOptions.headers,
                ...options.headers
            }
        };

        try {
            const response = await fetch(url, requestOptions);

            // Handle authentication errors
            if (response.status === 401) {
                this.clearAuth();
                this.redirectToLogin();
                throw new Error('Authentication failed');
            }

            return response;
        } catch (error) {
            console.error('API request failed:', error);
            throw error;
        }
    }

    // Login user
    async login(credentials) {
        try {
            const response = await fetch('/api/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(credentials)
            });

            if (response.ok) {
                const data = await response.json();
                this.setToken(data.token, credentials.remember);
                this.setUser(data.user);
                return data;
            } else {
                const error = await response.json();
                throw new Error(error.error || 'Login failed');
            }
        } catch (error) {
            console.error('Login error:', error);
            throw error;
        }
    }

    // Logout user
    async logout() {
        try {
            const token = this.getToken();
            
            if (token) {
                await fetch('/api/auth/logout', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    }
                });
            }
        } catch (error) {
            console.error('Logout error:', error);
        } finally {
            this.clearAuth();
            this.redirectToLogin();
        }
    }

    // Register user
    async register(userData) {
        try {
            const response = await fetch('/api/auth/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(userData)
            });

            if (response.ok) {
                const data = await response.json();
                return data;
            } else {
                const error = await response.json();
                throw new Error(error.error || 'Registration failed');
            }
        } catch (error) {
            console.error('Registration error:', error);
            throw error;
        }
    }

    // Get current user info
    async getCurrentUser() {
        try {
            const response = await this.apiRequest('/api/auth/me');
            
            if (response.ok) {
                const user = await response.json();
                this.setUser(user);
                return user;
            } else {
                throw new Error('Failed to get user info');
            }
        } catch (error) {
            console.error('Get user error:', error);
            throw error;
        }
    }

    // Change password
    async changePassword(passwordData) {
        try {
            const response = await this.apiRequest('/api/auth/change-password', {
                method: 'POST',
                body: JSON.stringify(passwordData)
            });

            if (response.ok) {
                return await response.json();
            } else {
                const error = await response.json();
                throw new Error(error.error || 'Failed to change password');
            }
        } catch (error) {
            console.error('Change password error:', error);
            throw error;
        }
    }

    // Redirect to login page
    redirectToLogin() {
        if (window.location.pathname !== '/login') {
            window.location.href = '/login';
        }
    }

    // Check authentication on page load
    checkAuth() {
        if (!this.isAuthenticated() && !this.isPublicPage()) {
            this.redirectToLogin();
            return false;
        }
        return true;
    }

    // Check if current page is public (doesn't require auth)
    isPublicPage() {
        const publicPages = ['/login', '/register'];
        return publicPages.includes(window.location.pathname);
    }

    // Initialize authentication
    init() {
        // Check authentication on page load
        if (!this.checkAuth()) {
            return;
        }

        // Load user profile if authenticated
        if (this.isAuthenticated()) {
            this.getCurrentUser().catch(error => {
                console.error('Failed to load user profile:', error);
            });
        }

        // Set up token refresh interval (optional)
        this.setupTokenRefresh();
    }

    // Setup automatic token refresh
    setupTokenRefresh() {
        // Refresh token every 30 minutes
        setInterval(async () => {
            if (this.isAuthenticated()) {
                try {
                    await this.refreshToken();
                } catch (error) {
                    console.error('Token refresh failed:', error);
                }
            }
        }, 30 * 60 * 1000);
    }

    // Refresh authentication token
    async refreshToken() {
        try {
            const response = await this.apiRequest('/api/auth/refresh', {
                method: 'POST'
            });

            if (response.ok) {
                const data = await response.json();
                this.setToken(data.token);
                return data;
            }
        } catch (error) {
            console.error('Token refresh error:', error);
            throw error;
        }
    }
}

// Create global auth instance
window.auth = new AuthManager();

// Initialize on DOM load
document.addEventListener('DOMContentLoaded', () => {
    window.auth.init();
});

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = AuthManager;
}