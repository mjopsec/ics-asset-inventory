// web/static/js/api-client.js

class APIClient {
    constructor(baseURL = '/api') {
        this.baseURL = baseURL;
        this.defaultHeaders = {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        };
    }

    // Get authentication headers
    getAuthHeaders() {
        const token = window.auth?.getToken();
        return token ? { 'Authorization': `Bearer ${token}` } : {};
    }

    // Make HTTP request with proper error handling
    async request(endpoint, options = {}) {
        const url = `${this.baseURL}${endpoint}`;
        
        const requestOptions = {
            credentials: 'include',
            ...options,
            headers: {
                ...this.defaultHeaders,
                ...this.getAuthHeaders(),
                ...options.headers
            }
        };

        try {
            const response = await fetch(url, requestOptions);

            // Handle authentication errors
            if (response.status === 401) {
                if (window.auth) {
                    window.auth.clearAuth();
                    window.auth.redirectToLogin();
                }
                throw new APIError('Authentication required', 401);
            }

            // Handle other HTTP errors
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new APIError(
                    errorData.error || `HTTP ${response.status}: ${response.statusText}`,
                    response.status,
                    errorData
                );
            }

            // Return response for further processing
            return response;
        } catch (error) {
            if (error instanceof APIError) {
                throw error;
            }
            throw new APIError(`Network error: ${error.message}`, 0, error);
        }
    }

    // GET request
    async get(endpoint, params = {}) {
        const url = new URL(`${this.baseURL}${endpoint}`, window.location.origin);
        Object.keys(params).forEach(key => {
            if (params[key] !== undefined && params[key] !== null) {
                url.searchParams.append(key, params[key]);
            }
        });

        const response = await this.request(url.pathname + url.search);
        return response.json();
    }

    // POST request
    async post(endpoint, data = {}) {
        const response = await this.request(endpoint, {
            method: 'POST',
            body: JSON.stringify(data)
        });
        return response.json();
    }

    // PUT request
    async put(endpoint, data = {}) {
        const response = await this.request(endpoint, {
            method: 'PUT',
            body: JSON.stringify(data)
        });
        return response.json();
    }

    // DELETE request
    async delete(endpoint) {
        const response = await this.request(endpoint, {
            method: 'DELETE'
        });
        return response.status === 204 ? null : response.json();
    }

    // PATCH request
    async patch(endpoint, data = {}) {
        const response = await this.request(endpoint, {
            method: 'PATCH',
            body: JSON.stringify(data)
        });
        return response.json();
    }

    // Upload file
    async upload(endpoint, file, additionalData = {}) {
        const formData = new FormData();
        formData.append('file', file);
        
        Object.keys(additionalData).forEach(key => {
            formData.append(key, additionalData[key]);
        });

        const response = await this.request(endpoint, {
            method: 'POST',
            body: formData,
            headers: {
                // Remove Content-Type to let browser set boundary
                ...this.getAuthHeaders()
            }
        });
        return response.json();
    }

    // Download file
    async download(endpoint, filename) {
        const response = await this.request(endpoint);
        
        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename || 'download';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
        }
    }
}

// Custom error class for API errors
class APIError extends Error {
    constructor(message, status, data = {}) {
        super(message);
        this.name = 'APIError';
        this.status = status;
        this.data = data;
    }
}

// Asset API methods
class AssetAPI extends APIClient {
    // Get all assets
    async getAssets(params = {}) {
        return this.get('/assets', params);
    }

    // Get single asset
    async getAsset(id) {
        return this.get(`/assets/${id}`);
    }

    // Create asset
    async createAsset(assetData) {
        return this.post('/assets', assetData);
    }

    // Update asset
    async updateAsset(id, assetData) {
        return this.put(`/assets/${id}`, assetData);
    }

    // Delete asset
    async deleteAsset(id) {
        return this.delete(`/assets/${id}`);
    }

    // Search assets
    async searchAssets(query, filters = {}) {
        return this.get('/assets/search', { q: query, ...filters });
    }

    // Get asset statistics
    async getAssetStats() {
        return this.get('/assets/stats');
    }
}

// Dashboard API methods
class DashboardAPI extends APIClient {
    // Get dashboard overview
    async getOverview() {
        return this.get('/dashboard/overview');
    }

    // Get dashboard metrics
    async getMetrics() {
        return this.get('/dashboard/metrics');
    }

    // Get alerts
    async getAlerts() {
        return this.get('/dashboard/alerts');
    }
}

// Discovery API methods
class DiscoveryAPI extends APIClient {
    // Start network scan
    async startScan(scanConfig) {
        return this.post('/discovery/scan', scanConfig);
    }

    // Get scan status
    async getScanStatus(scanId) {
        return this.get(`/discovery/scan/${scanId}/status`);
    }

    // Stop scan
    async stopScan(scanId) {
        return this.post(`/discovery/scan/${scanId}/stop`);
    }

    // Get scan history
    async getScanHistory() {
        return this.get('/discovery/history');
    }

    // Get discovered devices
    async getDiscoveredDevices(scanId) {
        return this.get(`/discovery/scan/${scanId}/devices`);
    }
}

// Security API methods
class SecurityAPI extends APIClient {
    // Get security overview
    async getSecurityOverview() {
        return this.get('/security/overview');
    }

    // Get vulnerabilities
    async getVulnerabilities(params = {}) {
        return this.get('/security/vulnerabilities', params);
    }

    // Get compliance status
    async getComplianceStatus() {
        return this.get('/security/compliance');
    }

    // Update vulnerability status
    async updateVulnerabilityStatus(vulnId, status) {
        return this.patch(`/security/vulnerabilities/${vulnId}`, { status });
    }
}

// Reports API methods
class ReportsAPI extends APIClient {
    // Generate report
    async generateReport(reportConfig) {
        return this.post('/reports/generate', reportConfig);
    }

    // Get report status
    async getReportStatus(reportId) {
        return this.get(`/reports/${reportId}/status`);
    }

    // Download report
    async downloadReport(reportId, filename) {
        return this.download(`/reports/${reportId}/download`, filename);
    }

    // Get report history
    async getReportHistory() {
        return this.get('/reports/history');
    }

    // Get scheduled reports
    async getScheduledReports() {
        return this.get('/reports/scheduled');
    }

    // Create scheduled report
    async createScheduledReport(scheduleConfig) {
        return this.post('/reports/scheduled', scheduleConfig);
    }
}

// Settings API methods
class SettingsAPI extends APIClient {
    // Get settings
    async getSettings(section = null) {
        const endpoint = section ? `/settings/${section}` : '/settings';
        return this.get(endpoint);
    }

    // Update settings
    async updateSettings(section, settings) {
        return this.put(`/settings/${section}`, settings);
    }

    // Get system info
    async getSystemInfo() {
        return this.get('/settings/system');
    }

    // Create backup
    async createBackup() {
        return this.post('/settings/backup');
    }

    // Restore backup
    async restoreBackup(file) {
        return this.upload('/settings/restore', file);
    }
}

// Create global API instances
window.api = {
    assets: new AssetAPI(),
    dashboard: new DashboardAPI(),
    discovery: new DiscoveryAPI(),
    security: new SecurityAPI(),
    reports: new ReportsAPI(),
    settings: new SettingsAPI()
};

// Export classes
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        APIClient,
        APIError,
        AssetAPI,
        DashboardAPI,
        DiscoveryAPI,
        SecurityAPI,
        ReportsAPI,
        SettingsAPI
    };
}