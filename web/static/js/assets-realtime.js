// web/static/js/assets-realtime.js
// Real-time status updates for assets page

let wsClient = null;
let statusUpdateInterval = null;

// Initialize real-time monitoring
function initializeRealtimeMonitoring() {
    // Initialize WebSocket connection
    wsClient = new WebSocketClient();
    
    // Register event handlers
    wsClient.on('asset_status_update', handleAssetStatusUpdate);
    
    // Connect to WebSocket
    wsClient.connect();
    
    // Start periodic status refresh for all assets
    startStatusRefresh();
}

// Handle asset status update from WebSocket
function handleAssetStatusUpdate(data) {
    console.log('Asset status update received:', data);
    
    const update = data.data || data;
    
    // Update asset card in grid view
    updateAssetCardStatus(update.asset_id, update.new_status, update.response_time);
    
    // Update asset row in list view
    updateAssetRowStatus(update.asset_id, update.new_status, update.response_time);
    
    // Show notification for critical assets
    if (update.old_status !== update.new_status) {
        const message = `${update.asset_name} is now ${update.new_status}`;
        const type = update.new_status === 'online' ? 'success' : 
                    update.new_status === 'offline' ? 'error' : 'warning';
        
        // Only show notifications for critical assets or status changes
        if (shouldShowNotification(update)) {
            showNotification(message, type);
        }
    }
    
    // Update statistics if visible
    updateStatusStatistics();
}

// Update asset card status in grid view
function updateAssetCardStatus(assetId, newStatus, responseTime) {
    const card = document.querySelector(`[data-asset-id="${assetId}"]`);
    if (!card) return;
    
    // Update status badge
    const statusElement = card.querySelector('.asset-status');
    if (statusElement) {
        // Remove all status classes
        statusElement.classList.remove('online', 'offline', 'unknown', 'error');
        statusElement.classList.add(newStatus);
        
        // Update status text
        const statusText = capitalizeFirst(newStatus);
        statusElement.innerHTML = `
            <span class="status-dot"></span>
            ${statusText}
        `;
        
        // Add pulse animation for status change
        statusElement.classList.add('status-changed');
        setTimeout(() => {
            statusElement.classList.remove('status-changed');
        }, 2000);
    }
    
    // Update response time if available
    if (responseTime && responseTime > 0) {
        const responseTimeElement = card.querySelector('.response-time');
        if (responseTimeElement) {
            responseTimeElement.textContent = `${responseTime}ms`;
        }
    }
    
    // Update last seen time
    const lastSeenElement = card.querySelector('.last-seen');
    if (lastSeenElement && newStatus === 'online') {
        lastSeenElement.textContent = 'Just now';
    }
}

// Update asset row status in list view
function updateAssetRowStatus(assetId, newStatus, responseTime) {
    const row = document.querySelector(`tr[data-asset-id="${assetId}"]`);
    if (!row) return;
    
    // Update status cell
    const statusCell = row.querySelector('.asset-status-cell');
    if (statusCell) {
        statusCell.innerHTML = `
            <span class="asset-status ${newStatus}">
                <span class="status-dot"></span>
                ${capitalizeFirst(newStatus)}
            </span>
        `;
        
        // Add highlight animation
        row.classList.add('status-updated');
        setTimeout(() => {
            row.classList.remove('status-updated');
        }, 2000);
    }
    
    // Update last seen cell
    const lastSeenCell = row.querySelector('.last-seen-cell');
    if (lastSeenCell && newStatus === 'online') {
        lastSeenCell.textContent = new Date().toLocaleString();
    }
}

// Check if notification should be shown
function shouldShowNotification(update) {
    // Get asset from current data
    const asset = assets.find(a => a.id === update.asset_id);
    if (!asset) return false;
    
    // Show notifications for:
    // 1. Critical assets always
    // 2. High priority assets going offline
    // 3. Any asset that was offline for more than 1 hour coming back online
    
    if (asset.criticality === 'critical') {
        return true;
    }
    
    if (asset.criticality === 'high' && update.new_status === 'offline') {
        return true;
    }
    
    if (update.old_status === 'offline' && update.new_status === 'online') {
        // Check if asset was offline for extended period
        const lastSeen = new Date(asset.last_seen);
        const timeDiff = Date.now() - lastSeen.getTime();
        return timeDiff > 3600000; // 1 hour
    }
    
    return false;
}

// Start periodic status refresh
function startStatusRefresh() {
    // Initial status check
    checkAllAssetsStatus();
    
    // Set up periodic refresh (every 5 minutes for ICS/OT safety)
    statusUpdateInterval = setInterval(() => {
        checkAllAssetsStatus();
    }, 5 * 60 * 1000); // 5 minutes
}

// Check status for all visible assets
async function checkAllAssetsStatus() {
    try {
        const token = getAuthToken();
        
        // Get monitoring status
        const response = await fetch('/api/monitoring/status', {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        if (response.ok) {
            const status = await response.json();
            updateMonitoringIndicator(status);
        }
    } catch (error) {
        console.error('Error checking monitoring status:', error);
    }
}

// Update monitoring indicator in UI
function updateMonitoringIndicator(status) {
    // Create or update monitoring indicator
    let indicator = document.getElementById('monitoringIndicator');
    if (!indicator) {
        indicator = document.createElement('div');
        indicator.id = 'monitoringIndicator';
        indicator.className = 'monitoring-indicator';
        
        // Insert after page actions
        const pageActions = document.querySelector('.page-actions');
        if (pageActions) {
            pageActions.appendChild(indicator);
        }
    }
    
    // Update indicator content
    const isActive = status.monitoring_enabled && status.active_monitors > 0;
    indicator.innerHTML = `
        <div class="monitoring-status ${isActive ? 'active' : 'inactive'}">
            <i class="fas fa-${isActive ? 'broadcast-tower' : 'pause-circle'}"></i>
            <span>Monitoring: ${isActive ? 'Active' : 'Inactive'}</span>
            ${isActive ? `<span class="monitor-count">${status.active_monitors} assets</span>` : ''}
        </div>
    `;
}

// Update status statistics
function updateStatusStatistics() {
    // Count assets by status
    const statusCounts = {
        online: 0,
        offline: 0,
        unknown: 0,
        error: 0
    };
    
    filteredAssets.forEach(asset => {
        const status = asset.status || 'unknown';
        statusCounts[status] = (statusCounts[status] || 0) + 1;
    });
    
    // Update statistics display if it exists
    const statsContainer = document.getElementById('statusStatistics');
    if (statsContainer) {
        statsContainer.innerHTML = `
            <div class="stat-item">
                <div class="stat-value online">${statusCounts.online}</div>
                <div class="stat-label">Online</div>
            </div>
            <div class="stat-item">
                <div class="stat-value offline">${statusCounts.offline}</div>
                <div class="stat-label">Offline</div>
            </div>
            <div class="stat-item">
                <div class="stat-value unknown">${statusCounts.unknown}</div>
                <div class="stat-label">Unknown</div>
            </div>
        `;
    }
}

// Enhanced asset card creation with real-time indicators
function createEnhancedAssetCard(asset) {
    const card = document.createElement('div');
    card.className = 'asset-card';
    card.dataset.assetId = asset.id;
    card.onclick = () => viewAssetDetails(asset.id);
    
    const iconClass = getAssetIconClass(asset.asset_type);
    const statusClass = asset.status || 'unknown';
    const criticalityClass = asset.criticality || 'medium';
    
    // Add monitoring indicator
    const monitoringBadge = asset.is_monitored ? 
        '<span class="monitoring-badge" title="Real-time monitoring active"><i class="fas fa-satellite-dish"></i></span>' : '';
    
    card.innerHTML = `
        <div class="asset-card-header">
            <div class="asset-info">
                <div class="asset-icon-lg ${iconClass}">
                    <i class="fas fa-${getAssetIcon(asset.asset_type)}"></i>
                </div>
                <div class="asset-meta">
                    <div class="asset-name">${asset.name}</div>
                    <div class="asset-type">${asset.asset_type}</div>
                </div>
            </div>
            <div class="asset-status-container">
                <div class="asset-status ${statusClass}">
                    <span class="status-dot"></span>
                    ${capitalizeFirst(statusClass)}
                </div>
                ${monitoringBadge}
            </div>
        </div>
        
        <div class="asset-details">
            <div class="detail-item">
                <div class="detail-label">IP Address</div>
                <div class="detail-value">${asset.ip_address || 'Not assigned'}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Protocol</div>
                <div class="detail-value">${asset.protocol || '-'}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Last Seen</div>
                <div class="detail-value last-seen">${formatLastSeen(asset.last_seen)}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Response</div>
                <div class="detail-value response-time">${asset.response_time || '-'}</div>
            </div>
        </div>
        
        <div class="criticality-indicator ${criticalityClass}">
            <i class="fas fa-exclamation-triangle"></i>
            ${capitalizeFirst(criticalityClass)} Priority
        </div>
        
        <div class="asset-actions">
            <button onclick="event.stopPropagation(); editAsset('${asset.id}')">
                <i class="fas fa-edit"></i> Edit
            </button>
            <button onclick="event.stopPropagation(); toggleMonitoring('${asset.id}', ${asset.is_monitored})">
                <i class="fas fa-${asset.is_monitored ? 'pause' : 'play'}"></i> 
                ${asset.is_monitored ? 'Pause' : 'Monitor'}
            </button>
        </div>
    `;
    
    return card;
}

// Toggle asset monitoring
async function toggleMonitoring(assetId, isCurrentlyMonitored) {
    try {
        const token = getAuthToken();
        const endpoint = isCurrentlyMonitored ? 'stop' : 'start';
        
        const response = await fetch(`/api/monitoring/assets/${assetId}/${endpoint}`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        if (response.ok) {
            const message = isCurrentlyMonitored ? 
                'Monitoring stopped for asset' : 
                'Monitoring started for asset';
            showNotification(message, 'success');
            
            // Update asset in local data
            const asset = assets.find(a => a.id === assetId);
            if (asset) {
                asset.is_monitored = !isCurrentlyMonitored;
                renderAssets(); // Re-render to show updated state
            }
        } else {
            throw new Error('Failed to toggle monitoring');
        }
    } catch (error) {
        console.error('Error toggling monitoring:', error);
        showNotification('Failed to toggle monitoring', 'error');
    }
}

// Format last seen time
function formatLastSeen(lastSeen) {
    if (!lastSeen) return 'Never';
    
    const date = new Date(lastSeen);
    const now = new Date();
    const diff = now - date;
    
    // Less than 1 minute
    if (diff < 60000) {
        return 'Just now';
    }
    
    // Less than 1 hour
    if (diff < 3600000) {
        const minutes = Math.floor(diff / 60000);
        return `${minutes}m ago`;
    }
    
    // Less than 24 hours
    if (diff < 86400000) {
        const hours = Math.floor(diff / 3600000);
        return `${hours}h ago`;
    }
    
    // More than 24 hours
    return date.toLocaleDateString();
}

// Add monitoring-specific styles
function addMonitoringStyles() {
    const styles = `
        <style>
            .monitoring-indicator {
                margin-left: 16px;
            }
            
            .monitoring-status {
                display: flex;
                align-items: center;
                gap: 8px;
                padding: 8px 16px;
                background-color: var(--bg-tertiary);
                border-radius: var(--radius-md);
                font-size: 14px;
            }
            
            .monitoring-status.active {
                background-color: #D1FAE5;
                color: #065F46;
            }
            
            .monitoring-status.inactive {
                background-color: #FEE2E2;
                color: #991B1B;
            }
            
            .monitoring-status i {
                animation: pulse 2s ease-in-out infinite;
            }
            
            @keyframes pulse {
                0%, 100% { opacity: 0.6; }
                50% { opacity: 1; }
            }
            
            .monitor-count {
                font-weight: 600;
                margin-left: 8px;
            }
            
            .monitoring-badge {
                position: absolute;
                top: 8px;
                right: 8px;
                width: 24px;
                height: 24px;
                background-color: var(--success-color);
                color: white;
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 12px;
                animation: pulse 2s ease-in-out infinite;
            }
            
            .asset-status-container {
                position: relative;
            }
            
            .status-changed {
                animation: statusPulse 0.5s ease-out;
            }
            
            @keyframes statusPulse {
                0% { transform: scale(1); }
                50% { transform: scale(1.1); }
                100% { transform: scale(1); }
            }
            
            .status-updated {
                animation: rowHighlight 1s ease-out;
            }
            
            @keyframes rowHighlight {
                0% { background-color: var(--primary-color); opacity: 0.2; }
                100% { background-color: transparent; opacity: 1; }
            }
            
            .criticality-indicator {
                display: flex;
                align-items: center;
                gap: 6px;
                padding: 6px 12px;
                border-radius: var(--radius-sm);
                font-size: 12px;
                font-weight: 500;
                margin: 12px 0;
            }
            
            .criticality-indicator.critical {
                background-color: #FEE2E2;
                color: #991B1B;
            }
            
            .criticality-indicator.high {
                background-color: #FEF3C7;
                color: #92400E;
            }
            
            .criticality-indicator.medium {
                background-color: #DBEAFE;
                color: #1E40AF;
            }
            
            .criticality-indicator.low {
                background-color: #F3F4F6;
                color: #374151;
            }
        </style>
    `;
    
    // Add styles to head if not already present
    if (!document.getElementById('monitoring-styles')) {
        const styleElement = document.createElement('div');
        styleElement.id = 'monitoring-styles';
        styleElement.innerHTML = styles;
        document.head.appendChild(styleElement.firstElementChild);
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Add monitoring styles
    addMonitoringStyles();
    
    // Initialize real-time monitoring after assets are loaded
    const originalLoadAssets = window.loadAssets;
    window.loadAssets = async function() {
        await originalLoadAssets();
        initializeRealtimeMonitoring();
    };
    
    // Override createAssetCard with enhanced version
    window.createAssetCard = createEnhancedAssetCard;
});

// Cleanup on page unload
window.addEventListener('beforeunload', function() {
    if (statusUpdateInterval) {
        clearInterval(statusUpdateInterval);
    }
    if (wsClient) {
        wsClient.disconnect();
    }
});
