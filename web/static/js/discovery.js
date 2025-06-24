// Discovery Page JavaScript - Fixed Implementation
let currentScan = null;
let progressInterval = null;
let scanResults = [];
let allDiscoveredDevices = new Map(); // Store all discovered devices by IP

// Helper function to get authentication token
function getAuthToken() {
    return getCookie('auth_token') || localStorage.getItem('token');
}

// Helper function to get cookie value
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
    return null;
}

// Initialize page
document.addEventListener('DOMContentLoaded', function() {
    setupEventListeners();
    loadScanHistory();
    loadProtocolPorts();
    
    // Check for active scans on page load
    checkActiveScans();
    
    // Initialize WebSocket for real-time updates
    initializeWebSocket();
});

// Setup event listeners
function setupEventListeners() {
    // Form submission
    const scanForm = document.getElementById('scanForm');
    if (scanForm) {
        scanForm.addEventListener('submit', handleScanSubmit);
    }
}

// Handle scan form submission
async function handleScanSubmit(e) {
    e.preventDefault();

    const formData = new FormData(e.target);
    
    // Get selected protocols
    const selectedProtocols = Array.from(document.querySelectorAll('input[name="protocols"]:checked'))
        .map(cb => cb.value);

    if (selectedProtocols.length === 0) {
        showNotification('Please select at least one protocol', 'warning');
        return;
    }

    // Build scan configuration
    const scanConfig = {
        ip_range: formData.get('ipRange') || document.getElementById('ipRange').value,
        scan_type: formData.get('scanType') || document.getElementById('scanType').value,
        timeout: parseInt(formData.get('timeout') || document.getElementById('timeout').value),
        max_concurrent: parseInt(formData.get('concurrent') || document.getElementById('concurrent').value),
        protocols: selectedProtocols
    };

    // Add custom port ranges if selected
    if (scanConfig.scan_type === 'custom') {
        scanConfig.port_ranges = [
            { start: 1, end: 1024 },
            { start: 502, end: 502 },
            { start: 20000, end: 20000 },
            { start: 44818, end: 44818 },
            { start: 47808, end: 47808 }
        ];
    }

    // Validate IP range
    if (!scanConfig.ip_range) {
        showNotification('Please enter an IP range', 'error');
        return;
    }

    if (!isValidIPRange(scanConfig.ip_range)) {
        showNotification('Please enter a valid IP range (e.g., 192.168.1.0/24)', 'error');
        return;
    }

    try {
        const token = getAuthToken();
        if (!token) {
            showNotification('Authentication required. Please login again.', 'error');
            window.location.href = '/login';
            return;
        }

        const response = await fetch('/api/discovery/scan', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(scanConfig)
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to start scan');
        }

        const result = await response.json();
        currentScan = result;
        
        showNotification('Scan started successfully', 'success');
        startProgressMonitoring(result.scan_id);
        
        // Show progress section
        document.getElementById('scanProgress').classList.add('active');
        
        // Clear previous results
        scanResults = [];
        
    } catch (error) {
        console.error('Error starting scan:', error);
        showNotification(error.message, 'error');
    }
}

// Validate IP range format
function isValidIPRange(ipRange) {
    // Check for CIDR notation (e.g., 192.168.1.0/24)
    const cidrRegex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
    
    // Check for single IP (e.g., 192.168.1.100)
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    
    // Check for IP range (e.g., 192.168.1.1-192.168.1.254)
    const rangeRegex = /^(\d{1,3}\.){3}\d{1,3}-(\d{1,3}\.){3}\d{1,3}$/;
    
    return cidrRegex.test(ipRange) || ipRegex.test(ipRange) || rangeRegex.test(ipRange);
}

// Start monitoring scan progress
function startProgressMonitoring(scanId) {
    // Clear any existing interval
    if (progressInterval) {
        clearInterval(progressInterval);
    }

    // Update progress immediately
    updateScanProgress(scanId);

    // Update every 2 seconds
    progressInterval = setInterval(() => {
        updateScanProgress(scanId);
    }, 2000);
}

// Update scan progress
async function updateScanProgress(scanId) {
    try {
        const token = getAuthToken();
        const response = await fetch(`/api/discovery/scan/${scanId}/progress`, {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (!response.ok) {
            throw new Error('Failed to get scan progress');
        }

        const progress = await response.json();
        displayProgress(progress);

        // Check if scan is complete
        if (progress.status === 'completed' || 
            progress.status === 'failed' || 
            progress.status === 'cancelled') {
            
            clearInterval(progressInterval);
            progressInterval = null;
            
            if (progress.status === 'completed') {
                showNotification('Scan completed successfully', 'success');
                await loadScanResults(scanId);
                
                // Auto-switch to results tab after a short delay
                setTimeout(() => {
                    switchTab('results');
                }, 1000);
            } else if (progress.status === 'failed') {
                showNotification('Scan failed', 'error');
            } else if (progress.status === 'cancelled') {
                showNotification('Scan was cancelled', 'info');
            }
            
            // Hide progress section after a delay
            setTimeout(() => {
                document.getElementById('scanProgress').classList.remove('active');
            }, 3000);
            
            // Reload scan history
            loadScanHistory();
        }

    } catch (error) {
        console.error('Error updating progress:', error);
    }
}

// Display progress information
function displayProgress(progress) {
    // Update progress bar
    const progressBar = document.getElementById('progressBar');
    if (progressBar) {
        progressBar.style.width = `${progress.progress || 0}%`;
    }

    // Update progress text
    const progressText = document.getElementById('progressText');
    if (progressText) {
        progressText.textContent = `${Math.round(progress.progress || 0)}%`;
    }

    // Update time
    const progressTime = document.getElementById('progressTime');
    if (progressTime) {
        progressTime.textContent = `Elapsed: ${progress.elapsed_time || '0:00'}`;
    }

    // Update statistics
    const devicesFound = document.getElementById('devicesFound');
    const ipsScanned = document.getElementById('ipsScanned');
    const protocolsDetected = document.getElementById('protocolsDetected');
    const errorsCount = document.getElementById('errorsCount');
    
    if (devicesFound) devicesFound.textContent = progress.discovered_hosts || 0;
    if (ipsScanned) ipsScanned.textContent = progress.scanned_hosts || 0;
    if (protocolsDetected) protocolsDetected.textContent = progress.discovered_hosts || 0;
    if (errorsCount) errorsCount.textContent = progress.errors ? progress.errors.length : 0;
}

// Stop scan
async function stopScan() {
    if (!currentScan) {
        showNotification('No active scan to stop', 'warning');
        return;
    }

    try {
        const token = getAuthToken();
        const response = await fetch(`/api/discovery/scan/${currentScan.scan_id}/stop`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (response.ok) {
            showNotification('Scan stopped', 'info');
            clearInterval(progressInterval);
            progressInterval = null;
            document.getElementById('scanProgress').classList.remove('active');
            currentScan = null;
        } else {
            throw new Error('Failed to stop scan');
        }
    } catch (error) {
        console.error('Error stopping scan:', error);
        showNotification('Failed to stop scan', 'error');
    }
}

// Load scan results
async function loadScanResults(scanId) {
    try {
        const token = getAuthToken();
        const response = await fetch(`/api/discovery/scan/${scanId}/results`, {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (!response.ok) {
            throw new Error('Failed to load scan results');
        }

        const data = await response.json();
        const devices = data.devices || [];
        
        // Update scanResults and merge with existing devices
        devices.forEach(device => {
            // Store in our Map to persist across scans
            allDiscoveredDevices.set(device.ip_address, device);
        });
        
        // Convert Map values to array for display
        scanResults = Array.from(allDiscoveredDevices.values());
        
        displayScanResults();

    } catch (error) {
        console.error('Error loading scan results:', error);
        showNotification('Failed to load scan results', 'error');
    }
}

// Display scan results
function displayScanResults() {
    const deviceGrid = document.getElementById('discoveredDevices');
    if (!deviceGrid) return;

    // Clear existing content
    deviceGrid.innerHTML = '';

    if (scanResults.length === 0) {
        deviceGrid.innerHTML = `
            <div class="empty-state" style="grid-column: 1 / -1;">
                <i class="fas fa-search"></i>
                <div class="empty-state-title">No Devices Found</div>
                <div class="empty-state-text">No devices were discovered during the scan</div>
                <button class="btn btn-primary" onclick="switchTab('scan')">
                    <i class="fas fa-radar"></i> Start New Scan
                </button>
            </div>`;
        return;
    }

    // Create device cards
    scanResults.forEach(device => {
        const deviceCard = createDeviceCard(device);
        deviceGrid.appendChild(deviceCard);
    });
}

// Create device card element
function createDeviceCard(device) {
    const card = document.createElement('div');
    card.className = 'device-card';
    
    const statusClass = device.is_new ? 'new' : 'existing';
    const deviceType = device.device_type || 'Unknown Device';
    const vendor = device.vendor || 'Unknown';
    const protocol = device.protocol || 'Unknown';
    const responseTime = device.response_time || 'N/A';
    
    // Get open ports info - fix the undefined issue
    const openPorts = device.open_ports || [];
    let portDisplay = 'N/A';
    if (openPorts.length > 0) {
        // Display first port or multiple ports
        portDisplay = openPorts.map(p => p.port).join(', ');
    }
    
    card.innerHTML = `
        <div class="device-header">
            <div class="device-info">
                <div class="device-name">${device.hostname || deviceType}</div>
                <div class="device-ip">${device.ip_address}</div>
            </div>
            <div class="device-status ${statusClass}">${device.is_new ? 'New' : 'Existing'}</div>
        </div>
        <div class="device-details">
            <div class="device-detail">
                <div class="device-detail-label">Protocol</div>
                <div class="device-detail-value">${protocol}</div>
            </div>
            <div class="device-detail">
                <div class="device-detail-label">Port</div>
                <div class="device-detail-value">${portDisplay}</div>
            </div>
            <div class="device-detail">
                <div class="device-detail-label">Vendor</div>
                <div class="device-detail-value">${vendor}</div>
            </div>
            <div class="device-detail">
                <div class="device-detail-label">Response Time</div>
                <div class="device-detail-value">${responseTime}</div>
            </div>
        </div>
        <div class="device-actions">
            <button class="btn btn-secondary" onclick="viewDeviceDetails('${device.ip_address}')">
                <i class="fas fa-info-circle"></i> Details
            </button>
            <button class="btn btn-primary" onclick="addDeviceToInventory('${device.ip_address}')" id="add-btn-${device.ip_address.replace(/\./g, '-')}">
                <i class="fas fa-plus"></i> Add to Inventory
            </button>
        </div>
    `;
    
    return card;
}

// Load scan history
async function loadScanHistory() {
    try {
        const token = getAuthToken();
        const response = await fetch('/api/discovery/history?limit=10', {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (!response.ok) {
            throw new Error('Failed to load scan history');
        }

        const data = await response.json();
        displayScanHistory(data.history || []);

    } catch (error) {
        console.error('Error loading scan history:', error);
    }
}

// Display scan history
function displayScanHistory(history) {
    const historyBody = document.getElementById('scanHistoryBody');
    if (!historyBody) return;

    if (history.length === 0) {
        historyBody.innerHTML = `
            <tr>
                <td colspan="7" style="text-align: center; padding: 40px; color: var(--text-tertiary);">
                    <i class="fas fa-history" style="font-size: 32px; opacity: 0.3; margin-bottom: 12px; display: block;"></i>
                    No scan history available
                </td>
            </tr>
        `;
        return;
    }

    historyBody.innerHTML = '';
    
    history.forEach(scan => {
        const row = document.createElement('tr');
        const statusClass = getStatusClass(scan.status);
        const duration = formatDuration(scan.duration);
        const scanDate = new Date(scan.created_at).toLocaleString();
        
        row.innerHTML = `
            <td>${scanDate}</td>
            <td><span class="scan-type-badge ${scan.scan_type}">${capitalizeFirst(scan.scan_type)}</span></td>
            <td>${scan.target}</td>
            <td>${duration}</td>
            <td>${scan.devices_found || 0}</td>
            <td><span class="scan-status ${statusClass}"><i class="fas fa-${getStatusIcon(scan.status)}"></i> ${capitalizeFirst(scan.status)}</span></td>
            <td>
                <button class="btn btn-secondary" style="padding: 6px 12px; font-size: 12px;" onclick="viewScanResults('${scan.id}')">
                    <i class="fas fa-eye"></i> View
                </button>
            </td>
        `;
        
        historyBody.appendChild(row);
    });
}

// Load protocol ports information
async function loadProtocolPorts() {
    try {
        const token = getAuthToken();
        const response = await fetch('/api/discovery/protocol-ports', {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (!response.ok) {
            console.warn('Failed to load protocol ports');
            return;
        }

        const protocolPorts = await response.json();
        updateProtocolCards(protocolPorts);

    } catch (error) {
        console.error('Error loading protocol ports:', error);
    }
}

// Update protocol cards with port information
function updateProtocolCards(protocolPorts) {
    Object.keys(protocolPorts).forEach(protocolKey => {
        const protocolData = protocolPorts[protocolKey];
        const protocolCard = document.querySelector(`input[value="${protocolKey}"]`)?.closest('.protocol-card');
        
        if (protocolCard) {
            const portElement = protocolCard.querySelector('.protocol-port');
            if (portElement && protocolData.default_port) {
                portElement.textContent = `Port ${protocolData.default_port}`;
            }
            
            const nameElement = protocolCard.querySelector('.protocol-name');
            if (nameElement && protocolData.name) {
                nameElement.textContent = protocolData.name;
            }
        }
    });
}

// Check for active scans on page load
async function checkActiveScans() {
    try {
        const token = getAuthToken();
        const response = await fetch('/api/discovery/active-scans', {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        if (!response.ok) return;
        
        const data = await response.json();
        if (data.active_scans && data.active_scans.length > 0) {
            const activeScan = data.active_scans[0];
            currentScan = activeScan;
            startProgressMonitoring(activeScan.scan_id);
            document.getElementById('scanProgress').classList.add('active');
        }
        
    } catch (error) {
        console.error('Error checking active scans:', error);
    }
}

// View device details
function viewDeviceDetails(deviceIP) {
    console.log('View details for device:', deviceIP);
    
    // Find device in scan results
    const device = scanResults.find(d => d.ip_address === deviceIP);
    if (!device) {
        showNotification('Device not found', 'error');
        return;
    }
    
    // If you have the modal implementation from the previous artifact, it will show the modal
    // Otherwise, show a simple alert with device info
    if (typeof populateDeviceDetailModal === 'function') {
        populateDeviceDetailModal(device);
        document.getElementById('deviceDetailModal').classList.add('active');
    } else {
        // Fallback to simple display
        const deviceInfo = `
Device Details:
IP Address: ${device.ip_address}
Hostname: ${device.hostname || 'Unknown'}
Type: ${device.device_type || 'Unknown'}
Vendor: ${device.vendor || 'Unknown'}
Protocol: ${device.protocol || 'Unknown'}
Open Ports: ${device.open_ports?.map(p => p.port).join(', ') || 'None'}
Response Time: ${device.response_time || 'N/A'}
        `;
        alert(deviceInfo);
    }
}

// Add device to inventory - Fixed implementation
async function addDeviceToInventory(deviceIP) {
    if (!currentScan && scanResults.length === 0) {
        showNotification('No scan data available', 'error');
        return;
    }
    
    // Find the device in our results
    const device = scanResults.find(d => d.ip_address === deviceIP);
    if (!device) {
        showNotification('Device not found in scan results', 'error');
        return;
    }
    
    // Get the button and show loading state
    const buttonId = `add-btn-${deviceIP.replace(/\./g, '-')}`;
    const addButton = document.getElementById(buttonId);
    if (addButton) {
        addButton.disabled = true;
        addButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Adding...';
    }
    
    try {
        const token = getAuthToken();
        
        // Use the most recent scan ID or the current scan ID
        let scanId = currentScan?.scan_id;
        
        // If no current scan, get the most recent from history
        if (!scanId) {
            const historyResponse = await fetch('/api/discovery/history?limit=1', {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            
            if (historyResponse.ok) {
                const historyData = await historyResponse.json();
                if (historyData.history && historyData.history.length > 0) {
                    scanId = historyData.history[0].id;
                }
            }
        }
        
        if (!scanId) {
            throw new Error('No scan context available');
        }
        
        const response = await fetch(`/api/discovery/scan/${scanId}/add-device`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                device_ip: deviceIP
            })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to add device to inventory');
        }

        const result = await response.json();
        showNotification('Device added to inventory successfully', 'success');
        
        // Update the device card to show it's been added
        updateDeviceCardStatus(deviceIP, 'added');
        
        // Update the device in our local storage
        const deviceToUpdate = allDiscoveredDevices.get(deviceIP);
        if (deviceToUpdate) {
            deviceToUpdate.is_new = false;
            allDiscoveredDevices.set(deviceIP, deviceToUpdate);
        }

    } catch (error) {
        console.error('Error adding device to inventory:', error);
        showNotification(error.message, 'error');
        
        // Reset button state
        if (addButton) {
            addButton.disabled = false;
            addButton.innerHTML = '<i class="fas fa-plus"></i> Add to Inventory';
        }
    }
}

// Update device card status
function updateDeviceCardStatus(deviceIP, status) {
    const deviceCards = document.querySelectorAll('.device-card');
    deviceCards.forEach(card => {
        const ipElement = card.querySelector('.device-ip');
        if (ipElement && ipElement.textContent === deviceIP) {
            const statusElement = card.querySelector('.device-status');
            if (statusElement && status === 'added') {
                statusElement.textContent = 'Added';
                statusElement.className = 'device-status existing';
            }
            
            // Update the add button
            const addButton = card.querySelector(`#add-btn-${deviceIP.replace(/\./g, '-')}`);
            if (addButton) {
                addButton.disabled = true;
                addButton.innerHTML = '<i class="fas fa-check"></i> Added';
                addButton.classList.remove('btn-primary');
                addButton.classList.add('btn-secondary');
            }
        }
    });
}

// View scan results from history
async function viewScanResults(scanId) {
    console.log('View scan results for:', scanId);
    
    // Load results for this specific scan
    await loadScanResults(scanId);
    
    // Switch to results tab
    switchTab('results');
}

// Tab switching function
function switchTab(tabName) {
    // Update tab buttons
    document.querySelectorAll('.tab').forEach(tab => {
        tab.classList.remove('active');
    });
    
    // Find and activate the clicked tab
    const activeTab = document.querySelector(`.tab[onclick*="${tabName}"]`);
    if (activeTab) {
        activeTab.classList.add('active');
    }

    // Update tab content
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });
    
    const activeContent = document.getElementById(tabName + 'Tab');
    if (activeContent) {
        activeContent.classList.add('active');
    }
    
    // Load data for specific tabs
    if (tabName === 'results') {
        // Display current results
        displayScanResults();
    } else if (tabName === 'history') {
        loadScanHistory();
    }
}

// Protocol selection toggle
function toggleProtocol(card) {
    card.classList.toggle('selected');
    const checkbox = card.querySelector('input[type="checkbox"]');
    checkbox.checked = !checkbox.checked;
}

// Reset form
function resetForm() {
    const form = document.getElementById('scanForm');
    if (form) {
        form.reset();
    }
    
    // Reset protocol selections
    document.querySelectorAll('.protocol-card').forEach(card => {
        card.classList.remove('selected');
        const checkbox = card.querySelector('input[type="checkbox"]');
        if (checkbox) {
            checkbox.checked = false;
        }
    });
    
    // Set default protocols
    const defaultProtocols = ['modbus', 'dnp3'];
    defaultProtocols.forEach(protocol => {
        const checkbox = document.querySelector(`input[value="${protocol}"]`);
        if (checkbox) {
            checkbox.checked = true;
            checkbox.closest('.protocol-card').classList.add('selected');
        }
    });
}

// Utility functions
function getStatusClass(status) {
    const statusMap = {
        'completed': 'completed',
        'running': 'running',
        'failed': 'failed',
        'cancelled': 'failed',
        'pending': 'running'
    };
    return statusMap[status] || 'unknown';
}

function getStatusIcon(status) {
    const iconMap = {
        'completed': 'check-circle',
        'running': 'spinner fa-spin',
        'failed': 'times-circle',
        'cancelled': 'times-circle',
        'pending': 'clock'
    };
    return iconMap[status] || 'question-circle';
}

function formatDuration(seconds) {
    if (!seconds) return '0s';
    
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    
    if (mins > 0) {
        return `${mins}m ${secs}s`;
    }
    return `${secs}s`;
}

function capitalizeFirst(str) {
    if (!str) return '';
    return str.charAt(0).toUpperCase() + str.slice(1);
}

// Show notification
function showNotification(message, type = 'info') {
    // Remove any existing notifications
    const existingNotification = document.querySelector('.notification');
    if (existingNotification) {
        existingNotification.remove();
    }
    
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    
    let icon = '';
    switch (type) {
        case 'success':
            icon = '<i class="fas fa-check-circle"></i>';
            break;
        case 'error':
            icon = '<i class="fas fa-exclamation-circle"></i>';
            break;
        case 'warning':
            icon = '<i class="fas fa-exclamation-triangle"></i>';
            break;
        case 'info':
        default:
            icon = '<i class="fas fa-info-circle"></i>';
            break;
    }
    
    notification.innerHTML = `${icon} ${message}`;
    
    // Add styles
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 16px 24px;
        border-radius: 8px;
        box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
        z-index: 9999;
        animation: slideIn 0.3s ease-out;
        display: flex;
        align-items: center;
        gap: 12px;
        max-width: 400px;
        font-size: 14px;
        font-weight: 500;
    `;
    
    // Set colors based on type
    const colors = {
        success: { bg: '#10B981', color: 'white' },
        error: { bg: '#EF4444', color: 'white' },
        warning: { bg: '#F59E0B', color: 'white' },
        info: { bg: '#3B82F6', color: 'white' }
    };
    
    const colorConfig = colors[type] || colors.info;
    notification.style.backgroundColor = colorConfig.bg;
    notification.style.color = colorConfig.color;
    
    document.body.appendChild(notification);
    
    // Remove after 5 seconds
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease-out';
        setTimeout(() => notification.remove(), 300);
    }, 5000);
}

// Add CSS animations if not already present
if (!document.querySelector('#notification-styles')) {
    const style = document.createElement('style');
    style.id = 'notification-styles';
    style.textContent = `
        @keyframes slideIn {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        @keyframes slideOut {
            from { transform: translateX(0); opacity: 1; }
            to { transform: translateX(100%); opacity: 0; }
        }
    `;
    document.head.appendChild(style);
}

// WebSocket handlers for real-time updates
function handleScanProgress(data) {
    if (currentScan && data.scan_id === currentScan.scan_id) {
        displayProgress({
            progress: data.progress,
            total_hosts: data.total_hosts,
            scanned_hosts: data.scanned_hosts,
            discovered_hosts: data.discovered_hosts,
            elapsed_time: data.elapsed_time,
            errors: []
        });
    }
}

function handleDeviceFound(data) {
    if (currentScan && data.scan_id === currentScan.scan_id) {
        // Add device to our local collection
        const device = {
            ip_address: data.ip_address,
            device_type: data.device_type,
            protocol: data.protocol,
            vendor: data.vendor,
            is_new: true,
            open_ports: [],
            response_time: 'Real-time'
        };
        
        allDiscoveredDevices.set(data.ip_address, device);
        
        // Show notification
        showNotification(`Device found: ${data.ip_address}`, 'info');
    }
}

function handleScanComplete(data) {
    if (currentScan && data.scan_id === currentScan.scan_id) {
        // Reload results to get complete data
        loadScanResults(data.scan_id);
    }
}

// Initialize WebSocket connection
function initializeWebSocket() {
    if (typeof wsClient !== 'undefined' && wsClient) {
        wsClient.on('scan_progress', handleScanProgress);
        wsClient.on('device_found', handleDeviceFound);
        wsClient.on('scan_complete', handleScanComplete);
    }
}