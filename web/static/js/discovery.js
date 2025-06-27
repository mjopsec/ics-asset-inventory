// web/static/js/discovery.js
// Discovery Page JavaScript - Fixed Version WITHOUT Protocol Requirements
let currentScan = null;
let progressInterval = null;
let scanResults = [];
let allDiscoveredDevices = new Map();
let wsClient = null;

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
    console.log('Discovery page initialized');
    setupEventListeners();
    loadScanHistory();
    
    // Clear old scan results on page load
    scanResults = [];
    allDiscoveredDevices.clear();
    currentScan = null;
    
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

// Initialize WebSocket connection
function initializeWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/events`;
    const token = getAuthToken();
    
    if (!token) {
        console.error('No authentication token found');
        return;
    }
    
    try {
        wsClient = new WebSocket(`${wsUrl}?token=${token}`);
        
        wsClient.onopen = () => {
            console.log('WebSocket connected for discovery');
        };
        
        wsClient.onmessage = (event) => {
            try {
                const message = JSON.parse(event.data);
                handleWebSocketMessage(message);
            } catch (error) {
                console.error('Error parsing WebSocket message:', error);
            }
        };
        
        wsClient.onerror = (error) => {
            console.error('WebSocket error:', error);
        };
        
        wsClient.onclose = () => {
            console.log('WebSocket disconnected, attempting reconnect...');
            setTimeout(initializeWebSocket, 5000);
        };
        
    } catch (error) {
        console.error('Failed to create WebSocket connection:', error);
    }
}

// Handle WebSocket messages
function handleWebSocketMessage(message) {
    const { type, data, timestamp } = message;
    
    console.log('WebSocket message received:', type, data);
    
    switch (type) {
        case 'scan_progress':
            handleScanProgress(data);
            break;
            
        case 'device_found':
            handleDeviceFound(data);
            break;
            
        case 'scan_complete':
            handleScanComplete(data);
            break;
            
        case 'scan_complete_with_results':
            handleScanCompleteWithResults(data);
            break;
            
        case 'scan_error':
            handleScanError(data);
            break;
            
        case 'asset_status_update':
            handleAssetStatusUpdate(data);
            break;
    }
}

// Handle scan form submission - FIXED VERSION WITHOUT PROTOCOL VALIDATION
async function handleScanSubmit(e) {
    e.preventDefault();

    console.log('Starting new scan');

    // Stop any existing scan first
    if (currentScan) {
        console.log('Stopping existing scan before starting new one');
        try {
            await stopScan(true);
        } catch (error) {
            console.error('Error stopping existing scan:', error);
        }
    }

    // Clear previous scan results
    scanResults = [];
    allDiscoveredDevices.clear();
    clearDisplayedResults();
    currentScan = null;
    
    // Clear any existing progress intervals
    if (progressInterval) {
        clearInterval(progressInterval);
        progressInterval = null;
    }
    
    const formData = new FormData(e.target);
    
    // Get scan type
    const scanType = formData.get('scanType');
    if (!scanType) {
        showNotification('Please select a scan type', 'error');
        return;
    }

    // Get IP range value
    const ipRangeInput = formData.get('ipRange') || document.getElementById('ipRange').value;
    
    // Validate IP range format
    if (!ipRangeInput || ipRangeInput.trim() === '') {
        showNotification('Please enter an IP range', 'error');
        return;
    }

    if (!isValidIPRange(ipRangeInput)) {
        showNotification('Please enter valid IP range(s). Examples: 192.168.1.0/24, 192.168.1.100, 192.168.1.1-192.168.1.10, or comma-separated', 'error');
        return;
    }

    // Build scan configuration based on scan type
    const scanConfig = {
        ip_range: ipRangeInput.trim(),
        scan_type: scanType,
        timeout: parseInt(formData.get('timeout') || '30'),
        max_concurrent: 20 // Reduced for better stability
    };

    // REMOVED: protocols array initialization and all protocol handling
    // The backend will handle port ranges based on scan type

    // Handle custom ports for custom scan type
    if (scanType === 'custom') {
        const customPorts = formData.get('customPorts') || document.getElementById('customPorts').value;
        if (!customPorts) {
            showNotification('Please enter custom ports', 'error');
            return;
        }
        scanConfig.port_ranges = parseCustomPorts(customPorts);
        if (scanConfig.port_ranges.length === 0) {
            showNotification('Invalid custom port format', 'error');
            return;
        }
    }

    // Log scan configuration for debugging
    console.log('Scan configuration:', scanConfig);

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
        
        console.log('Scan started:', result);
        
        showNotification('Scan started successfully', 'success');
        startProgressMonitoring(result.scan_id);
        
        // Show progress section
        document.getElementById('scanProgress').classList.add('active');
        
    } catch (error) {
        console.error('Error starting scan:', error);
        showNotification(error.message, 'error');
        currentScan = null;
    }
}

// Parse custom ports input
function parseCustomPorts(customPorts) {
    const portRanges = [];
    const parts = customPorts.split(',');
    
    for (const part of parts) {
        const trimmed = part.trim();
        if (!trimmed) continue;
        
        if (trimmed.includes('-')) {
            // Range format: 1000-2000
            const [start, end] = trimmed.split('-').map(p => parseInt(p.trim()));
            if (!isNaN(start) && !isNaN(end) && start <= end && start > 0 && end <= 65535) {
                portRanges.push({ start, end });
            }
        } else {
            // Single port
            const port = parseInt(trimmed);
            if (!isNaN(port) && port > 0 && port <= 65535) {
                portRanges.push({ start: port, end: port });
            }
        }
    }
    
    return portRanges;
}

// Clear displayed results
function clearDisplayedResults() {
    const deviceGrid = document.getElementById('discoveredDevices');
    if (deviceGrid) {
        deviceGrid.innerHTML = '';
    }
}

// Display scan results
function displayScanResults() {
    const deviceGrid = document.getElementById('discoveredDevices');
    if (!deviceGrid) {
        console.error('Device grid element not found');
        return;
    }

    deviceGrid.innerHTML = '';

    console.log('Displaying scan results:', scanResults.length);

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

    // Sort devices by IP address for consistent display
    const sortedResults = [...scanResults].sort((a, b) => {
        const ipA = (a.ip_address || '').split('.').map(num => parseInt(num) || 0);
        const ipB = (b.ip_address || '').split('.').map(num => parseInt(num) || 0);
        for (let i = 0; i < 4; i++) {
            if (ipA[i] !== ipB[i]) return ipA[i] - ipB[i];
        }
        return 0;
    });

    // Create device cards
    sortedResults.forEach((device, index) => {
        const deviceCard = createDeviceCard(device);
        deviceGrid.appendChild(deviceCard);
    });

    console.log('Devices displayed successfully');
}

// Create device card element
function createDeviceCard(device) {
    const card = document.createElement('div');
    card.className = 'device-card';
    card.setAttribute('data-ip', device.ip_address);
    
    const statusClass = device.in_inventory ? 'existing' : 'new';
    const statusText = device.in_inventory ? 'In Inventory' : 'New';
    const deviceType = device.device_type || 'Unknown Device';
    const vendor = device.vendor || 'Unknown';
    const protocol = device.protocol || 'Unknown';
    const responseTime = device.response_time || 'N/A';
    
    // Auto-classification indicator
    const autoClassified = device.fingerprint?.auto_classified || false;
    const classificationConfidence = device.fingerprint?.classification_confidence || 0;
    
    let portDisplay = 'N/A';
    if (device.open_ports && Array.isArray(device.open_ports) && device.open_ports.length > 0) {
        const ports = device.open_ports.map(p => {
            if (typeof p === 'object' && p.port) {
                return p.port;
            } else if (typeof p === 'number') {
                return p;
            }
            return null;
        }).filter(p => p !== null);
        
        if (ports.length > 0) {
            portDisplay = ports.join(', ');
        }
    }
    
    // Show inventory status indicator
    const inventoryIndicator = device.in_inventory ? 
        '<span class="inventory-indicator"><i class="fas fa-check-circle"></i> Already in inventory</span>' : '';
    
    card.innerHTML = `
        <div class="device-header">
            <div class="device-info">
                <div class="device-name">
                    ${device.hostname || deviceType}
                    ${autoClassified ? '<span class="auto-classified"><i class="fas fa-magic"></i> Auto-classified</span>' : ''}
                </div>
                <div class="device-ip">${device.ip_address}</div>
                ${inventoryIndicator}
            </div>
            <div class="device-status ${statusClass}">${statusText}</div>
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
                <div class="device-detail-label">Response</div>
                <div class="device-detail-value">${responseTime}</div>
            </div>
        </div>
        ${classificationConfidence > 0 ? `
        <div class="device-classification">
            <div class="classification-badge">
                <i class="fas fa-brain"></i>
                <span>Classification Confidence: ${classificationConfidence}%</span>
            </div>
        </div>
        ` : ''}
        <div class="device-actions">
            <button class="btn btn-secondary" onclick="viewDeviceDetails('${device.ip_address}')">
                <i class="fas fa-info-circle"></i> Details
            </button>
            ${device.in_inventory ? 
                `<button class="btn btn-secondary" disabled>
                    <i class="fas fa-check"></i> Already Added
                </button>` :
                `<button class="btn btn-primary" onclick="addDeviceToInventory('${device.ip_address}')" id="add-btn-${device.ip_address.replace(/\./g, '-')}">
                    <i class="fas fa-plus"></i> Add to Inventory
                </button>`
            }
        </div>
    `;
    
    return card;
}

// WebSocket handlers for real-time updates
function handleScanProgress(data) {
    if (currentScan && data.scan_id === currentScan.scan_id) {
        displayProgress({
            progress: data.progress,
            total_hosts: data.total_hosts,
            scanned_hosts: data.scanned_hosts,
            discovered_hosts: data.discovered_hosts,
            scanned_ports: data.scanned_ports,
            total_ports: data.total_ports,
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
    console.log('Scan complete (legacy):', data);
    if (currentScan && data.scan_id === currentScan.scan_id) {
        // Wait a bit for results to be fully saved
        setTimeout(() => {
            loadScanResults(data.scan_id);
        }, 3000);
    }
}

function handleScanCompleteWithResults(data) {
    console.log('Scan completed with results:', data);
    
    // Only process if this is our current scan
    if (!currentScan || data.scan_id !== currentScan.scan_id) {
        console.log('Ignoring scan complete for different scan');
        return;
    }
    
    // Clear previous results for new scan
    scanResults = [];
    allDiscoveredDevices.clear();
    
    if (data.devices && Array.isArray(data.devices)) {
        data.devices.forEach(device => {
            // Add metadata
            device.scan_timestamp = data.timestamp;
            device.scan_id = data.scan_id;
            
            // Ensure all required fields are present
            device.ip_address = device.ip_address || 'Unknown';
            device.device_type = device.device_type || 'Unknown Device';
            device.vendor = device.vendor || 'Unknown';
            device.protocol = device.protocol || 'Unknown';
            device.open_ports = device.open_ports || [];
            
            // Store in our Map
            allDiscoveredDevices.set(device.ip_address, device);
            
            // Add to current scan results
            scanResults.push(device);
        });
        
        console.log('Processed scan results:', scanResults.length);
    }
    
    // Update UI immediately
    displayScanResults();
    
    // Show notification
    showNotification(`Scan completed! Found ${data.devices_found} devices`, 'success');
    
    // Auto-switch to results tab after a short delay
    setTimeout(() => {
        switchTab('results');
    }, 500);
    
    // Clear progress monitoring
    if (progressInterval) {
        clearInterval(progressInterval);
        progressInterval = null;
    }
    
    // Hide progress section after delay
    setTimeout(() => {
        document.getElementById('scanProgress').classList.remove('active');
    }, 3000);
    
    // Reload scan history
    loadScanHistory();
    
    // Clear current scan
    currentScan = null;
}

function handleScanError(data) {
    if (currentScan && data.scan_id === currentScan.scan_id) {
        showNotification(`Scan error: ${data.error}`, 'error');
        
        // Clear progress monitoring
        if (progressInterval) {
            clearInterval(progressInterval);
            progressInterval = null;
        }
        
        // Hide progress section
        document.getElementById('scanProgress').classList.remove('active');
        
        // Clear current scan
        currentScan = null;
    }
}

function handleAssetStatusUpdate(data) {
    // Update asset status in real-time if displayed
    console.log('Asset status update:', data);
    
    // Update device card if visible
    updateDeviceCardStatus(data.ip_address, data.status);
}

// Start monitoring scan progress
function startProgressMonitoring(scanId) {
    // Clear any existing interval
    if (progressInterval) {
        clearInterval(progressInterval);
    }

    // Update progress immediately
    updateScanProgress(scanId);

    // Update every 2 seconds as backup
    progressInterval = setInterval(() => {
        if (!currentScan || currentScan.scan_id !== scanId) {
            clearInterval(progressInterval);
            progressInterval = null;
            return;
        }
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

        // Check if scan is complete (backup check)
        if (progress.status === 'completed' || 
            progress.status === 'failed' || 
            progress.status === 'cancelled') {
            
            clearInterval(progressInterval);
            progressInterval = null;
            
            if (progress.status === 'completed') {
                // Wait and load results if not received via WebSocket
                setTimeout(async () => {
                    if (scanResults.length === 0) {
                        await loadScanResults(scanId);
                        displayScanResults();
                        switchTab('results');
                    }
                }, 3000);
            }
            
            // Clear current scan
            currentScan = null;
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
    const portsScanned = document.getElementById('portsScanned');
    const errorsCount = document.getElementById('errorsCount');
    
    if (devicesFound) devicesFound.textContent = progress.discovered_hosts || 0;
    if (ipsScanned) ipsScanned.textContent = progress.scanned_hosts || 0;
    if (portsScanned) portsScanned.textContent = progress.scanned_ports || 0;
    if (errorsCount) errorsCount.textContent = progress.errors ? progress.errors.length : 0;
}

// Load scan results
async function loadScanResults(scanId) {
    try {
        const token = getAuthToken();
        console.log('Loading scan results for:', scanId);
        
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
        
        console.log('Loaded devices from API:', devices.length);
        
        // Clear current scan results
        scanResults = [];
        allDiscoveredDevices.clear();
        
        // Process each device
        devices.forEach(device => {
            // Add metadata
            device.scan_timestamp = new Date().toISOString();
            device.scan_id = scanId;
            
            // Ensure all fields are present
            device.ip_address = device.ip_address || 'Unknown';
            device.device_type = device.device_type || 'Unknown Device';
            device.vendor = device.vendor || 'Unknown';
            device.protocol = device.protocol || 'Unknown';
            device.open_ports = device.open_ports || [];
            
            // Store in our Map to persist across scans
            allDiscoveredDevices.set(device.ip_address, device);
            
            // Add to current scan results
            scanResults.push(device);
        });
        
        console.log('Processed scan results:', scanResults.length);
        
        // Display the results
        displayScanResults();

    } catch (error) {
        console.error('Error loading scan results:', error);
        showNotification('Failed to load scan results', 'error');
    }
}

// View scan results from history
async function viewScanResults(scanId) {
    console.log('View scan results for:', scanId);
    
    // Clear existing results first
    scanResults = [];
    allDiscoveredDevices.clear();
    clearDisplayedResults();
    
    // Ensure no active scan is considered
    currentScan = null;
    
    // Load results for this specific scan
    await loadScanResults(scanId);
    
    // Switch to results tab
    switchTab('results');
}

// Stop scan
async function stopScan(silent = false) {
    if (!currentScan) {
        if (!silent) {
            showNotification('No active scan to stop', 'warning');
        }
        return;
    }

    try {
        const token = getAuthToken();
        const scanId = currentScan.scan_id;
        
        const response = await fetch(`/api/discovery/scan/${scanId}/stop`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (response.ok) {
            if (!silent) {
                showNotification('Scan stopped', 'info');
            }
            
            // Clear intervals
            if (progressInterval) {
                clearInterval(progressInterval);
                progressInterval = null;
            }
            
            // Hide progress
            document.getElementById('scanProgress').classList.remove('active');
            
            // Clear current scan
            currentScan = null;
            
            // Reload scan history to show updated status
            loadScanHistory();
        } else {
            throw new Error('Failed to stop scan');
        }
    } catch (error) {
        console.error('Error stopping scan:', error);
        if (!silent) {
            showNotification('Failed to stop scan', 'error');
        }
    }
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
        // Always display current scan results when switching to results tab
        displayScanResults();
    } else if (tabName === 'history') {
        loadScanHistory();
    }
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
            currentScan = {
                scan_id: activeScan.scan_id,
                status: activeScan.status,
                start_time: activeScan.start_time
            };
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
    
    // Check if modal functions exist and use them
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
Open Ports: ${formatPortsForDisplay(device.open_ports)}
Response Time: ${device.response_time || 'N/A'}
In Inventory: ${device.in_inventory ? 'Yes' : 'No'}
        `;
        alert(deviceInfo);
    }
}

// Helper function to format ports for display
function formatPortsForDisplay(ports) {
    if (!ports || !Array.isArray(ports) || ports.length === 0) {
        return 'None';
    }
    
    const portNumbers = ports.map(p => {
        if (typeof p === 'object' && p.port) {
            return p.port;
        } else if (typeof p === 'number') {
            return p;
        }
        return null;
    }).filter(p => p !== null);
    
    return portNumbers.length > 0 ? portNumbers.join(', ') : 'None';
}

// Add device to inventory
async function addDeviceToInventory(deviceIP) {
    // Find the device in our current results
    const device = scanResults.find(d => d.ip_address === deviceIP);
    if (!device) {
        showNotification('Device not found in scan results', 'error');
        return;
    }
    
    // Check if already in inventory
    if (device.in_inventory) {
        showNotification('Device is already in inventory', 'warning');
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
        
        // Use the scan ID from the device
        const scanId = device.scan_id;
        
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
        
        // Update the device in our local data
        device.in_inventory = true;
        device.asset_id = result.asset.id;
        
        // Update the device card
        updateDeviceCardStatus(deviceIP, 'added');
        
        // Update the device in our local storage
        allDiscoveredDevices.set(deviceIP, device);

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
            if (statusElement) {
                if (status === 'added') {
                    statusElement.textContent = 'In Inventory';
                    statusElement.className = 'device-status existing';
                } else if (status === 'online') {
                    // Update online indicator if exists
                    const onlineIndicator = card.querySelector('.online-indicator');
                    if (onlineIndicator) {
                        onlineIndicator.classList.add('online');
                    }
                } else if (status === 'offline') {
                    // Update offline indicator if exists
                    const onlineIndicator = card.querySelector('.online-indicator');
                    if (onlineIndicator) {
                        onlineIndicator.classList.remove('online');
                    }
                }
            }
            
            // Replace the add button with "Already Added" for added status
            if (status === 'added') {
                const addButton = card.querySelector(`#add-btn-${deviceIP.replace(/\./g, '-')}`);
                if (addButton) {
                    const newButton = document.createElement('button');
                    newButton.className = 'btn btn-secondary';
                    newButton.disabled = true;
                    newButton.innerHTML = '<i class="fas fa-check"></i> Already Added';
                    addButton.parentNode.replaceChild(newButton, addButton);
                }
                
                // Add inventory indicator
                const deviceInfo = card.querySelector('.device-info');
                if (deviceInfo && !deviceInfo.querySelector('.inventory-indicator')) {
                    const indicator = document.createElement('span');
                    indicator.className = 'inventory-indicator';
                    indicator.innerHTML = '<i class="fas fa-check-circle"></i> Already in inventory';
                    deviceInfo.appendChild(indicator);
                }
            }
        }
    });
}

// Add all devices to inventory function
async function addAllDevicesToInventory() {
    if (scanResults.length === 0) {
        showNotification('No devices to add', 'warning');
        return;
    }

    // Filter out devices already in inventory
    const devicesToAdd = scanResults.filter(d => !d.in_inventory);
    
    if (devicesToAdd.length === 0) {
        showNotification('All devices are already in inventory', 'info');
        return;
    }

    try {
        const token = getAuthToken();
        
        // Get the scan ID from first device
        const scanId = scanResults[0].scan_id;
        
        if (!scanId) {
            throw new Error('No scan context available');
        }

        const response = await fetch(`/api/discovery/scan/${scanId}/add-all-devices`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to add devices');
        }

        const result = await response.json();
        showNotification(`Added ${result.added} new devices, updated ${result.updated} existing devices`, 'success');
        
        // Reload results to update UI
        await loadScanResults(scanId);
        
        // Update UI to reflect changes
        displayScanResults();

    } catch (error) {
        console.error('Error adding all devices:', error);
        showNotification(error.message, 'error');
    }
}

// Reset form
function resetForm() {
    const form = document.getElementById('scanForm');
    if (form) {
        form.reset();
    }
    
    // Reset scan type selection
    document.querySelectorAll('.scan-type-card').forEach(card => {
        card.classList.remove('selected');
    });
    
    // Select industrial scan by default
    const industrialCard = document.querySelector('.scan-type-card input[value="industrial"]')?.closest('.scan-type-card');
    if (industrialCard) {
        industrialCard.classList.add('selected');
        industrialCard.querySelector('input[type="radio"]').checked = true;
    }
    
    // Hide custom ports section
    const customPortsSection = document.getElementById('customPortsSection');
    if (customPortsSection) {
        customPortsSection.classList.remove('active');
    }
}

// Validate IP range format - ENHANCED for multiple formats and better validation
function isValidIPRange(ipRange) {
    // Split by comma for multiple entries
    const entries = ipRange.split(',').map(e => e.trim()).filter(e => e);
    
    if (entries.length === 0) {
        return false;
    }
    
    // Check each entry
    for (let entry of entries) {
        // Check for CIDR notation (e.g., 192.168.1.0/24)
        const cidrRegex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
        
        // Check for single IP (e.g., 192.168.1.100)
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
        
        // Check for IP range (e.g., 192.168.1.1-192.168.1.254)
        const rangeRegex = /^(\d{1,3}\.){3}\d{1,3}\s*-\s*(\d{1,3}\.){3}\d{1,3}$/;
        
        // Check if matches any valid format
        if (!cidrRegex.test(entry) && !ipRegex.test(entry) && !rangeRegex.test(entry)) {
            console.log('Invalid IP format:', entry);
            return false;
        }
        
        // For single IP, validate octets
        if (ipRegex.test(entry)) {
            const parts = entry.split('.');
            for (let part of parts) {
                const num = parseInt(part);
                if (num < 0 || num > 255) {
                    console.log('Invalid IP octet:', part);
                    return false;
                }
            }
        }
    }
    
    return true;
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

// Export functions for use in HTML
window.addAllDevicesToInventory = addAllDevicesToInventory;
window.switchTab = switchTab;
window.resetForm = resetForm;
window.viewDeviceDetails = viewDeviceDetails;
window.addDeviceToInventory = addDeviceToInventory;
window.viewScanResults = viewScanResults;
window.stopScan = stopScan;