// Add this to discovery.js - Enhanced device detail modal functionality

// Add modal HTML to the page
function addDeviceDetailModal() {
    const modalHTML = `
    <!-- Device Detail Modal -->
    <div class="modal-backdrop" id="deviceDetailModal">
        <div class="modal">
            <div class="modal-header">
                <h2 class="modal-title">Device Details</h2>
                <button class="modal-close" onclick="closeDeviceDetailModal()">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="modal-body">
                <!-- Tab Navigation -->
                <div class="modal-tabs">
                    <button type="button" class="modal-tab active" onclick="switchDetailTab('overview')">
                        <i class="fas fa-info-circle"></i>
                        <span>Overview</span>
                    </button>
                    <button type="button" class="modal-tab" onclick="switchDetailTab('network')">
                        <i class="fas fa-network-wired"></i>
                        <span>Network Info</span>
                    </button>
                    <button type="button" class="modal-tab" onclick="switchDetailTab('ports')">
                        <i class="fas fa-ethernet"></i>
                        <span>Open Ports</span>
                    </button>
                    <button type="button" class="modal-tab" onclick="switchDetailTab('fingerprint')">
                        <i class="fas fa-fingerprint"></i>
                        <span>Fingerprint</span>
                    </button>
                </div>

                <!-- Tab Contents -->
                <div class="modal-tab-content">
                    <!-- Overview Tab -->
                    <div id="overviewTab" class="tab-panel active">
                        <div class="device-detail-grid">
                            <div class="detail-section">
                                <h3 class="section-title">Basic Information</h3>
                                <div class="detail-row">
                                    <span class="detail-label">Device Type:</span>
                                    <span class="detail-value" id="detailDeviceType">-</span>
                                </div>
                                <div class="detail-row">
                                    <span class="detail-label">Hostname:</span>
                                    <span class="detail-value" id="detailHostname">-</span>
                                </div>
                                <div class="detail-row">
                                    <span class="detail-label">Vendor:</span>
                                    <span class="detail-value" id="detailVendor">-</span>
                                </div>
                                <div class="detail-row">
                                    <span class="detail-label">Model:</span>
                                    <span class="detail-value" id="detailModel">-</span>
                                </div>
                                <div class="detail-row">
                                    <span class="detail-label">Status:</span>
                                    <span class="detail-value">
                                        <span class="device-status new" id="detailStatus">New</span>
                                    </span>
                                </div>
                            </div>
                            <div class="detail-section">
                                <h3 class="section-title">Protocol Information</h3>
                                <div class="detail-row">
                                    <span class="detail-label">Protocol:</span>
                                    <span class="detail-value" id="detailProtocol">-</span>
                                </div>
                                <div class="detail-row">
                                    <span class="detail-label">Response Time:</span>
                                    <span class="detail-value" id="detailResponseTime">-</span>
                                </div>
                                <div class="detail-row">
                                    <span class="detail-label">Discovery Time:</span>
                                    <span class="detail-value" id="detailDiscoveryTime">-</span>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Network Tab -->
                    <div id="networkTab" class="tab-panel">
                        <div class="device-detail-grid">
                            <div class="detail-section full-width">
                                <h3 class="section-title">Network Configuration</h3>
                                <div class="detail-row">
                                    <span class="detail-label">IP Address:</span>
                                    <span class="detail-value monospace" id="detailIPAddress">-</span>
                                </div>
                                <div class="detail-row">
                                    <span class="detail-label">MAC Address:</span>
                                    <span class="detail-value monospace" id="detailMACAddress">-</span>
                                </div>
                                <div class="detail-row">
                                    <span class="detail-label">Subnet:</span>
                                    <span class="detail-value monospace" id="detailSubnet">-</span>
                                </div>
                                <div class="detail-row">
                                    <span class="detail-label">Gateway:</span>
                                    <span class="detail-value monospace" id="detailGateway">-</span>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Ports Tab -->
                    <div id="portsTab" class="tab-panel">
                        <div class="ports-table">
                            <table class="detail-table">
                                <thead>
                                    <tr>
                                        <th>Port</th>
                                        <th>Protocol</th>
                                        <th>Service</th>
                                        <th>Banner</th>
                                    </tr>
                                </thead>
                                <tbody id="detailPortsTable">
                                    <!-- Ports will be populated here -->
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <!-- Fingerprint Tab -->
                    <div id="fingerprintTab" class="tab-panel">
                        <div class="fingerprint-content">
                            <pre id="detailFingerprint" class="code-block"></pre>
                        </div>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeDeviceDetailModal()">Close</button>
                <button class="btn btn-primary" onclick="addDeviceFromModal()">
                    <i class="fas fa-plus"></i> Add to Inventory
                </button>
            </div>
        </div>
    </div>
    `;

    // Add modal to body
    document.body.insertAdjacentHTML('beforeend', modalHTML);

    // Add required styles
    addModalStyles();
}

// Add modal-specific styles
function addModalStyles() {
    const styles = `
    <style>
        /* Modal Styles from assets.html */
        .modal-backdrop {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: rgba(0, 0, 0, 0.5);
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 1000;
            padding: 20px;
            overflow-y: auto;
        }

        .modal-backdrop.active {
            display: flex;
        }

        .modal {
            background-color: var(--bg-secondary);
            border-radius: var(--radius-lg);
            width: 100%;
            max-width: 800px;
            max-height: 90vh;
            display: flex;
            flex-direction: column;
            box-shadow: var(--shadow-lg);
            margin: auto;
        }

        .modal-header {
            padding: 20px 24px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-shrink: 0;
        }

        .modal-title {
            font-size: 20px;
            font-weight: 600;
            color: var(--text-primary);
        }

        .modal-close {
            width: 32px;
            height: 32px;
            border: none;
            background: none;
            color: var(--text-tertiary);
            cursor: pointer;
            border-radius: var(--radius-md);
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.2s ease;
        }

        .modal-close:hover {
            background-color: var(--bg-tertiary);
            color: var(--text-primary);
        }

        .modal-body {
            padding: 24px;
            overflow-y: auto;
            flex: 1;
        }

        .modal-tabs {
            display: flex;
            gap: 8px;
            margin-bottom: 24px;
            border-bottom: 1px solid var(--border-color);
            overflow-x: auto;
            -webkit-overflow-scrolling: touch;
        }

        .modal-tab {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 12px 16px;
            border: none;
            background: none;
            color: var(--text-secondary);
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            white-space: nowrap;
            border-bottom: 2px solid transparent;
            transition: all 0.2s ease;
        }

        .modal-tab:hover {
            color: var(--text-primary);
        }

        .modal-tab.active {
            color: var(--primary-color);
            border-bottom-color: var(--primary-color);
        }

        .modal-tab i {
            font-size: 16px;
        }

        .modal-tab span {
            display: inline;
        }

        .tab-panel {
            display: none;
            animation: fadeIn 0.3s ease;
        }

        .tab-panel.active {
            display: block;
        }

        @keyframes fadeIn {
            from {
                opacity: 0;
                transform: translateY(10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .modal-footer {
            padding: 16px 24px;
            border-top: 1px solid var(--border-color);
            display: flex;
            justify-content: flex-end;
            gap: 12px;
            flex-shrink: 0;
        }

        /* Device Detail Specific Styles */
        .device-detail-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 32px;
        }

        .detail-section {
            display: flex;
            flex-direction: column;
            gap: 16px;
        }

        .detail-section.full-width {
            grid-column: 1 / -1;
        }

        .section-title {
            font-size: 16px;
            font-weight: 600;
            color: var(--text-primary);
            margin-bottom: 8px;
            padding-bottom: 8px;
            border-bottom: 1px solid var(--border-color);
        }

        .detail-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 0;
        }

        .detail-label {
            font-size: 14px;
            color: var(--text-secondary);
            font-weight: 500;
        }

        .detail-value {
            font-size: 14px;
            color: var(--text-primary);
            font-weight: 400;
            text-align: right;
        }

        .detail-value.monospace {
            font-family: 'Courier New', monospace;
            background-color: var(--bg-tertiary);
            padding: 4px 8px;
            border-radius: var(--radius-sm);
        }

        .detail-table {
            width: 100%;
            border-collapse: collapse;
        }

        .detail-table th {
            text-align: left;
            padding: 12px;
            font-weight: 600;
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-tertiary);
            background-color: var(--bg-tertiary);
            border-bottom: 1px solid var(--border-color);
        }

        .detail-table td {
            padding: 12px;
            border-bottom: 1px solid var(--border-color);
            font-size: 14px;
        }

        .detail-table tr:last-child td {
            border-bottom: none;
        }

        .code-block {
            background-color: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-md);
            padding: 16px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
        }

        .ports-table {
            overflow-x: auto;
        }

        .fingerprint-content {
            max-height: 400px;
            overflow-y: auto;
        }

        /* Responsive */
        @media (max-width: 768px) {
            .device-detail-grid {
                grid-template-columns: 1fr;
                gap: 24px;
            }

            .modal-tab span {
                display: none;
            }

            .modal-tab {
                padding: 10px;
            }
        }
    </style>
    `;

    // Add styles to head if not already present
    if (!document.getElementById('device-detail-modal-styles')) {
        const styleElement = document.createElement('div');
        styleElement.id = 'device-detail-modal-styles';
        styleElement.innerHTML = styles;
        document.head.appendChild(styleElement.firstElementChild);
    }
}

// Current device being viewed
let currentDeviceDetail = null;

// View device details function
function viewDeviceDetails(deviceIP) {
    // Find device in scan results
    const device = scanResults.find(d => d.ip_address === deviceIP);
    if (!device) {
        showNotification('Device not found', 'error');
        return;
    }

    currentDeviceDetail = device;

    // Populate modal with device data
    populateDeviceDetailModal(device);

    // Show modal
    document.getElementById('deviceDetailModal').classList.add('active');
}

// Populate device detail modal - FIXED VERSION
function populateDeviceDetailModal(device) {
    // Overview tab
    document.getElementById('detailDeviceType').textContent = device.device_type || 'Unknown';
    document.getElementById('detailHostname').textContent = device.hostname || 'Unknown';
    document.getElementById('detailVendor').textContent = device.vendor || 'Unknown';
    document.getElementById('detailModel').textContent = device.model || 'Unknown';
    document.getElementById('detailProtocol').textContent = device.protocol || 'Unknown';
    document.getElementById('detailResponseTime').textContent = device.response_time || '-';
    document.getElementById('detailDiscoveryTime').textContent = new Date().toLocaleString();

    // Update status
    const statusElement = document.getElementById('detailStatus');
    statusElement.textContent = device.is_new ? 'New' : 'Existing';
    statusElement.className = `device-status ${device.is_new ? 'new' : 'existing'}`;

    // Network tab
    document.getElementById('detailIPAddress').textContent = device.ip_address;
    document.getElementById('detailMACAddress').textContent = device.mac_address || 'Not Available';
    document.getElementById('detailSubnet').textContent = guessSubnet(device.ip_address);
    document.getElementById('detailGateway').textContent = guessGateway(device.ip_address);

    // Ports tab - FIXED to handle port data properly
    const portsTable = document.getElementById('detailPortsTable');
    portsTable.innerHTML = '';
    
    if (device.open_ports && device.open_ports.length > 0) {
        device.open_ports.forEach(portData => {
            const row = document.createElement('tr');
            
            // Handle different port data formats
            let port, protocol, service, banner;
            
            if (typeof portData === 'object') {
                port = portData.port || 'Unknown';
                protocol = portData.protocol || 'TCP';
                service = portData.service || identifyServiceEnhanced(port);
                banner = portData.banner || '-';
            } else if (typeof portData === 'number') {
                port = portData;
                protocol = 'TCP';
                service = identifyServiceEnhanced(port);
                banner = '-';
            } else {
                return; // Skip invalid data
            }
            
            row.innerHTML = `
                <td>${port}</td>
                <td>${protocol}</td>
                <td>${service}</td>
                <td>${banner}</td>
            `;
            portsTable.appendChild(row);
        });
    } else {
        portsTable.innerHTML = `
            <tr>
                <td colspan="4" style="text-align: center; color: var(--text-tertiary);">
                    No open ports detected
                </td>
            </tr>
        `;
    }

    // Fingerprint tab
    const fingerprintData = {
        ...device.fingerprint,
        discovery_info: {
            ip_address: device.ip_address,
            mac_address: device.mac_address,
            hostname: device.hostname,
            device_type: device.device_type,
            vendor: device.vendor,
            model: device.model,
            protocol: device.protocol,
            response_time: device.response_time,
            is_new: device.is_new,
            open_ports: device.open_ports
        }
    };
    
    document.getElementById('detailFingerprint').textContent = JSON.stringify(fingerprintData, null, 2);

    // Reset to first tab
    switchDetailTab('overview');
}

// Switch detail modal tabs
function switchDetailTab(tabName) {
    // Update tab buttons
    document.querySelectorAll('#deviceDetailModal .modal-tab').forEach(tab => {
        tab.classList.remove('active');
    });
    
    // Find and activate the clicked tab
    const tabs = document.querySelectorAll('#deviceDetailModal .modal-tab');
    const tabIndex = ['overview', 'network', 'ports', 'fingerprint'].indexOf(tabName);
    if (tabIndex >= 0 && tabs[tabIndex]) {
        tabs[tabIndex].classList.add('active');
    }

    // Update tab panels
    document.querySelectorAll('#deviceDetailModal .tab-panel').forEach(panel => {
        panel.classList.remove('active');
    });
    document.getElementById(tabName + 'Tab').classList.add('active');
}

// Close device detail modal
function closeDeviceDetailModal() {
    document.getElementById('deviceDetailModal').classList.remove('active');
    currentDeviceDetail = null;
}

// Add device from modal
function addDeviceFromModal() {
    if (!currentDeviceDetail) {
        showNotification('No device selected', 'error');
        return;
    }

    // Close modal first
    closeDeviceDetailModal();

    // Add device to inventory
    addDeviceToInventory(currentDeviceDetail.ip_address);
}

// Helper functions
function guessSubnet(ipAddress) {
    // Simple subnet guessing based on IP class
    const parts = ipAddress.split('.');
    if (parts.length !== 4) return 'Unknown';
    
    const firstOctet = parseInt(parts[0]);
    if (firstOctet >= 1 && firstOctet <= 126) {
        return ipAddress.split('.').slice(0, 3).join('.') + '.0/24';
    } else if (firstOctet >= 128 && firstOctet <= 191) {
        return ipAddress.split('.').slice(0, 3).join('.') + '.0/24';
    } else if (firstOctet >= 192 && firstOctet <= 223) {
        return ipAddress.split('.').slice(0, 3).join('.') + '.0/24';
    }
    return 'Unknown';
}

function guessGateway(ipAddress) {
    // Simple gateway guessing - typically .1 of the subnet
    const parts = ipAddress.split('.');
    if (parts.length !== 4) return 'Unknown';
    
    return parts.slice(0, 3).join('.') + '.1';
}

// Enhanced service identification with more protocols
function identifyServiceEnhanced(port) {
    const services = {
        // Standard services
        20: 'FTP Data',
        21: 'FTP Control',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        3389: 'RDP',
        
        // ICS/SCADA protocols
        102: 'S7 (Siemens)',
        161: 'SNMP',
        162: 'SNMP Trap',
        502: 'Modbus TCP',
        1911: 'Niagara Fox',
        2222: 'EtherNet/IP (Alt)',
        2404: 'IEC-104',
        4840: 'OPC UA',
        5094: 'HART-IP',
        9600: 'OMRON FINS',
        20000: 'DNP3',
        20547: 'DNP3 (Alt)',
        34962: 'Profinet',
        34963: 'Profinet',
        34964: 'Profinet',
        44818: 'EtherNet/IP',
        47808: 'BACnet',
        48898: 'OPC UA Discovery',
        
        // Additional industrial protocols
        1089: 'FF HSE',
        1090: 'FF HSE',
        1091: 'FF HSE',
        18245: 'GE SRTP',
        18246: 'GE SRTP',
        789: 'Red Lion Crimson',
        2455: 'WAGO',
        1962: 'PCWorx',
        41100: 'Schneider',
        1200: 'Codesys',
        2000: 'Cisco SCCP'
    };
    
    return services[port] || `Port ${port}`;
}

// Initialize modal when page loads
document.addEventListener('DOMContentLoaded', function() {
    // Add the modal to the page
    addDeviceDetailModal();
});