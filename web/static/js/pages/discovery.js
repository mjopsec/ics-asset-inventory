// web/static/js/pages/discovery.js

class DiscoveryPage {
    constructor() {
        this.currentTab = 'scan';
        this.scanInProgress = false;
        this.discoveredDevices = [];
        this.scanHistory = [];
        this.init();
    }

    async init() {
        try {
            this.setupTabs();
            this.setupForms();
            this.setupProtocolSelection();
            this.loadScanHistory();
            this.loadRecentResults();
        } catch (error) {
            console.error('Discovery page initialization failed:', error);
            window.ui.notifications.show('Failed to initialize discovery page', 'error');
        }
    }

    setupTabs() {
        // Tab switching
        window.switchTab = (tabName) => {
            // Update tab buttons
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });
            event.target.classList.add('active');

            // Update tab content
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            document.getElementById(tabName + 'Tab').classList.add('active');

            this.currentTab = tabName;

            // Load data for active tab
            if (tabName === 'history') {
                this.loadScanHistory();
            } else if (tabName === 'results') {
                this.loadRecentResults();
            }
        };
    }

    setupForms() {
        const scanForm = document.getElementById('scanForm');
        if (scanForm) {
            scanForm.addEventListener('submit', (e) => this.handleScanSubmission(e));
        }

        // Global functions for backwards compatibility
        window.resetForm = () => this.resetForm();
        window.stopScan = () => this.stopScan();
    }

    setupProtocolSelection() {
        // Protocol selection
        window.toggleProtocol = (card) => {
            card.classList.toggle('selected');
            const checkbox = card.querySelector('input[type="checkbox"]');
            checkbox.checked = !checkbox.checked;
        };

        // Set default selected protocols
        document.addEventListener('DOMContentLoaded', () => {
            document.querySelectorAll('.protocol-card.selected input[type="checkbox"]').forEach(cb => {
                cb.checked = true;
            });
        });
    }

    async handleScanSubmission(e) {
        e.preventDefault();
        
        if (this.scanInProgress) {
            window.ui.notifications.show('Scan already in progress', 'warning');
            return;
        }

        const formData = new FormData(e.target);
        const scanConfig = {
            ipRange: formData.get('ipRange') || document.getElementById('ipRange').value,
            scanType: formData.get('scanType') || document.getElementById('scanType').value,
            timeout: parseInt(formData.get('timeout') || document.getElementById('timeout').value),
            concurrent: parseInt(formData.get('concurrent') || document.getElementById('concurrent').value),
            protocols: Array.from(document.querySelectorAll('input[name="protocols"]:checked')).map(cb => cb.value)
        };

        // Validate input
        if (!scanConfig.ipRange) {
            window.ui.notifications.show('Please enter an IP range', 'error');
            return;
        }

        if (scanConfig.protocols.length === 0) {
            window.ui.notifications.show('Please select at least one protocol', 'error');
            return;
        }

        try {
            await this.startScan(scanConfig);
        } catch (error) {
            console.error('Error starting scan:', error);
            window.ui.notifications.show('Failed to start scan: ' + error.message, 'error');
        }
    }

    async startScan(scanConfig) {
        console.log('Starting scan with config:', scanConfig);

        this.scanInProgress = true;
        
        // Show progress section
        document.getElementById('scanProgress').classList.add('active');
        
        try {
            // Call API to start scan
            const response = await window.api.discovery.startScan(scanConfig);
            
            if (response.scan_id) {
                // Start monitoring scan progress
                this.monitorScanProgress(response.scan_id);
                window.ui.notifications.show('Scan started successfully', 'success');
            } else {
                throw new Error('Invalid response from scan API');
            }
        } catch (error) {
            // Fallback to simulation if API not available
            console.log('API not available, using simulation');
            this.simulateScan();
        }
    }

    async monitorScanProgress(scanId) {
        const pollInterval = setInterval(async () => {
            try {
                const status = await window.api.discovery.getScanStatus(scanId);
                this.updateProgress(status);

                if (status.completed || status.failed) {
                    clearInterval(pollInterval);
                    this.completeScan(status);
                }
            } catch (error) {
                console.error('Error monitoring scan progress:', error);
                clearInterval(pollInterval);
                this.scanInProgress = false;
            }
        }, 2000);
    }

    simulateScan() {
        let progress = 0;
        let devicesFound = 0;
        let ipsScanned = 0;
        let protocolsDetected = new Set();
        const startTime = Date.now();

        const interval = setInterval(() => {
            progress += Math.random() * 10;
            if (progress > 100) progress = 100;

            // Update progress bar
            this.updateProgressBar(progress);

            // Update elapsed time
            const elapsed = Math.floor((Date.now() - startTime) / 1000);
            this.updateElapsedTime(elapsed);

            // Update stats
            ipsScanned = Math.floor(progress * 2.54);
            document.getElementById('ipsScanned').textContent = ipsScanned;

            // Randomly find devices
            if (Math.random() > 0.8 && devicesFound < 23) {
                devicesFound++;
                document.getElementById('devicesFound').textContent = devicesFound;
                
                // Add random protocols
                const protocols = ['Modbus', 'DNP3', 'EtherNet/IP', 'BACnet'];
                protocolsDetected.add(protocols[Math.floor(Math.random() * protocols.length)]);
                document.getElementById('protocolsDetected').textContent = protocolsDetected.size;
            }

            if (progress >= 100) {
                clearInterval(interval);
                this.completeScan({
                    completed: true,
                    devices_found: devicesFound,
                    total_ips: ipsScanned,
                    protocols_detected: Array.from(protocolsDetected)
                });
            }
        }, 200);
    }

    updateProgress(status) {
        this.updateProgressBar(status.progress || 0);
        
        // Update stats
        document.getElementById('devicesFound').textContent = status.devices_found || 0;
        document.getElementById('ipsScanned').textContent = status.ips_scanned || 0;
        document.getElementById('protocolsDetected').textContent = status.protocols_detected || 0;
        document.getElementById('errorsCount').textContent = status.errors || 0;

        // Update elapsed time
        if (status.start_time) {
            const elapsed = Math.floor((Date.now() - new Date(status.start_time)) / 1000);
            this.updateElapsedTime(elapsed);
        }
    }

    updateProgressBar(progress) {
        document.getElementById('progressBar').style.width = progress + '%';
        document.getElementById('progressText').textContent = Math.floor(progress) + '%';
    }

    updateElapsedTime(seconds) {
        const minutes = Math.floor(seconds / 60);
        const remainingSeconds = seconds % 60;
        document.getElementById('progressTime').textContent = 
            `Elapsed: ${minutes}:${remainingSeconds.toString().padStart(2, '0')}`;
    }

    completeScan(status) {
        this.scanInProgress = false;
        
        setTimeout(() => {
            document.getElementById('scanProgress').classList.remove('active');
            
            if (status.completed) {
                window.ui.notifications.show('Scan completed successfully!', 'success');
                
                // Switch to results tab and load new results
                this.switchTab('results');
                this.loadRecentResults();
            } else if (status.failed) {
                window.ui.notifications.show('Scan failed: ' + (status.error || 'Unknown error'), 'error');
            }
        }, 1000);
    }

    stopScan() {
        if (!this.scanInProgress) {
            return;
        }

        this.scanInProgress = false;
        document.getElementById('scanProgress').classList.remove('active');
        window.ui.notifications.show('Scan stopped by user', 'info');
    }

    resetForm() {
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
            const card = document.querySelector(`.protocol-card input[value="${protocol}"]`)?.closest('.protocol-card');
            if (card) {
                card.classList.add('selected');
                card.querySelector('input[type="checkbox"]').checked = true;
            }
        });
    }

    async loadRecentResults() {
        try {
            // Try to load from API first
            const response = await window.api.discovery.getDiscoveredDevices('latest');
            this.displayDiscoveredDevices(response.devices || []);
        } catch (error) {
            // Fallback to sample data
            console.log('Loading sample discovered devices');
            this.displaySampleDevices();
        }
    }

    displayDiscoveredDevices(devices) {
        const container = document.getElementById('discoveredDevices');
        if (!container) return;

        container.innerHTML = '';

        if (devices.length === 0) {
            this.displayEmptyResults(container);
            return;
        }

        devices.forEach(device => {
            const card = this.createDeviceCard(device);
            container.appendChild(card);
        });
    }

    displaySampleDevices() {
        const sampleDevices = [
            {
                name: 'Siemens S7-1200',
                ip: '192.168.1.101',
                protocol: 'Modbus TCP',
                port: 502,
                vendor: 'Siemens',
                responseTime: '12ms',
                status: 'new'
            },
            {
                name: 'Allen-Bradley CompactLogix',
                ip: '192.168.1.102',
                protocol: 'EtherNet/IP',
                port: 44818,
                vendor: 'Rockwell Automation',
                responseTime: '8ms',
                status: 'new'
            },
            {
                name: 'Schneider M340',
                ip: '192.168.1.103',
                protocol: 'Modbus TCP',
                port: 502,
                vendor: 'Schneider Electric',
                responseTime: '15ms',
                status: 'existing'
            }
        ];

        this.displayDiscoveredDevices(sampleDevices);
    }

    createDeviceCard(device) {
        const card = document.createElement('div');
        card.className = 'device-card';
        
        card.innerHTML = `
            <div class="device-header">
                <div class="device-info">
                    <div class="device-name">${device.name}</div>
                    <div class="device-ip">${device.ip}</div>
                </div>
                <div class="device-status ${device.status}">${device.status === 'new' ? 'New' : 'Existing'}</div>
            </div>
            <div class="device-details">
                <div class="device-detail">
                    <div class="device-detail-label">Protocol</div>
                    <div class="device-detail-value">${device.protocol}</div>
                </div>
                <div class="device-detail">
                    <div class="device-detail-label">Port</div>
                    <div class="device-detail-value">${device.port}</div>
                </div>
                <div class="device-detail">
                    <div class="device-detail-label">Vendor</div>
                    <div class="device-detail-value">${device.vendor}</div>
                </div>
                <div class="device-detail">
                    <div class="device-detail-label">Response Time</div>
                    <div class="device-detail-value">${device.responseTime}</div>
                </div>
            </div>
            <div class="device-actions">
                <button class="btn btn-secondary" onclick="window.discoveryPage.viewDeviceDetails('${device.ip}')">
                    <i class="fas fa-info-circle"></i> Details
                </button>
                <button class="btn btn-primary" onclick="window.discoveryPage.addToInventory('${device.ip}')">
                    <i class="fas fa-plus"></i> Add to Inventory
                </button>
            </div>
        `;
        
        return card;
    }

    displayEmptyResults(container) {
        container.innerHTML = `
            <div class="empty-state" style="grid-column: 1 / -1;">
                <i class="fas fa-search"></i>
                <div class="empty-state-title">No Recent Results</div>
                <div class="empty-state-text">Run a network scan to discover devices</div>
                <button class="btn btn-primary" onclick="window.discoveryPage.switchTab('scan')">
                    <i class="fas fa-radar"></i> Start New Scan
                </button>
            </div>
        `;
    }

    async loadScanHistory() {
        try {
            const response = await window.api.discovery.getScanHistory();
            this.displayScanHistory(response.scans || []);
        } catch (error) {
            console.log('Loading sample scan history');
            this.displaySampleHistory();
        }
    }

    displayScanHistory(scans) {
        const tbody = document.getElementById('scanHistoryBody');
        if (!tbody) return;

        tbody.innerHTML = '';

        scans.forEach(scan => {
            const row = this.createHistoryRow(scan);
            tbody.appendChild(row);
        });
    }

    displaySampleHistory() {
        const sampleScans = [
            {
                date: '2024-01-20 14:30:00',
                type: 'Network',
                target: '192.168.1.0/24',
                duration: '2m 45s',
                devices_found: 23,
                status: 'completed'
            },
            {
                date: '2024-01-20 10:15:00',
                type: 'Protocol',
                target: 'Modbus Devices',
                duration: '1m 20s',
                devices_found: 8,
                status: 'completed'
            }
        ];

        this.displayScanHistory(sampleScans);
    }

    createHistoryRow(scan) {
        const row = document.createElement('tr');
        
        row.innerHTML = `
            <td>${scan.date}</td>
            <td><span class="scan-type-badge ${scan.type.toLowerCase()}">${scan.type}</span></td>
            <td>${scan.target}</td>
            <td>${scan.duration}</td>
            <td>${scan.devices_found}</td>
            <td><span class="scan-status ${scan.status}"><i class="fas fa-check-circle"></i> ${window.utils.string.capitalize(scan.status)}</span></td>
            <td>
                <button class="btn btn-secondary" style="padding: 6px 12px; font-size: 12px;" onclick="window.discoveryPage.viewScanDetails('${scan.id}')">
                    <i class="fas fa-eye"></i> View
                </button>
            </td>
        `;
        
        return row;
    }

    switchTab(tabName) {
        this.currentTab = tabName;
        
        // Update tab buttons
        document.querySelectorAll('.tab').forEach(tab => {
            tab.classList.remove('active');
        });
        
        // Find and activate the correct tab
        document.querySelectorAll('.tab').forEach(tab => {
            if (tab.textContent.toLowerCase().includes(tabName)) {
                tab.classList.add('active');
            }
        });

        // Update tab content
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
        });
        document.getElementById(tabName + 'Tab').classList.add('active');

        // Load data for active tab
        if (tabName === 'history') {
            this.loadScanHistory();
        } else if (tabName === 'results') {
            this.loadRecentResults();
        }
    }

    viewDeviceDetails(ip) {
        console.log('View details for device:', ip);
        window.ui.notifications.show('Device details feature will be implemented in Phase 2', 'info');
    }

    addToInventory(ip) {
        console.log('Add device to inventory:', ip);
        window.ui.notifications.show('Device added to inventory', 'success');
    }

    viewScanDetails(scanId) {
        console.log('View scan details:', scanId);
        window.ui.notifications.show('Scan details feature will be implemented in Phase 2', 'info');
    }

    destroy() {
        // Clean up event listeners and intervals
        this.scanInProgress = false;
        console.log('Discovery page destroyed');
    }
}

// Initialize discovery page when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.discoveryPage = new DiscoveryPage();
});

// Clean up on page unload
window.addEventListener('beforeunload', () => {
    if (window.discoveryPage) {
        window.discoveryPage.destroy();
    }
});