// web/static/js/pages/security.js

class SecurityPage {
    constructor() {
        this.currentTab = 'vulnerabilities';
        this.charts = {};
        this.vulnerabilities = [];
        this.complianceData = {};
        this.init();
    }

    async init() {
        try {
            await this.loadSecurityData();
            this.initCharts();
            this.setupTabs();
            this.setupFilters();
            this.setupRiskMatrix();
        } catch (error) {
            console.error('Security page initialization failed:', error);
            window.ui.notifications.show('Failed to initialize security page', 'error');
        }
    }

    async loadSecurityData() {
        try {
            window.ui.loading.show('main-content', 'Loading security data...');
            
            // Load security overview and metrics
            const [overview, vulnerabilities, compliance] = await Promise.all([
                this.loadSecurityOverview(),
                this.loadVulnerabilities(),
                this.loadComplianceData()
            ]);

            this.updateSecurityOverview(overview);
            this.vulnerabilities = vulnerabilities;
            this.complianceData = compliance;

        } catch (error) {
            console.error('Error loading security data:', error);
            window.ui.notifications.show('Failed to load security data', 'error');
        } finally {
            window.ui.loading.hide('main-content');
        }
    }

    async loadSecurityOverview() {
        try {
            const response = await window.api.security.getSecurityOverview();
            return response;
        } catch (error) {
            // Fallback to sample data
            return {
                critical_vulnerabilities: 3,
                high_risk_issues: 12,
                medium_risk_issues: 28,
                security_score: 89
            };
        }
    }

    async loadVulnerabilities() {
        try {
            const response = await window.api.security.getVulnerabilities();
            return response.vulnerabilities || [];
        } catch (error) {
            // Fallback to sample data
            return [
                {
                    cve_id: 'CVE-2023-32315',
                    title: 'Remote Code Execution in Modbus Implementation',
                    asset: 'Main PLC Controller',
                    severity: 'critical',
                    cvss: 9.8,
                    status: 'open',
                    discovered: '2024-01-20'
                },
                {
                    cve_id: 'CVE-2023-28456',
                    title: 'Authentication Bypass in HMI Web Interface',
                    asset: 'HMI Panel Line 1',
                    severity: 'high',
                    cvss: 8.2,
                    status: 'acknowledged',
                    discovered: '2024-01-18'
                },
                {
                    cve_id: 'CVE-2023-25789',
                    title: 'Buffer Overflow in DNP3 Parser',
                    asset: 'Remote Terminal Unit 3',
                    severity: 'critical',
                    cvss: 9.1,
                    status: 'open',
                    discovered: '2024-01-19'
                },
                {
                    cve_id: 'CVE-2023-22145',
                    title: 'Weak Encryption in Configuration Files',
                    asset: 'SCADA Server Primary',
                    severity: 'medium',
                    cvss: 6.5,
                    status: 'resolved',
                    discovered: '2024-01-15'
                }
            ];
        }
    }

    async loadComplianceData() {
        try {
            const response = await window.api.security.getComplianceStatus();
            return response;
        } catch (error) {
            // Fallback to sample data
            return {
                iec62443: {
                    score: 78,
                    status: 'warning',
                    items: [
                        { name: 'Network Segmentation', passed: true },
                        { name: 'Access Control', passed: true },
                        { name: 'Secure Remote Access', passed: false },
                        { name: 'Patch Management', passed: true },
                        { name: 'Security Monitoring', passed: false }
                    ]
                },
                nist: {
                    score: 92,
                    status: 'good',
                    items: [
                        { name: 'Identify', passed: true },
                        { name: 'Protect', passed: true },
                        { name: 'Detect', passed: true },
                        { name: 'Respond', passed: true },
                        { name: 'Recover', passed: false }
                    ]
                },
                corporate: {
                    score: 65,
                    status: 'poor',
                    items: [
                        { name: 'Password Policy', passed: true },
                        { name: 'Encryption Standards', passed: false },
                        { name: 'Backup Procedures', passed: false },
                        { name: 'Incident Response', passed: true },
                        { name: 'Security Training', passed: false }
                    ]
                }
            };
        }
    }

    updateSecurityOverview(overview) {
        // Update security cards with real data
        const cards = document.querySelectorAll('.security-card');
        if (cards.length >= 4) {
            cards[0].querySelector('.security-value').textContent = overview.critical_vulnerabilities || 0;
            cards[1].querySelector('.security-value').textContent = overview.high_risk_issues || 0;
            cards[2].querySelector('.security-value').textContent = overview.medium_risk_issues || 0;
            cards[3].querySelector('.security-value').textContent = (overview.security_score || 0) + '%';
        }
    }

    initCharts() {
        // Vulnerability Distribution Chart
        const vulnCtx = document.getElementById('vulnChart');
        if (vulnCtx) {
            this.charts.vulnerability = new Chart(vulnCtx.getContext('2d'), {
                type: 'doughnut',
                data: {
                    labels: ['Critical', 'High', 'Medium', 'Low'],
                    datasets: [{
                        data: [3, 12, 28, 45],
                        backgroundColor: [
                            '#EF4444',
                            '#F59E0B',
                            '#3B82F6',
                            '#10B981'
                        ],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: {
                                padding: 20,
                                usePointStyle: true
                            }
                        },
                        title: {
                            display: true,
                            text: 'Vulnerabilities by Severity',
                            font: { size: 16 }
                        }
                    }
                }
            });
        }

        // Vulnerability Trend Chart
        const trendCtx = document.getElementById('trendChart');
        if (trendCtx) {
            this.charts.trend = new Chart(trendCtx.getContext('2d'), {
                type: 'line',
                data: {
                    labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
                    datasets: [{
                        label: 'Critical',
                        data: [5, 4, 6, 3, 2, 3],
                        borderColor: '#EF4444',
                        backgroundColor: 'rgba(239, 68, 68, 0.1)',
                        tension: 0.4
                    }, {
                        label: 'High',
                        data: [15, 18, 14, 16, 13, 12],
                        borderColor: '#F59E0B',
                        backgroundColor: 'rgba(245, 158, 11, 0.1)',
                        tension: 0.4
                    }, {
                        label: 'Medium',
                        data: [32, 35, 30, 33, 29, 28],
                        borderColor: '#3B82F6',
                        backgroundColor: 'rgba(59, 130, 246, 0.1)',
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        title: {
                            display: true,
                            text: 'Vulnerability Trends',
                            font: { size: 16 }
                        }
                    },
                    scales: {
                        y: { beginAtZero: true }
                    }
                }
            });
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
            if (tabName === 'compliance') {
                this.renderComplianceData();
            } else if (tabName === 'risk') {
                this.setupRiskMatrix();
            }
        };
    }

    setupFilters() {
        // Filter handlers
        document.querySelectorAll('.filter-select').forEach(select => {
            select.addEventListener('change', () => {
                this.applyVulnerabilityFilters();
            });
        });

        // Search handler
        const searchInput = document.querySelector('.search-box input');
        if (searchInput) {
            let searchTimeout;
            searchInput.addEventListener('input', () => {
                clearTimeout(searchTimeout);
                searchTimeout = setTimeout(() => {
                    this.applyVulnerabilityFilters();
                }, 300);
            });
        }
    }

    applyVulnerabilityFilters() {
        const filters = {
            severity: document.querySelector('.filter-select').value,
            asset: document.querySelectorAll('.filter-select')[1]?.value || '',
            status: document.querySelectorAll('.filter-select')[2]?.value || '',
            search: document.querySelector('.search-box input')?.value.toLowerCase() || ''
        };

        const filteredVulnerabilities = this.vulnerabilities.filter(vuln => {
            const matchSeverity = !filters.severity || vuln.severity === filters.severity;
            const matchAsset = !filters.asset || vuln.asset.toLowerCase().includes(filters.asset);
            const matchStatus = !filters.status || vuln.status === filters.status;
            const matchSearch = !filters.search || 
                vuln.title.toLowerCase().includes(filters.search) ||
                vuln.cve_id.toLowerCase().includes(filters.search) ||
                vuln.asset.toLowerCase().includes(filters.search);

            return matchSeverity && matchAsset && matchStatus && matchSearch;
        });

        this.renderVulnerabilityTable(filteredVulnerabilities);
    }

    renderVulnerabilityTable(vulnerabilities) {
        const tbody = document.querySelector('#vulnerabilitiesTab .data-table tbody');
        if (!tbody) return;

        tbody.innerHTML = '';

        vulnerabilities.forEach(vuln => {
            const row = this.createVulnerabilityRow(vuln);
            tbody.appendChild(row);
        });

        if (vulnerabilities.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="8" style="text-align: center; padding: 40px; color: var(--text-tertiary);">
                        No vulnerabilities found matching the current filters.
                    </td>
                </tr>
            `;
        }
    }

    createVulnerabilityRow(vuln) {
        const row = document.createElement('tr');
        
        row.innerHTML = `
            <td>${vuln.cve_id}</td>
            <td>${vuln.title}</td>
            <td>${vuln.asset}</td>
            <td><span class="severity-badge ${vuln.severity}">${vuln.severity.toUpperCase()}</span></td>
            <td><span class="cvss-score ${vuln.severity}">${vuln.cvss}</span></td>
            <td><span class="status-badge ${vuln.status}"><i class="fas fa-circle"></i> ${window.utils.string.capitalize(vuln.status)}</span></td>
            <td>${vuln.discovered}</td>
            <td>
                <button class="btn btn-secondary" style="padding: 6px 12px; font-size: 12px;" onclick="window.securityPage.viewVulnerabilityDetails('${vuln.cve_id}')">
                    <i class="fas fa-eye"></i> View
                </button>
            </td>
        `;
        
        return row;
    }

    renderComplianceData() {
        // This would be called when switching to compliance tab
        // The compliance cards are already rendered in HTML
        // We could update them dynamically here if needed
        console.log('Compliance data rendered');
    }

    setupRiskMatrix() {
        // Risk matrix cell click handlers
        document.querySelectorAll('.risk-cell').forEach(cell => {
            cell.addEventListener('click', () => {
                const riskScore = cell.textContent;
                this.showRiskDetails(riskScore);
            });
        });
    }

    showRiskDetails(riskScore) {
        console.log('Risk score clicked:', riskScore);
        window.ui.notifications.show(`Risk assessment for score ${riskScore} - Feature coming in Phase 2`, 'info');
    }

    viewVulnerabilityDetails(cveId) {
        console.log('View vulnerability details:', cveId);
        window.ui.notifications.show('Vulnerability details feature will be implemented in Phase 2', 'info');
    }

    async runSecurityScan() {
        try {
            window.ui.notifications.show('Starting security scan...', 'info');
            
            // This would call the actual security scan API
            const response = await window.api.security.startScan();
            
            window.ui.notifications.show('Security scan completed', 'success');
            
            // Reload data after scan
            await this.loadSecurityData();
            
        } catch (error) {
            console.error('Security scan failed:', error);
            window.ui.notifications.show('Security scan feature will be implemented in Phase 2', 'info');
        }
    }

    generateRiskReport() {
        console.log('Generate risk report');
        window.ui.notifications.show('Risk report generation will be implemented in Phase 2', 'info');
    }

    updateCharts(data) {
        // Update vulnerability distribution chart
        if (this.charts.vulnerability && data.vulnerability_distribution) {
            const severities = ['critical', 'high', 'medium', 'low'];
            const chartData = severities.map(severity => 
                data.vulnerability_distribution[severity] || 0
            );
            
            this.charts.vulnerability.data.datasets[0].data = chartData;
            this.charts.vulnerability.update();
        }

        // Update trend chart
        if (this.charts.trend && data.vulnerability_trends) {
            this.charts.trend.data.datasets.forEach((dataset, index) => {
                dataset.data = data.vulnerability_trends[dataset.label.toLowerCase()] || [];
            });
            this.charts.trend.update();
        }
    }

    destroy() {
        // Clean up charts
        Object.values(this.charts).forEach(chart => {
            if (chart && typeof chart.destroy === 'function') {
                chart.destroy();
            }
        });

        console.log('Security page destroyed');
    }
}

// Global functions for backwards compatibility
window.switchTab = (tabName) => {
    if (window.securityPage) {
        window.securityPage.switchTab(tabName);
    }
};

// Initialize security page when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    // Ensure Chart.js is loaded before initializing
    if (typeof Chart !== 'undefined') {
        window.securityPage = new SecurityPage();
    } else {
        console.error('Chart.js is required for security page');
    }
});

// Clean up on page unload
window.addEventListener('beforeunload', () => {
    if (window.securityPage) {
        window.securityPage.destroy();
    }
});