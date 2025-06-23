// web/static/js/pages/dashboard.js

class DashboardPage {
    constructor() {
        this.charts = {};
        this.refreshInterval = null;
        this.init();
    }

    async init() {
        try {
            await this.loadDashboardData();
            this.initCharts();
            this.setupDropdown();
            this.setupRefresh();
            this.setupFABMenu();
            this.setupModals();
        } catch (error) {
            console.error('Dashboard initialization failed:', error);
            window.ui.notifications.show('Failed to initialize dashboard', 'error');
        }
    }

    async loadDashboardData() {
        try {
            window.ui.loading.show('dashboard-content', 'Loading dashboard data...');
            
            const [overview, metrics] = await Promise.all([
                window.api.dashboard.getOverview(),
                window.api.dashboard.getMetrics()
            ]);

            this.updateStats(overview);
            this.updateCharts(metrics);
            this.loadRecentAssets();

        } catch (error) {
            console.error('Error loading dashboard data:', error);
            window.ui.notifications.show('Failed to load dashboard data', 'error');
        } finally {
            window.ui.loading.hide('dashboard-content');
        }
    }

    updateStats(overview) {
        const stats = {
            totalAssets: overview.total_assets || 0,
            onlineAssets: overview.online_assets || 0,
            criticalAlerts: overview.critical_alerts || 0,
            recentScans: overview.recent_scans || 0
        };

        // Update stat values
        Object.entries(stats).forEach(([key, value]) => {
            const element = document.getElementById(key);
            if (element) {
                this.animateNumber(element, parseInt(element.textContent) || 0, value);
            }
        });

        // Update change indicators
        this.updateChangeIndicators(overview);
    }

    updateChangeIndicators(overview) {
        const indicators = {
            totalAssets: {
                element: document.querySelector('.stat-card:nth-child(1) .stat-change'),
                value: overview.new_assets_today || 0,
                positive: overview.new_assets_today > 0
            },
            onlineAssets: {
                element: document.querySelector('.stat-card:nth-child(2) .stat-change'),
                value: overview.total_assets > 0 ? Math.round((overview.online_assets / overview.total_assets) * 100) : 0,
                positive: true
            },
            criticalAlerts: {
                element: document.querySelector('.stat-card:nth-child(3) .stat-change'),
                value: overview.critical_alerts,
                positive: overview.critical_alerts === 0
            },
            recentScans: {
                element: document.querySelector('.stat-card:nth-child(4) .stat-change'),
                value: overview.recent_scans,
                positive: overview.recent_scans > 0
            }
        };

        Object.entries(indicators).forEach(([key, { element, value, positive }]) => {
            if (element) {
                element.className = `stat-change ${positive ? 'positive' : 'negative'}`;
                
                let icon = positive ? 'fa-arrow-up' : 'fa-arrow-down';
                let text = '';

                switch (key) {
                    case 'totalAssets':
                        icon = value > 0 ? 'fa-arrow-up' : 'fa-minus';
                        text = value > 0 ? `${value} new today` : 'No new assets today';
                        break;
                    case 'onlineAssets':
                        icon = 'fa-check';
                        text = `${value}% online`;
                        break;
                    case 'criticalAlerts':
                        icon = value > 0 ? 'fa-exclamation' : 'fa-check';
                        text = value > 0 ? 'Requires attention' : 'No critical issues';
                        break;
                    case 'recentScans':
                        icon = value > 0 ? 'fa-check' : 'fa-clock';
                        text = value > 0 ? 'Active scanning' : 'No recent scans';
                        break;
                }

                element.innerHTML = `<i class="fas ${icon}"></i> ${text}`;
            }
        });
    }

    animateNumber(element, start, end, duration = 1000) {
        const startTime = performance.now();
        
        const animate = (currentTime) => {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);
            
            const current = Math.floor(start + (end - start) * progress);
            element.textContent = current;
            
            if (progress < 1) {
                requestAnimationFrame(animate);
            }
        };
        
        requestAnimationFrame(animate);
    }

    initCharts() {
        // Asset Type Chart
        const assetTypeCtx = document.getElementById('assetTypeChart')?.getContext('2d');
        if (assetTypeCtx) {
            this.charts.assetType = new Chart(assetTypeCtx, {
                type: 'doughnut',
                data: {
                    labels: [],
                    datasets: [{
                        data: [],
                        backgroundColor: [
                            '#0EA5E9', '#10B981', '#F59E0B', 
                            '#8B5CF6', '#EF4444', '#06B6D4', '#EC4899'
                        ],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'right',
                            labels: {
                                padding: 20,
                                usePointStyle: true
                            }
                        },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                    const percentage = ((context.parsed / total) * 100).toFixed(1);
                                    return `${context.label}: ${context.parsed} (${percentage}%)`;
                                }
                            }
                        }
                    }
                }
            });
        }

        // Status Chart
        const statusCtx = document.getElementById('statusChart')?.getContext('2d');
        if (statusCtx) {
            this.charts.status = new Chart(statusCtx, {
                type: 'bar',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Device Status',
                        data: [],
                        backgroundColor: ['#10B981', '#EF4444', '#F59E0B', '#6B7280'],
                        borderRadius: 8
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: { stepSize: 1 }
                        }
                    }
                }
            });
        }
    }

    updateCharts(metrics) {
        // Update asset type chart
        if (this.charts.assetType && metrics.asset_distribution) {
            const hasData = Object.keys(metrics.asset_distribution).length > 0;
            
            if (hasData) {
                this.charts.assetType.data.labels = Object.keys(metrics.asset_distribution);
                this.charts.assetType.data.datasets[0].data = Object.values(metrics.asset_distribution);
            } else {
                this.charts.assetType.data.labels = ['No Data'];
                this.charts.assetType.data.datasets[0].data = [1];
                this.charts.assetType.data.datasets[0].backgroundColor = ['#E5E7EB'];
            }
            this.charts.assetType.update();
        }

        // Update status chart
        if (this.charts.status && metrics.status_distribution) {
            const hasData = Object.keys(metrics.status_distribution).length > 0;
            
            if (hasData) {
                this.charts.status.data.labels = Object.keys(metrics.status_distribution)
                    .map(s => window.utils.string.capitalize(s));
                this.charts.status.data.datasets[0].data = Object.values(metrics.status_distribution);
            } else {
                this.charts.status.data.labels = ['No Data'];
                this.charts.status.data.datasets[0].data = [0];
            }
            this.charts.status.update();
        }
    }

    async loadRecentAssets() {
        try {
            const response = await window.api.assets.getAssets({
                limit: 5,
                sort_by: 'created_at',
                sort_order: 'DESC'
            });

            const tbody = document.getElementById('assetsTableBody');
            if (!tbody) return;

            if (response.data && response.data.length > 0) {
                tbody.innerHTML = '';
                response.data.forEach(asset => {
                    const row = this.createAssetRow(asset);
                    tbody.appendChild(row);
                });
            } else {
                this.displayEmptyAssets(tbody);
            }
        } catch (error) {
            console.error('Error loading recent assets:', error);
            const tbody = document.getElementById('assetsTableBody');
            if (tbody) {
                this.displayEmptyAssets(tbody);
            }
        }
    }

    createAssetRow(asset) {
        const row = document.createElement('tr');
        const statusClass = asset.status || 'unknown';
        const criticalityClass = asset.criticality || 'medium';
        const lastSeen = asset.last_seen ? 
            window.utils.date.formatDate(asset.last_seen) : 'Never';

        row.innerHTML = `
            <td>
                <div class="asset-info">
                    <div class="asset-icon">
                        <i class="fas fa-${this.getAssetIcon(asset.asset_type)}"></i>
                    </div>
                    <div class="asset-details">
                        <div class="asset-name">${asset.name}</div>
                        <div class="asset-ip">${asset.ip_address || 'No IP'}</div>
                    </div>
                </div>
            </td>
            <td>${asset.asset_type || 'Unknown'}</td>
            <td>
                <span class="status-badge ${statusClass}">
                    <span class="status-indicator"></span>
                    ${window.utils.string.capitalize(statusClass)}
                </span>
            </td>
            <td>${asset.protocol || '-'}</td>
            <td>
                <span class="criticality-badge ${criticalityClass}">
                    ${criticalityClass}
                </span>
            </td>
            <td>${lastSeen}</td>
        `;

        row.style.cursor = 'pointer';
        row.onclick = () => window.location.href = `/assets/${asset.id}`;

        return row;
    }

    displayEmptyAssets(tbody) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6" style="text-align: center; padding: 40px; color: var(--text-tertiary);">
                    <i class="fas fa-cube" style="font-size: 32px; opacity: 0.3; margin-bottom: 12px; display: block;"></i>
                    No assets found. Start by adding your industrial devices to the inventory.
                    <br><br>
                    <a href="/assets" class="btn btn-primary" style="text-decoration: none;">
                        <i class="fas fa-plus"></i> Add Assets
                    </a>
                </td>
            </tr>
        `;
    }

    getAssetIcon(type) {
        const icons = {
            'PLC': 'microchip',
            'HMI': 'desktop',
            'RTU': 'broadcast-tower',
            'Switch': 'network-wired',
            'Server': 'server',
            'Sensor': 'thermometer-half',
            'Actuator': 'cogs'
        };
        return icons[type] || 'cube';
    }

    setupDropdown() {
        const userProfile = document.getElementById('userProfile');
        const profileDropdown = document.getElementById('profileDropdown');

        if (userProfile && profileDropdown) {
            userProfile.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                window.ui.dropdowns.toggle('profileDropdown');
            });

            // Load user profile data
            this.loadUserProfile();
        }
    }

    async loadUserProfile() {
        try {
            const user = await window.auth.getCurrentUser();
            this.updateUserDisplay(user);
        } catch (error) {
            console.error('Failed to load user profile:', error);
        }
    }

    updateUserDisplay(user) {
        const initial = user.username.charAt(0).toUpperCase();
        
        // Update topbar
        const elements = {
            userAvatar: document.getElementById('userAvatar'),
            userName: document.getElementById('userName'),
            userRole: document.getElementById('userRole'),
            dropdownAvatar: document.getElementById('dropdownAvatar'),
            dropdownName: document.getElementById('dropdownName'),
            dropdownEmail: document.getElementById('dropdownEmail')
        };

        if (elements.userAvatar) elements.userAvatar.textContent = initial;
        if (elements.userName) elements.userName.textContent = user.username;
        if (elements.userRole) elements.userRole.textContent = window.utils.string.capitalize(user.role);
        if (elements.dropdownAvatar) elements.dropdownAvatar.textContent = initial;
        if (elements.dropdownName) elements.dropdownName.textContent = user.username;
        if (elements.dropdownEmail) elements.dropdownEmail.textContent = user.email;
    }

    setupFABMenu() {
        const fabButton = document.getElementById('fabButton');
        const fabMenu = document.getElementById('fabMenu');

        if (!fabButton || !fabMenu) return;

        let menuOpen = false;

        fabButton.addEventListener('click', (e) => {
            e.stopPropagation();
            menuOpen = !menuOpen;
            fabMenu.classList.toggle('active');
            fabButton.innerHTML = menuOpen ? 
                '<i class="fas fa-times"></i>' : 
                '<i class="fas fa-plus"></i>';
        });

        // Close on outside click
        document.addEventListener('click', (e) => {
            if (!fabButton.contains(e.target) && !fabMenu.contains(e.target)) {
                menuOpen = false;
                fabMenu.classList.remove('active');
                fabButton.innerHTML = '<i class="fas fa-plus"></i>';
            }
        });

        // FAB menu actions
        fabMenu.querySelectorAll('.fab-menu-item').forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                const action = item.textContent.trim();

                switch (action) {
                    case 'Add Asset':
                        window.location.href = '/assets';
                        break;
                    case 'Start Scan':
                        window.location.href = '/discovery';
                        break;
                    case 'Export Report':
                        window.ui.notifications.show('Report export feature coming soon', 'info');
                        break;
                }

                // Close menu
                menuOpen = false;
                fabMenu.classList.remove('active');
                fabButton.innerHTML = '<i class="fas fa-plus"></i>';
            });
        });
    }

    setupModals() {
        // Profile modal handlers
        window.openProfileModal = () => {
            window.ui.modals.show('profileModal');
            window.ui.dropdowns.closeAll();
        };

        window.closeProfileModal = () => {
            window.ui.modals.close('profileModal');
        };

        window.openChangePassword = () => {
            window.ui.modals.show('changePasswordModal');
            window.ui.dropdowns.closeAll();
        };

        window.closeChangePasswordModal = () => {
            window.ui.modals.close('changePasswordModal');
            const form = document.getElementById('changePasswordForm');
            if (form) form.reset();
        };

        window.openAccountSettings = () => {
            window.ui.notifications.show('Account settings will be available in the next update', 'info');
            window.ui.dropdowns.closeAll();
            window.ui.modals.close('profileModal');
        };

        window.showActivityLog = () => {
            window.ui.notifications.show('Activity log will be available in the next update', 'info');
            window.ui.dropdowns.closeAll();
        };

        window.handleLogout = async () => {
            try {
                await window.auth.logout();
            } catch (error) {
                console.error('Logout error:', error);
                window.auth.clearAuth();
                window.location.href = '/login';
            }
        };

        // Change password form
        const changePasswordForm = document.getElementById('changePasswordForm');
        if (changePasswordForm) {
            changePasswordForm.addEventListener('submit', this.handleChangePassword.bind(this));
        }
    }

    async handleChangePassword(e) {
        e.preventDefault();
        
        const formData = new FormData(e.target);
        const data = {
            current_password: formData.get('currentPassword'),
            new_password: formData.get('newPassword'),
            confirm_password: formData.get('confirmPassword')
        };

        // Validate passwords match
        if (data.new_password !== data.confirm_password) {
            window.ui.notifications.show('Passwords do not match', 'error');
            return;
        }

        try {
            const submitBtn = e.target.querySelector('button[type="submit"]');
            window.ui.loading.button(submitBtn, true);

            await window.auth.changePassword(data);
            
            window.ui.notifications.show('Password changed successfully', 'success');
            window.ui.modals.close('changePasswordModal');
            e.target.reset();

        } catch (error) {
            console.error('Change password error:', error);
            window.ui.notifications.show(
                error.message || 'Failed to change password', 
                'error'
            );
        } finally {
            const submitBtn = e.target.querySelector('button[type="submit"]');
            window.ui.loading.button(submitBtn, false);
        }
    }

    setupRefresh() {
        // Auto-refresh every 30 seconds
        this.refreshInterval = setInterval(() => {
            this.loadDashboardData();
        }, 30000);

        // Refresh on visibility change
        document.addEventListener('visibilitychange', () => {
            if (!document.hidden) {
                this.loadDashboardData();
            }
        });

        // Manual refresh
        const refreshBtn = document.getElementById('refreshBtn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => {
                this.loadDashboardData();
            });
        }
    }

    destroy() {
        // Clean up intervals and event listeners
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
        }

        // Destroy charts
        Object.values(this.charts).forEach(chart => {
            if (chart && typeof chart.destroy === 'function') {
                chart.destroy();
            }
        });
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new DashboardPage();
});

// Clean up on page unload
window.addEventListener('beforeunload', () => {
    if (window.dashboard) {
        window.dashboard.destroy();
    }
});