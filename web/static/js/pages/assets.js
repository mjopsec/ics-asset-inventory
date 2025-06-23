// web/static/js/pages/assets.js

class AssetsPage {
    constructor() {
        this.currentView = 'grid';
        this.assets = [];
        this.filteredAssets = [];
        this.sortColumn = null;
        this.sortOrder = 'asc';
        this.init();
    }

    async init() {
        try {
            await this.loadAssets();
            this.setupFilters();
            this.setupSearch();
            this.setupForms();
            this.setupViewToggle();
            this.setupModals();
        } catch (error) {
            console.error('Assets page initialization failed:', error);
            window.ui.notifications.show('Failed to initialize assets page', 'error');
        }
    }

    async loadAssets() {
        try {
            window.ui.loading.show('main-content', 'Loading assets...');
            
            const response = await window.api.assets.getAssets();
            
            if (response.data) {
                this.assets = response.data;
                this.filteredAssets = [...this.assets];
                this.renderAssets();
            } else {
                this.assets = [];
                this.filteredAssets = [];
                this.renderAssets();
            }
        } catch (error) {
            console.error('Error loading assets:', error);
            window.ui.notifications.show('Failed to load assets', 'error');
        } finally {
            window.ui.loading.hide('main-content');
        }
    }

    renderAssets() {
        if (this.currentView === 'grid') {
            this.renderGridView();
        } else {
            this.renderListView();
        }
    }

    renderGridView() {
        const gridContainer = document.getElementById('gridView');
        gridContainer.innerHTML = '';
        
        if (this.filteredAssets.length === 0) {
            gridContainer.innerHTML = this.getEmptyStateHTML();
            return;
        }
        
        this.filteredAssets.forEach(asset => {
            const card = this.createAssetCard(asset);
            gridContainer.appendChild(card);
        });
    }

    renderListView() {
        const tbody = document.getElementById('assetsTableBody');
        tbody.innerHTML = '';
        
        if (this.filteredAssets.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="8" style="text-align: center; padding: 60px 20px;">
                        ${this.getEmptyStateHTML()}
                    </td>
                </tr>
            `;
            return;
        }
        
        this.filteredAssets.forEach(asset => {
            const row = this.createAssetRow(asset);
            tbody.appendChild(row);
        });
    }

    getEmptyStateHTML() {
        return `
            <div class="empty-state">
                <i class="fas fa-cube"></i>
                <h3 class="empty-state-title">No Assets Found</h3>
                <p class="empty-state-text">Start by adding your first asset to the inventory</p>
                <button class="btn btn-primary" onclick="window.assetsPage.openAddAssetModal()">
                    <i class="fas fa-plus"></i> Add Your First Asset
                </button>
            </div>
        `;
    }

    createAssetCard(asset) {
        const card = document.createElement('div');
        card.className = 'asset-card';
        card.onclick = () => this.viewAssetDetails(asset.id);
        
        const iconClass = this.getAssetIconClass(asset.asset_type);
        const statusClass = asset.status || 'unknown';
        const criticalityClass = asset.criticality || 'medium';
        
        card.innerHTML = `
            <div class="asset-card-header">
                <div class="asset-info">
                    <div class="asset-icon-lg ${iconClass}">
                        <i class="fas fa-${this.getAssetIcon(asset.asset_type)}"></i>
                    </div>
                    <div class="asset-meta">
                        <div class="asset-name">${asset.name}</div>
                        <div class="asset-type">${asset.asset_type}</div>
                    </div>
                </div>
                <div class="asset-status ${statusClass}">
                    <span class="status-dot"></span>
                    ${window.utils.string.capitalize(statusClass)}
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
                    <div class="detail-label">Vendor</div>
                    <div class="detail-value">${asset.vendor || '-'}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Criticality</div>
                    <div class="detail-value">${window.utils.string.capitalize(criticalityClass)}</div>
                </div>
            </div>
            
            <div class="asset-actions">
                <button onclick="event.stopPropagation(); window.assetsPage.editAsset('${asset.id}')">
                    <i class="fas fa-edit"></i> Edit
                </button>
                <button onclick="event.stopPropagation(); window.assetsPage.scanAsset('${asset.id}')">
                    <i class="fas fa-search"></i> Scan
                </button>
            </div>
        `;
        
        return card;
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
                        <span class="asset-name">${asset.name}</span>
                        <span class="asset-ip">${asset.vendor || ''} ${asset.model || ''}</span>
                    </div>
                </div>
            </td>
            <td>${asset.asset_type}</td>
            <td>${asset.ip_address || '-'}</td>
            <td>
                <span class="status-badge ${statusClass}">
                    <span class="status-dot"></span>
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
            <td>
                <div class="flex gap-2">
                    <button class="btn btn-secondary btn-sm" onclick="window.assetsPage.viewAssetDetails('${asset.id}')">
                        <i class="fas fa-eye"></i>
                    </button>
                    <button class="btn btn-secondary btn-sm" onclick="window.assetsPage.editAsset('${asset.id}')">
                        <i class="fas fa-edit"></i>
                    </button>
                </div>
            </td>
        `;
        
        return row;
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

    getAssetIconClass(type) {
        const classes = {
            'PLC': 'plc',
            'HMI': 'hmi',
            'RTU': 'rtu'
        };
        return classes[type] || '';
    }

    setupFilters() {
        const filters = ['filterType', 'filterStatus', 'filterCriticality', 'filterProtocol'];
        
        filters.forEach(filterId => {
            const element = document.getElementById(filterId);
            if (element) {
                element.addEventListener('change', () => this.applyFilters());
            }
        });
    }

    setupSearch() {
        const searchInput = document.getElementById('assetSearch');
        if (searchInput) {
            let searchTimeout;
            searchInput.addEventListener('input', () => {
                clearTimeout(searchTimeout);
                searchTimeout = setTimeout(() => {
                    this.applyFilters();
                }, 300);
            });
        }
    }

    applyFilters() {
        const filters = {
            type: document.getElementById('filterType')?.value || '',
            status: document.getElementById('filterStatus')?.value || '',
            criticality: document.getElementById('filterCriticality')?.value || '',
            protocol: document.getElementById('filterProtocol')?.value || '',
            search: document.getElementById('assetSearch')?.value.toLowerCase() || ''
        };
        
        this.filteredAssets = this.assets.filter(asset => {
            const matchType = !filters.type || asset.asset_type === filters.type;
            const matchStatus = !filters.status || asset.status === filters.status;
            const matchCriticality = !filters.criticality || asset.criticality === filters.criticality;
            const matchProtocol = !filters.protocol || asset.protocol === filters.protocol;
            const matchSearch = !filters.search || 
                asset.name.toLowerCase().includes(filters.search) ||
                (asset.ip_address && asset.ip_address.includes(filters.search)) ||
                (asset.vendor && asset.vendor.toLowerCase().includes(filters.search));
            
            return matchType && matchStatus && matchCriticality && matchProtocol && matchSearch;
        });
        
        this.renderAssets();
    }

    setupViewToggle() {
        const toggleButtons = document.querySelectorAll('.view-toggle button');
        toggleButtons.forEach(button => {
            button.addEventListener('click', (e) => {
                const view = e.target.closest('button').onclick.toString().includes('grid') ? 'grid' : 'list';
                this.setView(view);
            });
        });
    }

    setView(view) {
        this.currentView = view;
        
        // Update toggle buttons
        document.querySelectorAll('.view-toggle button').forEach(btn => {
            btn.classList.remove('active');
        });
        
        if (view === 'grid') {
            document.querySelector('.view-toggle button[onclick*="grid"]').classList.add('active');
            document.getElementById('gridView').classList.remove('hidden');
            document.getElementById('listView').classList.add('hidden');
        } else {
            document.querySelector('.view-toggle button[onclick*="list"]').classList.add('active');
            document.getElementById('gridView').classList.add('hidden');
            document.getElementById('listView').classList.remove('hidden');
        }
        
        this.renderAssets();
    }

    setupForms() {
        // Add asset form
        const addForm = document.getElementById('addAssetForm');
        if (addForm) {
            addForm.addEventListener('submit', (e) => this.handleAssetSubmission(e, 'create'));
        }

        // Edit asset form
        const editForm = document.getElementById('editAssetForm');
        if (editForm) {
            editForm.addEventListener('submit', (e) => this.handleAssetSubmission(e, 'edit'));
        }
    }

    setupModals() {
        // Modal functions
        window.openAddAssetModal = () => {
            window.ui.modals.show('addAssetModal');
        };

        window.closeAddAssetModal = () => {
            window.ui.modals.close('addAssetModal');
            document.getElementById('addAssetForm').reset();
        };

        window.closeEditAssetModal = () => {
            window.ui.modals.close('editAssetModal');
            document.getElementById('editAssetForm').reset();
        };

        window.switchModalTab = (tabName) => {
            // Update tab buttons
            document.querySelectorAll('.modal-tab').forEach(tab => {
                tab.classList.remove('active');
            });
            event.target.closest('.modal-tab').classList.add('active');
            
            // Update tab panels
            document.querySelectorAll('.tab-panel').forEach(panel => {
                panel.classList.remove('active');
            });
            document.getElementById(tabName + 'Tab').classList.add('active');
        };

        // Global functions for backwards compatibility
        window.setView = (view) => this.setView(view);
        window.openAddAssetModal = window.openAddAssetModal;
        window.closeAddAssetModal = window.closeAddAssetModal;
        window.closeEditAssetModal = window.closeEditAssetModal;
        window.switchModalTab = window.switchModalTab;
    }

    async handleAssetSubmission(e, action) {
        e.preventDefault();
        
        const form = e.target;
        const formData = new FormData(form);
        const assetData = Object.fromEntries(formData);
        
        // Convert port to integer if it exists and is not empty
        if (assetData.port && assetData.port !== '') {
            assetData.port = parseInt(assetData.port, 10);
        } else {
            delete assetData.port;
        }
        
        // Remove empty fields
        Object.keys(assetData).forEach(key => {
            if (assetData[key] === '' || assetData[key] === null || assetData[key] === undefined) {
                delete assetData[key];
            }
        });
        
        // Show loading state
        const submitBtn = form.querySelector('button[type="submit"]');
        window.ui.loading.button(submitBtn, true);
        
        try {
            if (action === 'create') {
                await window.api.assets.createAsset(assetData);
                window.ui.modals.close('addAssetModal');
                window.ui.notifications.show('Asset added successfully', 'success');
            } else {
                const assetId = document.getElementById('editAssetId').value;
                await window.api.assets.updateAsset(assetId, assetData);
                window.ui.modals.close('editAssetModal');
                window.ui.notifications.show('Asset updated successfully', 'success');
            }
            
            // Reload assets
            await this.loadAssets();
            form.reset();
            
        } catch (error) {
            console.error('Error saving asset:', error);
            window.ui.notifications.show(
                error.message || 'Failed to save asset', 
                'error'
            );
        } finally {
            window.ui.loading.button(submitBtn, false);
        }
    }

    editAsset(assetId) {
        const asset = this.assets.find(a => a.id === assetId);
        if (!asset) {
            window.ui.notifications.show('Asset not found', 'error');
            return;
        }
        
        // Reset tabs to first tab
        document.querySelectorAll('.modal-tab').forEach((tab, index) => {
            tab.classList.toggle('active', index === 0);
        });
        document.querySelectorAll('.tab-panel').forEach((panel, index) => {
            panel.classList.toggle('active', index === 0);
        });
        
        // Populate form fields
        const fields = {
            'editAssetId': asset.id,
            'editAssetName': asset.name || '',
            'editAssetType': asset.asset_type || '',
            'editAssetIP': asset.ip_address || '',
            'editAssetMAC': asset.mac_address || '',
            'editAssetVendor': asset.vendor || '',
            'editAssetModel': asset.model || '',
            'editAssetVersion': asset.version || '',
            'editAssetSerial': asset.serial_number || '',
            'editAssetProtocol': asset.protocol || '',
            'editAssetPort': asset.port || '',
            'editAssetCriticality': asset.criticality || 'medium',
            'editAssetLocation': asset.location || '',
            'editAssetZone': asset.zone || '',
            'editAssetSite': asset.site || '',
            'editAssetDepartment': asset.department || '',
            'editAssetDescription': asset.description || ''
        };

        Object.entries(fields).forEach(([id, value]) => {
            const element = document.getElementById(id);
            if (element) {
                element.value = value;
            }
        });
        
        // Show edit modal
        window.ui.modals.show('editAssetModal');
    }

    viewAssetDetails(assetId) {
        window.location.href = `/assets/${assetId}`;
    }

    scanAsset(assetId) {
        console.log('Scan asset:', assetId);
        window.ui.notifications.show('Scan functionality will be implemented in Phase 2', 'info');
    }

    async deleteAsset(assetId) {
        if (!confirm('Are you sure you want to delete this asset?')) {
            return;
        }

        try {
            await window.api.assets.deleteAsset(assetId);
            window.ui.notifications.show('Asset deleted successfully', 'success');
            await this.loadAssets();
        } catch (error) {
            console.error('Error deleting asset:', error);
            window.ui.notifications.show(
                error.message || 'Failed to delete asset', 
                'error'
            );
        }
    }

    sortAssets(column) {
        if (this.sortColumn === column) {
            this.sortOrder = this.sortOrder === 'asc' ? 'desc' : 'asc';
        } else {
            this.sortColumn = column;
            this.sortOrder = 'asc';
        }

        this.filteredAssets = window.utils.array.sortBy(
            this.filteredAssets, 
            column, 
            this.sortOrder
        );

        this.renderAssets();
        this.updateSortIndicators();
    }

    updateSortIndicators() {
        // Remove all sort indicators
        document.querySelectorAll('.data-table th i').forEach(icon => {
            icon.className = 'fas fa-sort';
        });

        // Add current sort indicator
        if (this.sortColumn) {
            const th = document.querySelector(`[data-sort="${this.sortColumn}"]`);
            if (th) {
                const icon = th.querySelector('i');
                if (icon) {
                    icon.className = `fas fa-sort-${this.sortOrder === 'asc' ? 'up' : 'down'}`;
                }
            }
        }
    }

    exportAssets() {
        const csvData = this.convertToCSV(this.filteredAssets);
        const blob = new Blob([csvData], { type: 'text/csv' });
        const url = window.URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        a.download = `assets_export_${new Date().toISOString().split('T')[0]}.csv`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        
        window.URL.revokeObjectURL(url);
        window.ui.notifications.show('Assets exported successfully', 'success');
    }

    convertToCSV(assets) {
        if (assets.length === 0) return '';

        const headers = [
            'Name', 'Type', 'IP Address', 'MAC Address', 'Vendor', 'Model', 
            'Version', 'Serial Number', 'Protocol', 'Port', 'Status', 
            'Criticality', 'Location', 'Zone', 'Site', 'Department', 
            'Description', 'Created', 'Updated'
        ];

        const rows = assets.map(asset => [
            asset.name || '',
            asset.asset_type || '',
            asset.ip_address || '',
            asset.mac_address || '',
            asset.vendor || '',
            asset.model || '',
            asset.version || '',
            asset.serial_number || '',
            asset.protocol || '',
            asset.port || '',
            asset.status || '',
            asset.criticality || '',
            asset.location || '',
            asset.zone || '',
            asset.site || '',
            asset.department || '',
            asset.description || '',
            asset.created_at ? new Date(asset.created_at).toLocaleDateString() : '',
            asset.updated_at ? new Date(asset.updated_at).toLocaleDateString() : ''
        ]);

        const csvContent = [headers, ...rows]
            .map(row => row.map(field => `"${field}"`).join(','))
            .join('\n');

        return csvContent;
    }

    destroy() {
        // Clean up event listeners and intervals if any
        console.log('Assets page destroyed');
    }
}

// Global functions for backwards compatibility
window.setView = (view) => {
    if (window.assetsPage) {
        window.assetsPage.setView(view);
    }
};

window.openAddAssetModal = () => {
    window.ui.modals.show('addAssetModal');
};

window.closeAddAssetModal = () => {
    window.ui.modals.close('addAssetModal');
    const form = document.getElementById('addAssetForm');
    if (form) form.reset();
};

window.closeEditAssetModal = () => {
    window.ui.modals.close('editAssetModal');
    const form = document.getElementById('editAssetForm');
    if (form) form.reset();
};

window.switchModalTab = (tabName) => {
    // Update tab buttons
    document.querySelectorAll('.modal-tab').forEach(tab => {
        tab.classList.remove('active');
    });
    event.target.closest('.modal-tab').classList.add('active');
    
    // Update tab panels
    document.querySelectorAll('.tab-panel').forEach(panel => {
        panel.classList.remove('active');
    });
    document.getElementById(tabName + 'Tab').classList.add('active');
};

// Initialize assets page when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.assetsPage = new AssetsPage();
});

// Clean up on page unload
window.addEventListener('beforeunload', () => {
    if (window.assetsPage) {
        window.assetsPage.destroy();
    }
});

// Setup table sort handlers
document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.data-table th[data-sort]').forEach(th => {
        th.style.cursor = 'pointer';
        th.addEventListener('click', () => {
            const column = th.dataset.sort;
            if (window.assetsPage) {
                window.assetsPage.sortAssets(column);
            }
        });
    });

    // Setup export button
    const exportBtn = document.querySelector('.btn[onclick*="export"]') || 
                     document.querySelector('button:contains("Export")');
    if (exportBtn) {
        exportBtn.addEventListener('click', (e) => {
            e.preventDefault();
            if (window.assetsPage) {
                window.assetsPage.exportAssets();
            }
        });
    }
});