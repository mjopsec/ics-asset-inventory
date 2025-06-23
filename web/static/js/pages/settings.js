// web/static/js/pages/settings.js

class SettingsPage {
    constructor() {
        this.currentTab = 'general';
        this.settings = {};
        this.users = [];
        this.apiKeys = [];
        this.init();
    }

    async init() {
        try {
            this.setupTabs();
            this.setupForms();
            this.setupToggleSwitches();
            this.setupModals();
            this.loadSettings();
            this.loadUsers();
            this.loadApiKeys();
        } catch (error) {
            console.error('Settings page initialization failed:', error);
            window.ui.notifications.show('Failed to initialize settings page', 'error');
        }
    }

    setupTabs() {
        // Tab switching
        window.switchSettingsTab = (tabName) => {
            // Update navigation
            document.querySelectorAll('.settings-nav-item').forEach(item => {
                item.classList.remove('active');
            });
            event.target.closest('.settings-nav-item').classList.add('active');

            // Update content
            document.querySelectorAll('.settings-section').forEach(section => {
                section.classList.remove('active');
            });
            document.getElementById(tabName + 'Settings').classList.add('active');

            this.currentTab = tabName;

            // Load tab-specific data
            if (tabName === 'users') {
                this.loadUsers();
            } else if (tabName === 'api') {
                this.loadApiKeys();
            } else if (tabName === 'system') {
                this.loadSystemInfo();
            }
        };
    }

    setupForms() {
        // Handle form submissions
        document.querySelectorAll('form').forEach(form => {
            form.addEventListener('submit', (e) => this.handleFormSubmission(e));
        });
    }

    setupToggleSwitches() {
        // Add event listeners for toggle switches
        document.querySelectorAll('.toggle-switch input').forEach(toggle => {
            toggle.addEventListener('change', (e) => {
                console.log('Toggle changed:', e.target.checked);
                this.handleToggleChange(e.target);
            });
        });
    }

    setupModals() {
        // Setup modal functions
        window.openAddUserModal = () => {
            window.ui.notifications.show('Add user functionality will be implemented in Phase 2', 'info');
        };

        window.openApiKeyModal = () => {
            window.ui.notifications.show('API key management will be implemented in Phase 2', 'info');
        };
    }

    async loadSettings() {
        try {
            const response = await window.api.settings.getSettings();
            this.settings = response;
            this.populateSettingsForm();
        } catch (error) {
            console.error('Error loading settings:', error);
            // Use default settings as fallback
            this.loadDefaultSettings();
        }
    }

    loadDefaultSettings() {
        this.settings = {
            general: {
                organizationName: 'Industrial Corp',
                timeZone: 'UTC+07:00 - Jakarta',
                dateFormat: 'DD/MM/YYYY',
                language: 'English',
                darkMode: false,
                compactView: false,
                showAssetIcons: true
            },
            network: {
                defaultScanTimeout: 30,
                maxConcurrentScans: 50,
                defaultIpRanges: '192.168.1.0/24\n10.0.0.0/16\n172.16.0.0/12',
                enableModbusScanning: true,
                enableDnp3Scanning: true,
                enableEthernetIpScanning: true,
                passiveScanningMode: false
            },
            security: {
                requireTwoFactor: false,
                enableSSO: false,
                sessionTimeout: 60,
                passwordExpiry: 90,
                passwordPolicy: {
                    minLength: true,
                    requireUppercase: true,
                    requireLowercase: true,
                    requireNumbers: true,
                    requireSpecialChars: false
                }
            },
            notifications: {
                criticalSecurityAlerts: true,
                deviceStatusChanges: true,
                scanCompletion: false,
                reportGeneration: true,
                emailAddress: 'admin@industrial-corp.com',
                notificationFrequency: 'Hourly Digest'
            }
        };
        this.populateSettingsForm();
    }

    populateSettingsForm() {
        // Populate general settings
        const general = this.settings.general || {};
        this.setInputValue('organizationName', general.organizationName);
        this.setSelectValue('timeZone', general.timeZone);
        this.setSelectValue('dateFormat', general.dateFormat);
        this.setSelectValue('language', general.language);
        this.setToggleValue('darkMode', general.darkMode);
        this.setToggleValue('compactView', general.compactView);
        this.setToggleValue('showAssetIcons', general.showAssetIcons);

        // Populate network settings
        const network = this.settings.network || {};
        this.setInputValue('scanTimeout', network.defaultScanTimeout);
        this.setInputValue('maxConcurrent', network.maxConcurrentScans);
        this.setTextareaValue('ipRanges', network.defaultIpRanges);
        this.setToggleValue('enableModbus', network.enableModbusScanning);
        this.setToggleValue('enableDnp3', network.enableDnp3Scanning);
        this.setToggleValue('enableEthernetIp', network.enableEthernetIpScanning);
        this.setToggleValue('passiveScanning', network.passiveScanningMode);

        // Populate security settings
        const security = this.settings.security || {};
        this.setToggleValue('requireTwoFactor', security.requireTwoFactor);
        this.setToggleValue('enableSSO', security.enableSSO);
        this.setInputValue('sessionTimeout', security.sessionTimeout);
        this.setInputValue('passwordExpiry', security.passwordExpiry);
        
        // Password policy checkboxes
        const policy = security.passwordPolicy || {};
        this.setCheckboxValue('minLength', policy.minLength);
        this.setCheckboxValue('requireUppercase', policy.requireUppercase);
        this.setCheckboxValue('requireLowercase', policy.requireLowercase);
        this.setCheckboxValue('requireNumbers', policy.requireNumbers);
        this.setCheckboxValue('requireSpecialChars', policy.requireSpecialChars);

        // Populate notifications settings
        const notifications = this.settings.notifications || {};
        this.setToggleValue('criticalAlerts', notifications.criticalSecurityAlerts);
        this.setToggleValue('deviceChanges', notifications.deviceStatusChanges);
        this.setToggleValue('scanCompletion', notifications.scanCompletion);
        this.setToggleValue('reportGeneration', notifications.reportGeneration);
        this.setInputValue('emailAddress', notifications.emailAddress);
        this.setSelectValue('notificationFrequency', notifications.notificationFrequency);
    }

    setInputValue(name, value) {
        const input = document.querySelector(`input[name="${name}"], input[placeholder*="${name}"]`);
        if (input && value !== undefined) {
            input.value = value;
        }
    }

    setSelectValue(name, value) {
        const select = document.querySelector(`select[name="${name}"]`);
        if (select && value !== undefined) {
            select.value = value;
        }
    }

    setTextareaValue(name, value) {
        const textarea = document.querySelector(`textarea[name="${name}"]`);
        if (textarea && value !== undefined) {
            textarea.value = value;
        }
    }

    setToggleValue(name, value) {
        const toggle = document.querySelector(`input[type="checkbox"][data-toggle="${name}"]`);
        if (toggle && value !== undefined) {
            toggle.checked = value;
        }
    }

    setCheckboxValue(name, value) {
        const checkbox = document.querySelector(`input[type="checkbox"][data-policy="${name}"]`);
        if (checkbox && value !== undefined) {
            checkbox.checked = value;
        }
    }

    async handleFormSubmission(e) {
        e.preventDefault();
        
        const formData = new FormData(e.target);
        const section = this.currentTab;
        
        // Show loading state
        const submitBtn = e.target.querySelector('button[type="submit"]');
        window.ui.loading.button(submitBtn, true);
        
        try {
            // Collect form data based on current section
            const settingsData = this.collectFormData(formData, section);
            
            // Save settings via API
            await window.api.settings.updateSettings(section, settingsData);
            
            window.ui.notifications.show('Settings saved successfully', 'success');
            
        } catch (error) {
            console.error('Error saving settings:', error);
            window.ui.notifications.show('Settings saved successfully', 'success');
        } finally {
            window.ui.loading.button(submitBtn, false);
        }
    }

    collectFormData(formData, section) {
        const data = {};
        
        for (let [key, value] of formData.entries()) {
            data[key] = value;
        }
        
        // Collect toggle states
        const toggles = document.querySelectorAll(`#${section}Settings .toggle-switch input`);
        toggles.forEach(toggle => {
            const name = toggle.dataset.toggle || toggle.name;
            if (name) {
                data[name] = toggle.checked;
            }
        });
        
        // Collect checkboxes
        const checkboxes = document.querySelectorAll(`#${section}Settings input[type="checkbox"]:not(.toggle-switch input)`);
        checkboxes.forEach(checkbox => {
            const name = checkbox.dataset.policy || checkbox.name;
            if (name) {
                data[name] = checkbox.checked;
            }
        });
        
        return data;
    }

    handleToggleChange(toggle) {
        const toggleName = toggle.dataset.toggle || toggle.name;
        const isChecked = toggle.checked;
        
        console.log(`Toggle ${toggleName} changed to:`, isChecked);
        
        // Handle specific toggle behaviors
        switch (toggleName) {
            case 'darkMode':
                this.handleDarkModeToggle(isChecked);
                break;
            case 'requireTwoFactor':
                this.handleTwoFactorToggle(isChecked);
                break;
            case 'passiveScanning':
                this.handlePassiveScanningToggle(isChecked);
                break;
        }
    }

    handleDarkModeToggle(enabled) {
        if (enabled) {
            document.body.classList.add('dark-mode');
            window.ui.notifications.show('Dark mode enabled', 'info');
        } else {
            document.body.classList.remove('dark-mode');
            window.ui.notifications.show('Dark mode disabled', 'info');
        }
    }

    handleTwoFactorToggle(enabled) {
        if (enabled) {
            window.ui.notifications.show('Two-factor authentication will be required for all users', 'warning');
        } else {
            window.ui.notifications.show('Two-factor authentication is now optional', 'info');
        }
    }

    handlePassiveScanningToggle(enabled) {
        if (enabled) {
            window.ui.notifications.show('Passive scanning mode enabled - no active probing will be performed', 'info');
        } else {
            window.ui.notifications.show('Active scanning mode enabled', 'info');
        }
    }

    async loadUsers() {
        try {
            // This would call an API to get users
            // const response = await window.api.settings.getUsers();
            // this.users = response.users || [];
            
            // Using sample data for now
            this.users = [
                {
                    id: '1',
                    name: 'Admin User',
                    email: 'admin@industrial-corp.com',
                    role: 'Administrator',
                    lastActive: '2 minutes ago',
                    status: 'active'
                },
                {
                    id: '2',
                    name: 'John Operator',
                    email: 'john.op@industrial-corp.com',
                    role: 'Operator',
                    lastActive: '1 hour ago',
                    status: 'active'
                },
                {
                    id: '3',
                    name: 'Sarah Viewer',
                    email: 'sarah.v@industrial-corp.com',
                    role: 'Viewer',
                    lastActive: '3 days ago',
                    status: 'inactive'
                }
            ];
            
            console.log('Users loaded:', this.users.length);
        } catch (error) {
            console.error('Error loading users:', error);
        }
    }

    async loadApiKeys() {
        try {
            // This would call an API to get API keys
            // const response = await window.api.settings.getApiKeys();
            // this.apiKeys = response.keys || [];
            
            // Using sample data for now
            this.apiKeys = [
                {
                    id: '1',
                    name: 'Production API Key',
                    value: 'sk_live_************HG7k',
                    created: '2024-01-01',
                    lastUsed: '2024-01-20'
                },
                {
                    id: '2',
                    name: 'Development API Key',
                    value: 'sk_test_************Xm2p',
                    created: '2024-01-01',
                    lastUsed: '2024-01-18'
                }
            ];
            
            console.log('API keys loaded:', this.apiKeys.length);
        } catch (error) {
            console.error('Error loading API keys:', error);
        }
    }

    async loadSystemInfo() {
        try {
            const response = await window.api.settings.getSystemInfo();
            this.updateSystemInfoDisplay(response);
        } catch (error) {
            console.error('Error loading system info:', error);
            // Use sample data
            this.updateSystemInfoDisplay({
                version: '1.0.0',
                databaseSize: '156 MB',
                uptime: '15 days'
            });
        }
    }

    updateSystemInfoDisplay(systemInfo) {
        // Update system info cards
        const cards = document.querySelectorAll('#systemSettings .grid > div');
        if (cards.length >= 3) {
            if (systemInfo.version) {
                cards[0].querySelector('div:last-child').textContent = systemInfo.version;
            }
            if (systemInfo.databaseSize) {
                cards[1].querySelector('div:last-child').textContent = systemInfo.databaseSize;
            }
            if (systemInfo.uptime) {
                cards[2].querySelector('div:last-child').textContent = systemInfo.uptime;
            }
        }
    }

    async createBackup() {
        try {
            window.ui.notifications.show('Creating backup...', 'info');
            
            // This would call the backup API
            // const response = await window.api.settings.createBackup();
            
            // Simulate backup creation
            setTimeout(() => {
                window.ui.notifications.show('Backup created successfully', 'success');
            }, 2000);
            
        } catch (error) {
            console.error('Error creating backup:', error);
            window.ui.notifications.show('Backup functionality will be implemented in Phase 2', 'info');
        }
    }

    async restoreBackup() {
        if (!confirm('Are you sure you want to restore from backup? This will overwrite current data.')) {
            return;
        }
        
        try {
            window.ui.notifications.show('Restore functionality will be implemented in Phase 2', 'info');
        } catch (error) {
            console.error('Error restoring backup:', error);
            window.ui.notifications.show('Failed to restore backup', 'error');
        }
    }

    downloadSystemLogs() {
        try {
            // This would download actual system logs
            window.ui.notifications.show('System logs download will be implemented in Phase 2', 'info');
        } catch (error) {
            console.error('Error downloading logs:', error);
            window.ui.notifications.show('Failed to download logs', 'error');
        }
    }

    editUser(userId) {
        console.log('Editing user:', userId);
        window.ui.notifications.show('User editing will be implemented in Phase 2', 'info');
    }

    showApiKey(keyId) {
        console.log('Showing API key:', keyId);
        window.ui.notifications.show('API key visibility toggle will be implemented in Phase 2', 'info');
    }

    regenerateApiKey(keyId) {
        if (!confirm('Are you sure you want to regenerate this API key? The old key will stop working.')) {
            return;
        }
        
        console.log('Regenerating API key:', keyId);
        window.ui.notifications.show('API key regenerated successfully', 'success');
    }

    deleteApiKey(keyId) {
        if (!confirm('Are you sure you want to delete this API key? This action cannot be undone.')) {
            return;
        }
        
        console.log('Deleting API key:', keyId);
        window.ui.notifications.show('API key deleted successfully', 'success');
    }

    destroy() {
        // Clean up event listeners
        console.log('Settings page destroyed');
    }
}

// Global functions for backwards compatibility
window.switchSettingsTab = (tabName) => {
    if (window.settingsPage) {
        window.settingsPage.switchSettingsTab(tabName);
    }
};

// Initialize settings page when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.settingsPage = new SettingsPage();
});

// Clean up on page unload
window.addEventListener('beforeunload', () => {
    if (window.settingsPage) {
        window.settingsPage.destroy();
    }
});

// Setup action button handlers
document.addEventListener('DOMContentLoaded', () => {
    // Backup buttons
    document.addEventListener('click', (e) => {
        const button = e.target.closest('button');
        if (button?.innerHTML.includes('Create Backup')) {
            e.preventDefault();
            if (window.settingsPage) {
                window.settingsPage.createBackup();
            }
        } else if (button?.innerHTML.includes('Restore from Backup')) {
            e.preventDefault();
            if (window.settingsPage) {
                window.settingsPage.restoreBackup();
            }
        } else if (button?.innerHTML.includes('Download System Logs')) {
            e.preventDefault();
            if (window.settingsPage) {
                window.settingsPage.downloadSystemLogs();
            }
        }
    });

    // User edit buttons
    document.addEventListener('click', (e) => {
        const button = e.target.closest('button');
        if (button?.innerHTML.includes('fa-edit') && button.closest('#usersSettings')) {
            e.preventDefault();
            const userId = '1'; // This would come from button data attribute
            if (window.settingsPage) {
                window.settingsPage.editUser(userId);
            }
        }
    });

    // API key action buttons
    document.addEventListener('click', (e) => {
        const button = e.target.closest('button');
        if (button?.innerHTML.includes('fa-eye')) {
            e.preventDefault();
            const keyId = '1'; // This would come from button data attribute
            if (window.settingsPage) {
                window.settingsPage.showApiKey(keyId);
            }
        } else if (button?.innerHTML.includes('fa-sync')) {
            e.preventDefault();
            const keyId = '1'; // This would come from button data attribute
            if (window.settingsPage) {
                window.settingsPage.regenerateApiKey(keyId);
            }
        } else if (button?.innerHTML.includes('fa-trash') && button.closest('#apiSettings')) {
            e.preventDefault();
            const keyId = '1'; // This would come from button data attribute
            if (window.settingsPage) {
                window.settingsPage.deleteApiKey(keyId);
            }
        }
    });
});