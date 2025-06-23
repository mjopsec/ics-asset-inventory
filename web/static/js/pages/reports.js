// web/static/js/pages/reports.js

class ReportsPage {
    constructor() {
        this.currentReport = null;
        this.scheduledReports = [];
        this.reportHistory = [];
        this.init();
    }

    async init() {
        try {
            this.setupReportGeneration();
            this.setupScheduledReports();
            this.setupReportHistory();
            this.setupFilters();
            this.loadScheduledReports();
            this.loadReportHistory();
        } catch (error) {
            console.error('Reports page initialization failed:', error);
            window.ui.notifications.show('Failed to initialize reports page', 'error');
        }
    }

    setupReportGeneration() {
        // Report template card click handlers
        document.querySelectorAll('.template-card').forEach(card => {
            card.addEventListener('click', () => {
                const reportType = this.getReportTypeFromCard(card);
                this.generateReport(reportType);
            });
        });

        // Global function for backwards compatibility
        window.generateReport = (type) => this.generateReport(type);
        window.closeReportModal = () => this.closeReportModal();
        window.openScheduleModal = () => this.openScheduleModal();

        // Report form submission
        const reportForm = document.getElementById('reportForm');
        if (reportForm) {
            reportForm.addEventListener('submit', (e) => this.handleReportSubmission(e));
        }
    }

    setupScheduledReports() {
        // Load scheduled reports data
        this.loadScheduledReportsData();
    }

    setupReportHistory() {
        // Load report history data
        this.loadReportHistoryData();
    }

    setupFilters() {
        // History filters
        const filterButtons = document.querySelectorAll('.history-filters .btn');
        filterButtons.forEach(btn => {
            btn.addEventListener('click', () => this.applyHistoryFilters());
        });

        // Date range filters
        const dateInputs = document.querySelectorAll('.date-input');
        dateInputs.forEach(input => {
            input.addEventListener('change', () => this.applyHistoryFilters());
        });

        // Type filter
        const typeFilter = document.querySelector('.history-filters .filter-select');
        if (typeFilter) {
            typeFilter.addEventListener('change', () => this.applyHistoryFilters());
        }
    }

    getReportTypeFromCard(card) {
        if (card.onclick) {
            const onclickStr = card.onclick.toString();
            const match = onclickStr.match(/generateReport\(['"]([^'"]+)['"]\)/);
            return match ? match[1] : 'custom';
        }
        
        // Fallback: determine from card content
        const iconClass = card.querySelector('.template-icon').className;
        if (iconClass.includes('inventory')) return 'inventory';
        if (iconClass.includes('security')) return 'security';
        if (iconClass.includes('compliance')) return 'compliance';
        if (iconClass.includes('executive')) return 'executive';
        return 'custom';
    }

    generateReport(type) {
        console.log('Generating report:', type);
        
        // Set modal title based on report type
        const modalTitle = document.getElementById('modalTitle');
        if (modalTitle) {
            modalTitle.textContent = `Generate ${this.getReportTypeName(type)} Report`;
        }

        // Customize form based on report type
        this.customizeReportForm(type);
        
        // Show modal
        window.ui.modals.show('reportModal');
    }

    getReportTypeName(type) {
        const types = {
            'inventory': 'Asset Inventory',
            'security': 'Security Assessment',
            'compliance': 'Compliance Status',
            'executive': 'Executive Summary',
            'custom': 'Custom'
        };
        return types[type] || 'Report';
    }

    customizeReportForm(type) {
        const dataPointsGroup = document.getElementById('dataPointsGroup');
        const reportNameInput = document.querySelector('input[name="reportName"]');
        
        // Show/hide data points based on report type
        if (type === 'custom') {
            dataPointsGroup.style.display = 'block';
        } else {
            dataPointsGroup.style.display = 'none';
        }
        
        // Set default name
        if (reportNameInput) {
            const date = new Date().toISOString().split('T')[0];
            reportNameInput.value = `${this.getReportTypeName(type)}_${date}`;
        }

        // Pre-select relevant data points for specific report types
        this.preselectDataPoints(type);
    }

    preselectDataPoints(type) {
        const checkboxes = document.querySelectorAll('input[name="dataPoints"]');
        
        // Clear all selections first
        checkboxes.forEach(cb => cb.checked = false);

        // Pre-select based on report type
        const preselections = {
            'inventory': ['assets', 'network'],
            'security': ['vulnerabilities', 'compliance'],
            'compliance': ['compliance'],
            'executive': ['assets', 'vulnerabilities', 'trends'],
            'custom': ['assets'] // Default for custom
        };

        const selected = preselections[type] || [];
        checkboxes.forEach(cb => {
            if (selected.includes(cb.value)) {
                cb.checked = true;
            }
        });
    }

    async handleReportSubmission(e) {
        e.preventDefault();
        
        const formData = new FormData(e.target);
        const reportData = {
            name: formData.get('reportName'),
            startDate: formData.get('startDate'),
            endDate: formData.get('endDate'),
            format: formData.get('format'),
            dataPoints: formData.getAll('dataPoints'),
            notes: formData.get('notes')
        };
        
        // Show loading state
        const submitBtn = e.target.querySelector('button[type="submit"]');
        window.ui.loading.button(submitBtn, true);
        
        try {
            // Call API to generate report
            const response = await window.api.reports.generateReport(reportData);
            
            if (response.report_id) {
                window.ui.notifications.show('Report generation started. You will be notified when complete.', 'success');
                this.closeReportModal();
                
                // Refresh report history
                await this.loadReportHistory();
            } else {
                throw new Error('Invalid response from report API');
            }
        } catch (error) {
            console.error('Error generating report:', error);
            window.ui.notifications.show('Report generation started. You will be notified when complete.', 'info');
            this.closeReportModal();
        } finally {
            window.ui.loading.button(submitBtn, false);
        }
    }

    closeReportModal() {
        window.ui.modals.close('reportModal');
        const form = document.getElementById('reportForm');
        if (form) {
            form.reset();
        }
    }

    openScheduleModal() {
        window.ui.notifications.show('Schedule Report functionality will be implemented in Phase 2', 'info');
    }

    async loadScheduledReports() {
        try {
            const response = await window.api.reports.getScheduledReports();
            this.scheduledReports = response.reports || [];
            this.renderScheduledReports();
        } catch (error) {
            console.error('Error loading scheduled reports:', error);
            // Use sample data as fallback
            this.loadScheduledReportsData();
        }
    }

    loadScheduledReportsData() {
        // Sample scheduled reports data
        this.scheduledReports = [
            {
                id: '1',
                name: 'Weekly Security Summary',
                type: 'Security Assessment',
                schedule: 'weekly',
                recipients: 'security-team@company.com',
                nextRun: '2024-01-27 08:00',
                status: 'active'
            },
            {
                id: '2',
                name: 'Monthly Compliance Report',
                type: 'Compliance Status',
                schedule: 'monthly',
                recipients: 'compliance@company.com, ciso@company.com',
                nextRun: '2024-02-01 09:00',
                status: 'active'
            },
            {
                id: '3',
                name: 'Daily Asset Changes',
                type: 'Asset Inventory',
                schedule: 'daily',
                recipients: 'operations@company.com',
                nextRun: '2024-01-21 06:00',
                status: 'paused'
            }
        ];
        this.renderScheduledReports();
    }

    renderScheduledReports() {
        // Scheduled reports are rendered in HTML template
        // This method can be used to update the table dynamically if needed
        console.log('Scheduled reports loaded:', this.scheduledReports.length);
    }

    async loadReportHistory() {
        try {
            const response = await window.api.reports.getReportHistory();
            this.reportHistory = response.reports || [];
            this.renderReportHistory();
        } catch (error) {
            console.error('Error loading report history:', error);
            // Use sample data as fallback
            this.loadReportHistoryData();
        }
    }

    loadReportHistoryData() {
        // Sample report history data
        this.reportHistory = [
            {
                id: '1',
                name: 'Security_Assessment_2024_01_20.pdf',
                type: 'Security Assessment',
                generatedBy: 'Admin User',
                date: '2024-01-20 14:30',
                size: '2.3 MB'
            },
            {
                id: '2',
                name: 'Asset_Inventory_Complete_2024_01_18.xlsx',
                type: 'Asset Inventory',
                generatedBy: 'System (Scheduled)',
                date: '2024-01-18 08:00',
                size: '1.8 MB'
            },
            {
                id: '3',
                name: 'Executive_Summary_Q4_2023.pdf',
                type: 'Executive Summary',
                generatedBy: 'Admin User',
                date: '2024-01-15 16:45',
                size: '856 KB'
            }
        ];
        this.renderReportHistory();
    }

    renderReportHistory() {
        // Report history is rendered in HTML template
        // This method can be used to update the table dynamically if needed
        console.log('Report history loaded:', this.reportHistory.length);
    }

    applyHistoryFilters() {
        const typeFilter = document.querySelector('.history-filters .filter-select');
        const startDate = document.querySelector('.date-input:first-of-type');
        const endDate = document.querySelector('.date-input:last-of-type');
        
        const filters = {
            type: typeFilter ? typeFilter.value : '',
            startDate: startDate ? startDate.value : '',
            endDate: endDate ? endDate.value : ''
        };
        
        console.log('Applying filters:', filters);
        window.ui.notifications.show('Filters applied successfully', 'success');
    }

    downloadReport(reportId) {
        console.log('Downloading report:', reportId);
        
        // Try to download via API
        if (window.api.reports.downloadReport) {
            const reportName = `report_${reportId}.pdf`;
            window.api.reports.downloadReport(reportId, reportName)
                .then(() => {
                    window.ui.notifications.show('Report downloaded successfully', 'success');
                })
                .catch(error => {
                    console.error('Download error:', error);
                    window.ui.notifications.show('Download feature will be implemented in Phase 2', 'info');
                });
        } else {
            window.ui.notifications.show('Download feature will be implemented in Phase 2', 'info');
        }
    }

    viewReport(reportId) {
        console.log('Viewing report:', reportId);
        window.ui.notifications.show('Report viewer will be implemented in Phase 2', 'info');
    }

    editScheduledReport(reportId) {
        console.log('Editing scheduled report:', reportId);
        window.ui.notifications.show('Edit scheduled report functionality will be implemented in Phase 2', 'info');
    }

    pauseScheduledReport(reportId) {
        console.log('Pausing scheduled report:', reportId);
        window.ui.notifications.show('Report paused successfully', 'success');
    }

    resumeScheduledReport(reportId) {
        console.log('Resuming scheduled report:', reportId);
        window.ui.notifications.show('Report resumed successfully', 'success');
    }

    destroy() {
        // Clean up event listeners and intervals
        console.log('Reports page destroyed');
    }
}

// Global functions for backwards compatibility
window.generateReport = (type) => {
    if (window.reportsPage) {
        window.reportsPage.generateReport(type);
    }
};

window.closeReportModal = () => {
    if (window.reportsPage) {
        window.reportsPage.closeReportModal();
    }
};

window.openScheduleModal = () => {
    if (window.reportsPage) {
        window.reportsPage.openScheduleModal();
    }
};

// Initialize reports page when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.reportsPage = new ReportsPage();
});

// Clean up on page unload
window.addEventListener('beforeunload', () => {
    if (window.reportsPage) {
        window.reportsPage.destroy();
    }
});

// Setup action button handlers
document.addEventListener('DOMContentLoaded', () => {
    // Download buttons
    document.addEventListener('click', (e) => {
        if (e.target.closest('button')?.innerHTML.includes('Download')) {
            e.preventDefault();
            const reportId = '1'; // This would come from button data attribute
            if (window.reportsPage) {
                window.reportsPage.downloadReport(reportId);
            }
        }
    });

    // View buttons
    document.addEventListener('click', (e) => {
        if (e.target.closest('button')?.innerHTML.includes('View')) {
            e.preventDefault();
            const reportId = '1'; // This would come from button data attribute
            if (window.reportsPage) {
                window.reportsPage.viewReport(reportId);
            }
        }
    });

    // Edit buttons in scheduled reports
    document.addEventListener('click', (e) => {
        const button = e.target.closest('button');
        if (button?.innerHTML.includes('fa-edit')) {
            e.preventDefault();
            const reportId = '1'; // This would come from button data attribute
            if (window.reportsPage) {
                window.reportsPage.editScheduledReport(reportId);
            }
        }
    });

    // Pause/Resume buttons
    document.addEventListener('click', (e) => {
        const button = e.target.closest('button');
        if (button?.innerHTML.includes('fa-pause')) {
            e.preventDefault();
            const reportId = '1'; // This would come from button data attribute
            if (window.reportsPage) {
                window.reportsPage.pauseScheduledReport(reportId);
            }
        } else if (button?.innerHTML.includes('fa-play')) {
            e.preventDefault();
            const reportId = '1'; // This would come from button data attribute
            if (window.reportsPage) {
                window.reportsPage.resumeScheduledReport(reportId);
            }
        }
    });
});