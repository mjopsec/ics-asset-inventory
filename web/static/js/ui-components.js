// web/static/js/ui-components.js

// Notification System
class NotificationManager {
    constructor() {
        this.container = this.createContainer();
        this.notifications = new Map();
        this.idCounter = 0;
    }

    createContainer() {
        const container = document.createElement('div');
        container.id = 'notification-container';
        container.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 9999;
            display: flex;
            flex-direction: column;
            gap: 12px;
            max-width: 400px;
        `;
        document.body.appendChild(container);
        return container;
    }

    show(message, type = 'info', duration = 5000) {
        const id = ++this.idCounter;
        const notification = this.createNotification(id, message, type);
        
        this.container.appendChild(notification);
        this.notifications.set(id, notification);

        // Animate in
        requestAnimationFrame(() => {
            notification.style.animation = 'slideIn 0.3s ease-out';
        });

        // Auto remove
        if (duration > 0) {
            setTimeout(() => this.remove(id), duration);
        }

        return id;
    }

    createNotification(id, message, type) {
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.style.cssText = `
            padding: 16px 24px;
            border-radius: 8px;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
            display: flex;
            align-items: center;
            gap: 12px;
            max-width: 100%;
            word-wrap: break-word;
            position: relative;
            cursor: pointer;
        `;

        // Set colors based on type
        const colors = {
            success: { bg: '#10B981', color: 'white' },
            error: { bg: '#EF4444', color: 'white' },
            warning: { bg: '#F59E0B', color: 'white' },
            info: { bg: '#3B82F6', color: 'white' }
        };

        const colorScheme = colors[type] || colors.info;
        notification.style.backgroundColor = colorScheme.bg;
        notification.style.color = colorScheme.color;

        // Add icon
        const icons = {
            success: 'fa-check-circle',
            error: 'fa-exclamation-circle',
            warning: 'fa-exclamation-triangle',
            info: 'fa-info-circle'
        };

        const icon = document.createElement('i');
        icon.className = `fas ${icons[type] || icons.info}`;
        icon.style.fontSize = '18px';

        // Add message
        const messageEl = document.createElement('span');
        messageEl.textContent = message;
        messageEl.style.flex = '1';

        // Add close button
        const closeBtn = document.createElement('button');
        closeBtn.innerHTML = '<i class="fas fa-times"></i>';
        closeBtn.style.cssText = `
            background: none;
            border: none;
            color: inherit;
            cursor: pointer;
            padding: 4px;
            border-radius: 4px;
            opacity: 0.8;
        `;
        closeBtn.onclick = (e) => {
            e.stopPropagation();
            this.remove(id);
        };

        notification.appendChild(icon);
        notification.appendChild(messageEl);
        notification.appendChild(closeBtn);

        // Click to dismiss
        notification.onclick = () => this.remove(id);

        return notification;
    }

    remove(id) {
        const notification = this.notifications.get(id);
        if (notification) {
            notification.style.animation = 'slideOut 0.3s ease-out';
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
                this.notifications.delete(id);
            }, 300);
        }
    }

    clear() {
        this.notifications.forEach((_, id) => this.remove(id));
    }
}

// Modal Manager
class ModalManager {
    constructor() {
        this.activeModals = new Set();
        this.setupKeyboardHandlers();
    }

    setupKeyboardHandlers() {
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && this.activeModals.size > 0) {
                const modals = Array.from(this.activeModals);
                const lastModal = modals[modals.length - 1];
                this.close(lastModal);
            }
        });
    }

    show(modalId) {
        const modal = document.getElementById(modalId);
        if (!modal) {
            console.error(`Modal with id "${modalId}" not found`);
            return;
        }

        modal.classList.add('active');
        this.activeModals.add(modalId);
        document.body.style.overflow = 'hidden';

        // Setup backdrop click handler
        const backdrop = modal.querySelector('.modal-backdrop') || modal;
        backdrop.onclick = (e) => {
            if (e.target === backdrop) {
                this.close(modalId);
            }
        };

        // Setup close button handlers
        modal.querySelectorAll('.modal-close').forEach(btn => {
            btn.onclick = () => this.close(modalId);
        });
    }

    close(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.classList.remove('active');
            this.activeModals.delete(modalId);
            
            if (this.activeModals.size === 0) {
                document.body.style.overflow = '';
            }
        }
    }

    toggle(modalId) {
        const modal = document.getElementById(modalId);
        if (modal && modal.classList.contains('active')) {
            this.close(modalId);
        } else {
            this.show(modalId);
        }
    }
}

// Dropdown Manager
class DropdownManager {
    constructor() {
        this.activeDropdowns = new Set();
        this.setupGlobalHandlers();
    }

    setupGlobalHandlers() {
        document.addEventListener('click', (e) => {
            this.activeDropdowns.forEach(dropdownId => {
                const dropdown = document.getElementById(dropdownId);
                const trigger = document.querySelector(`[data-dropdown="${dropdownId}"]`);
                
                if (dropdown && trigger && 
                    !dropdown.contains(e.target) && 
                    !trigger.contains(e.target)) {
                    this.close(dropdownId);
                }
            });
        });

        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.closeAll();
            }
        });
    }

    toggle(dropdownId) {
        const dropdown = document.getElementById(dropdownId);
        if (!dropdown) return;

        if (this.activeDropdowns.has(dropdownId)) {
            this.close(dropdownId);
        } else {
            this.show(dropdownId);
        }
    }

    show(dropdownId) {
        const dropdown = document.getElementById(dropdownId);
        if (!dropdown) return;

        // Close other dropdowns
        this.closeAll();

        dropdown.style.display = 'block';
        dropdown.style.opacity = '0';
        dropdown.style.transform = 'translateY(-10px)';

        requestAnimationFrame(() => {
            dropdown.classList.add('active');
            dropdown.style.opacity = '1';
            dropdown.style.transform = 'translateY(0)';
        });

        this.activeDropdowns.add(dropdownId);
    }

    close(dropdownId) {
        const dropdown = document.getElementById(dropdownId);
        if (!dropdown) return;

        dropdown.classList.remove('active');
        dropdown.style.opacity = '0';
        dropdown.style.transform = 'translateY(-10px)';

        setTimeout(() => {
            dropdown.style.display = 'none';
        }, 200);

        this.activeDropdowns.delete(dropdownId);
    }

    closeAll() {
        this.activeDropdowns.forEach(id => this.close(id));
    }
}

// Tab Manager
class TabManager {
    constructor() {
        this.setupTabHandlers();
    }

    setupTabHandlers() {
        document.addEventListener('click', (e) => {
            const tab = e.target.closest('[data-tab]');
            if (tab) {
                e.preventDefault();
                const tabName = tab.dataset.tab;
                const container = tab.closest('[data-tab-container]');
                if (container) {
                    this.switchTab(container, tabName);
                }
            }
        });
    }

    switchTab(container, tabName) {
        // Update tab buttons
        container.querySelectorAll('[data-tab]').forEach(tab => {
            tab.classList.toggle('active', tab.dataset.tab === tabName);
        });

        // Update tab content
        container.querySelectorAll('[data-tab-content]').forEach(content => {
            content.classList.toggle('active', content.dataset.tabContent === tabName);
        });

        // Trigger custom event
        container.dispatchEvent(new CustomEvent('tabChanged', {
            detail: { tabName }
        }));
    }
}

// Loading Manager
class LoadingManager {
    constructor() {
        this.loadingElements = new Map();
    }

    show(elementId, text = 'Loading...') {
        const element = document.getElementById(elementId);
        if (!element) return;

        const originalContent = element.innerHTML;
        this.loadingElements.set(elementId, originalContent);

        element.innerHTML = `
            <div class="loading-state" style="display: flex; align-items: center; justify-content: center; gap: 12px; padding: 20px;">
                <div class="loading-spinner" style="
                    width: 20px;
                    height: 20px;
                    border: 2px solid #E2E8F0;
                    border-radius: 50%;
                    border-top-color: #0EA5E9;
                    animation: spin 1s linear infinite;
                "></div>
                <span style="color: #64748B;">${text}</span>
            </div>
        `;
        element.style.pointerEvents = 'none';
    }

    hide(elementId) {
        const element = document.getElementById(elementId);
        const originalContent = this.loadingElements.get(elementId);
        
        if (element && originalContent !== undefined) {
            element.innerHTML = originalContent;
            element.style.pointerEvents = '';
            this.loadingElements.delete(elementId);
        }
    }

    button(button, loading = true) {
        if (loading) {
            button.dataset.originalText = button.innerHTML;
            button.innerHTML = `
                <span class="loading-spinner" style="
                    display: inline-block;
                    width: 16px;
                    height: 16px;
                    border: 2px solid rgba(255, 255, 255, 0.3);
                    border-radius: 50%;
                    border-top-color: white;
                    animation: spin 0.8s linear infinite;
                    margin-right: 8px;
                "></span>
                Loading...
            `;
            button.disabled = true;
        } else {
            button.innerHTML = button.dataset.originalText || 'Submit';
            button.disabled = false;
            delete button.dataset.originalText;
        }
    }
}

// Form Validator
class FormValidator {
    constructor() {
        this.validators = {
            required: (value) => value.trim() !== '',
            email: (value) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value),
            minLength: (value, min) => value.length >= min,
            maxLength: (value, max) => value.length <= max,
            pattern: (value, pattern) => new RegExp(pattern).test(value),
            number: (value) => !isNaN(value) && isFinite(value),
            url: (value) => {
                try {
                    new URL(value);
                    return true;
                } catch {
                    return false;
                }
            }
        };
    }

    validateForm(formElement) {
        const errors = [];
        const inputs = formElement.querySelectorAll('[data-validate]');

        inputs.forEach(input => {
            const rules = input.dataset.validate.split('|');
            const fieldErrors = this.validateField(input, rules);
            if (fieldErrors.length > 0) {
                errors.push({ element: input, errors: fieldErrors });
                this.showFieldError(input, fieldErrors[0]);
            } else {
                this.clearFieldError(input);
            }
        });

        return errors;
    }

    validateField(input, rules) {
        const errors = [];
        const value = input.value;

        rules.forEach(rule => {
            const [validator, param] = rule.split(':');
            
            if (this.validators[validator]) {
                if (!this.validators[validator](value, param)) {
                    errors.push(this.getErrorMessage(validator, param, input));
                }
            }
        });

        return errors;
    }

    showFieldError(input, message) {
        input.classList.add('error');
        
        let errorElement = input.parentNode.querySelector('.field-error');
        if (!errorElement) {
            errorElement = document.createElement('div');
            errorElement.className = 'field-error';
            errorElement.style.cssText = `
                color: #EF4444;
                font-size: 12px;
                margin-top: 4px;
            `;
            input.parentNode.appendChild(errorElement);
        }
        
        errorElement.textContent = message;
    }

    clearFieldError(input) {
        input.classList.remove('error');
        const errorElement = input.parentNode.querySelector('.field-error');
        if (errorElement) {
            errorElement.remove();
        }
    }

    getErrorMessage(validator, param, input) {
        const fieldName = input.dataset.fieldName || input.name || 'Field';
        
        const messages = {
            required: `${fieldName} is required`,
            email: `Please enter a valid email address`,
            minLength: `${fieldName} must be at least ${param} characters`,
            maxLength: `${fieldName} must not exceed ${param} characters`,
            pattern: `${fieldName} format is invalid`,
            number: `${fieldName} must be a valid number`,
            url: `Please enter a valid URL`
        };

        return messages[validator] || `${fieldName} is invalid`;
    }
}

// Initialize global UI managers
window.ui = {
    notifications: new NotificationManager(),
    modals: new ModalManager(),
    dropdowns: new DropdownManager(),
    tabs: new TabManager(),
    loading: new LoadingManager(),
    validator: new FormValidator()
};

// Add CSS animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
    @keyframes spin {
        to { transform: rotate(360deg); }
    }
`;
document.head.appendChild(style);

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        NotificationManager,
        ModalManager,
        DropdownManager,
        TabManager,
        LoadingManager,
        FormValidator
    };
}