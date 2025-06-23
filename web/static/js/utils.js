// web/static/js/utils.js

// Date and Time Utilities
const DateUtils = {
    // Format date to local string
    formatDate(date, options = {}) {
        const defaultOptions = {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit'
        };
        return new Date(date).toLocaleString(undefined, { ...defaultOptions, ...options });
    },

    // Get relative time (e.g., "2 hours ago")
    getRelativeTime(date) {
        const now = new Date();
        const diffMs = now - new Date(date);
        const diffMinutes = Math.floor(diffMs / (1000 * 60));
        const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
        const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

        if (diffMinutes < 1) return 'Just now';
        if (diffMinutes < 60) return `${diffMinutes} minute${diffMinutes > 1 ? 's' : ''} ago`;
        if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
        if (diffDays < 30) return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
        
        return this.formatDate(date, { year: 'numeric', month: 'short', day: 'numeric' });
    },

    // Check if date is today
    isToday(date) {
        const today = new Date();
        const checkDate = new Date(date);
        return today.toDateString() === checkDate.toDateString();
    },

    // Get time ago in short format
    getTimeAgoShort(date) {
        const now = new Date();
        const diffMs = now - new Date(date);
        const diffMinutes = Math.floor(diffMs / (1000 * 60));
        const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
        const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

        if (diffMinutes < 1) return 'now';
        if (diffMinutes < 60) return `${diffMinutes}m`;
        if (diffHours < 24) return `${diffHours}h`;
        return `${diffDays}d`;
    }
};

// String Utilities
const StringUtils = {
    // Capitalize first letter
    capitalize(str) {
        if (!str) return '';
        return str.charAt(0).toUpperCase() + str.slice(1);
    },

    // Convert to title case
    toTitleCase(str) {
        return str.replace(/\w\S*/g, (txt) => 
            txt.charAt(0).toUpperCase() + txt.substr(1).toLowerCase()
        );
    },

    // Truncate string with ellipsis
    truncate(str, length = 100, suffix = '...') {
        if (str.length <= length) return str;
        return str.substring(0, length).trim() + suffix;
    },

    // Generate random string
    generateId(length = 8) {
        const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        let result = '';
        for (let i = 0; i < length; i++) {
            result += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return result;
    },

    // Escape HTML
    escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    },

    // Remove HTML tags
    stripHtml(str) {
        const div = document.createElement('div');
        div.innerHTML = str;
        return div.textContent || div.innerText || '';
    }
};

// Number Utilities
const NumberUtils = {
    // Format number with commas
    formatNumber(num) {
        return new Intl.NumberFormat().format(num);
    },

    // Format bytes to human readable
    formatBytes(bytes, decimals = 2) {
        if (bytes === 0) return '0 Bytes';
        
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        
        return parseFloat((bytes / Math.pow(k, i)).toFixed(decimals)) + ' ' + sizes[i];
    },

    // Format percentage
    formatPercentage(value, total, decimals = 1) {
        if (total === 0) return '0%';
        return ((value / total) * 100).toFixed(decimals) + '%';
    },

    // Generate random number between min and max
    random(min, max) {
        return Math.floor(Math.random() * (max - min + 1)) + min;
    },

    // Clamp number between min and max
    clamp(num, min, max) {
        return Math.min(Math.max(num, min), max);
    }
};

// Array Utilities
const ArrayUtils = {
    // Remove duplicates from array
    unique(arr) {
        return [...new Set(arr)];
    },

    // Group array by key
    groupBy(arr, key) {
        return arr.reduce((groups, item) => {
            const group = item[key];
            groups[group] = groups[group] || [];
            groups[group].push(item);
            return groups;
        }, {});
    },

    // Sort array by key
    sortBy(arr, key, order = 'asc') {
        return [...arr].sort((a, b) => {
            const aVal = a[key];
            const bVal = b[key];
            
            if (order === 'desc') {
                return bVal > aVal ? 1 : bVal < aVal ? -1 : 0;
            }
            return aVal > bVal ? 1 : aVal < bVal ? -1 : 0;
        });
    },

    // Chunk array into smaller arrays
    chunk(arr, size) {
        const chunks = [];
        for (let i = 0; i < arr.length; i += size) {
            chunks.push(arr.slice(i, i + size));
        }
        return chunks;
    },

    // Filter array by search term
    search(arr, searchTerm, keys = []) {
        if (!searchTerm) return arr;
        
        const term = searchTerm.toLowerCase();
        return arr.filter(item => {
            if (keys.length === 0) {
                // Search all string properties
                return Object.values(item).some(value => 
                    typeof value === 'string' && value.toLowerCase().includes(term)
                );
            }
            
            // Search specific keys
            return keys.some(key => {
                const value = item[key];
                return typeof value === 'string' && value.toLowerCase().includes(term);
            });
        });
    }
};

// DOM Utilities
const DOMUtils = {
    // Wait for element to exist
    waitForElement(selector, timeout = 5000) {
        return new Promise((resolve, reject) => {
            const element = document.querySelector(selector);
            if (element) {
                resolve(element);
                return;
            }

            const observer = new MutationObserver(() => {
                const element = document.querySelector(selector);
                if (element) {
                    observer.disconnect();
                    resolve(element);
                }
            });

            observer.observe(document.body, {
                childList: true,
                subtree: true
            });

            setTimeout(() => {
                observer.disconnect();
                reject(new Error(`Element ${selector} not found within ${timeout}ms`));
            }, timeout);
        });
    },

    // Check if element is in viewport
    isInViewport(element) {
        const rect = element.getBoundingClientRect();
        return (
            rect.top >= 0 &&
            rect.left >= 0 &&
            rect.bottom <= (window.innerHeight || document.documentElement.clientHeight) &&
            rect.right <= (window.innerWidth || document.documentElement.clientWidth)
        );
    },

    // Smooth scroll to element
    scrollTo(element, offset = 0) {
        const rect = element.getBoundingClientRect();
        const top = rect.top + window.pageYOffset - offset;
        
        window.scrollTo({
            top: top,
            behavior: 'smooth'
        });
    },

    // Get computed style value
    getStyle(element, property) {
        return window.getComputedStyle(element).getPropertyValue(property);
    },

    // Create element with attributes
    createElement(tag, attributes = {}, children = []) {
        const element = document.createElement(tag);
        
        Object.entries(attributes).forEach(([key, value]) => {
            if (key === 'className') {
                element.className = value;
            } else if (key === 'innerHTML') {
                element.innerHTML = value;
            } else if (key === 'textContent') {
                element.textContent = value;
            } else {
                element.setAttribute(key, value);
            }
        });

        children.forEach(child => {
            if (typeof child === 'string') {
                element.appendChild(document.createTextNode(child));
            } else {
                element.appendChild(child);
            }
        });

        return element;
    }
};

// URL Utilities
const URLUtils = {
    // Get URL parameters
    getParams() {
        return new URLSearchParams(window.location.search);
    },

    // Get specific parameter
    getParam(name) {
        return this.getParams().get(name);
    },

    // Set URL parameter without reload
    setParam(name, value) {
        const params = this.getParams();
        params.set(name, value);
        const newURL = `${window.location.pathname}?${params.toString()}`;
        history.replaceState(null, '', newURL);
    },

    // Remove URL parameter
    removeParam(name) {
        const params = this.getParams();
        params.delete(name);
        const newURL = params.toString() ? 
            `${window.location.pathname}?${params.toString()}` : 
            window.location.pathname;
        history.replaceState(null, '', newURL);
    },

    // Build query string from object
    buildQuery(params) {
        return new URLSearchParams(params).toString();
    }
};

// Storage Utilities
const StorageUtils = {
    // Local storage with JSON support
    local: {
        set(key, value) {
            try {
                localStorage.setItem(key, JSON.stringify(value));
                return true;
            } catch (e) {
                console.error('localStorage set error:', e);
                return false;
            }
        },

        get(key, defaultValue = null) {
            try {
                const item = localStorage.getItem(key);
                return item ? JSON.parse(item) : defaultValue;
            } catch (e) {
                console.error('localStorage get error:', e);
                return defaultValue;
            }
        },

        remove(key) {
            try {
                localStorage.removeItem(key);
                return true;
            } catch (e) {
                console.error('localStorage remove error:', e);
                return false;
            }
        },

        clear() {
            try {
                localStorage.clear();
                return true;
            } catch (e) {
                console.error('localStorage clear error:', e);
                return false;
            }
        }
    },

    // Session storage with JSON support
    session: {
        set(key, value) {
            try {
                sessionStorage.setItem(key, JSON.stringify(value));
                return true;
            } catch (e) {
                console.error('sessionStorage set error:', e);
                return false;
            }
        },

        get(key, defaultValue = null) {
            try {
                const item = sessionStorage.getItem(key);
                return item ? JSON.parse(item) : defaultValue;
            } catch (e) {
                console.error('sessionStorage get error:', e);
                return defaultValue;
            }
        },

        remove(key) {
            try {
                sessionStorage.removeItem(key);
                return true;
            } catch (e) {
                console.error('sessionStorage remove error:', e);
                return false;
            }
        },

        clear() {
            try {
                sessionStorage.clear();
                return true;
            } catch (e) {
                console.error('sessionStorage clear error:', e);
                return false;
            }
        }
    }
};

// Device/Browser Detection
const DeviceUtils = {
    // Check if mobile device
    isMobile() {
        return /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
    },

    // Check if tablet
    isTablet() {
        return /iPad|Android(?!.*Mobile)/i.test(navigator.userAgent);
    },

    // Check if desktop
    isDesktop() {
        return !this.isMobile() && !this.isTablet();
    },

    // Get viewport size
    getViewport() {
        return {
            width: window.innerWidth || document.documentElement.clientWidth,
            height: window.innerHeight || document.documentElement.clientHeight
        };
    },

    // Check if online
    isOnline() {
        return navigator.onLine;
    },

    // Get browser info
    getBrowser() {
        const ua = navigator.userAgent;
        let browser = 'Unknown';
        
        if (ua.includes('Firefox')) browser = 'Firefox';
        else if (ua.includes('Chrome')) browser = 'Chrome';
        else if (ua.includes('Safari')) browser = 'Safari';
        else if (ua.includes('Edge')) browser = 'Edge';
        else if (ua.includes('Opera')) browser = 'Opera';
        
        return browser;
    }
};

// Export utilities
window.utils = {
    date: DateUtils,
    string: StringUtils,
    number: NumberUtils,
    array: ArrayUtils,
    dom: DOMUtils,
    url: URLUtils,
    storage: StorageUtils,
    device: DeviceUtils
};

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        DateUtils,
        StringUtils,
        NumberUtils,
        ArrayUtils,
        DOMUtils,
        URLUtils,
        StorageUtils,
        DeviceUtils
    };
}