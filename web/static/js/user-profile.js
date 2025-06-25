// User Profile Component - Reusable across all pages
// Include this script in all pages that need user profile functionality

// Initialize user profile when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeUserProfile();
});

// Initialize user profile component
function initializeUserProfile() {
    // Load user data
    loadUserProfile();
    
    // Setup dropdown menu
    setupProfileDropdown();
    
    // Add necessary styles if not already present
    addProfileStyles();
}

// Add profile styles to the page
function addProfileStyles() {
    if (document.getElementById('user-profile-styles')) return;
    
    const styles = `
    <style id="user-profile-styles">
        /* User Profile Styles */
        .user-profile {
            display: flex;
            align-items: center;
            gap: 12px;
            cursor: pointer;
            padding: 8px 12px;
            border-radius: var(--radius-md);
            transition: all 0.2s ease;
            position: relative;
        }

        .user-profile:hover {
            background-color: var(--bg-tertiary);
        }

        .user-avatar {
            width: 36px;
            height: 36px;
            border-radius: 50%;
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: 600;
        }

        .user-info {
            display: flex;
            flex-direction: column;
            align-items: flex-start;
        }

        .user-name {
            font-size: 14px;
            font-weight: 600;
            color: var(--text-primary);
        }

        .user-role {
            font-size: 12px;
            color: var(--text-tertiary);
        }

        /* Profile Dropdown Styles */
        .profile-dropdown {
            position: absolute;
            top: calc(100% + 8px);
            right: 0;
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-lg);
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1);
            min-width: 240px;
            display: none;
            z-index: 9999;
            opacity: 0;
            transform: translateY(-10px);
            transition: all 0.2s ease;
        }

        .profile-dropdown.active {
            display: block !important;
            opacity: 1 !important;
            transform: translateY(0) !important;
        }

        .dropdown-header {
            padding: 16px;
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .dropdown-avatar {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: 600;
        }

        .dropdown-info {
            flex: 1;
        }

        .dropdown-name {
            font-size: 14px;
            font-weight: 600;
            color: var(--text-primary);
        }

        .dropdown-email {
            font-size: 12px;
            color: var(--text-secondary);
        }

        .dropdown-divider {
            height: 1px;
            background-color: var(--border-color);
            margin: 0;
        }

        .dropdown-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px 16px;
            color: var(--text-secondary);
            text-decoration: none;
            transition: all 0.2s ease;
            font-size: 14px;
            cursor: pointer;
        }

        .dropdown-item:hover {
            background-color: var(--bg-tertiary);
            color: var(--text-primary);
        }

        .dropdown-item.logout {
            color: var(--danger-color);
        }

        .dropdown-item.logout:hover {
            background-color: #FEE2E2;
        }

        .dropdown-item i {
            width: 16px;
            text-align: center;
        }

        /* Notification Styles */
        .notifications {
            position: relative;
            cursor: pointer;
            margin-right: 16px;
        }

        .notification-icon {
            width: 40px;
            height: 40px;
            border-radius: var(--radius-md);
            background-color: var(--bg-tertiary);
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--text-secondary);
            font-size: 18px;
            transition: all 0.2s ease;
        }

        .notification-icon:hover {
            color: var(--text-primary);
            background-color: var(--bg-primary);
        }

        .notification-badge {
            position: absolute;
            top: -4px;
            right: -4px;
            width: 20px;
            height: 20px;
            background-color: var(--danger-color);
            color: white;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 11px;
            font-weight: 600;
        }

        @media (max-width: 768px) {
            .user-info {
                display: none;
            }
        }
    </style>
    `;
    
    document.head.insertAdjacentHTML('beforeend', styles);
}

// Create profile HTML structure
function createProfileHTML() {
    return `
        <div class="notifications">
            <div class="notification-icon">
                <i class="fas fa-bell"></i>
                <span class="notification-badge">3</span>
            </div>
        </div>
        
        <div class="user-menu-container">
            <div class="user-menu" onclick="toggleUserMenu()">
                <div class="user-avatar" id="userAvatar">JD</div>
                <div class="user-info">
                    <div class="user-name" id="userName">John Doe</div>
                    <div class="user-role" id="userRole">Administrator</div>
                </div>
                <i class="fas fa-chevron-down" style="color: var(--text-tertiary); font-size: 12px; margin-left: 8px;"></i>
            </div>
            
            <div class="dropdown-menu profile-dropdown" id="userDropdown">
                <div class="dropdown-header">
                    <div class="dropdown-avatar" id="dropdownAvatar">JD</div>
                    <div class="dropdown-info">
                        <div class="dropdown-name" id="dropdownName">John Doe</div>
                        <div class="dropdown-email" id="dropdownEmail">john@example.com</div>
                    </div>
                </div>
                <div class="dropdown-divider"></div>
                <a href="/profile" class="dropdown-item">
                    <i class="fas fa-user"></i>
                    My Profile
                </a>
                <a href="/settings" class="dropdown-item">
                    <i class="fas fa-cog"></i>
                    Account Settings
                </a>
                <a href="#" class="dropdown-item" onclick="openChangePassword(); return false;">
                    <i class="fas fa-key"></i>
                    Change Password
                </a>
                <div class="dropdown-divider"></div>
                <a href="#" class="dropdown-item" onclick="showActivityLog(); return false;">
                    <i class="fas fa-history"></i>
                    Activity Log
                </a>
                <a href="/settings" class="dropdown-item">
                    <i class="fas fa-sliders-h"></i>
                    System Settings
                </a>
                <div class="dropdown-divider"></div>
                <a href="#" class="dropdown-item logout" onclick="handleLogout(); return false;">
                    <i class="fas fa-sign-out-alt"></i>
                    Logout
                </a>
            </div>
        </div>
    `;
}

// Setup profile dropdown
function setupProfileDropdown() {
    const dropdown = document.getElementById('userDropdown');
    if (!dropdown) return;
    
    // Close dropdown when clicking outside
    document.addEventListener('click', function(e) {
        if (!e.target.closest('.user-menu-container')) {
            dropdown.classList.remove('active');
        }
    });
}

// Toggle user dropdown menu
function toggleUserMenu() {
    const dropdown = document.getElementById('userDropdown');
    if (dropdown) {
        dropdown.classList.toggle('active');
    }
}

// Load user profile
async function loadUserProfile() {
    try {
        const token = localStorage.getItem('token') || getCookie('auth_token');
        const response = await fetch('/api/auth/me', {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (response.ok) {
            const user = await response.json();
            updateUserProfile(user);
        }
    } catch (error) {
        console.error('Error loading user profile:', error);
    }
}

// Update user profile display
function updateUserProfile(user) {
    // Update user name
    const userName = document.getElementById('userName');
    if (userName) {
        userName.textContent = user.username || 'User';
    }

    // Update user role
    const userRole = document.getElementById('userRole');
    if (userRole) {
        userRole.textContent = capitalizeFirst(user.role || 'User');
    }

    // Update avatar initials
    const userAvatar = document.getElementById('userAvatar');
    if (userAvatar) {
        const initials = getInitials(user.username || 'User');
        userAvatar.textContent = initials;
    }

    // Update dropdown info
    const dropdownName = document.getElementById('dropdownName');
    if (dropdownName) {
        dropdownName.textContent = user.username || 'User';
    }

    const dropdownEmail = document.getElementById('dropdownEmail');
    if (dropdownEmail) {
        dropdownEmail.textContent = user.email || '';
    }

    const dropdownAvatar = document.getElementById('dropdownAvatar');
    if (dropdownAvatar) {
        const initials = getInitials(user.username || 'User');
        dropdownAvatar.textContent = initials;
    }
}

// Get initials from name
function getInitials(name) {
    const parts = name.split(' ');
    if (parts.length >= 2) {
        return parts[0][0].toUpperCase() + parts[1][0].toUpperCase();
    }
    return name.substring(0, 2).toUpperCase();
}

// Capitalize first letter
function capitalizeFirst(str) {
    return str.charAt(0).toUpperCase() + str.slice(1);
}

// Get cookie helper
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
    return null;
}

// Logout function
async function handleLogout() {
    try {
        const token = localStorage.getItem('token') || getCookie('auth_token');
        
        await fetch('/api/auth/logout', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });
        
        // Clear local storage and redirect
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        document.cookie = 'auth_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
        
        window.location.href = '/login';
    } catch (error) {
        console.error('Error during logout:', error);
        localStorage.removeItem('token');
        window.location.href = '/login';
    }
}

// Placeholder functions
function openChangePassword() {
    showNotification('Change password feature coming soon', 'info');
    toggleUserMenu();
}

function showActivityLog() {
    showNotification('Activity log feature coming soon', 'info');
    toggleUserMenu();
}

// Show notification helper
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
        background: ${type === 'success' ? '#10B981' : type === 'error' ? '#EF4444' : type === 'warning' ? '#F59E0B' : '#3B82F6'};
        color: white;
    `;
    
    document.body.appendChild(notification);
    
    // Remove after 5 seconds
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease-out';
        setTimeout(() => notification.remove(), 300);
    }, 5000);
}

// Export for use in other scripts
window.UserProfile = {
    init: initializeUserProfile,
    createHTML: createProfileHTML,
    load: loadUserProfile,
    logout: handleLogout
};