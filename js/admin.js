// ===== FIREBASE IMPORTS =====
import { initializeApp } from "https://www.gstatic.com/firebasejs/11.0.2/firebase-app.js";
import { getAuth, signInWithEmailAndPassword, signOut, onAuthStateChanged, browserSessionPersistence, setPersistence } from "https://www.gstatic.com/firebasejs/11.0.2/firebase-auth.js";
import { getFirestore, collection, getDocs, doc, deleteDoc, updateDoc, setDoc, getDoc, orderBy, query, where, addDoc, serverTimestamp, limit } from "https://www.gstatic.com/firebasejs/11.0.2/firebase-firestore.js";

// ===== SECURITY: Input Sanitization =====
const SecurityUtils = {
    // HTML entity encoding to prevent XSS
    escapeHtml(str) {
        if (str === null || str === undefined) return '';
        const div = document.createElement('div');
        div.textContent = String(str);
        return div.innerHTML;
    },

    // Strict email validation
    isValidEmail(email) {
        if (!email || typeof email !== 'string') return false;
        if (email.length > 254) return false; // RFC 5321
        const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
        return emailRegex.test(email);
    },

    // Sanitize string input with length limit
    sanitizeString(str, maxLength = 255) {
        if (str === null || str === undefined) return '';
        return String(str).trim().slice(0, maxLength);
    },

    // Validate and sanitize team name
    sanitizeTeamName(name) {
        const sanitized = this.sanitizeString(name, 100);
        // Remove potentially dangerous characters but allow common ones
        return sanitized.replace(/[<>\"'`]/g, '');
    },

    // Validate USN format (adjust pattern as needed)
    isValidUSN(usn) {
        if (!usn) return true; // Optional field
        const usnRegex = /^[A-Za-z0-9]{6,15}$/;
        return usnRegex.test(usn);
    },

    // Sanitize object - remove unexpected fields
    sanitizeObject(obj, allowedFields) {
        if (!obj || typeof obj !== 'object') return {};
        const sanitized = {};
        for (const field of allowedFields) {
            if (obj.hasOwnProperty(field)) {
                sanitized[field] = obj[field];
            }
        }
        return sanitized;
    },

    // Validate document ID format (Firestore)
    isValidDocId(id) {
        if (!id || typeof id !== 'string') return false;
        // Firestore doc IDs: 1-1500 bytes, no forward slashes
        return id.length >= 1 && id.length <= 1500 && !id.includes('/');
    }
};

// ===== SECURITY: Rate Limiter (Client-side) =====
class ClientRateLimiter {
    constructor(options = {}) {
        this.maxAttempts = options.maxAttempts || 5;
        this.windowMs = options.windowMs || 60000; // 1 minute
        this.blockDurationMs = options.blockDurationMs || 300000; // 5 minutes
        this.attempts = new Map();
        this.blocked = new Map();
    }

    isBlocked(key) {
        const blockUntil = this.blocked.get(key);
        if (blockUntil && Date.now() < blockUntil) {
            return true;
        }
        if (blockUntil) this.blocked.delete(key);
        return false;
    }

    recordAttempt(key) {
        if (this.isBlocked(key)) {
            return { allowed: false, retryAfter: Math.ceil((this.blocked.get(key) - Date.now()) / 1000) };
        }

        const now = Date.now();
        const windowStart = now - this.windowMs;

        let attempts = this.attempts.get(key) || [];
        attempts = attempts.filter(t => t > windowStart);
        attempts.push(now);
        this.attempts.set(key, attempts);

        if (attempts.length > this.maxAttempts) {
            this.blocked.set(key, now + this.blockDurationMs);
            return { allowed: false, retryAfter: Math.ceil(this.blockDurationMs / 1000) };
        }

        return { allowed: true, remaining: this.maxAttempts - attempts.length };
    }

    reset(key) {
        this.attempts.delete(key);
        this.blocked.delete(key);
    }
}

// Initialize rate limiters for different actions
const rateLimiters = {
    login: new ClientRateLimiter({ maxAttempts: 5, windowMs: 60000, blockDurationMs: 300000 }),
    delete: new ClientRateLimiter({ maxAttempts: 10, windowMs: 60000, blockDurationMs: 60000 }),
    update: new ClientRateLimiter({ maxAttempts: 30, windowMs: 60000, blockDurationMs: 30000 }),
    bulkAction: new ClientRateLimiter({ maxAttempts: 5, windowMs: 60000, blockDurationMs: 120000 })
};

// ===== FIREBASE CONFIGURATION =====
// Load config from external config.js file (gitignored for security)
// Note: Firebase API keys are designed to be public. Security is enforced via:
// 1. Firebase Security Rules (server-side)
// 2. Firebase Authentication
// 3. App Check (recommended for production)

if (typeof window.firebaseConfig === 'undefined') {
    console.error('[Admin] Firebase config not found. Please create config.js from config.example.js');
    alert('⚠️ Configuration Error\n\nFirebase configuration not found.\n\nPlease create config.js from config.example.js with your Firebase credentials.');
    throw new Error('Firebase configuration required');
}

const app = initializeApp(window.firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);

// ===== GLOBAL STATE =====
let promptquestData = [];
let isLoading = true;
const rowsPerPage = 5;
let currentPage = 1;
let searchTimeouts = {};
let currentDrawerTeamId = null;
let currentDrawerTeamData = null;
let allEvents = []; // Store all loaded events

// ===== ADMIN ROLE MANAGEMENT =====
// Stores the current admin's role and permissions
const AdminPermissions = {
    currentAdmin: null,

    // Set the current admin data after login
    setAdmin(adminData) {
        this.currentAdmin = adminData;
        console.log('[AdminPermissions] Set admin:', adminData?.email, 'Role:', adminData?.role);
    },

    // Clear admin data on logout
    clear() {
        this.currentAdmin = null;
    },

    // Check if current user is super admin
    isSuperAdmin() {
        return this.currentAdmin?.role === 'super';
    },

    // Check if current user is normal admin
    isNormalAdmin() {
        return this.currentAdmin?.role === 'normal';
    },

    // Check if user can access a specific event
    canAccessEvent(eventCode) {
        if (!this.currentAdmin) return false;
        if (this.isSuperAdmin()) return true;
        return this.currentAdmin.assignedEvents?.includes(eventCode) || false;
    },

    // Check if user can delete (super admin only)
    canDelete() {
        return this.isSuperAdmin();
    },

    // Check if user can manage other admins
    canManageAdmins() {
        return this.isSuperAdmin();
    },

    // Check if user can access trash
    canAccessTrash() {
        return this.isSuperAdmin();
    },

    // Check if user can manage config
    canManageConfig() {
        return this.isSuperAdmin();
    },

    // Check if user can manage registration routing
    canManageRouting() {
        if (this.isSuperAdmin()) return true;
        return this.currentAdmin?.canManageRouting || false;
    },

    // Check if user can create new events
    canCreateEvents() {
        return this.isSuperAdmin();
    },

    // Get list of accessible events for normal admin
    getAccessibleEvents() {
        if (this.isSuperAdmin()) return null; // null = all events
        return this.currentAdmin?.assignedEvents || [];
    },

    // Get current admin info
    getAdminInfo() {
        return {
            email: this.currentAdmin?.email || 'Unknown',
            role: this.currentAdmin?.role || 'unknown',
            displayName: this.currentAdmin?.displayName || 'Admin',
            assignedEvents: this.currentAdmin?.assignedEvents || []
        };
    }
};
window.AdminPermissions = AdminPermissions;

// Check admin role from Firestore after Firebase Auth login
// Supports two lookup methods:
// 1. By UID (for existing admins already bound)
// 2. By email query (for newly added admins, then binds their UID)
async function checkAdminRole(user) {
    if (!user) {
        console.error('[checkAdminRole] No user provided');
        return null;
    }

    try {
        // First, try to find by UID (fastest, for already-bound admins)
        let adminDocRef = doc(db, 'admins', user.uid);
        let adminDoc = await getDoc(adminDocRef);
        let adminData = null;
        let docId = user.uid;

        if (adminDoc.exists()) {
            adminData = adminDoc.data();
            console.log('[checkAdminRole] Found admin by UID');
        } else {
            // Fallback: Query by email (for newly added admins)
            console.log('[checkAdminRole] Not found by UID, searching by email...');
            const adminsRef = collection(db, 'admins');
            const emailQuery = query(adminsRef, where('email', '==', user.email));
            const querySnapshot = await getDocs(emailQuery);

            if (!querySnapshot.empty) {
                // Found by email - get the first matching doc
                const foundDoc = querySnapshot.docs[0];
                adminData = foundDoc.data();
                docId = foundDoc.id;
                console.log('[checkAdminRole] Found admin by email, doc ID:', docId);

                // Migrate: Create new doc with proper UID, delete old one
                if (docId !== user.uid) {
                    console.log('[checkAdminRole] Migrating admin doc to use UID:', user.uid);
                    await setDoc(doc(db, 'admins', user.uid), {
                        ...adminData,
                        uid: user.uid,
                        migratedFrom: docId,
                        migratedAt: serverTimestamp()
                    });
                    // Delete old document
                    await deleteDoc(doc(db, 'admins', docId));
                    console.log('[checkAdminRole] Migration complete');
                }
            }
        }

        if (!adminData) {
            console.warn('[checkAdminRole] User not found in admins collection:', user.email);
            return null;
        }

        // Check if admin is active
        if (!adminData.isActive) {
            console.warn('[checkAdminRole] Admin account is deactivated:', user.email);
            return null;
        }

        // Validate role
        if (!['super', 'normal'].includes(adminData.role)) {
            console.error('[checkAdminRole] Invalid role:', adminData.role);
            return null;
        }

        const result = {
            uid: user.uid,
            email: user.email,
            role: adminData.role,
            displayName: adminData.displayName || user.email,
            assignedEvents: adminData.assignedEvents || [],
            canManageRouting: adminData.canManageRouting || false,
            isActive: adminData.isActive
        };

        // Store in AdminPermissions
        AdminPermissions.setAdmin(result);

        console.log('[checkAdminRole] Admin verified:', result.email, 'Role:', result.role);
        return result;

    } catch (error) {
        console.error('[checkAdminRole] Error checking admin role:', error);
        return null;
    }
}
window.checkAdminRole = checkAdminRole;

// ===== TOAST =====
function showToast(message) {
    const toast = document.getElementById('toast');
    if (!toast) return;
    // Sanitize message to prevent XSS
    toast.textContent = SecurityUtils.escapeHtml(message);
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 3000);
}
window.showToast = showToast;

// ===== SECURITY: Rate Limiter =====
let loginRateLimiter = null;
if (window.RateLimiter && window.SECURITY_CONFIG) {
    loginRateLimiter = new window.RateLimiter({
        ...window.SECURITY_CONFIG.rateLimiting.login,
        name: 'admin_login'
    });
}

// ===== SESSION TIMEOUT WITH VISUAL COUNTDOWN =====
let inactivityTimer;
let countdownInterval;
const SESSION_TIMEOUT_MS = 10 * 60 * 1000; // 10 minutes
const WARNING_THRESHOLD_MS = 3 * 60 * 1000; // Show warning at 3 min
const DANGER_THRESHOLD_MS = 2 * 60 * 1000; // Red at 2 min
let sessionEndTime = 0;

function formatTime(ms) {
    if (ms <= 0) return '0:00';
    const totalSeconds = Math.ceil(ms / 1000);
    const minutes = Math.floor(totalSeconds / 60);
    const seconds = totalSeconds % 60;
    return `${minutes}:${seconds.toString().padStart(2, '0')}`;
}

function updateTimerDisplay() {
    const now = Date.now();
    const remaining = Math.max(0, sessionEndTime - now);
    const timerEl = document.getElementById('sessionTimeRemaining');
    const timerContainer = document.getElementById('sessionTimer');
    const warningBanner = document.getElementById('sessionWarning');
    const warningCountdown = document.getElementById('warningCountdown');

    if (timerEl) {
        timerEl.textContent = formatTime(remaining);
    }

    // Update timer visual state
    if (timerContainer) {
        timerContainer.classList.remove('warning', 'danger');
        if (remaining <= DANGER_THRESHOLD_MS) {
            timerContainer.classList.add('danger');
        } else if (remaining <= WARNING_THRESHOLD_MS) {
            timerContainer.classList.add('warning');
        }
    }

    // Show/hide warning banner
    if (warningBanner) {
        if (remaining <= WARNING_THRESHOLD_MS && remaining > 0) {
            warningBanner.classList.add('active');
            if (warningCountdown) {
                warningCountdown.textContent = formatTime(remaining);
            }
        } else {
            warningBanner.classList.remove('active');
        }
    }

    // Auto logout at 0
    if (remaining <= 0 && auth.currentUser) {
        clearInterval(countdownInterval);
        sessionEndTime = 0;
        signOut(auth).then(() => {
            AdminPermissions.clear();
            document.getElementById('admin-dashboard').classList.remove('active');
            document.getElementById('login-page').style.display = 'flex';
            if (timerEl) timerEl.textContent = '10:00';
            if (timerContainer) timerContainer.classList.remove('warning', 'danger');
            if (warningBanner) warningBanner.classList.remove('active');
            showToast('⏰ Session expired due to inactivity');
        });
    }
}

function resetInactivityTimer() {
    // Reset the session end time
    sessionEndTime = Date.now() + SESSION_TIMEOUT_MS;

    // Clear existing interval and start fresh
    clearInterval(countdownInterval);
    countdownInterval = setInterval(updateTimerDisplay, 1000);

    // Remove warning state
    const warningBanner = document.getElementById('sessionWarning');
    if (warningBanner) warningBanner.classList.remove('active');

    // Immediate update
    updateTimerDisplay();
}

function refreshSession() {
    resetInactivityTimer();
    showToast('✅ Session refreshed! 10 minutes remaining.');
}
window.refreshSession = refreshSession;

function dismissSessionWarning() {
    const warningBanner = document.getElementById('sessionWarning');
    if (warningBanner) warningBanner.classList.remove('active');
}
window.dismissSessionWarning = dismissSessionWarning;

// Session timer counts down from login. Use "Stay Logged In" button to refresh.

// ===== SETTINGS DROPDOWN =====
function toggleSettingsDropdown() {
    const dropdown = document.getElementById('settingsDropdown');
    if (dropdown) {
        dropdown.classList.toggle('active');
    }
}
window.toggleSettingsDropdown = toggleSettingsDropdown;

// Close settings dropdown when clicking outside
document.addEventListener('click', (e) => {
    const dropdown = document.getElementById('settingsDropdown');
    const btn = document.querySelector('.settings-btn');
    if (dropdown && btn && !dropdown.contains(e.target) && !btn.contains(e.target)) {
        dropdown.classList.remove('active');
    }
});

function saveSettings() {
    showToast('✅ Settings saved');
}
window.saveSettings = saveSettings;

// ===== LOGOUT HANDLER =====
function handleLogout() {
    signOut(auth)
        .then(() => {
            clearInterval(countdownInterval);
            sessionEndTime = 0;
            AdminPermissions.clear(); // Clear admin permissions on logout
            document.getElementById('admin-dashboard').classList.remove('active');
            document.getElementById('login-page').style.display = 'flex';

            // Reset timer display
            const timerEl = document.getElementById('sessionTimeRemaining');
            if (timerEl) timerEl.textContent = '10:00';
            const timerContainer = document.getElementById('sessionTimer');
            if (timerContainer) timerContainer.classList.remove('warning', 'danger');
            const warningBanner = document.getElementById('sessionWarning');
            if (warningBanner) warningBanner.classList.remove('active');

            showToast('Logged out successfully');
            console.log('Logout successful');
        })
        .catch((error) => {
            console.error('Logout error:', error);
            showToast('Error logging out');
        });
}
window.handleLogout = handleLogout;

// ===== ROLE-BASED UI VISIBILITY =====
function applyRoleBasedUI() {
    const isSuperAdmin = AdminPermissions.isSuperAdmin();
    const accessibleEvents = AdminPermissions.getAccessibleEvents();

    console.log('[applyRoleBasedUI] Super Admin:', isSuperAdmin, 'Accessible Events:', accessibleEvents);

    // === DELETE BUTTONS: Only visible to super admin ===
    document.querySelectorAll('.action-btn.delete, .delete-btn, [data-action="delete"]').forEach(btn => {
        btn.style.display = isSuperAdmin ? '' : 'none';
    });

    // === TRASH BUTTON: Only visible to super admin ===
    const trashBtn = document.getElementById('trash-btn') || document.querySelector('[onclick*="openTrashView"]');
    if (trashBtn) {
        trashBtn.style.display = isSuperAdmin ? '' : 'none';
    }

    // === ADMIN MANAGEMENT TAB: Only visible to super admin ===
    const adminMgmtTab = document.getElementById('admin-management-tab');
    if (adminMgmtTab) {
        adminMgmtTab.style.display = isSuperAdmin ? '' : 'none';
    }

    // === BULK DELETE BUTTON: Only visible to super admin ===
    const bulkDeleteBtn = document.querySelector('[onclick*="bulkDeleteSelected"]');
    if (bulkDeleteBtn) {
        bulkDeleteBtn.style.display = isSuperAdmin ? '' : 'none';
    }

    // === CONFIG SETTINGS: Only visible to super admin ===
    const configSection = document.getElementById('config-section');
    if (configSection) {
        configSection.style.display = isSuperAdmin ? '' : 'none';
    }

    // === FILTER EVENTS FOR NORMAL ADMINS ===
    if (!isSuperAdmin && accessibleEvents) {
        document.querySelectorAll('.event-card, .event-tab[data-event]').forEach(card => {
            const eventCode = card.dataset.event;
            if (eventCode && !accessibleEvents.includes(eventCode)) {
                card.style.display = 'none';
            }
        });
    }

    // === UPDATE HEADER WITH ROLE BADGE ===
    const headerRoleBadge = document.getElementById('admin-role-badge');
    if (headerRoleBadge) {
        const info = AdminPermissions.getAdminInfo();
        headerRoleBadge.innerHTML = isSuperAdmin
            ? '<span class="role-badge super">🔴 Super Admin</span>'
            : `<span class="role-badge normal">🟡 Admin</span>`;
    }

    // === DISABLE DELETE IN DRAWER FOR NORMAL ADMINS ===
    const drawerDeleteBtn = document.getElementById('drawerDeleteBtn');
    if (drawerDeleteBtn) {
        drawerDeleteBtn.style.display = isSuperAdmin ? '' : 'none';
    }

    // === ADMIN MANAGEMENT QUICK ACTION: Only visible to super admin ===
    const adminMgmtAction = document.getElementById('admin-management-action');
    if (adminMgmtAction) {
        adminMgmtAction.style.display = isSuperAdmin ? '' : 'none';
    }

    // === CREATE EVENT BUTTON: Only visible to super admin ===
    const createEventBtn = document.querySelector('[onclick*="openCreateEventModal"]');
    if (createEventBtn) {
        createEventBtn.style.display = isSuperAdmin ? '' : 'none';
    }

    // === REGISTRATION ROUTING CARD: Only visible to admins with routing permission ===
    const routingCard = document.querySelector('.routing-config-card');
    if (routingCard) {
        routingCard.style.display = AdminPermissions.canManageRouting() ? '' : 'none';
    }
}
window.applyRoleBasedUI = applyRoleBasedUI;

// ===== ADMIN MANAGEMENT FUNCTIONS =====
async function openAdminManagement() {
    if (!AdminPermissions.isSuperAdmin()) {
        showToast('❌ Access denied. Super Admin only.');
        return;
    }

    document.getElementById('adminManagementModal').classList.add('active');
    populateEventCheckboxes();
    await loadAdminList();
}
window.openAdminManagement = openAdminManagement;

async function loadAdminList() {
    const container = document.getElementById('adminListContainer');
    container.innerHTML = '<div style="text-align: center; padding: 20px; color: var(--text-muted);">Loading admins...</div>';

    try {
        const adminsRef = collection(db, 'admins');
        const snapshot = await getDocs(adminsRef);

        if (snapshot.empty) {
            container.innerHTML = '<div style="text-align: center; padding: 20px; color: var(--text-muted);">No admins found</div>';
            return;
        }

        let html = '';
        snapshot.forEach(docSnap => {
            const admin = docSnap.data();
            const roleClass = admin.role === 'super' ? 'super' : 'normal';
            const roleLabel = admin.role === 'super' ? '🔴 Super' : '🟡 Normal';
            const eventsText = admin.role === 'super' ? 'All events' : (admin.assignedEvents?.join(', ') || 'None');
            const routingText = admin.role === 'super' ? '✓' : (admin.canManageRouting ? '✓' : '✗');
            const isSelf = auth.currentUser?.uid === docSnap.id;

            html += `
                <div class="admin-list-item" data-uid="${SecurityUtils.escapeHtml(docSnap.id)}">
                    <div class="admin-info">
                        <span class="admin-email">${SecurityUtils.escapeHtml(admin.email || 'Unknown')}</span>
                        <div class="admin-meta">
                            <span class="admin-role-tag ${roleClass}">${roleLabel}</span>
                            <span>Events: ${SecurityUtils.escapeHtml(eventsText)}</span>
                            <span title="Can manage registration routing">Routing: ${routingText}</span>
                        </div>
                    </div>
                    ${!isSelf ? `
                    <div class="admin-actions">
                        <button class="admin-action-btn edit" onclick="openEditAdminModal('${SecurityUtils.escapeHtml(docSnap.id)}')">Edit</button>
                        <button class="admin-action-btn remove" onclick="removeAdmin('${SecurityUtils.escapeHtml(docSnap.id)}', '${SecurityUtils.escapeHtml(admin.email || '')}')">Remove</button>
                    </div>` : '<span style="color: var(--text-muted); font-size: 12px;">(You)</span>'}
                </div>
            `;
        });

        container.innerHTML = html;
    } catch (error) {
        console.error('[loadAdminList] Error:', error);
        container.innerHTML = '<div style="text-align: center; padding: 20px; color: var(--accent-red);">Error loading admins</div>';
    }
}
window.loadAdminList = loadAdminList;

function populateEventCheckboxes() {
    const container = document.getElementById('eventCheckboxes');

    // If allEvents not loaded yet, show loading message
    if (!allEvents || allEvents.length === 0) {
        container.innerHTML = '<span style="color: var(--text-muted);">Loading events...</span>';
        // Try to load events
        loadAllEvents().then(() => {
            populateEventCheckboxes(); // Retry after loading
        });
        return;
    }

    // Use dynamic allEvents array - automatically includes new events
    container.innerHTML = allEvents
        .filter(e => e.isActive)
        .map(e => `
            <label class="event-checkbox-item">
                <input type="checkbox" name="assignedEvents" value="${SecurityUtils.escapeHtml(e.code)}">
                <span>${SecurityUtils.escapeHtml(e.emoji)} ${SecurityUtils.escapeHtml(e.name)}</span>
            </label>
        `).join('');
}

function toggleEventAssignment() {
    const roleSelect = document.getElementById('newAdminRole');
    const eventGroup = document.getElementById('eventAssignmentGroup');
    eventGroup.style.display = roleSelect.value === 'normal' ? '' : 'none';
}
window.toggleEventAssignment = toggleEventAssignment;

async function addNewAdmin() {
    if (!AdminPermissions.isSuperAdmin()) {
        showToast('❌ Access denied');
        return;
    }

    const email = document.getElementById('newAdminEmail').value.trim();
    const displayName = document.getElementById('newAdminDisplayName').value.trim();
    const role = document.getElementById('newAdminRole').value;

    if (!email || !SecurityUtils.isValidEmail(email)) {
        showToast('❌ Please enter a valid email address');
        return;
    }

    // Get assigned events for normal admins
    let assignedEvents = [];
    let canManageRouting = false;
    if (role === 'normal') {
        document.querySelectorAll('#eventCheckboxes input:checked').forEach(cb => {
            assignedEvents.push(cb.value);
        });
        if (assignedEvents.length === 0) {
            showToast('❌ Please select at least one event for the admin');
            return;
        }
        canManageRouting = document.getElementById('newAdminCanManageRouting')?.checked || false;
    }

    try {
        // Check if email already exists in admins collection
        const adminsRef = collection(db, 'admins');
        const emailQuery = query(adminsRef, where('email', '==', email));
        const existing = await getDocs(emailQuery);

        if (!existing.empty) {
            showToast('❌ An admin with this email already exists');
            return;
        }

        // Create admin document with temporary ID
        // When the user logs in for the first time, checkAdminRole() will:
        // 1. Find this document by email query
        // 2. Migrate it to use their Firebase Auth UID as the document ID
        const tempId = 'pending_' + email.replace(/[^a-zA-Z0-9]/g, '_');

        await setDoc(doc(db, 'admins', tempId), {
            email: email,
            displayName: displayName || email.split('@')[0],
            role: role,
            assignedEvents: role === 'super' ? [] : assignedEvents,
            canManageRouting: role === 'super' ? true : canManageRouting,
            isActive: true,
            createdAt: serverTimestamp(),
            createdBy: auth.currentUser?.email || 'unknown',
            pendingActivation: true
        });

        showToast('✅ Admin added successfully');
        await logAdminAction('admin_added', { email, role, assignedEvents });

        // Clear form
        document.getElementById('newAdminEmail').value = '';
        document.getElementById('newAdminDisplayName').value = '';
        document.getElementById('newAdminRole').value = 'normal';
        const routingCheckbox = document.getElementById('newAdminCanManageRouting');
        if (routingCheckbox) routingCheckbox.checked = false;
        toggleEventAssignment();
        populateEventCheckboxes();

        // Refresh list
        await loadAdminList();

    } catch (error) {
        console.error('[addNewAdmin] Error:', error);
        showToast('❌ Error adding admin: ' + error.message);
    }
}
window.addNewAdmin = addNewAdmin;

async function removeAdmin(uid, email) {
    if (!AdminPermissions.isSuperAdmin()) {
        showToast('❌ Access denied');
        return;
    }

    if (uid === auth.currentUser?.uid) {
        showToast('❌ You cannot remove yourself');
        return;
    }

    if (!confirm(`Are you sure you want to remove ${email} as an admin?`)) {
        return;
    }

    try {
        await deleteDoc(doc(db, 'admins', uid));
        showToast('✅ Admin removed successfully');
        await logAdminAction('admin_removed', { uid, email });
        await loadAdminList();
    } catch (error) {
        console.error('[removeAdmin] Error:', error);
        showToast('❌ Error removing admin: ' + error.message);
    }
}
window.removeAdmin = removeAdmin;

// ===== EDIT ADMIN FUNCTIONS =====
async function openEditAdminModal(uid) {
    if (!AdminPermissions.isSuperAdmin()) {
        showToast('❌ Access denied');
        return;
    }

    try {
        // Fetch admin data from Firestore
        const adminDoc = await getDoc(doc(db, 'admins', uid));
        if (!adminDoc.exists()) {
            showToast('❌ Admin not found');
            return;
        }

        const adminData = adminDoc.data();

        // Populate the edit form
        document.getElementById('editAdminUid').value = uid;
        document.getElementById('editAdminEmail').value = adminData.email || '';
        document.getElementById('editAdminRole').value = adminData.role || 'normal';
        document.getElementById('editAdminCanManageRouting').checked = adminData.canManageRouting || false;

        // Populate event checkboxes
        populateEditEventCheckboxes(adminData.assignedEvents || []);

        // Show/hide event assignment based on role
        toggleEditEventAssignment();

        // Open the modal
        document.getElementById('editAdminModal').classList.add('active');
    } catch (error) {
        console.error('[openEditAdminModal] Error:', error);
        showToast('❌ Error loading admin data');
    }
}
window.openEditAdminModal = openEditAdminModal;

function populateEditEventCheckboxes(selectedEvents = []) {
    const container = document.getElementById('editEventCheckboxes');

    if (!allEvents || allEvents.length === 0) {
        container.innerHTML = '<span style="color: var(--text-muted);">No events available</span>';
        return;
    }

    container.innerHTML = allEvents
        .filter(e => e.isActive)
        .map(e => {
            const isChecked = selectedEvents.includes(e.code) ? 'checked' : '';
            return `
                <label class="event-checkbox-item">
                    <input type="checkbox" name="editAssignedEvents" value="${SecurityUtils.escapeHtml(e.code)}" ${isChecked}>
                    <span>${SecurityUtils.escapeHtml(e.emoji)} ${SecurityUtils.escapeHtml(e.name)}</span>
                </label>
            `;
        }).join('');
}

function toggleEditEventAssignment() {
    const roleSelect = document.getElementById('editAdminRole');
    const eventGroup = document.getElementById('editEventAssignmentGroup');
    const routingGroup = document.getElementById('editRoutingPermissionGroup');
    const isNormal = roleSelect.value === 'normal';

    eventGroup.style.display = isNormal ? '' : 'none';
    routingGroup.style.display = isNormal ? '' : 'none';
}
window.toggleEditEventAssignment = toggleEditEventAssignment;

async function saveAdminChanges() {
    if (!AdminPermissions.isSuperAdmin()) {
        showToast('❌ Access denied');
        return;
    }

    const uid = document.getElementById('editAdminUid').value;
    const role = document.getElementById('editAdminRole').value;
    const canManageRouting = document.getElementById('editAdminCanManageRouting').checked;

    if (!uid) {
        showToast('❌ Invalid admin ID');
        return;
    }

    // Get assigned events for normal admins
    let assignedEvents = [];
    if (role === 'normal') {
        document.querySelectorAll('#editEventCheckboxes input:checked').forEach(cb => {
            assignedEvents.push(cb.value);
        });
        if (assignedEvents.length === 0) {
            showToast('❌ Please select at least one event for the admin');
            return;
        }
    }

    try {
        await updateDoc(doc(db, 'admins', uid), {
            role: role,
            assignedEvents: role === 'super' ? [] : assignedEvents,
            canManageRouting: role === 'super' ? true : canManageRouting
        });

        showToast('✅ Admin updated successfully');
        await logAdminAction('admin_updated', { uid, role, assignedEvents, canManageRouting });

        // Close modal and refresh list
        closeModal('editAdminModal');
        await loadAdminList();
    } catch (error) {
        console.error('[saveAdminChanges] Error:', error);
        showToast('❌ Error updating admin: ' + error.message);
    }
}
window.saveAdminChanges = saveAdminChanges;

// ===== AUDIT LOGGING =====
async function logAdminAction(action, details = {}) {
    try {
        await addDoc(collection(db, 'auditLogs'), {
            action, details,
            adminEmail: auth.currentUser?.email || 'unknown',
            timestamp: serverTimestamp(),
            userAgent: navigator.userAgent
        });
    } catch (e) { console.warn('[Audit] Failed:', e); }
}
window.logAdminAction = logAdminAction;

// ===== FIRESTORE OPERATIONS (SECURED) =====
window.deleteFromFirestore = async function (collectionPath, docId, teamName = 'Unknown') {
    // Input validation
    if (!SecurityUtils.isValidDocId(docId)) {
        console.error('Invalid document ID');
        return { success: false, error: 'Invalid document ID' };
    }

    // Rate limiting
    const rateCheck = rateLimiters.delete.recordAttempt('delete_' + (auth.currentUser?.uid || 'anon'));
    if (!rateCheck.allowed) {
        showToast(`⏳ Too many requests. Try again in ${rateCheck.retryAfter}s`);
        return { success: false, error: 'Rate limited' };
    }

    // Sanitize inputs
    const sanitizedCollection = SecurityUtils.sanitizeString(collectionPath, 100);
    const sanitizedTeamName = SecurityUtils.sanitizeTeamName(teamName);

    try {
        const docRef = doc(db, sanitizedCollection, docId);
        const docSnap = await getDoc(docRef);
        if (docSnap.exists()) {
            const teamData = docSnap.data();
            await setDoc(doc(db, 'trash', docId), {
                ...teamData,
                originalCollection: sanitizedCollection,
                deletedAt: serverTimestamp(),
                deletedBy: auth.currentUser?.email || 'unknown'
            });
            await deleteDoc(docRef);
            await logAdminAction('SOFT_DELETE', {
                teamId: docId,
                teamName: SecurityUtils.escapeHtml(teamData.teamName || sanitizedTeamName)
            });
            return { success: true, deletedData: teamData };
        }
        return { success: false };
    } catch (error) {
        console.error('Error deleting:', error);
        return { success: false, error: error.message };
    }
};

window.updateInFirestore = async function (collectionPath, docId, data) {
    // Input validation
    if (!SecurityUtils.isValidDocId(docId)) {
        console.error('Invalid document ID');
        return false;
    }

    // Rate limiting
    const rateCheck = rateLimiters.update.recordAttempt('update_' + (auth.currentUser?.uid || 'anon'));
    if (!rateCheck.allowed) {
        showToast(`⏳ Too many requests. Try again in ${rateCheck.retryAfter}s`);
        return false;
    }

    // Sanitize collection path
    const sanitizedCollection = SecurityUtils.sanitizeString(collectionPath, 100);

    // Whitelist allowed fields for updates
    const allowedFields = [
        'teamName', 'email', 'status', 'isWinner', 'winnerPosition',
        'member1Name', 'member1Detail', 'member2Name', 'member2Detail',
        'member3Name', 'member3Detail', 'member1', 'member2', 'member3'
    ];
    const sanitizedData = SecurityUtils.sanitizeObject(data, allowedFields);

    // Sanitize string values
    for (const key in sanitizedData) {
        if (typeof sanitizedData[key] === 'string') {
            sanitizedData[key] = SecurityUtils.sanitizeString(sanitizedData[key], 255);
        }
    }

    try {
        await updateDoc(doc(db, sanitizedCollection, docId), sanitizedData);
        await logAdminAction('UPDATE', { teamId: docId, changes: Object.keys(sanitizedData) });
        return true;
    } catch (error) {
        console.error('Error updating:', error);
        return false;
    }
};

window.undoDelete = async function (docId) {
    try {
        const trashRef = doc(db, 'trash', docId);
        const trashSnap = await getDoc(trashRef);
        if (trashSnap.exists()) {
            const data = trashSnap.data();
            const originalCollection = data.originalCollection || 'registrations';
            delete data.originalCollection; delete data.deletedAt; delete data.deletedBy;
            await setDoc(doc(db, originalCollection, docId), data);
            await deleteDoc(trashRef);
            return true;
        }
        return false;
    } catch (error) { console.error('Error restoring:', error); return false; }
};

// ===== ATTENDANCE TRACKING =====
async function markAttended(docId, attended, eventCode) {
    if (!SecurityUtils.isValidDocId(docId)) {
        showToast('⚠️ Invalid team ID');
        return false;
    }

    try {
        await updateDoc(doc(db, 'registrations', docId), {
            attended: attended,
            attendedAt: attended ? serverTimestamp() : null
        });
        await logAdminAction('ATTENDANCE', {
            teamId: docId,
            eventCode: eventCode,
            attended: attended
        });
        showToast(attended ? '✅ Marked as attended' : '⬜ Marked as not attended');
        return true;
    } catch (error) {
        console.error('Error updating attendance:', error);
        showToast('⚠️ Error updating attendance');
        return false;
    }
}
window.markAttended = markAttended;
function openEditModal(teamId, teamName, m1Name, m1Detail, m2Name, m2Detail, m3Name, m3Detail, email) {
    // Validate document ID
    if (!SecurityUtils.isValidDocId(teamId)) {
        showToast('⚠️ Invalid team ID');
        return;
    }

    // Sanitize all inputs before setting values
    document.getElementById('editTeamId').value = SecurityUtils.sanitizeString(teamId, 100);
    document.getElementById('editTeamName').value = SecurityUtils.sanitizeTeamName(teamName);
    document.getElementById('editM1Name').value = SecurityUtils.sanitizeString(m1Name, 100);
    document.getElementById('editM1Detail').value = SecurityUtils.sanitizeString(m1Detail, 100);
    document.getElementById('editM2Name').value = SecurityUtils.sanitizeString(m2Name, 100);
    document.getElementById('editM2Detail').value = SecurityUtils.sanitizeString(m2Detail, 100);
    document.getElementById('editM3Name').value = SecurityUtils.sanitizeString(m3Name, 100);
    document.getElementById('editM3Detail').value = SecurityUtils.sanitizeString(m3Detail, 100);
    document.getElementById('editEmail').value = SecurityUtils.sanitizeString(email, 254);
    document.getElementById('editModal').classList.add('active');
}
window.openEditModal = openEditModal;

function openDeleteModal(teamId, teamName) {
    // Validate document ID
    if (!SecurityUtils.isValidDocId(teamId)) {
        showToast('⚠️ Invalid team ID');
        return;
    }

    document.getElementById('deleteTeamId').value = SecurityUtils.sanitizeString(teamId, 100);
    // Use textContent (safe) instead of innerHTML
    document.getElementById('deleteTeamName').textContent = SecurityUtils.sanitizeTeamName(teamName);
    document.getElementById('deleteModal').classList.add('active');
}
window.openDeleteModal = openDeleteModal;

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) modal.classList.remove('active');
}
window.closeModal = closeModal;

async function saveEdit() {
    const teamId = document.getElementById('editTeamId').value;

    // Validate document ID
    if (!SecurityUtils.isValidDocId(teamId)) {
        showToast('⚠️ Invalid team ID');
        return;
    }

    // Get and sanitize all inputs
    const teamName = SecurityUtils.sanitizeTeamName(document.getElementById('editTeamName').value);
    const email = SecurityUtils.sanitizeString(document.getElementById('editEmail').value, 254);
    const m1Name = SecurityUtils.sanitizeString(document.getElementById('editM1Name').value, 100);

    // Validation
    if (!teamName || teamName.length < 2) {
        showToast('⚠️ Team name must be at least 2 characters');
        return;
    }
    if (teamName.length > 100) {
        showToast('⚠️ Team name too long (max 100 characters)');
        return;
    }
    if (!m1Name || m1Name.length < 2) {
        showToast('⚠️ Member 1 name must be at least 2 characters');
        return;
    }
    if (email && !SecurityUtils.isValidEmail(email)) {
        showToast('⚠️ Invalid email format');
        return;
    }

    const data = {
        teamName,
        email,
        member1Name: m1Name,
        member1Detail: SecurityUtils.sanitizeString(document.getElementById('editM1Detail').value, 100),
        member2Name: SecurityUtils.sanitizeString(document.getElementById('editM2Name').value, 100),
        member2Detail: SecurityUtils.sanitizeString(document.getElementById('editM2Detail').value, 100),
        member3Name: SecurityUtils.sanitizeString(document.getElementById('editM3Name').value, 100),
        member3Detail: SecurityUtils.sanitizeString(document.getElementById('editM3Detail').value, 100),
    };

    const success = await window.updateInFirestore('registrations', teamId, data);
    showToast(success ? '✅ Team updated!' : '⚠️ Update failed');
    closeModal('editModal');
}
window.saveEdit = saveEdit;

async function confirmDelete() {
    const teamId = document.getElementById('deleteTeamId').value;
    const teamName = document.getElementById('deleteTeamName')?.textContent || 'Team';
    closeModal('deleteModal');

    const result = await window.deleteFromFirestore('registrations', teamId, teamName);
    if (result.success) {
        showToast(`🗑️ Deleted "${teamName}"`);
        const row = document.querySelector(`tr[data-team="${teamId}"]`);
        if (row) row.remove();
    } else {
        showToast('⚠️ Delete failed');
    }
}
window.confirmDelete = confirmDelete;

// ===== TEAM DRAWER (SECURED) =====
function openTeamDrawer(teamId, teamData) {
    // Validate inputs
    if (!SecurityUtils.isValidDocId(teamId)) {
        showToast('⚠️ Invalid team ID');
        return;
    }
    if (!teamData || typeof teamData !== 'object') {
        showToast('⚠️ Invalid team data');
        return;
    }

    currentDrawerTeamId = teamId;
    currentDrawerTeamData = teamData;

    const el = (id) => document.getElementById(id);

    // Use textContent for safe rendering (prevents XSS)
    el('drawerTeamName').textContent = SecurityUtils.sanitizeTeamName(teamData.teamName) || '—';
    el('drawerEmail').textContent = SecurityUtils.sanitizeString(teamData.email, 254) || '—';

    const status = SecurityUtils.sanitizeString(teamData.status, 20) || 'Pending';
    const safeStatus = ['Pending', 'Verified'].includes(status) ? status : 'Pending';
    el('drawerStatus').innerHTML = `<span class="status-pill ${safeStatus.toLowerCase()}">${SecurityUtils.escapeHtml(safeStatus)}</span>`;

    let regText = '—';
    if (teamData.registeredAt) {
        try {
            const date = teamData.registeredAt.toDate ? teamData.registeredAt.toDate() : new Date(teamData.registeredAt.seconds * 1000);
            regText = date.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
        } catch (e) { }
    }
    el('drawerRegisteredAt').textContent = regText;
    if (el('drawerUpdatedAt')) el('drawerUpdatedAt').textContent = regText;

    const membersContainer = el('drawerMembers');
    membersContainer.innerHTML = '';

    // Safely render members
    [teamData.member1, teamData.member2, teamData.member3].forEach(m => {
        if (m?.name) {
            const memberDiv = document.createElement('div');
            memberDiv.className = 'member-detail';
            memberDiv.innerHTML = `
                <span class="member-name">👤 ${SecurityUtils.escapeHtml(SecurityUtils.sanitizeString(m.name, 100))}</span>
                <div class="member-info-row"><span>USN</span><span>${SecurityUtils.escapeHtml(SecurityUtils.sanitizeString(m.usn, 20) || '—')}</span></div>
                <div class="member-info-row"><span>Dept</span><span>${SecurityUtils.escapeHtml(SecurityUtils.sanitizeString(m.dept, 50) || '—')}</span></div>
            `;
            membersContainer.appendChild(memberDiv);
        }
    });

    if (!membersContainer.innerHTML) {
        membersContainer.innerHTML = '<p style="color:var(--text-muted);text-align:center;padding:20px;">No members</p>';
    }

    el('drawerVerifyBtn').textContent = safeStatus === 'Verified' ? '⏸ Mark Pending' : '✓ Verify';
    el('teamDrawerOverlay').classList.add('active');
    document.getElementById('teamDrawer').classList.add('active');
    document.body.style.overflow = 'hidden';
}
window.openTeamDrawer = openTeamDrawer;

function closeTeamDrawer() {
    document.getElementById('teamDrawerOverlay').classList.remove('active');
    document.getElementById('teamDrawer').classList.remove('active');
    document.body.style.overflow = '';
    currentDrawerTeamId = null;
    currentDrawerTeamData = null;
}
window.closeTeamDrawer = closeTeamDrawer;

function editFromDrawer() {
    if (!currentDrawerTeamId || !currentDrawerTeamData) return;
    const teamId = currentDrawerTeamId;
    const d = currentDrawerTeamData;
    closeTeamDrawer();
    openEditModal(teamId, d.teamName || '', d.member1?.name || '', `${d.member1?.usn || ''} • ${d.member1?.dept || ''}`, d.member2?.name || '', `${d.member2?.usn || ''} • ${d.member2?.dept || ''}`, d.member3?.name || '', `${d.member3?.usn || ''} • ${d.member3?.dept || ''}`, d.email || '');
}
window.editFromDrawer = editFromDrawer;

async function verifyFromDrawer() {
    if (!currentDrawerTeamId || !currentDrawerTeamData) return;
    await toggleStatus(currentDrawerTeamId, currentDrawerTeamData.status || 'Pending');
    const newStatus = (currentDrawerTeamData.status || 'Pending') === 'Verified' ? 'Pending' : 'Verified';
    currentDrawerTeamData.status = newStatus;
    document.getElementById('drawerStatus').innerHTML = `<span class="status-pill ${newStatus.toLowerCase()}">${newStatus}</span>`;
    document.getElementById('drawerVerifyBtn').textContent = newStatus === 'Verified' ? '⏸ Mark Pending' : '✓ Verify';
}
window.verifyFromDrawer = verifyFromDrawer;

function deleteFromDrawer() {
    if (!currentDrawerTeamId || !currentDrawerTeamData) return;
    const teamId = currentDrawerTeamId;
    const teamName = currentDrawerTeamData.teamName || 'Team';
    closeTeamDrawer();
    openDeleteModal(teamId, teamName);
}
window.deleteFromDrawer = deleteFromDrawer;

function handleRowClick(event, teamId, teamDataStr) {
    // Validate document ID
    if (!SecurityUtils.isValidDocId(teamId)) {
        showToast('⚠️ Invalid team ID');
        return;
    }

    if (event.target.closest('.row-checkbox, .status-pill, a.email-link')) return;
    if (event.target.closest('.action-buttons') && !event.target.closest('.action-btn.view')) return;

    try {
        const teamData = JSON.parse(decodeURIComponent(teamDataStr));
        // Basic validation of parsed data
        if (!teamData || typeof teamData !== 'object') {
            throw new Error('Invalid data format');
        }
        openTeamDrawer(teamId, teamData);
    } catch (e) {
        console.error('Error parsing team data:', e);
        showToast('⚠️ Could not load details');
    }
}
window.handleRowClick = handleRowClick;

// ===== STATUS TOGGLE (SECURED) =====
async function toggleStatus(teamId, currentStatus) {
    // Validate inputs
    if (!SecurityUtils.isValidDocId(teamId)) {
        showToast('⚠️ Invalid team ID');
        return;
    }

    // Validate status value
    const validStatuses = ['Pending', 'Verified'];
    const sanitizedStatus = SecurityUtils.sanitizeString(currentStatus, 20);
    if (!validStatuses.includes(sanitizedStatus)) {
        showToast('⚠️ Invalid status');
        return;
    }

    const newStatus = sanitizedStatus === 'Verified' ? 'Pending' : 'Verified';
    const success = await window.updateInFirestore('registrations', teamId, { status: newStatus });

    if (success) {
        const row = document.querySelector(`tr[data-team="${CSS.escape(teamId)}"]`);
        if (row) {
            const pill = row.querySelector('.status-pill');
            if (pill) {
                pill.textContent = newStatus;
                pill.className = `status-pill clickable ${newStatus.toLowerCase()}`;
            }
        }
        showToast(`✅ Status: ${newStatus}`);
    }
}
window.toggleStatus = toggleStatus;

// ===== BULK ACTIONS (SECURED) =====
async function bulkUpdateStatus(newStatus) {
    // Normalize status to capitalized format
    const statusMap = {
        'verified': 'Verified',
        'pending': 'Pending',
        'Verified': 'Verified',
        'Pending': 'Pending'
    };

    const normalizedStatus = statusMap[newStatus];
    if (!normalizedStatus) {
        showToast('⚠️ Invalid status');
        return;
    }

    // Rate limiting
    const rateCheck = rateLimiters.bulkAction.recordAttempt('bulk_' + (auth.currentUser?.uid || 'anon'));
    if (!rateCheck.allowed) {
        showToast(`⏳ Too many bulk actions. Try again in ${rateCheck.retryAfter}s`);
        return;
    }

    const selected = document.querySelectorAll('.row-checkbox:checked[data-team-id]');
    if (selected.length === 0) { showToast('No teams selected'); return; }
    if (selected.length > 50) { showToast('⚠️ Maximum 50 teams at once'); return; }
    if (!confirm(`Update ${selected.length} team(s) to "${normalizedStatus}"?`)) return;

    let count = 0;
    for (const cb of selected) {
        const teamId = cb.dataset.teamId;
        if (SecurityUtils.isValidDocId(teamId) && await window.updateInFirestore('registrations', teamId, { status: normalizedStatus })) {
            count++;
        }
    }
    showToast(`✅ Updated ${count} team(s)`);
    clearBulkSelection();
    if (window.reloadFirestoreData) window.reloadFirestoreData();
}
window.bulkUpdateStatus = bulkUpdateStatus;

async function bulkDeleteSelected() {
    // Rate limiting
    const rateCheck = rateLimiters.bulkAction.recordAttempt('bulkdel_' + (auth.currentUser?.uid || 'anon'));
    if (!rateCheck.allowed) {
        showToast(`⏳ Too many bulk actions. Try again in ${rateCheck.retryAfter}s`);
        return;
    }

    const selected = document.querySelectorAll('.row-checkbox:checked');
    if (selected.length === 0) { showToast('No teams selected'); return; }
    if (selected.length > 20) { showToast('⚠️ Maximum 20 deletions at once'); return; }
    if (!confirm(`Delete ${selected.length} team(s)? This moves them to trash.`)) return;

    let count = 0;
    for (const cb of selected) {
        const teamId = cb.dataset.teamId;
        if (SecurityUtils.isValidDocId(teamId)) {
            const result = await window.deleteFromFirestore('registrations', teamId);
            if (result.success) count++;
        }
    }
    showToast(`🗑️ Deleted ${count} team(s)`);
    clearBulkSelection();
    if (window.reloadFirestoreData) window.reloadFirestoreData();
}
window.bulkDeleteSelected = bulkDeleteSelected;

function bulkEmailSelected() {
    const selected = document.querySelectorAll('.row-checkbox:checked');
    if (selected.length === 0) { showToast('No teams selected'); return; }
    const emails = [];
    selected.forEach(cb => {
        const row = cb.closest('tr');
        const link = row?.querySelector('.email-link');
        if (link?.textContent && link.textContent !== '—') emails.push(link.textContent.trim());
    });
    if (emails.length === 0) { showToast('⚠️ No emails found'); return; }
    window.open(`mailto:${[...new Set(emails)].join(',')}?subject=${encodeURIComponent('ISTE Event Update')}`);
    showToast(`📧 Opening email for ${emails.length} recipient(s)`);
}
window.bulkEmailSelected = bulkEmailSelected;

function clearBulkSelection() {
    document.querySelectorAll('.row-checkbox').forEach(cb => cb.checked = false);
    document.getElementById('bulkActionBar').classList.remove('active');
}
window.clearBulkSelection = clearBulkSelection;

// ===== TRASH VIEW =====
async function openTrashView() {
    document.getElementById('trashModal').classList.add('active');
    const content = document.getElementById('trashContent');
    content.innerHTML = '<p style="text-align:center;padding:40px;">Loading...</p>';
    try {
        const snapshot = await getDocs(collection(db, 'trash'));
        if (snapshot.empty) { content.innerHTML = '<p style="text-align:center;padding:40px;">🎉 Trash is empty!</p>'; return; }
        let html = '<table class="data-table" style="width:100%"><thead><tr><th>Team</th><th>Event</th><th>Deleted</th><th>Actions</th></tr></thead><tbody>';
        snapshot.forEach(docSnap => {
            const d = docSnap.data();
            const deleted = d.deletedAt?.toDate ? d.deletedAt.toDate().toLocaleDateString() : '—';
            html += `<tr><td><strong>${d.teamName || '—'}</strong></td><td>${d.event || '—'}</td><td>${deleted}</td><td><button class="action-btn" onclick="restoreFromTrash('${docSnap.id}')" style="background:rgba(16,185,129,0.1)">♻️</button><button class="action-btn delete" onclick="permanentDelete('${docSnap.id}')">🗑️</button></td></tr>`;
        });
        content.innerHTML = html + '</tbody></table>';
    } catch (err) { content.innerHTML = '<p style="color:var(--accent-red);text-align:center;padding:40px;">⚠️ Error loading trash</p>'; }
}
window.openTrashView = openTrashView;

async function restoreFromTrash(docId) {
    if (await window.undoDelete(docId)) {
        showToast('♻️ Restored!');
        openTrashView();
        if (window.reloadFirestoreData) window.reloadFirestoreData();
    } else { showToast('⚠️ Could not restore'); }
}
window.restoreFromTrash = restoreFromTrash;

async function permanentDelete(docId) {
    if (!confirm('⚠️ Permanently delete?')) return;
    try {
        await deleteDoc(doc(db, 'trash', docId));
        showToast('🗑️ Permanently deleted');
        openTrashView();
    } catch (e) { showToast('⚠️ Error'); }
}
window.permanentDelete = permanentDelete;

// ===== EVENT NAVIGATION =====
function openEventView(eventCode) {
    document.getElementById('event-selector-view')?.classList.add('hidden');
    document.getElementById('event-detail-view')?.classList.add('active');
    document.querySelectorAll('.event-tab[data-event]').forEach(tab => {
        tab.classList.toggle('active', tab.dataset.event === eventCode);
    });
    switchEvent(eventCode);
    // Update stats for selected event
    if (typeof updateDashboardStats === 'function') {
        updateDashboardStats(eventCode);
    }
}
window.openEventView = openEventView;

function backToEventSelector() {
    document.getElementById('event-detail-view')?.classList.remove('active');
    document.getElementById('event-selector-view')?.classList.remove('hidden');
    // Reset stats to global view
    if (typeof updateDashboardStats === 'function') {
        updateDashboardStats();
    }
}
window.backToEventSelector = backToEventSelector;

function switchEvent(eventName, btn) {
    document.querySelectorAll('.event-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.event-content').forEach(c => c.classList.remove('active'));
    if (btn) btn.classList.add('active');
    else document.querySelector(`.event-tab[data-event="${eventName}"]`)?.classList.add('active');
    document.getElementById(eventName + '-content')?.classList.add('active');
    // Update stats for the switched event
    if (typeof updateDashboardStats === 'function') {
        updateDashboardStats(eventName);
    }
}
window.switchEvent = switchEvent;

function switchSubTab(eventName, subName, btn) {
    const parent = document.getElementById(eventName + '-content');
    if (!parent) return;
    parent.querySelectorAll('.sub-tab').forEach(t => t.classList.remove('active'));
    parent.querySelectorAll('.sub-content').forEach(c => c.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById(eventName + '-' + subName)?.classList.add('active');
}
window.switchSubTab = switchSubTab;

// ===== DATA LOADERS (SECURED) =====
async function loadTestingData() {
    try {
        const snapshot = await getDocs(query(collection(db, 'registrations'), where('eventCode', '==', 'testing'), orderBy('registeredAt', 'desc')));
        window.testingDataCount = snapshot.size;
        const tbody = document.getElementById('testing-tbody');
        if (!tbody) return;
        if (snapshot.empty) {
            tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;padding:40px;color:var(--text-muted);">No registrations</td></tr>';
            return;
        }
        tbody.innerHTML = '';
        let i = 1;
        snapshot.forEach(docSnap => {
            const d = docSnap.data();
            const docId = docSnap.id;

            // Sanitize all data before rendering
            const safeTeamName = SecurityUtils.escapeHtml(SecurityUtils.sanitizeTeamName(d.teamName));
            const safeEmail = SecurityUtils.escapeHtml(SecurityUtils.sanitizeString(d.email, 254));
            const safeM1Name = SecurityUtils.escapeHtml(SecurityUtils.sanitizeString(d.member1?.name, 100) || '-');
            const safeM1Detail = SecurityUtils.escapeHtml(`${SecurityUtils.sanitizeString(d.member1?.usn, 20) || ''} • ${SecurityUtils.sanitizeString(d.member1?.dept, 50) || ''}`);
            const safeM2Name = SecurityUtils.escapeHtml(SecurityUtils.sanitizeString(d.member2?.name, 100) || '-');
            const safeM2Detail = SecurityUtils.escapeHtml(`${SecurityUtils.sanitizeString(d.member2?.usn, 20) || ''} • ${SecurityUtils.sanitizeString(d.member2?.dept, 50) || ''}`);
            const safeM3Name = SecurityUtils.escapeHtml(SecurityUtils.sanitizeString(d.member3?.name, 100) || '-');
            const safeM3Detail = SecurityUtils.escapeHtml(`${SecurityUtils.sanitizeString(d.member3?.usn, 20) || ''} • ${SecurityUtils.sanitizeString(d.member3?.dept, 50) || ''}`);
            const safeStatus = ['Pending', 'Verified'].includes(d.status) ? d.status : 'Pending';

            // Safely encode team data for onclick
            const teamDataStr = encodeURIComponent(JSON.stringify(d));

            tbody.innerHTML += `<tr data-team="${SecurityUtils.escapeHtml(docId)}" class="clickable-row" onclick="handleRowClick(event,'${SecurityUtils.escapeHtml(docId)}','${teamDataStr}')">
                <td onclick="event.stopPropagation()"><input type="checkbox" class="row-checkbox" data-team-id="${SecurityUtils.escapeHtml(docId)}" onchange="toggleRowSelection()"></td>
                <td><span class="team-badge">${i++}</span></td>
                <td><strong>${safeTeamName || '—'}</strong></td>
                <td><div class="member-info"><span class="name">${safeM1Name}</span><span class="detail">${safeM1Detail}</span></div></td>
                <td><div class="member-info"><span class="name">${safeM2Name}</span><span class="detail">${safeM2Detail}</span></div></td>
                <td><div class="member-info"><span class="name">${safeM3Name}</span><span class="detail">${safeM3Detail}</span></div></td>
                <td><a href="mailto:${safeEmail}" class="email-link" onclick="event.stopPropagation()">${safeEmail}</a></td>
                <td onclick="event.stopPropagation()"><span class="status-pill clickable ${safeStatus.toLowerCase()}" onclick="toggleStatus('${SecurityUtils.escapeHtml(docId)}','${safeStatus}')">${safeStatus}</span></td>
                <td onclick="event.stopPropagation()"><div class="action-buttons">
                    <button class="action-btn view" onclick="handleRowClick(event,'${SecurityUtils.escapeHtml(docId)}','${teamDataStr}')">👁️</button>
                    <button class="action-btn verify" onclick="toggleStatus('${SecurityUtils.escapeHtml(docId)}','${safeStatus}')">✓</button>
                    <button class="action-btn edit" onclick="openEditModal('${SecurityUtils.escapeHtml(docId)}','${safeTeamName.replace(/'/g, "\\'")}','${safeM1Name.replace(/'/g, "\\'")}','${safeM1Detail.replace(/'/g, "\\'")}','${safeM2Name.replace(/'/g, "\\'")}','${safeM2Detail.replace(/'/g, "\\'")}','${safeM3Name.replace(/'/g, "\\'")}','${safeM3Detail.replace(/'/g, "\\'")}','${safeEmail}')">✏️</button>
                    <button class="action-btn delete" onclick="openDeleteModal('${SecurityUtils.escapeHtml(docId)}','${safeTeamName.replace(/'/g, "\\'")}')">🗑️</button>
                </div></td></tr>`;
        });
        setTimeout(() => checkForDuplicates('testing'), 100);
    } catch (err) {
        console.error('Error loading testing data:', err);
        showToast('⚠️ Error loading data');
    }
}

async function loadUIBattleData() {
    try {
        const snapshot = await getDocs(query(collection(db, 'registrations'), where('eventCode', '==', 'uibattle'), orderBy('registeredAt', 'desc')));
        window.uibattleDataCount = snapshot.size;
        const tbody = document.getElementById('uibattle-tbody');
        if (!tbody) return;
        if (snapshot.empty) {
            tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;padding:40px;color:var(--text-muted);">No registrations</td></tr>';
            return;
        }
        tbody.innerHTML = '';
        let i = 1;
        snapshot.forEach(docSnap => {
            const d = docSnap.data();
            const docId = docSnap.id;

            // Sanitize all data before rendering
            const safeTeamName = SecurityUtils.escapeHtml(SecurityUtils.sanitizeTeamName(d.teamName));
            const safeEmail = SecurityUtils.escapeHtml(SecurityUtils.sanitizeString(d.email, 254));
            const safeM1Name = SecurityUtils.escapeHtml(SecurityUtils.sanitizeString(d.member1?.name, 100) || '-');
            const safeM1Detail = SecurityUtils.escapeHtml(`${SecurityUtils.sanitizeString(d.member1?.usn, 20) || ''} • ${SecurityUtils.sanitizeString(d.member1?.dept, 50) || ''}`);
            const safeM2Name = SecurityUtils.escapeHtml(SecurityUtils.sanitizeString(d.member2?.name, 100) || '-');
            const safeM2Detail = SecurityUtils.escapeHtml(`${SecurityUtils.sanitizeString(d.member2?.usn, 20) || ''} • ${SecurityUtils.sanitizeString(d.member2?.dept, 50) || ''}`);
            const safeM3Name = SecurityUtils.escapeHtml(SecurityUtils.sanitizeString(d.member3?.name, 100) || '-');
            const safeM3Detail = SecurityUtils.escapeHtml(`${SecurityUtils.sanitizeString(d.member3?.usn, 20) || ''} • ${SecurityUtils.sanitizeString(d.member3?.dept, 50) || ''}`);
            const safeStatus = ['Pending', 'Verified'].includes(d.status) ? d.status : 'Pending';

            // Safely encode team data for onclick
            const teamDataStr = encodeURIComponent(JSON.stringify(d));

            tbody.innerHTML += `<tr data-team="${SecurityUtils.escapeHtml(docId)}" class="clickable-row" onclick="handleRowClick(event,'${SecurityUtils.escapeHtml(docId)}','${teamDataStr}')">
                <td onclick="event.stopPropagation()"><input type="checkbox" class="row-checkbox" data-team-id="${SecurityUtils.escapeHtml(docId)}" onchange="toggleRowSelection()"></td>
                <td><span class="team-badge">${i++}</span></td>
                <td><strong>${safeTeamName || '—'}</strong></td>
                <td><div class="member-info"><span class="name">${safeM1Name}</span><span class="detail">${safeM1Detail}</span></div></td>
                <td><div class="member-info"><span class="name">${safeM2Name}</span><span class="detail">${safeM2Detail}</span></div></td>
                <td><div class="member-info"><span class="name">${safeM3Name}</span><span class="detail">${safeM3Detail}</span></div></td>
                <td><a href="mailto:${safeEmail}" class="email-link" onclick="event.stopPropagation()">${safeEmail}</a></td>
                <td onclick="event.stopPropagation()"><span class="status-pill clickable ${safeStatus.toLowerCase()}" onclick="toggleStatus('${SecurityUtils.escapeHtml(docId)}','${safeStatus}')">${safeStatus}</span></td>
                <td onclick="event.stopPropagation()"><div class="action-buttons">
                    <button class="action-btn view" onclick="handleRowClick(event,'${SecurityUtils.escapeHtml(docId)}','${teamDataStr}')">👁️</button>
                    <button class="action-btn verify" onclick="toggleStatus('${SecurityUtils.escapeHtml(docId)}','${safeStatus}')">✓</button>
                    <button class="action-btn edit" onclick="openEditModal('${SecurityUtils.escapeHtml(docId)}','${safeTeamName.replace(/'/g, "\\'")}','${safeM1Name.replace(/'/g, "\\'")}','${safeM1Detail.replace(/'/g, "\\'")}','${safeM2Name.replace(/'/g, "\\'")}','${safeM2Detail.replace(/'/g, "\\'")}','${safeM3Name.replace(/'/g, "\\'")}','${safeM3Detail.replace(/'/g, "\\'")}','${safeEmail}')">✏️</button>
                    <button class="action-btn delete" onclick="openDeleteModal('${SecurityUtils.escapeHtml(docId)}','${safeTeamName.replace(/'/g, "\\'")}')">🗑️</button>
                </div></td></tr>`;
        });
        setTimeout(() => checkForDuplicates('uibattle'), 100);
    } catch (err) {
        console.error('Error loading UI Battle data:', err);
        showToast('⚠️ Error loading data');
    }
}

function checkForDuplicates(tableId) {
    const tbody = document.getElementById(`${tableId}-tbody`);
    if (!tbody) return;
    const emailMap = new Map();
    tbody.querySelectorAll('tr').forEach(row => {
        const link = row.querySelector('.email-link');
        if (link) {
            const email = link.textContent.toLowerCase().trim();
            if (email && email !== '—') {
                if (!emailMap.has(email)) emailMap.set(email, []);
                emailMap.get(email).push(row);
            }
        }
    });
    emailMap.forEach(rows => {
        if (rows.length > 1) rows.forEach(row => {
            row.classList.add('duplicate-warning');
            const cell = row.querySelector('td:nth-child(3)');
            if (cell && !cell.querySelector('.duplicate-badge')) cell.insertAdjacentHTML('beforeend', '<span class="duplicate-badge" title="Duplicate email">⚠️</span>');
        });
    });
}
window.checkForDuplicates = checkForDuplicates;

// ===== DYNAMIC EVENT SYSTEM =====

// Load all events from Firestore
async function loadAllEvents() {
    try {
        const eventsSnapshot = await getDocs(query(collection(db, 'events'), orderBy('createdAt', 'desc')));
        allEvents = [];

        eventsSnapshot.forEach(docSnap => {
            const eventData = docSnap.data();
            allEvents.push({
                code: docSnap.id,
                name: eventData.name || docSnap.id,
                emoji: eventData.emoji || '📋',
                isActive: eventData.isActive !== false,
                createdAt: eventData.createdAt
            });
        });

        // If no events in Firestore, use default events (backward compatibility)
        if (allEvents.length === 0) {
            allEvents = [
                { code: 'testing', name: 'Testing', emoji: '🧪', isActive: true },
                { code: 'promptquest', name: 'PromptQuest', emoji: '🎯', isActive: true },
                { code: 'uibattle', name: 'UI Battle', emoji: '🎨', isActive: true },
                { code: 'hackathon', name: 'Hackathon', emoji: '💻', isActive: true }
            ];
        }

        return allEvents;
    } catch (error) {
        console.error('Error loading events:', error);
        // Fallback to default events
        allEvents = [
            { code: 'testing', name: 'Testing', emoji: '🧪', isActive: true },
            { code: 'promptquest', name: 'PromptQuest', emoji: '🎯', isActive: true },
            { code: 'uibattle', name: 'UI Battle', emoji: '🎨', isActive: true },
            { code: 'hackathon', name: 'Hackathon', emoji: '💻', isActive: true }
        ];
        return allEvents;
    }
}
window.loadAllEvents = loadAllEvents;

// Generate event selector cards dynamically
async function generateEventCards() {
    const grid = document.getElementById('eventSelectorGrid');
    if (!grid) return;

    // Show loading
    grid.innerHTML = `<div class="event-loading" id="eventCardsLoader">
        <div class="spinner"></div>
        <p>Loading events...</p>
    </div>`;

    await loadAllEvents();

    // Clear grid and generate cards
    grid.innerHTML = '';

    for (const event of allEvents) {
        if (!event.isActive) continue;

        // Skip events that normal admin doesn't have access to
        // Only filter if there's an active admin session with restrictions
        const isSuperAdmin = AdminPermissions.isSuperAdmin();
        const accessibleEvents = AdminPermissions.getAccessibleEvents();

        // If no admin is logged in yet, or user is super admin, show all events
        // accessibleEvents is null for super admin, empty/array for normal admin
        if (AdminPermissions.currentAdmin && !isSuperAdmin && accessibleEvents && accessibleEvents.length > 0) {
            if (!accessibleEvents.includes(event.code)) {
                console.log('[generateEventCards] Skipping event (no access):', event.code);
                continue;
            }
        }

        // Get registration count for this event (only if admin has access)
        let count = 0;
        try {
            // Skip counting if admin doesn't have access to this event
            if (!AdminPermissions.canAccessEvent(event.code)) {
                console.log('[generateEventCards] Skipping count for event (no access):', event.code);
            } else {
                const countQuery = query(collection(db, 'registrations'), where('eventCode', '==', event.code));
                const countSnapshot = await getDocs(countQuery);
                count = countSnapshot.size;
                window[`${event.code}DataCount`] = count;
            }
        } catch (e) {
            console.warn(`Could not count registrations for ${event.code}`, e);
        }

        const safeCode = SecurityUtils.escapeHtml(event.code);
        const safeName = SecurityUtils.escapeHtml(event.name);
        const safeEmoji = SecurityUtils.escapeHtml(event.emoji);

        // Hide delete button for normal admins
        const deleteBtn = isSuperAdmin
            ? `<button class="event-delete-btn" onclick="event.stopPropagation(); openDeleteEventModal('${safeCode}', '${safeName}')" title="Delete Event">🗑️</button>`
            : '';

        grid.innerHTML += `
            <div class="event-select-card" data-event="${safeCode}" onclick="openEventView('${safeCode}')">
                ${deleteBtn}
                <div class="icon">${safeEmoji}</div>
                <h4>${safeName}</h4>
                <span class="count" id="${safeCode}-count">👥 ${count} teams</span>
            </div>`;
    }
}
window.generateEventCards = generateEventCards;

// Generate event tabs dynamically
function generateEventTabs() {
    const tabsContainer = document.getElementById('dynamicEventTabs');
    if (!tabsContainer) return;

    tabsContainer.innerHTML = '';
    const isSuperAdmin = AdminPermissions.isSuperAdmin();
    const accessibleEvents = AdminPermissions.getAccessibleEvents();
    let firstAccessible = true;

    allEvents.forEach((event, index) => {
        if (!event.isActive) return;

        // Skip events that normal admin doesn't have access to
        if (AdminPermissions.currentAdmin && !isSuperAdmin && accessibleEvents && accessibleEvents.length > 0) {
            if (!accessibleEvents.includes(event.code)) {
                return;
            }
        }

        const safeCode = SecurityUtils.escapeHtml(event.code);
        const safeName = SecurityUtils.escapeHtml(event.name);
        const safeEmoji = SecurityUtils.escapeHtml(event.emoji);

        const isFirst = firstAccessible;
        firstAccessible = false;

        tabsContainer.innerHTML += `
            <button class="event-tab ${isFirst ? 'active' : ''}" onclick="switchEvent('${safeCode}', this)" data-event="${safeCode}">
                ${safeEmoji} ${safeName}
            </button>`;
    });
}
window.generateEventTabs = generateEventTabs;

function generateEventContents() {
    const container = document.getElementById('dynamicEventContents');
    if (!container) return;

    container.innerHTML = '';
    const isSuperAdmin = AdminPermissions.isSuperAdmin();
    const accessibleEvents = AdminPermissions.getAccessibleEvents();
    let firstAccessible = true;

    allEvents.forEach((event, index) => {
        if (!event.isActive) return;

        // Skip events that normal admin doesn't have access to
        if (AdminPermissions.currentAdmin && !isSuperAdmin && accessibleEvents && accessibleEvents.length > 0) {
            if (!accessibleEvents.includes(event.code)) {
                return;
            }
        }

        const safeCode = SecurityUtils.escapeHtml(event.code);
        const safeName = SecurityUtils.escapeHtml(event.name);
        const safeEmoji = SecurityUtils.escapeHtml(event.emoji);

        const isFirst = firstAccessible;
        firstAccessible = false;

        container.innerHTML += `
            <div id="${safeCode}-content" class="event-content ${isFirst ? 'active' : ''}">
                <div class="sub-tabs">
                    <button class="sub-tab active" onclick="switchSubTab('${safeCode}', 'reg', this)">📝 Registration</button>
                    <button class="sub-tab" onclick="switchSubTab('${safeCode}', 'winners', this)">🏆 Winners</button>
                    <button class="sub-tab" onclick="switchSubTab('${safeCode}', 'images', this)">📸 Images</button>
                </div>

                <div id="${safeCode}-reg" class="sub-content active">
                    <div class="data-table-wrapper">
                        <div class="data-table-header">
                            <div class="header-left">
                                <span class="data-table-title">${safeEmoji} ${safeName} Participants</span>
                                <div class="table-filters" style="margin-left: 20px;">
                                    <div class="filter-tabs">
                                        <label class="filter-tab">
                                            <input type="radio" name="statusFilter-${safeCode}" value="all" checked>
                                            <span class="tab-text">All Requests</span>
                                        </label>
                                        <label class="filter-tab">
                                            <input type="radio" name="statusFilter-${safeCode}" value="verified">
                                            <span class="tab-text">Verified</span>
                                        </label>
                                        <label class="filter-tab">
                                            <input type="radio" name="statusFilter-${safeCode}" value="pending">
                                            <span class="tab-text">Pending</span>
                                        </label>
                                    </div>
                                </div>
                            </div>
                            <div class="data-table-controls">
                                <button class="filter-toggle-btn" id="filterToggle-${safeCode}" onclick="toggleFilterBar('${safeCode}')">
                                    🔽 Filter
                                </button>
                                <button class="table-refresh-btn" onclick="refreshEventData('${safeCode}')" title="Refresh data">
                                    <span class="refresh-icon">↻</span>
                                </button>
                                <div class="search-wrapper">
                                    <span class="search-icon">🔍</span>
                                    <input type="text" class="table-search-input" id="${safeCode}-search"
                                        placeholder="Search..."
                                        onkeyup="handleTableSearch('${safeCode}', this.value)">
                                </div>
                            </div>
                        </div>

                        <div class="filter-bar" id="filterBar-${safeCode}">
                            <div class="filter-group">
                                <label>Date Range</label>
                                <div class="animated-calendar" id="calendar-${safeCode}">
                                    <div class="calendar-trigger" onclick="toggleCalendar('${safeCode}')">
                                        <span class="calendar-icon">📅</span>
                                        <span class="calendar-text placeholder" id="calendarText-${safeCode}">Select date range</span>
                                    </div>
                                    <div class="calendar-dropdown" id="calendarDropdown-${safeCode}">
                                        <div class="calendar-header">
                                            <button class="calendar-nav-btn" onclick="calendarPrevYear('${safeCode}')" title="Previous Year">«</button>
                                            <button class="calendar-nav-btn" onclick="calendarPrevMonth('${safeCode}')" title="Previous Month">‹</button>
                                            <span class="calendar-title" id="calendarTitle-${safeCode}">February 2026</span>
                                            <button class="calendar-nav-btn" onclick="calendarNextMonth('${safeCode}')" title="Next Month">›</button>
                                            <button class="calendar-nav-btn" onclick="calendarNextYear('${safeCode}')" title="Next Year">»</button>
                                        </div>
                                        <div class="calendar-weekdays">
                                            <span class="calendar-weekday">Su</span>
                                            <span class="calendar-weekday">Mo</span>
                                            <span class="calendar-weekday">Tu</span>
                                            <span class="calendar-weekday">We</span>
                                            <span class="calendar-weekday">Th</span>
                                            <span class="calendar-weekday">Fr</span>
                                            <span class="calendar-weekday">Sa</span>
                                        </div>
                                        <div class="calendar-days" id="calendarDays-${safeCode}"></div>
                                        <div class="calendar-footer">
                                            <button class="calendar-footer-btn" onclick="calendarSelectToday('${safeCode}')">
                                                <span class="check-icon">✓</span> Today
                                            </button>
                                            <button class="calendar-footer-btn" onclick="calendarClear('${safeCode}')">
                                                × Clear
                                            </button>
                                        </div>
                                    </div>
                                </div>
                                <input type="hidden" id="filterDateFrom-${safeCode}">
                                <input type="hidden" id="filterDateTo-${safeCode}">
                            </div>
                            <div class="filter-group">
                                <label>Status</label>
                                <select id="filterStatus-${safeCode}">
                                    <option value="">All</option>
                                    <option value="pending">Pending</option>
                                    <option value="verified">Verified</option>
                                </select>
                            </div>
                            <div class="filter-actions">
                                <button class="filter-btn apply" onclick="applyFilters('${safeCode}')">Apply</button>
                                <button class="filter-btn clear" onclick="clearFilters('${safeCode}')">Clear</button>
                            </div>
                        </div>

                        <table class="data-table" id="${safeCode}-table">
                            <thead>
                                <tr>
                                    <th style="width: 40px;"><input type="checkbox" class="row-checkbox"
                                            id="selectAll-${safeCode}"
                                            onchange="toggleSelectAll(this.checked, '${safeCode}')"
                                            title="Select all"></th>
                                    <th>Team</th>
                                    <th>Team Name</th>
                                    <th>Member 1</th>
                                    <th>Member 2</th>
                                    <th>Member 3</th>
                                    <th>Email</th>
                                    <th>Status</th>
                                    <th>Attended</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody id="${safeCode}-tbody">
                                <tr><td colspan="10" style="text-align:center;padding:40px;color:var(--text-muted);">
                                    <div class="spinner" style="margin: 0 auto 10px;"></div>
                                    Loading registrations...
                                </td></tr>
                            </tbody>
                        </table>
                    </div>
                    <div class="pagination" id="${safeCode}-pagination"></div>
                </div>

                <div id="${safeCode}-winners" class="sub-content">
                    <div class="placeholder-box">
                        <div class="icon">🏆</div>
                        <h4>Winners Coming Soon!</h4>
                        <p>${safeName} winners will be announced after the event.</p>
                    </div>
                </div>

                <div id="${safeCode}-images" class="sub-content">
                    <div class="placeholder-box">
                        <div class="icon">📷</div>
                        <h4>Event Photos Coming Soon!</h4>
                        <p>Photos will be uploaded after the event.</p>
                    </div>
                </div>
            </div>`;
    });

    // Setup status filter listeners for each event
    setupEventFilterListeners();
}
window.generateEventContents = generateEventContents;

// Setup filter listeners for dynamically created events
function setupEventFilterListeners() {
    allEvents.forEach(event => {
        if (!event.isActive) return;

        document.querySelectorAll(`input[name="statusFilter-${event.code}"]`).forEach(radio => {
            radio.addEventListener('change', (e) => {
                applyStatusFilter(e.target.value, event.code);
            });
        });
    });
}

// Generic data loader for any event
async function loadEventData(eventCode) {
    try {
        const snapshot = await getDocs(query(
            collection(db, 'registrations'),
            where('eventCode', '==', eventCode),
            orderBy('registeredAt', 'desc')
        ));

        window[`${eventCode}DataCount`] = snapshot.size;

        const tbody = document.getElementById(`${eventCode}-tbody`);
        if (!tbody) return;

        if (snapshot.empty) {
            tbody.innerHTML = '<tr><td colspan="10" style="text-align:center;padding:40px;color:var(--text-muted);">No registrations</td></tr>';
            return;
        }

        tbody.innerHTML = '';
        let i = 1;

        snapshot.forEach(docSnap => {
            const d = docSnap.data();
            const docId = docSnap.id;

            // Sanitize all data before rendering
            const safeTeamName = SecurityUtils.escapeHtml(SecurityUtils.sanitizeTeamName(d.teamName));
            const safeEmail = SecurityUtils.escapeHtml(SecurityUtils.sanitizeString(d.email, 254));
            const safeM1Name = SecurityUtils.escapeHtml(SecurityUtils.sanitizeString(d.member1?.name, 100) || '-');
            const safeM1Detail = SecurityUtils.escapeHtml(`${SecurityUtils.sanitizeString(d.member1?.usn, 20) || ''} • ${SecurityUtils.sanitizeString(d.member1?.dept, 50) || ''}`);
            const safeM2Name = SecurityUtils.escapeHtml(SecurityUtils.sanitizeString(d.member2?.name, 100) || '-');
            const safeM2Detail = SecurityUtils.escapeHtml(`${SecurityUtils.sanitizeString(d.member2?.usn, 20) || ''} • ${SecurityUtils.sanitizeString(d.member2?.dept, 50) || ''}`);
            const safeM3Name = SecurityUtils.escapeHtml(SecurityUtils.sanitizeString(d.member3?.name, 100) || '-');
            const safeM3Detail = SecurityUtils.escapeHtml(`${SecurityUtils.sanitizeString(d.member3?.usn, 20) || ''} • ${SecurityUtils.sanitizeString(d.member3?.dept, 50) || ''}`);
            const safeStatus = ['Pending', 'Verified'].includes(d.status) ? d.status : 'Pending';
            const isAttended = d.attended === true;

            // Winner badge HTML
            const winnerBadge = d.isWinner ?
                `<span class="winner-badge ${d.winnerPosition === 1 ? 'gold' : d.winnerPosition === 2 ? 'silver' : 'bronze'}">🏆 ${d.winnerPosition === 1 ? '1st' : d.winnerPosition === 2 ? '2nd' : '3rd'}</span>` : '';

            // Winner button - shows remove option if already winner
            const winnerBtn = d.isWinner ?
                `<button class="action-btn winner" title="Remove Winner Status" onclick="removeWinner('${SecurityUtils.escapeHtml(docId)}', '${eventCode}')">❌</button>` :
                `<button class="action-btn winner" title="Set as Winner" onclick="openWinnerModal('${SecurityUtils.escapeHtml(docId)}', '${safeTeamName.replace(/'/g, "\\'")}', '${eventCode}')">🏆</button>`;

            // Safely encode team data for onclick
            const teamDataStr = encodeURIComponent(JSON.stringify(d));

            tbody.innerHTML += `<tr data-team="${SecurityUtils.escapeHtml(docId)}" data-registered-at="${d.registeredAt ? (d.registeredAt.toDate ? d.registeredAt.toDate().toISOString() : new Date(d.registeredAt.seconds * 1000).toISOString()) : ''}" class="clickable-row" onclick="handleRowClick(event,'${SecurityUtils.escapeHtml(docId)}','${teamDataStr}')">
                <td onclick="event.stopPropagation()"><input type="checkbox" class="row-checkbox" data-team-id="${SecurityUtils.escapeHtml(docId)}" onchange="toggleRowSelection()"></td>
                <td><span class="team-badge">${i++}</span></td>
                <td><strong>${safeTeamName || '—'}</strong>${winnerBadge}</td>
                <td><div class="member-info"><span class="name">${safeM1Name}</span><span class="detail">${safeM1Detail}</span></div></td>
                <td><div class="member-info"><span class="name">${safeM2Name}</span><span class="detail">${safeM2Detail}</span></div></td>
                <td><div class="member-info"><span class="name">${safeM3Name}</span><span class="detail">${safeM3Detail}</span></div></td>
                <td><a href="mailto:${safeEmail}" class="email-link" onclick="event.stopPropagation()">${safeEmail}</a></td>
                <td onclick="event.stopPropagation()"><span class="status-pill clickable ${safeStatus.toLowerCase()}" onclick="toggleStatus('${SecurityUtils.escapeHtml(docId)}','${safeStatus}')">${safeStatus}</span></td>
                <td onclick="event.stopPropagation()" style="text-align:center;">
                    <input type="checkbox" class="attended-checkbox" ${isAttended ? 'checked' : ''} 
                        onchange="markAttended('${SecurityUtils.escapeHtml(docId)}', this.checked, '${eventCode}')" 
                        title="${isAttended ? 'Mark as not attended' : 'Mark as attended'}">
                </td>
                <td onclick="event.stopPropagation()"><div class="action-buttons">
                    <button class="action-btn view" onclick="handleRowClick(event,'${SecurityUtils.escapeHtml(docId)}','${teamDataStr}')">👁️</button>
                    ${winnerBtn}
                    <button class="action-btn verify" onclick="toggleStatus('${SecurityUtils.escapeHtml(docId)}','${safeStatus}')">✓</button>
                    <button class="action-btn edit" onclick="openEditModal('${SecurityUtils.escapeHtml(docId)}','${safeTeamName.replace(/'/g, "\\'")}','${safeM1Name.replace(/'/g, "\\'")}','${safeM1Detail.replace(/'/g, "\\'")}','${safeM2Name.replace(/'/g, "\\'")}','${safeM2Detail.replace(/'/g, "\\'")}','${safeM3Name.replace(/'/g, "\\'")}','${safeM3Detail.replace(/'/g, "\\'")}','${safeEmail}')">✏️</button>
                    <button class="action-btn delete" onclick="openDeleteModal('${SecurityUtils.escapeHtml(docId)}','${safeTeamName.replace(/'/g, "\\'")}')">🗑️</button>
                </div></td></tr>`;
        });

        // Update count badge
        const countEl = document.getElementById(`${eventCode}-count`);
        if (countEl) countEl.textContent = `👥 ${snapshot.size} teams`;

        setTimeout(() => checkForDuplicates(eventCode), 100);
    } catch (err) {
        console.error(`Error loading ${eventCode} data:`, err);
        const tbody = document.getElementById(`${eventCode}-tbody`);
        if (tbody) {
            tbody.innerHTML = '<tr><td colspan="10" style="text-align:center;padding:40px;color:var(--accent-red);">Error loading data</td></tr>';
        }
    }
}
window.loadEventData = loadEventData;

// Load data for all events (respects admin access permissions)
async function loadAllEventData() {
    for (const event of allEvents) {
        if (!event.isActive) continue;
        // Skip loading data for events the admin doesn't have access to
        if (!AdminPermissions.canAccessEvent(event.code)) {
            console.log('[loadAllEventData] Skipping event (no access):', event.code);
            continue;
        }
        await loadEventData(event.code);
    }
}
window.loadAllEventData = loadAllEventData;

// Refresh event data
async function refreshEventData(eventCode) {
    showToast(`🔄 Refreshing ${eventCode}...`);
    await loadEventData(eventCode);
    showToast(`✅ ${eventCode} refreshed!`);
}
window.refreshEventData = refreshEventData;

// Initialize dynamic event system
async function initDynamicEvents() {
    try {
        // Generate event selector cards
        await generateEventCards();

        // Generate event tabs
        generateEventTabs();

        // Generate event content sections
        generateEventContents();

        // Load data for all events
        await loadAllEventData();

        console.log('Dynamic event system initialized with', allEvents.length, 'events');
    } catch (error) {
        console.error('Error initializing dynamic events:', error);
        showToast('⚠️ Error loading events');
    }
}
window.initDynamicEvents = initDynamicEvents;

window.reloadFirestoreData = async function () {
    await loadAllEventData();
};

// ===== MISC FUNCTIONS =====
// function toggleNav() {
//     document.getElementById('navLinks')?.classList.toggle('active');
//     document.getElementById('hamburger')?.classList.toggle('active');
// }
// window.toggleNav = toggleNav;


function handleExport() { showToast('📥 Export feature coming soon'); }
window.handleExport = handleExport;

function handleSendEmail() { showToast('📧 Email feature'); }
window.handleSendEmail = handleSendEmail;

function handleAddEvent() { document.getElementById('createEventModal')?.classList.add('active'); }
window.handleAddEvent = handleAddEvent;

// ===== REGISTRATION ROUTING DROPDOWN =====
function toggleDropdown() {
    const dropdown = document.getElementById('routingDropdown');
    if (dropdown) {
        dropdown.classList.toggle('open');
    }
}
window.toggleDropdown = toggleDropdown;

function selectOption(element) {
    const value = element.dataset.value;
    const text = element.querySelector('span:not(.icon):not(.check)').textContent;
    const icon = element.querySelector('.icon').textContent;

    // Update selected state
    document.querySelectorAll('.select-item').forEach(item => item.classList.remove('selected'));
    element.classList.add('selected');

    // Update trigger button text
    document.getElementById('selectedEventText').textContent = text;
    document.querySelector('.select-trigger .icon').textContent = icon;

    // Update routing status
    const activeEventName = document.getElementById('activeEventName');
    if (activeEventName) {
        activeEventName.textContent = text.replace(' (Sandbox)', '');
    }

    // Close dropdown
    document.getElementById('routingDropdown')?.classList.remove('open');

    // Save to Firestore (routing config)
    saveRoutingConfig(value);

    showToast(`✅ Registration routing set to ${text}`);
}
window.selectOption = selectOption;

async function saveRoutingConfig(eventCode) {
    try {
        await setDoc(doc(db, 'config', 'routing'), {
            activeEvent: eventCode,
            updatedAt: serverTimestamp(),
            updatedBy: auth.currentUser?.email || 'unknown'
        });
        await logAdminAction('UPDATE_ROUTING', { activeEvent: eventCode });
    } catch (error) {
        console.error('Error saving routing config:', error);
        showToast('⚠️ Failed to save routing config');
    }
}
window.saveRoutingConfig = saveRoutingConfig;

async function loadRoutingConfig() {
    try {
        const configDoc = await getDoc(doc(db, 'config', 'routing'));
        if (configDoc.exists()) {
            const config = configDoc.data();
            const activeEvent = config.activeEvent || 'testing';

            // Update UI to reflect saved routing
            const item = document.querySelector(`.select-item[data-value="${activeEvent}"]`);
            if (item) {
                selectOption(item);
            }
        }
    } catch (error) {
        console.error('Error loading routing config:', error);
    }
}
window.loadRoutingConfig = loadRoutingConfig;

// Close dropdown when clicking outside
document.addEventListener('click', (e) => {
    const dropdown = document.getElementById('routingDropdown');
    if (dropdown && !dropdown.contains(e.target)) {
        dropdown.classList.remove('open');
    }
});

// Alias for openCreateEventModal
function openCreateEventModal() {
    document.getElementById('createEventModal')?.classList.add('active');
    // Reset form
    document.getElementById('newEventName').value = '';
    document.getElementById('newEventCode').value = '';
    document.getElementById('selectedEventEmoji').value = '🎯';
    document.querySelectorAll('.emoji-option').forEach(btn => btn.classList.remove('selected'));
    document.querySelector('.emoji-option[data-emoji="🎯"]')?.classList.add('selected');
}
window.openCreateEventModal = openCreateEventModal;

// Select emoji for new event
function selectEventEmoji(emoji, btn) {
    document.getElementById('selectedEventEmoji').value = emoji;
    document.querySelectorAll('.emoji-option').forEach(b => b.classList.remove('selected'));
    btn.classList.add('selected');
}
window.selectEventEmoji = selectEventEmoji;

// Create new event
async function createNewEvent() {
    const name = document.getElementById('newEventName').value.trim();
    const code = document.getElementById('newEventCode').value.trim().toLowerCase();
    const emoji = document.getElementById('selectedEventEmoji').value || '🎯';

    // Validation
    if (!name || name.length < 2) {
        showToast('⚠️ Event name must be at least 2 characters');
        return;
    }
    if (!code || code.length < 2) {
        showToast('⚠️ Event code must be at least 2 characters');
        return;
    }
    if (!/^[a-z0-9_]+$/.test(code)) {
        showToast('⚠️ Event code can only contain lowercase letters, numbers and underscores');
        return;
    }

    try {
        // Check if event code already exists
        const existingEvent = await getDoc(doc(db, 'events', code));
        if (existingEvent.exists()) {
            showToast('⚠️ An event with this code already exists');
            return;
        }

        // Create event in Firestore
        await setDoc(doc(db, 'events', code), {
            name: SecurityUtils.sanitizeString(name, 100),
            code: code,
            emoji: emoji,
            createdAt: serverTimestamp(),
            createdBy: auth.currentUser?.email || 'unknown',
            isActive: true
        });

        await logAdminAction('CREATE_EVENT', { eventCode: code, eventName: name });
        showToast(`✅ Event "${name}" created successfully!`);
        closeModal('createEventModal');

        // Dynamically update the UI without page reload
        showToast('🔄 Updating event list...');
        await initDynamicEvents();
        showToast(`🎉 "${name}" is now ready to accept registrations!`);

    } catch (error) {
        console.error('Error creating event:', error);
        showToast('⚠️ Failed to create event');
    }
}
window.createNewEvent = createNewEvent;

// Delete entire event and all its registrations
async function deleteEvent(eventCode) {
    if (!eventCode) {
        showToast('⚠️ Invalid event code');
        return;
    }

    const confirmMsg = `⚠️ Are you sure you want to delete the event "${eventCode}"?\n\nThis will permanently delete:\n- The event configuration\n- ALL registrations for this event\n\nThis action cannot be undone!`;

    if (!confirm(confirmMsg)) return;

    // Double confirmation for safety
    const doubleConfirm = prompt(`Type "${eventCode}" to confirm deletion:`);
    if (doubleConfirm !== eventCode) {
        showToast('❌ Deletion cancelled - event code did not match');
        return;
    }

    try {
        showToast('🔄 Deleting event...');

        // Delete all registrations for this event
        const registrationsQuery = query(collection(db, 'registrations'), where('eventCode', '==', eventCode));
        const registrationsSnapshot = await getDocs(registrationsQuery);

        let deletedCount = 0;
        for (const docSnap of registrationsSnapshot.docs) {
            await deleteDoc(doc(db, 'registrations', docSnap.id));
            deletedCount++;
        }

        // Delete the event document
        await deleteDoc(doc(db, 'events', eventCode));

        await logAdminAction('DELETE_EVENT', { eventCode, registrationsDeleted: deletedCount });
        showToast(`🗑️ Event "${eventCode}" deleted with ${deletedCount} registrations`);

        // Dynamically update the UI without page reload
        await initDynamicEvents();

        // Go back to event selector if currently viewing the deleted event
        backToEventSelector();
    } catch (error) {
        console.error('Error deleting event:', error);
        showToast('⚠️ Failed to delete event');
    }
}
window.deleteEvent = deleteEvent;

// Open delete event confirmation modal
function openDeleteEventModal(eventCode, eventName) {
    if (!confirm(`Are you sure you want to delete "${eventName || eventCode}"?\n\nThis will delete ALL registrations for this event!`)) {
        return;
    }
    deleteEvent(eventCode);
}
window.openDeleteEventModal = openDeleteEventModal;

// ===== WINNER MODAL FUNCTIONS =====
function openWinnerModal(teamId, teamName, eventCode) {
    document.getElementById('winnerTeamId').value = teamId;
    document.getElementById('winnerTeamName').textContent = teamName;
    document.getElementById('winnerEventCode').value = eventCode;
    document.getElementById('selectedWinnerPosition').value = '';

    // Reset position button selections
    document.querySelectorAll('.winner-position-btn').forEach(btn => {
        btn.classList.remove('selected');
    });

    document.getElementById('winnerModal').classList.add('active');
}
window.openWinnerModal = openWinnerModal;

function selectWinnerPosition(position, btn) {
    // Store the selected position
    document.getElementById('selectedWinnerPosition').value = position;

    // Update button visuals
    document.querySelectorAll('.winner-position-btn').forEach(b => {
        b.classList.remove('selected');
    });
    btn.classList.add('selected');
}
window.selectWinnerPosition = selectWinnerPosition;

async function confirmSetWinner() {
    const teamId = document.getElementById('winnerTeamId').value;
    const position = parseInt(document.getElementById('selectedWinnerPosition').value);
    const eventCode = document.getElementById('winnerEventCode').value;

    if (!position) {
        showToast('⚠️ Please select a position');
        return;
    }

    try {
        const success = await window.updateInFirestore('registrations', teamId, {
            isWinner: true,
            winnerPosition: position
        });

        if (success) {
            showToast(`🏆 Winner set to position ${position}!`);
            closeModal('winnerModal');

            // Refresh the specific event data
            if (eventCode) {
                await loadEventData(eventCode);
            } else {
                await loadAllEventData();
            }
        } else {
            showToast('⚠️ Failed to set winner (permission denied)');
        }
    } catch (err) {
        console.error('Set winner error:', err);
        showToast('❌ Error setting winner');
    }
}
window.confirmSetWinner = confirmSetWinner;

// Remove winner status
async function removeWinner(teamId, eventCode) {
    if (!confirm('Remove winner status from this team?')) return;

    try {
        const success = await window.updateInFirestore('registrations', teamId, {
            isWinner: false,
            winnerPosition: null
        });

        if (success) {
            showToast('✅ Winner status removed');

            // Refresh the specific event data
            if (eventCode) {
                await loadEventData(eventCode);
            } else {
                await loadAllEventData();
            }
        }
    } catch (err) {
        console.error('Remove winner error:', err);
        showToast('❌ Error removing winner');
    }
}
window.removeWinner = removeWinner;

function togglePasswordVisibility() {
    const input = document.getElementById('password');
    const toggleBtn = document.querySelector('.password-toggle');
    if (!input) return;

    if (input.type === 'password') {
        input.type = 'text';
        if (toggleBtn) toggleBtn.textContent = '🙈';
    } else {
        input.type = 'password';
        if (toggleBtn) toggleBtn.textContent = '👁️';
    }
}
window.togglePasswordVisibility = togglePasswordVisibility;

function refreshTableData() {
    if (window.reloadFirestoreData) window.reloadFirestoreData().then(() => showToast('✅ Refreshed!'));
}
window.refreshTableData = refreshTableData;

// ===== FILTER BAR FUNCTIONS =====
function toggleFilterBar(eventName) {
    const filterBar = document.getElementById(`filterBar-${eventName}`);
    const toggleBtn = document.getElementById(`filterToggle-${eventName}`);

    if (!filterBar || !toggleBtn) return;

    if (filterBar.classList.contains('active')) {
        filterBar.classList.remove('active');
        toggleBtn.classList.remove('active');
        toggleBtn.innerHTML = '🔽 Filter';
    } else {
        filterBar.classList.add('active');
        toggleBtn.classList.add('active');
        toggleBtn.innerHTML = '🔼 Filter';
    }
}
window.toggleFilterBar = toggleFilterBar;

function applyStatusFilter(status, eventName = 'testing') {
    const tbody = document.getElementById(`${eventName}-tbody`);
    if (!tbody) return;

    const rows = tbody.querySelectorAll('tr');
    let visibleCount = 0;

    rows.forEach(row => {
        const statusCell = row.querySelector('.status-pill');
        const rowStatus = statusCell ? statusCell.textContent.toLowerCase().trim() : '';

        let showRow = true;
        if (status && status !== 'all') {
            showRow = rowStatus === status.toLowerCase();
        }

        row.style.display = showRow ? '' : 'none';
        if (showRow) visibleCount++;
    });

    showToast(`🔍 Showing ${visibleCount} of ${rows.length} teams`);
}
window.applyStatusFilter = applyStatusFilter;

async function applyFilters(eventName) {
    const dateFrom = document.getElementById(`filterDateFrom-${eventName}`)?.value;
    const dateTo = document.getElementById(`filterDateTo-${eventName}`)?.value;
    const status = document.getElementById(`filterStatus-${eventName}`)?.value?.toLowerCase();

    const tbody = document.getElementById(`${eventName}-tbody`);
    if (!tbody) return;

    const rows = tbody.querySelectorAll('tr[data-team]');
    let visibleCount = 0;

    // Parse date range if provided
    const fromDate = dateFrom ? new Date(dateFrom) : null;
    const toDate = dateTo ? new Date(dateTo) : null;
    if (fromDate) fromDate.setHours(0, 0, 0, 0);
    if (toDate) toDate.setHours(23, 59, 59, 999);

    rows.forEach(row => {
        const statusCell = row.querySelector('.status-pill');
        const rowStatus = statusCell ? statusCell.textContent.toLowerCase().trim() : '';

        // Get registration date from data attribute
        const regDateAttr = row.getAttribute('data-registered-at');
        let rowDate = null;
        if (regDateAttr) {
            rowDate = new Date(regDateAttr);
        }

        let showRow = true;

        // Status filter
        if (status && status !== 'all' && status !== '' && rowStatus !== status) {
            showRow = false;
        }

        // Date range filter
        if (showRow && (fromDate || toDate) && rowDate) {
            if (fromDate && rowDate < fromDate) {
                showRow = false;
            }
            if (toDate && rowDate > toDate) {
                showRow = false;
            }
        }

        row.style.display = showRow ? '' : 'none';
        if (showRow) visibleCount++;
    });

    showToast(`🔍 Showing ${visibleCount} of ${rows.length} teams`);
    await logAdminAction('FILTER_APPLIED', { eventName, status, dateFrom, dateTo });
}
window.applyFilters = applyFilters;

function clearFilters(eventName) {
    const tbody = document.getElementById(`${eventName}-tbody`);
    if (!tbody) return;

    tbody.querySelectorAll('tr').forEach(row => row.style.display = '');

    // Reset filter inputs
    const statusSelect = document.getElementById(`filterStatus-${eventName}`);
    const dateFrom = document.getElementById(`filterDateFrom-${eventName}`);
    const dateTo = document.getElementById(`filterDateTo-${eventName}`);

    if (statusSelect) statusSelect.value = '';
    if (dateFrom) dateFrom.value = '';
    if (dateTo) dateTo.value = '';

    // Reset radio buttons for this specific event
    const allRadio = document.querySelector(`input[name="statusFilter-${eventName}"][value="all"]`);
    if (allRadio) allRadio.checked = true;

    // Clear calendar state for this event
    if (typeof calendarClear === 'function') {
        calendarClear(eventName);
    }

    showToast('🔄 Filters cleared');
}
window.clearFilters = clearFilters;

// ===== ROW SELECTION =====
function toggleRowSelection() {
    updateBulkActionBar();
}
window.toggleRowSelection = toggleRowSelection;

function toggleSelectAll(checked, eventName = 'testing') {
    const tbody = document.getElementById(`${eventName}-tbody`);
    if (!tbody) return;

    tbody.querySelectorAll('.row-checkbox').forEach(cb => {
        cb.checked = checked;
    });
    updateBulkActionBar();
}
window.toggleSelectAll = toggleSelectAll;

function updateBulkActionBar() {
    const selected = document.querySelectorAll('.row-checkbox:checked');
    const count = selected.length;
    const bar = document.getElementById('bulkActionBar');
    const countEl = document.getElementById('bulkCount');

    if (count > 0) {
        bar.classList.add('active');
        if (countEl) countEl.textContent = `${count} selected`;
    } else {
        bar.classList.remove('active');
    }
}
window.updateBulkActionBar = updateBulkActionBar;

// ===== LOGIN (SECURED) =====
window.handleLogin = function (event) {
    event.preventDefault();

    // Rate limiting
    const rateCheck = rateLimiters.login.recordAttempt('login');
    if (!rateCheck.allowed) {
        const errorEl = document.getElementById('errorMessage');
        errorEl.style.display = 'block';
        errorEl.textContent = `⏳ Too many attempts. Try again in ${rateCheck.retryAfter} seconds`;
        return;
    }

    const email = SecurityUtils.sanitizeString(document.getElementById('username').value, 254);
    const password = document.getElementById('password').value;
    const errorEl = document.getElementById('errorMessage');
    const loginBtn = document.getElementById('loginBtn');

    errorEl.style.display = 'none';

    // Validate email format
    if (!SecurityUtils.isValidEmail(email)) {
        errorEl.style.display = 'block';
        errorEl.textContent = 'Please enter a valid email address';
        return;
    }

    // Password length check (Firebase requires 6+, we enforce 8+)
    if (!password || password.length < 8 || password.length > 128) {
        errorEl.style.display = 'block';
        errorEl.textContent = 'Password must be 8-128 characters';
        return;
    }

    loginBtn.disabled = true;
    loginBtn.textContent = 'Signing in...';

    signInWithEmailAndPassword(auth, email, password)
        .then(async (userCredential) => {
            // Check admin role from Firestore
            const adminData = await checkAdminRole(userCredential.user);

            if (!adminData) {
                // User is not an admin or is deactivated
                await signOut(auth);
                errorEl.style.display = 'block';
                errorEl.textContent = '❌ Access denied. You are not authorized as an admin.';
                return;
            }

            // Reset rate limiter on successful login
            rateLimiters.login.reset('login');

            // Apply role-based UI visibility
            applyRoleBasedUI();

            // Re-initialize events with proper role filtering
            // This ensures normal admins only see their assigned events
            await initDynamicEvents();

            // Load routing config
            loadRoutingConfig();

            // Render the registrations chart after data is loaded
            renderRegistrationsChart();

            // Update analytics hub with live data
            updateAnalyticsHub();

            // Update dashboard stats
            updateDashboardStats();

            // Show appropriate dashboard
            document.getElementById('login-page').style.display = 'none';
            document.getElementById('admin-dashboard').classList.add('active');

            // Show role-specific welcome message
            const roleLabel = adminData.role === 'super' ? '🔴 Super Admin' : '🟡 Admin';
            showToast(`Welcome, ${roleLabel}!`);

            // Start session countdown timer
            resetInactivityTimer();

            console.log('[Login] Success:', adminData.email, 'Role:', adminData.role);
        })
        .catch((error) => {
            errorEl.style.display = 'block';
            // Generic error message to prevent user enumeration
            errorEl.textContent = 'Invalid email or password';
            console.warn('Login failed:', error.code);
        })
        .finally(() => {
            loginBtn.disabled = false;
            loginBtn.textContent = 'Sign In';
        });
};

// ===== EVENT LISTENERS =====
document.addEventListener('click', (e) => {
    if (e.target.classList.contains('modal-overlay')) e.target.classList.remove('active');
    const overlay = document.getElementById('teamDrawerOverlay');
    if (e.target === overlay) closeTeamDrawer();
});

document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        document.querySelectorAll('.modal-overlay.active').forEach(m => m.classList.remove('active'));
        closeTeamDrawer();
    }
});

onAuthStateChanged(auth, (user) => { if (user) resetInactivityTimer(); });

// ===== REGISTRATIONS CHART =====
let registrationsChart = null;

async function renderRegistrationsChart() {
    const canvas = document.getElementById('registrationsChart');
    if (!canvas || typeof Chart === 'undefined') {
        console.log('[Chart] Canvas or Chart.js not available');
        return;
    }

    try {
        const labels = [];
        const data = [];
        const colors = [
            'rgba(249, 115, 22, 0.8)',   // ember orange
            'rgba(251, 113, 133, 0.8)',  // coral pink
            'rgba(252, 211, 77, 0.8)',   // warm yellow
            'rgba(16, 185, 129, 0.8)',   // green
            'rgba(6, 182, 212, 0.8)',    // cyan
            'rgba(236, 72, 153, 0.8)'    // pink
        ];
        const borderColors = [
            'rgba(249, 115, 22, 1)',
            'rgba(251, 113, 133, 1)',
            'rgba(252, 211, 77, 1)',
            'rgba(16, 185, 129, 1)',
            'rgba(6, 182, 212, 1)',
            'rgba(236, 72, 153, 1)'
        ];

        // Add Testing event
        const testingCount = window.testingDataCount || 0;
        labels.push('Testing');
        data.push(testingCount);

        // Add PromptQuest event
        const promptquestCount = window.promptquestDataCount || 0;
        labels.push('PromptQuest');
        data.push(promptquestCount);

        // Add UI Battle event
        const uibattleCount = window.uibattleDataCount || 0;
        labels.push('UI Battle');
        data.push(uibattleCount);

        // Destroy existing chart if any
        if (registrationsChart) {
            registrationsChart.destroy();
        }

        registrationsChart = new Chart(canvas, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Teams Registered',
                    data: data,
                    backgroundColor: colors.slice(0, labels.length),
                    borderColor: borderColors.slice(0, labels.length),
                    borderWidth: 1,
                    borderRadius: 8,
                    borderSkipped: false
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: 'rgba(22, 22, 26, 0.95)',
                        titleColor: '#FFFBF5',
                        bodyColor: '#FFFBF5',
                        borderColor: 'rgba(249, 115, 22, 0.3)',
                        borderWidth: 1,
                        padding: 12,
                        cornerRadius: 8,
                        callbacks: {
                            label: (ctx) => ` ${ctx.raw} teams`
                        }
                    }
                },
                scales: {
                    x: {
                        grid: { display: false },
                        ticks: { color: '#9CA3AF', font: { size: 12 } }
                    },
                    y: {
                        beginAtZero: true,
                        grid: { color: 'rgba(249, 115, 22, 0.1)' },
                        ticks: {
                            color: '#9CA3AF',
                            font: { size: 12 },
                            stepSize: 1
                        }
                    }
                }
            }
        });

        console.log('[Chart] Rendered with data:', { labels, data });
    } catch (err) {
        console.error('[Chart] Render error:', err);
    }
}

window.renderRegistrationsChart = renderRegistrationsChart;

// ===== ANALYTICS HUB (Dynamic Data) =====
async function updateAnalyticsHub() {
    try {
        // Get all registration counts
        const testingCount = window.testingDataCount || 0;
        const promptquestCount = window.promptquestDataCount || 0;
        const uibattleCount = window.uibattleDataCount || 0;
        const totalTeams = testingCount + promptquestCount + uibattleCount;

        // Get today's registrations (simplified - counts from today)
        let newToday = 0;
        let pendingCount = 0;
        let verifiedCount = 0;

        // Query registrations to calculate stats (respects admin permissions)
        try {
            const regsRef = collection(db, 'registrations');
            let snapshot;

            // For normal admins, only query registrations they have access to
            if (!AdminPermissions.isSuperAdmin()) {
                const accessibleEvents = AdminPermissions.getAccessibleEvents();
                if (accessibleEvents && accessibleEvents.length > 0) {
                    // Firestore 'in' query supports up to 10 values
                    // Split into chunks if more than 10 accessible events
                    const chunks = [];
                    for (let i = 0; i < accessibleEvents.length; i += 10) {
                        chunks.push(accessibleEvents.slice(i, i + 10));
                    }

                    // Query each chunk and merge results
                    const allDocs = [];
                    for (const chunk of chunks) {
                        const chunkQuery = query(regsRef, where('eventCode', 'in', chunk));
                        const chunkSnapshot = await getDocs(chunkQuery);
                        chunkSnapshot.forEach(doc => allDocs.push(doc));
                    }
                    snapshot = { forEach: (fn) => allDocs.forEach(fn), size: allDocs.length };
                } else {
                    // No accessible events, skip stats
                    console.log('[Hub] No accessible events for normal admin, skipping stats');
                    snapshot = { forEach: () => { }, size: 0 };
                }
            } else {
                // Super admin can query all registrations
                snapshot = await getDocs(regsRef);
            }

            const today = new Date();
            today.setHours(0, 0, 0, 0);

            snapshot.forEach(docSnap => {
                const data = docSnap.data();

                // Count pending vs verified
                if (data.status === 'Verified') {
                    verifiedCount++;
                } else {
                    pendingCount++;
                }

                // Count today's registrations
                if (data.registeredAt) {
                    const regDate = data.registeredAt.toDate ? data.registeredAt.toDate() : new Date(data.registeredAt);
                    if (regDate >= today) {
                        newToday++;
                    }
                }
            });
        } catch (e) {
            console.log('[Hub] Could not fetch detailed stats:', e);
        }

        // Calculate verification rate
        const verificationRate = totalTeams > 0 ? Math.round((verifiedCount / totalTeams) * 100) : 0;

        // Update Stats Summary
        const newTodayEl = document.getElementById('totalTeamsToday');
        const pendingEl = document.getElementById('pendingVerifications');
        const rateEl = document.getElementById('verificationRate');

        if (newTodayEl) newTodayEl.textContent = `+${newToday}`;
        if (pendingEl) pendingEl.textContent = pendingCount;
        if (rateEl) rateEl.textContent = `${verificationRate}%`;

        // Update Top Performers (sorted by count)
        const events = [
            { name: 'Testing', count: testingCount },
            { name: 'PromptQuest', count: promptquestCount },
            { name: 'UI Battle', count: uibattleCount }
        ].sort((a, b) => b.count - a.count);

        const performersContainer = document.querySelector('.top-performers');
        if (performersContainer) {
            const h4 = performersContainer.querySelector('h4');
            performersContainer.innerHTML = '';
            if (h4) performersContainer.appendChild(h4);
            else performersContainer.innerHTML = '<h4>🏆 Top Events This Week</h4>';

            events.forEach((event, index) => {
                const item = document.createElement('div');
                item.className = 'performer-item';
                item.innerHTML = `
                    <span class="performer-rank">${index + 1}</span>
                    <span class="performer-name">${event.name}</span>
                    <span class="performer-count">${event.count} teams</span>
                `;
                performersContainer.appendChild(item);
            });
        }

        console.log('[Hub] Analytics updated:', { newToday, pendingCount, verifiedCount, verificationRate });
    } catch (err) {
        console.error('[Hub] Update error:', err);
    }
}

window.updateAnalyticsHub = updateAnalyticsHub;

// ===== ANIMATED CALENDAR COMPONENT =====
const calendarState = {};

function initCalendarState(eventCode) {
    if (!calendarState[eventCode]) {
        const now = new Date();
        calendarState[eventCode] = {
            currentMonth: now.getMonth(),
            currentYear: now.getFullYear(),
            fromDate: null,
            toDate: null,
            selectingStart: true
        };
    }

    // Ensure currentMonth and currentYear are valid
    const state = calendarState[eventCode];
    if (typeof state.currentMonth !== 'number' || isNaN(state.currentMonth)) {
        state.currentMonth = new Date().getMonth();
    }
    if (typeof state.currentYear !== 'number' || isNaN(state.currentYear)) {
        state.currentYear = new Date().getFullYear();
    }

    return calendarState[eventCode];
}

function toggleCalendar(eventCode) {
    const dropdown = document.getElementById(`calendarDropdown-${eventCode}`);
    const trigger = dropdown?.previousElementSibling;

    // Close all other calendars
    document.querySelectorAll('.calendar-dropdown.open').forEach(d => {
        if (d.id !== `calendarDropdown-${eventCode}`) {
            d.classList.remove('open');
            d.previousElementSibling?.classList.remove('active');
        }
    });

    if (dropdown) {
        dropdown.classList.toggle('open');
        trigger?.classList.toggle('active');

        if (dropdown.classList.contains('open')) {
            // CSS handles positioning via absolute positioning

            initCalendarState(eventCode);

            // If there's a selected fromDate, navigate to that month
            const state = calendarState[eventCode];
            if (state && state.fromDate) {
                // Ensure fromDate is a proper Date object
                const fromDateObj = state.fromDate instanceof Date ? state.fromDate : new Date(state.fromDate);
                if (!isNaN(fromDateObj.getTime())) {
                    state.currentMonth = fromDateObj.getMonth();
                    state.currentYear = fromDateObj.getFullYear();
                }
            }

            renderCalendar(eventCode);
        }
    }
}
window.toggleCalendar = toggleCalendar;

function renderCalendar(eventCode) {
    const state = initCalendarState(eventCode);
    const daysContainer = document.getElementById(`calendarDays-${eventCode}`);
    const titleEl = document.getElementById(`calendarTitle-${eventCode}`);

    if (!daysContainer || !titleEl) return;

    const months = ['January', 'February', 'March', 'April', 'May', 'June',
        'July', 'August', 'September', 'October', 'November', 'December'];

    titleEl.textContent = `${months[state.currentMonth]} ${state.currentYear}`;

    const firstDay = new Date(state.currentYear, state.currentMonth, 1);
    const lastDay = new Date(state.currentYear, state.currentMonth + 1, 0);
    const startDay = firstDay.getDay();
    const daysInMonth = lastDay.getDate();


    const today = new Date();
    today.setHours(0, 0, 0, 0);

    daysContainer.innerHTML = '';

    // Empty cells for days before first
    for (let i = 0; i < startDay; i++) {
        daysContainer.innerHTML += '<button class="calendar-day empty"></button>';
    }

    // Days of month
    for (let day = 1; day <= daysInMonth; day++) {
        const date = new Date(state.currentYear, state.currentMonth, day);
        date.setHours(0, 0, 0, 0);

        let classes = 'calendar-day';

        if (date.getTime() === today.getTime()) {
            classes += ' today';
        }

        // Range highlighting
        if (state.fromDate && state.toDate) {
            const from = new Date(state.fromDate).setHours(0, 0, 0, 0);
            const to = new Date(state.toDate).setHours(0, 0, 0, 0);
            const curr = date.getTime();

            if (curr === from && curr === to) {
                classes += ' selected range-start range-end';
            } else if (curr === from) {
                classes += ' selected range-start';
            } else if (curr === to) {
                classes += ' selected range-end';
            } else if (curr > from && curr < to) {
                classes += ' in-range';
            }
        } else if (state.fromDate && !state.toDate) {
            const from = new Date(state.fromDate).setHours(0, 0, 0, 0);
            if (date.getTime() === from) {
                classes += ' selected range-start';
            }
        }

        daysContainer.innerHTML += `<button class="${classes}" onclick="selectCalendarDay('${eventCode}', ${day})">${day}</button>`;
    }
}
window.renderCalendar = renderCalendar;

function selectCalendarDay(eventCode, day) {
    const state = calendarState[eventCode];
    if (!state) return;

    const selectedDate = new Date(state.currentYear, state.currentMonth, day);

    if (state.selectingStart || (state.fromDate && state.toDate)) {
        // Starting new selection
        state.fromDate = selectedDate;
        state.toDate = null;
        state.selectingStart = false;
    } else {
        // Completing range
        if (selectedDate < state.fromDate) {
            state.toDate = state.fromDate;
            state.fromDate = selectedDate;
        } else {
            state.toDate = selectedDate;
        }
        state.selectingStart = true;

        // Close calendar after end date is selected
        setTimeout(() => {
            const dropdown = document.getElementById(`calendarDropdown-${eventCode}`);
            if (dropdown) {
                dropdown.classList.remove('open');
                dropdown.previousElementSibling?.classList.remove('active');
            }
        }, 300);
    }

    renderCalendar(eventCode);
    updateCalendarText(eventCode);
    updateHiddenInputs(eventCode);
}
window.selectCalendarDay = selectCalendarDay;

function updateCalendarText(eventCode) {
    const state = calendarState[eventCode];
    const textEl = document.getElementById(`calendarText-${eventCode}`);

    if (!state || !textEl) return;

    if (state.fromDate && state.toDate) {
        textEl.textContent = `${formatDate(state.fromDate)} – ${formatDate(state.toDate)}`;
        textEl.classList.remove('placeholder');
    } else if (state.fromDate) {
        textEl.textContent = `${formatDate(state.fromDate)} – Select end`;
        textEl.classList.remove('placeholder');
    } else {
        textEl.textContent = 'Select date range';
        textEl.classList.add('placeholder');
    }
}

function updateHiddenInputs(eventCode) {
    const state = calendarState[eventCode];
    const fromInput = document.getElementById(`filterDateFrom-${eventCode}`);
    const toInput = document.getElementById(`filterDateTo-${eventCode}`);

    if (fromInput && state?.fromDate) {
        fromInput.value = state.fromDate.toISOString().split('T')[0];
    } else if (fromInput) {
        fromInput.value = '';
    }

    if (toInput && state?.toDate) {
        toInput.value = state.toDate.toISOString().split('T')[0];
    } else if (toInput) {
        toInput.value = '';
    }
}

function formatDate(date) {
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    return `${months[date.getMonth()]} ${date.getDate()}, ${date.getFullYear()}`;
}

function calendarPrevMonth(eventCode) {
    const state = calendarState[eventCode];
    if (!state) return;

    state.currentMonth--;
    if (state.currentMonth < 0) {
        state.currentMonth = 11;
        state.currentYear--;
    }
    renderCalendar(eventCode);
}
window.calendarPrevMonth = calendarPrevMonth;

function calendarNextMonth(eventCode) {
    const state = calendarState[eventCode];
    if (!state) return;

    state.currentMonth++;
    if (state.currentMonth > 11) {
        state.currentMonth = 0;
        state.currentYear++;
    }
    renderCalendar(eventCode);
}
window.calendarNextMonth = calendarNextMonth;

function calendarPrevYear(eventCode) {
    const state = calendarState[eventCode];
    if (state) {
        state.currentYear--;
        renderCalendar(eventCode);
    }
}
window.calendarPrevYear = calendarPrevYear;

function calendarNextYear(eventCode) {
    const state = calendarState[eventCode];
    if (state) {
        state.currentYear++;
        renderCalendar(eventCode);
    }
}
window.calendarNextYear = calendarNextYear;

function calendarSelectToday(eventCode) {
    const state = calendarState[eventCode];
    if (!state) return;

    const today = new Date();
    state.currentMonth = today.getMonth();
    state.currentYear = today.getFullYear();
    state.fromDate = today;
    state.toDate = today;
    state.selectingStart = true;

    renderCalendar(eventCode);
    updateCalendarText(eventCode);
    updateHiddenInputs(eventCode);
}
window.calendarSelectToday = calendarSelectToday;

function calendarClear(eventCode) {
    const state = calendarState[eventCode];
    if (!state) return;

    state.fromDate = null;
    state.toDate = null;
    state.selectingStart = true;

    renderCalendar(eventCode);
    updateCalendarText(eventCode);
    updateHiddenInputs(eventCode);
}
window.calendarClear = calendarClear;

// Close calendar on outside click
document.addEventListener('click', (e) => {
    if (!e.target.closest('.animated-calendar')) {
        document.querySelectorAll('.calendar-dropdown.open').forEach(d => {
            d.classList.remove('open');
            d.previousElementSibling?.classList.remove('active');
        });
    }
});

// ===== DASHBOARD STATS =====
async function updateDashboardStats(eventCode = null) {
    try {
        const statsTeams = document.getElementById('stat-totalTeams');
        const statsParticipants = document.getElementById('stat-participants');
        const statsEvents = document.getElementById('stat-events');
        const statsGallery = document.getElementById('stat-gallery');
        const statsTeamsChange = document.getElementById('stat-teamsChange');
        const statsParticipantsChange = document.getElementById('stat-participantsChange');
        const statsEventsChange = document.getElementById('stat-eventsChange');
        const statsGalleryChange = document.getElementById('stat-galleryChange');

        // Get events list
        await loadAllEvents();
        const activeEventCount = allEvents.filter(e => e.isActive).length;

        const isSuperAdmin = AdminPermissions.isSuperAdmin();
        const accessibleEvents = AdminPermissions.getAccessibleEvents();

        // Determine which event(s) to query
        let eventsToQuery = [];
        let statsLabel = '';

        if (eventCode) {
            // Specific event requested (e.g., when viewing an event)
            eventsToQuery = [eventCode];
            const eventName = allEvents.find(e => e.code === eventCode)?.name || eventCode;
            statsLabel = `📊 ${eventName}`;
        } else if (isSuperAdmin) {
            // Super admin: show global stats from ALL events
            eventsToQuery = allEvents.filter(e => e.isActive).map(e => e.code);
            statsLabel = 'All events';
        } else {
            // Normal admin: show stats from active routing event
            try {
                const configDoc = await getDoc(doc(db, 'config', 'routing'));
                const activeRoutingEvent = configDoc.exists() ? (configDoc.data().activeEvent || 'testing') : 'testing';

                // Only use if they have access
                if (accessibleEvents && accessibleEvents.includes(activeRoutingEvent)) {
                    eventsToQuery = [activeRoutingEvent];
                } else if (accessibleEvents && accessibleEvents.length > 0) {
                    eventsToQuery = [accessibleEvents[0]]; // Fallback to first accessible
                } else {
                    eventsToQuery = ['testing']; // Ultimate fallback
                }
                const eventName = allEvents.find(e => e.code === eventsToQuery[0])?.name || eventsToQuery[0];
                statsLabel = `📊 ${eventName}`;
            } catch (e) {
                console.warn('[Stats] Could not load routing config, using first accessible event');
                eventsToQuery = accessibleEvents && accessibleEvents.length > 0 ? [accessibleEvents[0]] : ['testing'];
                statsLabel = 'Current event';
            }
        }

        // Query each event and sum up stats
        let totalTeams = 0;
        let totalParticipants = 0;
        let newThisWeek = 0;
        let todayCount = 0;
        const weekAgo = new Date();
        weekAgo.setDate(weekAgo.getDate() - 7);
        const today = new Date();
        today.setHours(0, 0, 0, 0);

        for (const code of eventsToQuery) {
            try {
                const regQuery = query(collection(db, 'registrations'), where('eventCode', '==', code));
                const regSnapshot = await getDocs(regQuery);
                totalTeams += regSnapshot.size;

                regSnapshot.forEach(docSnap => {
                    const d = docSnap.data();
                    // Count participants
                    totalParticipants += [d.member1, d.member2, d.member3].filter(m => m?.name).length;

                    // Count new registrations
                    if (d.registeredAt) {
                        const regDate = d.registeredAt.toDate ? d.registeredAt.toDate() : new Date(d.registeredAt.seconds * 1000);
                        if (regDate > weekAgo) newThisWeek++;
                        if (regDate >= today) todayCount++;
                    }
                });
            } catch (e) {
                console.warn(`[Stats] Could not fetch stats for ${code}:`, e.message);
            }
        }

        // Get gallery photos count (if super admin)
        let galleryCount = 0;
        if (isSuperAdmin) {
            try {
                const gallerySnapshot = await getDocs(collection(db, 'gallery'));
                galleryCount = gallerySnapshot.size;
            } catch (e) {
                console.log('[Stats] Could not fetch gallery count');
            }
        }

        // Update UI with animation & remove skeletons
        function revealStatCard(cardId, statEl, value, changeEl, changeText) {
            const card = document.getElementById(cardId);
            if (card) {
                card.classList.remove('skeleton-loading');
                card.classList.add('loaded');
            }
            if (statEl) {
                statEl.textContent = '';
                if (typeof window.animateStat === 'function' && typeof value === 'number' && !isNaN(value)) {
                    window.animateStat(statEl.id, value);
                } else {
                    statEl.textContent = value;
                }
            }
            if (changeEl) changeEl.textContent = changeText;
        }

        revealStatCard('card-totalTeams', statsTeams, totalTeams, statsTeamsChange, newThisWeek > 0 ? `↑ ${newThisWeek} this week` : statsLabel);
        setTimeout(() => revealStatCard('card-participants', statsParticipants, totalParticipants, statsParticipantsChange, todayCount > 0 ? `↑ ${todayCount} today` : statsLabel), 120);
        setTimeout(() => revealStatCard('card-events', statsEvents, activeEventCount, statsEventsChange, 'Active events'), 240);
        setTimeout(() => revealStatCard('card-gallery', statsGallery, galleryCount || '--', statsGalleryChange, isSuperAdmin ? 'Uploaded' : '--'), 360);

        console.log('[Stats] Dashboard stats updated for:', eventsToQuery.join(', '));
    } catch (error) {
        console.error('Error updating dashboard stats:', error);
        // Set fallback values
        const fallbackStats = ['stat-totalTeams', 'stat-participants', 'stat-events', 'stat-gallery'];
        fallbackStats.forEach(id => {
            const el = document.getElementById(id);
            if (el) el.textContent = '--';
        });
    }
}
window.updateDashboardStats = updateDashboardStats;


// ===== INIT =====
window.addEventListener('DOMContentLoaded', async () => {
    // Set session-based persistence - user must re-login when browser closes
    await setPersistence(auth, browserSessionPersistence);

    // Check if user is already authenticated (only within this browser session)
    const unsubscribe = onAuthStateChanged(auth, async (user) => {
        // Unsubscribe immediately - we only need this check once on load
        unsubscribe();

        if (user) {
            // User is already logged in - verify admin role and load data
            const adminData = await checkAdminRole(user);
            if (adminData) {
                // Apply role-based UI
                applyRoleBasedUI();

                // Show dashboard
                document.getElementById('login-page').style.display = 'none';
                document.getElementById('admin-dashboard').classList.add('active');

                // Initialize the dynamic event system
                await initDynamicEvents();

                // Load routing config
                loadRoutingConfig();

                // Render the registrations chart after data is loaded
                renderRegistrationsChart();

                // Update analytics hub with live data
                updateAnalyticsHub();

                // Update dashboard stats
                updateDashboardStats();

                // Start session countdown timer
                resetInactivityTimer();
            } else {
                // User exists but not an admin - sign out
                await signOut(auth);
            }
        }
        // If no user, just show login page (default state)
    });
});

// ===== MOBILE NAVBAR TOGGLE =====
function toggleNav() {
    const navLinks = document.getElementById("navLinks");
    const hamburger = document.getElementById("hamburger");
    navLinks.classList.toggle("active");
    hamburger.classList.toggle("active");
}
window.toggleNav = toggleNav;

// Close mobile menu when clicking outside
document.addEventListener("click", function (event) {
    const navLinks = document.getElementById("navLinks");
    const hamburger = document.getElementById("hamburger");
    const navbar = document.getElementById("navbar");
    if (navbar && !navbar.contains(event.target) && navLinks.classList.contains("active")) {
        navLinks.classList.remove("active");
        hamburger.classList.remove("active");
    }
});

// ===== TEAM MANAGEMENT =====
let teamMembersData = [];
let currentTeamFilter = 'all';

// Open Team Management Modal
function openTeamManagement() {
    document.getElementById('teamManagementModal').classList.add('active');
    loadTeamMembers();
}
window.openTeamManagement = openTeamManagement;

// Load all team members from Firebase
async function loadTeamMembers() {
    const listContainer = document.getElementById('teamMembersList');
    listContainer.innerHTML = `
        <div class="team-mgmt-loading">
            <div style="font-size: 32px; margin-bottom: 8px;">⏳</div>
            Loading team members...
        </div>`;

    try {
        const teamQuery = query(collection(db, 'teamMembers'), orderBy('order', 'asc'));
        const snapshot = await getDocs(teamQuery);

        teamMembersData = [];
        snapshot.forEach(doc => {
            teamMembersData.push({ id: doc.id, ...doc.data() });
        });

        renderTeamMembersList();
    } catch (error) {
        console.error('Error loading team members:', error);
        listContainer.innerHTML = `
            <div class="team-mgmt-empty">
                <div class="team-mgmt-empty-icon">⚠️</div>
                <div class="team-mgmt-empty-text" style="color: #ef4444;">Error loading team members</div>
            </div>`;
    }
}

// Filter team members by category
function filterTeamMembers(category, btn) {
    currentTeamFilter = category;

    // Update active tab
    document.querySelectorAll('.team-mgmt-tab').forEach(tab => tab.classList.remove('active'));
    btn.classList.add('active');

    renderTeamMembersList();
}
window.filterTeamMembers = filterTeamMembers;

// Render team members list
function renderTeamMembersList() {
    const listContainer = document.getElementById('teamMembersList');

    let filteredMembers = teamMembersData;
    if (currentTeamFilter !== 'all') {
        filteredMembers = teamMembersData.filter(m => m.category === currentTeamFilter);
    }

    if (filteredMembers.length === 0) {
        listContainer.innerHTML = `
            <div class="team-mgmt-empty">
                <div class="team-mgmt-empty-icon">👥</div>
                <div class="team-mgmt-empty-text">No team members found</div>
            </div>`;
        return;
    }

    const categoryLabels = {
        'faculty': 'Faculty Coordinator',
        'core': 'Core Team',
        'volunteers': 'Volunteer'
    };

    // Helper to get admin-relative path (admin1/ needs ../ prefix for root-relative paths)
    // const getAdminImagePath = (path) => {
    //     if (!path) return '';
    //     // If it's already a full URL, use as-is
    //     if (path.startsWith('http://') || path.startsWith('https://')) return path;
    //     // Normalize backslashes to forward slashes
    //     const normalizedPath = path.replace(/\\/g, '/');
    //     // For local paths like "images/...", prepend "../" for admin folder
    //     if (normalizedPath.startsWith('images/')) return '../' + normalizedPath;
    //     return normalizedPath;
    // };

    const getAdminImagePath = (path) => {
    if (!path) return '';
    // If it's already a full URL, use as-is
    if (path.startsWith('http://') || path.startsWith('https://')) return path;
    // Normalize backslashes to forward slashes
    const normalizedPath = path.replace(/\\/g, '/');
    // For local paths like "Name.png", prepend "images/" and "../" for admin folder
    if (!normalizedPath.startsWith('images/')) {
        return '../images/' + normalizedPath;
    }
    // If already has images/ prefix
    return '../' + normalizedPath;
    };

    
    listContainer.innerHTML = filteredMembers.map(member => `
        <div class="team-mgmt-item" data-id="${member.id}">
            ${member.imageUrl
            ? `<img class="team-mgmt-item-avatar" src="${SecurityUtils.escapeHtml(getAdminImagePath(member.imageUrl))}" alt="${SecurityUtils.escapeHtml(member.name)}" onerror="this.style.display='none'; this.nextElementSibling.style.display='flex';">
                   <div class="team-mgmt-item-avatar team-mgmt-avatar-placeholder" style="display:none;">${getInitials(member.name)}</div>`
            : `<div class="team-mgmt-item-avatar team-mgmt-avatar-placeholder">${getInitials(member.name)}</div>`}
            <div class="team-mgmt-item-info">
                <div class="team-mgmt-item-name">${SecurityUtils.escapeHtml(member.name)}</div>
                <div class="team-mgmt-item-role">${SecurityUtils.escapeHtml(member.role)}</div>
                <span class="team-mgmt-item-category ${member.category}">${categoryLabels[member.category] || member.category}</span>
            </div>
            <div class="team-mgmt-item-actions">
                <button class="team-mgmt-action-btn edit" onclick="openEditMember('${member.id}')" title="Edit">✏️</button>
                ${AdminPermissions.canDelete() ? `<button class="team-mgmt-action-btn delete" onclick="openDeleteMember('${member.id}')" title="Delete">🗑️</button>` : ''}
            </div>
        </div>
    `).join('');
}

// Get initials from name
function getInitials(name) {
    if (!name) return '?';
    return name.split(' ').map(n => n[0]).join('').toUpperCase().slice(0, 2);
}

// Add new team member
async function addTeamMember() {
    const name = document.getElementById('newMemberName').value.trim();
    const category = document.getElementById('newMemberCategory').value;
    const role = document.getElementById('newMemberRole').value.trim();
    const department = document.getElementById('newMemberDept').value.trim();
    const imageUrl = document.getElementById('newMemberImage').value.trim();
    const order = parseInt(document.getElementById('newMemberOrder').value) || 1;
    const linkedin = document.getElementById('newMemberLinkedin').value.trim();
    const github = document.getElementById('newMemberGithub').value.trim();
    const email = document.getElementById('newMemberEmail').value.trim();

    if (!name || !category || !role) {
        showToast('Please fill in all required fields', 'error');
        return;
    }

    // Only super admins can manage team members
    if (!AdminPermissions.isSuperAdmin()) {
        showToast('Only super admins can add team members', 'error');
        return;
    }

    try {
        const memberData = {
            name: SecurityUtils.sanitizeString(name, 100),
            category: category,
            role: SecurityUtils.sanitizeString(role, 50),
            department: SecurityUtils.sanitizeString(department, 50),
            imageUrl: imageUrl ? SecurityUtils.sanitizeString(imageUrl, 500) : '',
            order: order,
            socials: {
                linkedin: linkedin ? SecurityUtils.sanitizeString(linkedin, 200) : '',
                github: github ? SecurityUtils.sanitizeString(github, 200) : '',
                email: email ? SecurityUtils.sanitizeString(email, 100) : ''
            },
            createdAt: serverTimestamp(),
            updatedAt: serverTimestamp()
        };

        await addDoc(collection(db, 'teamMembers'), memberData);

        // Clear form
        document.getElementById('newMemberName').value = '';
        document.getElementById('newMemberRole').value = '';
        document.getElementById('newMemberDept').value = '';
        document.getElementById('newMemberImage').value = '';
        document.getElementById('newMemberOrder').value = '1';
        document.getElementById('newMemberLinkedin').value = '';
        document.getElementById('newMemberGithub').value = '';
        document.getElementById('newMemberEmail').value = '';

        showToast('Team member added successfully!', 'success');
        loadTeamMembers();
    } catch (error) {
        console.error('Error adding team member:', error);
        showToast('Error adding team member', 'error');
    }
}
window.addTeamMember = addTeamMember;

// Open edit member modal
function openEditMember(memberId) {
    const member = teamMembersData.find(m => m.id === memberId);
    if (!member) return;

    document.getElementById('editMemberId').value = memberId;
    document.getElementById('editMemberName').value = member.name || '';
    document.getElementById('editMemberCategory').value = member.category || 'core';
    document.getElementById('editMemberRole').value = member.role || '';
    document.getElementById('editMemberDept').value = member.department || '';
    document.getElementById('editMemberImage').value = member.imageUrl || '';
    document.getElementById('editMemberOrder').value = member.order || 1;
    document.getElementById('editMemberLinkedin').value = member.socials?.linkedin || '';
    document.getElementById('editMemberGithub').value = member.socials?.github || '';
    document.getElementById('editMemberEmailAddr').value = member.socials?.email || '';

    document.getElementById('editMemberModal').classList.add('active');
}
window.openEditMember = openEditMember;

// Save team member edit
async function saveTeamMemberEdit() {
    const memberId = document.getElementById('editMemberId').value;
    const name = document.getElementById('editMemberName').value.trim();
    const category = document.getElementById('editMemberCategory').value;
    const role = document.getElementById('editMemberRole').value.trim();
    const department = document.getElementById('editMemberDept').value.trim();
    const imageUrl = document.getElementById('editMemberImage').value.trim();
    const order = parseInt(document.getElementById('editMemberOrder').value) || 1;
    const linkedin = document.getElementById('editMemberLinkedin').value.trim();
    const github = document.getElementById('editMemberGithub').value.trim();
    const email = document.getElementById('editMemberEmailAddr').value.trim();

    if (!name || !category || !role) {
        showToast('Please fill in all required fields', 'error');
        return;
    }

    // Only super admins can manage team members
    if (!AdminPermissions.isSuperAdmin()) {
        showToast('Only super admins can edit team members', 'error');
        return;
    }

    try {
        const memberRef = doc(db, 'teamMembers', memberId);
        await updateDoc(memberRef, {
            name: SecurityUtils.sanitizeString(name, 100),
            category: category,
            role: SecurityUtils.sanitizeString(role, 50),
            department: SecurityUtils.sanitizeString(department, 50),
            imageUrl: imageUrl ? SecurityUtils.sanitizeString(imageUrl, 500) : '',
            order: order,
            socials: {
                linkedin: linkedin ? SecurityUtils.sanitizeString(linkedin, 200) : '',
                github: github ? SecurityUtils.sanitizeString(github, 200) : '',
                email: email ? SecurityUtils.sanitizeString(email, 100) : ''
            },
            updatedAt: serverTimestamp()
        });

        closeModal('editMemberModal');
        showToast('Team member updated successfully!', 'success');
        loadTeamMembers();
    } catch (error) {
        console.error('Error updating team member:', error);
        showToast('Error updating team member', 'error');
    }
}
window.saveTeamMemberEdit = saveTeamMemberEdit;

// Open delete confirmation
function openDeleteMember(memberId) {
    const member = teamMembersData.find(m => m.id === memberId);
    if (!member) return;

    document.getElementById('deleteMemberId').value = memberId;
    document.getElementById('deleteMemberName').textContent = member.name;
    document.getElementById('deleteMemberModal').classList.add('active');
}
window.openDeleteMember = openDeleteMember;

// Confirm delete team member
async function confirmDeleteMember() {
    const memberId = document.getElementById('deleteMemberId').value;

    // Only super admins can delete team members
    if (!AdminPermissions.canDelete()) {
        closeModal('deleteMemberModal');
        showToast('Only super admins can delete team members', 'error');
        return;
    }

    try {
        // Pre-check: verify admin doc exists with UID for Firestore rules
        const currentUser = auth.currentUser;
        if (currentUser) {
            const adminDocRef = doc(db, 'admins', currentUser.uid);
            const adminDoc = await getDoc(adminDocRef);
            if (!adminDoc.exists()) {
                console.error('[Delete] Admin doc not found for UID:', currentUser.uid, '- Firestore rules will reject. Attempting migration...');
                // Try to find and migrate admin doc by email
                const adminsRef = collection(db, 'admins');
                const emailQuery = query(adminsRef, where('email', '==', currentUser.email));
                const querySnapshot = await getDocs(emailQuery);
                if (!querySnapshot.empty) {
                    const foundDoc = querySnapshot.docs[0];
                    const adminData = foundDoc.data();
                    await setDoc(doc(db, 'admins', currentUser.uid), {
                        ...adminData,
                        uid: currentUser.uid,
                        migratedFrom: foundDoc.id,
                        migratedAt: serverTimestamp()
                    });
                    await deleteDoc(doc(db, 'admins', foundDoc.id));
                    console.log('[Delete] Admin doc migrated to UID:', currentUser.uid);
                } else {
                    closeModal('deleteMemberModal');
                    showToast('Admin verification failed. Please re-login.', 'error');
                    return;
                }
            } else {
                const data = adminDoc.data();
                console.log('[Delete] Admin doc verified - role:', data.role, 'isActive:', data.isActive);
                if (data.role !== 'super' || data.isActive !== true) {
                    closeModal('deleteMemberModal');
                    showToast('Insufficient permissions. Your admin doc may need updating.', 'error');
                    return;
                }
            }
        }

        await deleteDoc(doc(db, 'teamMembers', memberId));
        closeModal('deleteMemberModal');
        showToast('Team member deleted successfully!', 'success');
        loadTeamMembers();
    } catch (error) {
        console.error('Error deleting team member:', error);
        if (error.code === 'permission-denied') {
            showToast('Permission denied. Check Firestore rules & admin doc.', 'error');
        } else {
            showToast('Error deleting team member: ' + error.message, 'error');
        }
    }
}
window.confirmDeleteMember = confirmDeleteMember;

// ===== FEEDBACK VIEWER =====
let feedbackData = [];

async function openFeedbackViewer() {
    document.getElementById('feedbackModal').classList.add('active');
    await loadFeedback();
}
window.openFeedbackViewer = openFeedbackViewer;

async function loadFeedback() {
    const feedbackList = document.getElementById('feedbackList');
    
    try {
        const snapshot = await getDocs(
            query(collection(db, 'feedback'), orderBy('timestamp', 'desc'), limit(100))
        );
        
        feedbackData = [];
        const ratingCounts = { 1: 0, 2: 0, 3: 0, 4: 0 };
        
        snapshot.forEach(doc => {
            const data = { id: doc.id, ...doc.data() };
            feedbackData.push(data);
            if (data.rating >= 1 && data.rating <= 4) {
                ratingCounts[data.rating]++;
            }
        });
        
        // Update stats
        document.getElementById('rating4Count').textContent = ratingCounts[4];
        document.getElementById('rating3Count').textContent = ratingCounts[3];
        document.getElementById('rating2Count').textContent = ratingCounts[2];
        document.getElementById('rating1Count').textContent = ratingCounts[1];
        
        // Render feedback list
        if (feedbackData.length === 0) {
            feedbackList.innerHTML = `
                <div class="feedback-empty">
                    <div class="feedback-empty-icon">📭</div>
                    <p>No feedback yet</p>
                </div>
            `;
            return;
        }
        
        const ratingEmojis = {
            1: '😢',
            2: '😕',
            3: '🙂',
            4: '😄'
        };
        
        const ratingLabels = {
            1: 'Very Unhappy',
            2: 'Unhappy',
            3: 'Happy',
            4: 'Very Happy'
        };
        
        feedbackList.innerHTML = feedbackData.map(item => {
            const date = item.timestamp?.toDate?.() 
                ? item.timestamp.toDate().toLocaleDateString('en-US', { 
                    year: 'numeric', month: 'short', day: 'numeric', 
                    hour: '2-digit', minute: '2-digit' 
                }) 
                : 'Unknown date';
            
            return `
                <div class="feedback-item" data-id="${item.id}">
                    <div class="feedback-item-header">
                        <div class="feedback-rating">
                            <span class="rating-emoji">${ratingEmojis[item.rating] || '❓'}</span>
                            <span class="rating-label">${ratingLabels[item.rating] || 'Unknown'}</span>
                        </div>
                        <div class="feedback-actions">
                            <span class="feedback-date">${date}</span>
                            <button class="feedback-delete-btn" onclick="deleteFeedback('${item.id}')" title="Delete">🗑️</button>
                        </div>
                    </div>
                    ${item.feedback ? `<div class="feedback-message">${SecurityUtils.escapeHtml(item.feedback)}</div>` : ''}
                    <div class="feedback-meta">
                        <span>📄 ${item.page || 'Unknown page'}</span>
                    </div>
                </div>
            `;
        }).join('');
        
    } catch (error) {
        console.error('Error loading feedback:', error);
        feedbackList.innerHTML = `
            <div class="feedback-empty">
                <div class="feedback-empty-icon">❌</div>
                <p>Error loading feedback</p>
            </div>
        `;
    }
}

function exportFeedback() {
    if (feedbackData.length === 0) {
        showToast('No feedback to export', 'error');
        return;
    }
    
    const ratingLabels = { 1: 'Very Unhappy', 2: 'Unhappy', 3: 'Happy', 4: 'Very Happy' };
    
    const csvContent = [
        ['Date', 'Rating', 'Rating Label', 'Feedback', 'Page'].join(','),
        ...feedbackData.map(item => {
            const date = item.timestamp?.toDate?.() 
                ? item.timestamp.toDate().toISOString() 
                : '';
            return [
                `"${date}"`,
                item.rating,
                `"${ratingLabels[item.rating] || 'Unknown'}"`,
                `"${(item.feedback || '').replace(/"/g, '""')}"`,
                `"${item.page || ''}"`
            ].join(',');
        })
    ].join('\n');
    
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `feedback_export_${new Date().toISOString().split('T')[0]}.csv`;
    link.click();
    
    showToast('Feedback exported successfully!', 'success');
}
window.exportFeedback = exportFeedback;

async function deleteFeedback(feedbackId) {
    if (!confirm('Delete this feedback?')) return;
    
    try {
        await deleteDoc(doc(db, 'feedback', feedbackId));
        showToast('Feedback deleted', 'success');
        await loadFeedback(); // Refresh list
    } catch (error) {
        console.error('Error deleting feedback:', error);
        showToast('Error deleting feedback: ' + error.message, 'error');
    }
}
window.deleteFeedback = deleteFeedback;

async function clearAllFeedback() {
    const count = feedbackData.length;
    if (count === 0) {
        showToast('No feedback to clear', 'error');
        return;
    }
    
    if (!confirm(`Are you sure you want to delete ALL ${count} feedback entries? This cannot be undone.`)) return;
    
    try {
        // Delete all feedback documents
        const deletePromises = feedbackData.map(item => 
            deleteDoc(doc(db, 'feedback', item.id))
        );
        await Promise.all(deletePromises);
        
        showToast(`Cleared ${count} feedback entries`, 'success');
        await loadFeedback(); // Refresh list
    } catch (error) {
        console.error('Error clearing feedback:', error);
        showToast('Error clearing feedback: ' + error.message, 'error');
    }
}
window.clearAllFeedback = clearAllFeedback;
