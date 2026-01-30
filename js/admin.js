// ===== FIREBASE IMPORTS =====
import { initializeApp } from "https://www.gstatic.com/firebasejs/11.0.2/firebase-app.js";
import { getAuth, signInWithEmailAndPassword, signOut, onAuthStateChanged } from "https://www.gstatic.com/firebasejs/11.0.2/firebase-auth.js";
import { getFirestore, collection, getDocs, doc, deleteDoc, updateDoc, setDoc, getDoc, orderBy, query, where, addDoc, serverTimestamp } from "https://www.gstatic.com/firebasejs/11.0.2/firebase-firestore.js";

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
// Note: Firebase API keys are designed to be public. Security is enforced via:
// 1. Firebase Security Rules (server-side)
// 2. Firebase Authentication
// 3. App Check (recommended for production)
const firebaseConfig = {
    apiKey: "AIzaSyAf1JlNjAsUGib1PpZWF6xELseRERpLE48",
    authDomain: "iste-toce.firebaseapp.com",
    projectId: "iste-toce",
    storageBucket: "iste-toce.firebasestorage.app",
    messagingSenderId: "918228043244",
    appId: "1:918228043244:web:891b81cc0a80127588ecc9",
    measurementId: "G-RWG0BCFGEJ"
};

const app = initializeApp(firebaseConfig);
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

// ===== SESSION TIMEOUT =====
let inactivityTimer;
const SESSION_TIMEOUT_MS = 30 * 60 * 1000;

function resetInactivityTimer() {
    clearTimeout(inactivityTimer);
    if (auth.currentUser) {
        inactivityTimer = setTimeout(() => {
            signOut(auth).then(() => showToast('Session expired'));
        }, SESSION_TIMEOUT_MS);
    }
}

['click', 'keypress', 'scroll', 'mousemove'].forEach(event => {
    document.addEventListener(event, resetInactivityTimer, { passive: true });
});

// ===== LOGOUT HANDLER =====
function handleLogout() {
    signOut(auth)
        .then(() => {
            clearTimeout(inactivityTimer);
            document.getElementById('admin-dashboard').classList.remove('active');
            document.getElementById('login-page').style.display = 'flex';
            showToast('Logged out successfully');
            console.log('Logout successful');
        })
        .catch((error) => {
            console.error('Logout error:', error);
            showToast('Error logging out');
        });
}
window.handleLogout = handleLogout;

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
window.deleteFromFirestore = async function(collectionPath, docId, teamName = 'Unknown') {
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

window.updateInFirestore = async function(collectionPath, docId, data) {
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

window.undoDelete = async function(docId) {
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

// ===== MODAL FUNCTIONS (SECURED) =====
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
        } catch (e) {}
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
    document.body.style.overflow = 'hidden';
}
window.openTeamDrawer = openTeamDrawer;

function closeTeamDrawer() {
    document.getElementById('teamDrawerOverlay').classList.remove('active');
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
    // Validate status
    const validStatuses = ['Pending', 'Verified', 'verified', 'pending'];
    if (!validStatuses.includes(newStatus)) {
        showToast('⚠️ Invalid status');
        return;
    }
    
    // Rate limiting
    const rateCheck = rateLimiters.bulkAction.recordAttempt('bulk_' + (auth.currentUser?.uid || 'anon'));
    if (!rateCheck.allowed) {
        showToast(`⏳ Too many bulk actions. Try again in ${rateCheck.retryAfter}s`);
        return;
    }
    
    const selected = document.querySelectorAll('.row-checkbox:checked');
    if (selected.length === 0) { showToast('No teams selected'); return; }
    if (selected.length > 50) { showToast('⚠️ Maximum 50 teams at once'); return; }
    if (!confirm(`Update ${selected.length} team(s) to "${newStatus}"?`)) return;
    
    let count = 0;
    for (const cb of selected) {
        const teamId = cb.dataset.teamId;
        if (SecurityUtils.isValidDocId(teamId) && await window.updateInFirestore('registrations', teamId, { status: newStatus })) {
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
}
window.openEventView = openEventView;

function backToEventSelector() {
    document.getElementById('event-detail-view')?.classList.remove('active');
    document.getElementById('event-selector-view')?.classList.remove('hidden');
}
window.backToEventSelector = backToEventSelector;

function switchEvent(eventName, btn) {
    document.querySelectorAll('.event-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.event-content').forEach(c => c.classList.remove('active'));
    if (btn) btn.classList.add('active');
    else document.querySelector(`.event-tab[data-event="${eventName}"]`)?.classList.add('active');
    document.getElementById(eventName + '-content')?.classList.add('active');
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
        const snapshot = await getDocs(query(collection(db, 'registrations'), where('event', '==', 'testing'), orderBy('registeredAt', 'desc')));
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
                    <button class="action-btn edit" onclick="openEditModal('${SecurityUtils.escapeHtml(docId)}','${safeTeamName.replace(/'/g,"\\'")}','${safeM1Name.replace(/'/g,"\\'")}','${safeM1Detail.replace(/'/g,"\\'")}','${safeM2Name.replace(/'/g,"\\'")}','${safeM2Detail.replace(/'/g,"\\'")}','${safeM3Name.replace(/'/g,"\\'")}','${safeM3Detail.replace(/'/g,"\\'")}','${safeEmail}')">✏️</button>
                    <button class="action-btn delete" onclick="openDeleteModal('${SecurityUtils.escapeHtml(docId)}','${safeTeamName.replace(/'/g,"\\'")}')">🗑️</button>
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
        const snapshot = await getDocs(query(collection(db, 'registrations'), where('event', '==', 'uibattle'), orderBy('registeredAt', 'desc')));
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
                    <button class="action-btn edit" onclick="openEditModal('${SecurityUtils.escapeHtml(docId)}','${safeTeamName.replace(/'/g,"\\'")}','${safeM1Name.replace(/'/g,"\\'")}','${safeM1Detail.replace(/'/g,"\\'")}','${safeM2Name.replace(/'/g,"\\'")}','${safeM2Detail.replace(/'/g,"\\'")}','${safeM3Name.replace(/'/g,"\\'")}','${safeM3Detail.replace(/'/g,"\\'")}','${safeEmail}')">✏️</button>
                    <button class="action-btn delete" onclick="openDeleteModal('${SecurityUtils.escapeHtml(docId)}','${safeTeamName.replace(/'/g,"\\'")}')">🗑️</button>
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
        
        // Get registration count for this event
        let count = 0;
        try {
            const countQuery = query(collection(db, 'registrations'), where('event', '==', event.code));
            const countSnapshot = await getDocs(countQuery);
            count = countSnapshot.size;
            window[`${event.code}DataCount`] = count;
        } catch (e) {
            console.warn(`Could not count registrations for ${event.code}`, e);
        }
        
        const safeCode = SecurityUtils.escapeHtml(event.code);
        const safeName = SecurityUtils.escapeHtml(event.name);
        const safeEmoji = SecurityUtils.escapeHtml(event.emoji);
        
        grid.innerHTML += `
            <div class="event-select-card" onclick="openEventView('${safeCode}')">
                <button class="event-delete-btn" onclick="event.stopPropagation(); openDeleteEventModal('${safeCode}', '${safeName}')" title="Delete Event">🗑️</button>
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
    
    allEvents.forEach((event, index) => {
        if (!event.isActive) return;
        
        const safeCode = SecurityUtils.escapeHtml(event.code);
        const safeName = SecurityUtils.escapeHtml(event.name);
        const safeEmoji = SecurityUtils.escapeHtml(event.emoji);
        
        const isFirst = index === 0;
        
        tabsContainer.innerHTML += `
            <button class="event-tab ${isFirst ? 'active' : ''}" onclick="switchEvent('${safeCode}', this)" data-event="${safeCode}">
                ${safeEmoji} ${safeName}
            </button>`;
    });
}
window.generateEventTabs = generateEventTabs;

// Generate event content sections dynamically
function generateEventContents() {
    const container = document.getElementById('dynamicEventContents');
    if (!container) return;
    
    container.innerHTML = '';
    
    allEvents.forEach((event, index) => {
        if (!event.isActive) return;
        
        const safeCode = SecurityUtils.escapeHtml(event.code);
        const safeName = SecurityUtils.escapeHtml(event.name);
        const safeEmoji = SecurityUtils.escapeHtml(event.emoji);
        
        const isFirst = index === 0;
        
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
                                <label>From Date</label>
                                <input type="date" id="filterDateFrom-${safeCode}">
                            </div>
                            <div class="filter-group">
                                <label>To Date</label>
                                <input type="date" id="filterDateTo-${safeCode}">
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
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody id="${safeCode}-tbody">
                                <tr><td colspan="9" style="text-align:center;padding:40px;color:var(--text-muted);">
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
            where('event', '==', eventCode), 
            orderBy('registeredAt', 'desc')
        ));
        
        window[`${eventCode}DataCount`] = snapshot.size;
        
        const tbody = document.getElementById(`${eventCode}-tbody`);
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
            
            // Winner badge HTML
            const winnerBadge = d.isWinner ?
                `<span class="winner-badge ${d.winnerPosition === 1 ? 'gold' : d.winnerPosition === 2 ? 'silver' : 'bronze'}">🏆 ${d.winnerPosition === 1 ? '1st' : d.winnerPosition === 2 ? '2nd' : '3rd'}</span>` : '';
            
            // Winner button - shows remove option if already winner
            const winnerBtn = d.isWinner ?
                `<button class="action-btn winner" title="Remove Winner Status" onclick="removeWinner('${SecurityUtils.escapeHtml(docId)}', '${eventCode}')">❌</button>` :
                `<button class="action-btn winner" title="Set as Winner" onclick="openWinnerModal('${SecurityUtils.escapeHtml(docId)}', '${safeTeamName.replace(/'/g,"\\'")}', '${eventCode}')">🏆</button>`;
            
            // Safely encode team data for onclick
            const teamDataStr = encodeURIComponent(JSON.stringify(d));
            
            tbody.innerHTML += `<tr data-team="${SecurityUtils.escapeHtml(docId)}" class="clickable-row" onclick="handleRowClick(event,'${SecurityUtils.escapeHtml(docId)}','${teamDataStr}')">
                <td onclick="event.stopPropagation()"><input type="checkbox" class="row-checkbox" data-team-id="${SecurityUtils.escapeHtml(docId)}" onchange="toggleRowSelection()"></td>
                <td><span class="team-badge">${i++}</span></td>
                <td><strong>${safeTeamName || '—'}</strong>${winnerBadge}</td>
                <td><div class="member-info"><span class="name">${safeM1Name}</span><span class="detail">${safeM1Detail}</span></div></td>
                <td><div class="member-info"><span class="name">${safeM2Name}</span><span class="detail">${safeM2Detail}</span></div></td>
                <td><div class="member-info"><span class="name">${safeM3Name}</span><span class="detail">${safeM3Detail}</span></div></td>
                <td><a href="mailto:${safeEmail}" class="email-link" onclick="event.stopPropagation()">${safeEmail}</a></td>
                <td onclick="event.stopPropagation()"><span class="status-pill clickable ${safeStatus.toLowerCase()}" onclick="toggleStatus('${SecurityUtils.escapeHtml(docId)}','${safeStatus}')">${safeStatus}</span></td>
                <td onclick="event.stopPropagation()"><div class="action-buttons">
                    <button class="action-btn view" onclick="handleRowClick(event,'${SecurityUtils.escapeHtml(docId)}','${teamDataStr}')">👁️</button>
                    ${winnerBtn}
                    <button class="action-btn verify" onclick="toggleStatus('${SecurityUtils.escapeHtml(docId)}','${safeStatus}')">✓</button>
                    <button class="action-btn edit" onclick="openEditModal('${SecurityUtils.escapeHtml(docId)}','${safeTeamName.replace(/'/g,"\\'")}','${safeM1Name.replace(/'/g,"\\'")}','${safeM1Detail.replace(/'/g,"\\'")}','${safeM2Name.replace(/'/g,"\\'")}','${safeM2Detail.replace(/'/g,"\\'")}','${safeM3Name.replace(/'/g,"\\'")}','${safeM3Detail.replace(/'/g,"\\'")}','${safeEmail}')">✏️</button>
                    <button class="action-btn delete" onclick="openDeleteModal('${SecurityUtils.escapeHtml(docId)}','${safeTeamName.replace(/'/g,"\\'")}')">🗑️</button>
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
            tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;padding:40px;color:var(--accent-red);">Error loading data</td></tr>';
        }
    }
}
window.loadEventData = loadEventData;

// Load data for all events
async function loadAllEventData() {
    for (const event of allEvents) {
        if (!event.isActive) continue;
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

window.reloadFirestoreData = async function() {
    await loadAllEventData();
};

// ===== MISC FUNCTIONS =====
function toggleNav() {
    document.getElementById('navLinks')?.classList.toggle('active');
    document.getElementById('hamburger')?.classList.toggle('active');
}
window.toggleNav = toggleNav;

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
        const registrationsQuery = query(collection(db, 'registrations'), where('event', '==', eventCode));
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

function toggleSettingsDropdown() { document.getElementById('settingsDropdown')?.classList.toggle('active'); }
window.toggleSettingsDropdown = toggleSettingsDropdown;

function togglePasswordVisibility() {
    const input = document.getElementById('password');
    const toggleBtn = document.getElementById('passwordToggle');
    if (!input || !toggleBtn) return;
    
    const eyeOpen = toggleBtn.querySelector('.eye-open');
    const eyeClosed = toggleBtn.querySelector('.eye-closed');
    
    if (input.type === 'password') {
        input.type = 'text';
        if (eyeOpen) eyeOpen.style.display = 'none';
        if (eyeClosed) eyeClosed.style.display = 'block';
    } else {
        input.type = 'password';
        if (eyeOpen) eyeOpen.style.display = 'block';
        if (eyeClosed) eyeClosed.style.display = 'none';
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
    
    const rows = tbody.querySelectorAll('tr');
    let visibleCount = 0;
    
    rows.forEach(row => {
        const statusCell = row.querySelector('.status-pill');
        const rowStatus = statusCell ? statusCell.textContent.toLowerCase().trim() : '';

        let showRow = true;

        // Status filter
        if (status && status !== 'all' && rowStatus !== status) {
            showRow = false;
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
window.handleLogin = function(event) {
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
        .then(() => {
            // Reset rate limiter on successful login
            rateLimiters.login.reset('login');
            document.getElementById('login-page').style.display = 'none';
            document.getElementById('admin-dashboard').classList.add('active');
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

// ===== INIT =====
window.addEventListener('DOMContentLoaded', async () => {
    // Initialize the dynamic event system - this replaces hardcoded event loading
    await initDynamicEvents();
    
    // Load routing config
    loadRoutingConfig();
});
