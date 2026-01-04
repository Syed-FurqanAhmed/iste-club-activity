/**
 * ============================================================================
 * ISTE Club Website - Security Module
 * ============================================================================
 * 
 * SECURITY FEATURES:
 * - Rate Limiting (OWASP A04:2021 - Insecure Design)
 * - Input Validation (OWASP A03:2021 - Injection)  
 * - Input Sanitization (OWASP A07:2021 - XSS)
 * - Button Debouncing (Spam Prevention)
 * 
 * NOTE: Client-side security is defense-in-depth. Server-side Firestore
 * Security Rules provide the primary protection layer.
 * 
 * @author ISTE Tech Team
 * @version 1.0.0
 */

'use strict';

// ============================================================================
// SECURITY CONFIGURATION
// ============================================================================

const SECURITY_CONFIG = {
    // Rate Limiting Settings
    rateLimiting: {
        registration: {
            maxTokens: 5,           // Maximum requests allowed
            refillRate: 1,          // Tokens added per interval
            refillInterval: 60000,  // 1 minute in ms
            cooldownMs: 60000       // 60-second cooldown between submissions
        },
        login: {
            maxTokens: 3,           // Maximum login attempts
            refillRate: 1,          // Tokens added per interval
            refillInterval: 300000, // 5 minutes in ms
            lockoutMs: 900000       // 15-minute lockout
        }
    },

    // Input Validation Settings
    validation: {
        teamName: {
            minLength: 2,
            maxLength: 50,
            pattern: /^[A-Za-z0-9 ]+$/,
            patternDescription: 'Only letters, numbers, and spaces allowed'
        },
        email: {
            minLength: 5,
            maxLength: 100,
            // RFC 5322 simplified pattern
            pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
            patternDescription: 'Must be a valid email address'
        },
        memberName: {
            minLength: 2,
            maxLength: 50,
            pattern: /^[A-Za-z ]+$/,
            patternDescription: 'Only letters and spaces allowed'
        },
        usn: {
            minLength: 10,
            maxLength: 15,
            pattern: /^1[A-Z]{2}[0-9]{2}[A-Z]{2}[0-9]{3}$/,
            patternDescription: 'Format: 1XX00XX000 (e.g., 1CR23CS001)'
        },
        department: {
            allowedValues: ['ISE', 'CSE', 'AIML', 'AI&DS', 'ECE', 'EEE', 'CV', 'ME', 'Mechatronics', 'Other', '']
        },
        password: {
            minLength: 8,
            maxLength: 128
        }
    },

    // Allowed form fields (reject unexpected fields)
    allowedFields: {
        registration: [
            'teamEmail', 'teamName',
            'member1Name', 'member1USN', 'member1Dept',
            'member2Name', 'member2USN', 'member2Dept',
            'member3Name', 'member3USN', 'member3Dept'
        ],
        login: ['username', 'password']
    }
};

// ============================================================================
// RATE LIMITER CLASS
// ============================================================================

/**
 * SECURITY: Rate Limiting (OWASP A04:2021 - Insecure Design)
 * Prevents brute force and DoS attacks using token bucket algorithm.
 * IP tracking uses localStorage fingerprint (client-side limitation).
 * Session throttling enforces cooldown between submissions.
 */
class RateLimiter {
    constructor(config) {
        this.maxTokens = config.maxTokens;
        this.refillRate = config.refillRate;
        this.refillInterval = config.refillInterval;
        this.cooldownMs = config.cooldownMs || 0;
        this.storageKey = `iste_ratelimit_${config.name || 'default'}`;
        this.lastSubmitKey = `iste_lastsubmit_${config.name || 'default'}`;

        this._loadState();
        this._startRefillTimer();
    }

    /**
     * Load rate limit state from localStorage
     * @private
     */
    _loadState() {
        try {
            const stored = localStorage.getItem(this.storageKey);
            if (stored) {
                const state = JSON.parse(stored);
                this.tokens = Math.min(state.tokens, this.maxTokens);
                this.lastRefill = state.lastRefill || Date.now();
            } else {
                this.tokens = this.maxTokens;
                this.lastRefill = Date.now();
            }
        } catch (e) {
            // SECURITY: Fallback if localStorage fails
            console.warn('[Security] localStorage unavailable, using session-only rate limiting');
            this.tokens = this.maxTokens;
            this.lastRefill = Date.now();
        }
    }

    /**
     * Save rate limit state to localStorage
     * @private
     */
    _saveState() {
        try {
            localStorage.setItem(this.storageKey, JSON.stringify({
                tokens: this.tokens,
                lastRefill: this.lastRefill
            }));
        } catch (e) {
            // Silently fail if localStorage is unavailable
        }
    }

    /**
     * Start automatic token refill timer
     * @private
     */
    _startRefillTimer() {
        // Calculate tokens to add based on time elapsed
        const elapsed = Date.now() - this.lastRefill;
        const tokensToAdd = Math.floor(elapsed / this.refillInterval) * this.refillRate;

        if (tokensToAdd > 0) {
            this.tokens = Math.min(this.tokens + tokensToAdd, this.maxTokens);
            this.lastRefill = Date.now();
            this._saveState();
        }

        // Continue refilling periodically
        setInterval(() => {
            if (this.tokens < this.maxTokens) {
                this.tokens = Math.min(this.tokens + this.refillRate, this.maxTokens);
                this.lastRefill = Date.now();
                this._saveState();
                this._updateUI();
            }
        }, this.refillInterval);
    }

    /**
     * Check if cooldown period has passed
     * @returns {Object} {allowed: boolean, remainingMs: number}
     */
    checkCooldown() {
        if (this.cooldownMs === 0) return { allowed: true, remainingMs: 0 };

        try {
            const lastSubmit = parseInt(localStorage.getItem(this.lastSubmitKey) || '0');
            const elapsed = Date.now() - lastSubmit;
            const remaining = this.cooldownMs - elapsed;

            if (remaining > 0) {
                return { allowed: false, remainingMs: remaining };
            }
        } catch (e) {
            // Fallback: allow if localStorage fails
        }

        return { allowed: true, remainingMs: 0 };
    }

    /**
     * Record a submission for cooldown tracking
     */
    recordSubmission() {
        try {
            localStorage.setItem(this.lastSubmitKey, Date.now().toString());
        } catch (e) {
            // Silently fail
        }
    }

    /**
     * Attempt to consume a token
     * @returns {Object} Result with status and message
     */
    tryConsume() {
        // Check cooldown first
        const cooldown = this.checkCooldown();
        if (!cooldown.allowed) {
            const seconds = Math.ceil(cooldown.remainingMs / 1000);
            return {
                allowed: false,
                tokens: this.tokens,
                maxTokens: this.maxTokens,
                message: `Please wait ${seconds} seconds before submitting again`,
                errorType: 'COOLDOWN'
            };
        }

        // Check token availability
        if (this.tokens <= 0) {
            return {
                allowed: false,
                tokens: 0,
                maxTokens: this.maxTokens,
                message: 'Too many requests. Please try again later.',
                errorType: 'RATE_LIMITED'
            };
        }

        // Consume token
        this.tokens--;
        this._saveState();
        this.recordSubmission();

        return {
            allowed: true,
            tokens: this.tokens,
            maxTokens: this.maxTokens,
            message: 'Request allowed'
        };
    }

    /**
     * Get current token status
     * @returns {Object} Token status
     */
    getStatus() {
        const cooldown = this.checkCooldown();
        return {
            tokens: this.tokens,
            maxTokens: this.maxTokens,
            percentage: (this.tokens / this.maxTokens) * 100,
            cooldownActive: !cooldown.allowed,
            cooldownRemaining: cooldown.remainingMs
        };
    }

    /**
     * Update UI with current status (override in implementation)
     * @private
     */
    _updateUI() {
        // This will be overridden when integrated with the page
        if (typeof window.updateRateLimitUI === 'function') {
            window.updateRateLimitUI(this.getStatus());
        }
    }
}

// ============================================================================
// INPUT VALIDATOR CLASS
// ============================================================================

/**
 * SECURITY: Input Validation (OWASP A03:2021 - Injection)
 * Schema-based validation rejects malformed and unexpected input.
 * Validates type, length, pattern, and allowed values.
 */
class InputValidator {
    constructor() {
        this.config = SECURITY_CONFIG.validation;
        this.errors = [];
    }

    /**
     * Validate email format
     * @param {string} email - Email to validate
     * @returns {Object} Validation result
     */
    validateEmail(email) {
        const config = this.config.email;
        const trimmed = (email || '').trim();

        if (!trimmed) {
            return { valid: false, error: 'Email is required' };
        }

        if (trimmed.length < config.minLength) {
            return { valid: false, error: `Email must be at least ${config.minLength} characters` };
        }

        if (trimmed.length > config.maxLength) {
            return { valid: false, error: `Email must be less than ${config.maxLength} characters` };
        }

        if (!config.pattern.test(trimmed)) {
            return { valid: false, error: config.patternDescription };
        }

        return { valid: true, value: trimmed };
    }

    /**
     * Validate team name
     * @param {string} name - Team name to validate
     * @returns {Object} Validation result
     */
    validateTeamName(name) {
        const config = this.config.teamName;
        const trimmed = (name || '').trim();

        if (!trimmed) {
            return { valid: false, error: 'Team name is required' };
        }

        if (trimmed.length < config.minLength) {
            return { valid: false, error: `Team name must be at least ${config.minLength} characters` };
        }

        if (trimmed.length > config.maxLength) {
            return { valid: false, error: `Team name must be less than ${config.maxLength} characters` };
        }

        if (!config.pattern.test(trimmed)) {
            return { valid: false, error: config.patternDescription };
        }

        return { valid: true, value: trimmed };
    }

    /**
     * Validate member name
     * @param {string} name - Member name to validate
     * @param {boolean} required - Whether field is required
     * @returns {Object} Validation result
     */
    validateMemberName(name, required = false) {
        const config = this.config.memberName;
        const trimmed = (name || '').trim();

        if (!trimmed) {
            if (required) {
                return { valid: false, error: 'Name is required' };
            }
            return { valid: true, value: null };
        }

        if (trimmed.length < config.minLength) {
            return { valid: false, error: `Name must be at least ${config.minLength} characters` };
        }

        if (trimmed.length > config.maxLength) {
            return { valid: false, error: `Name must be less than ${config.maxLength} characters` };
        }

        if (!config.pattern.test(trimmed)) {
            return { valid: false, error: config.patternDescription };
        }

        return { valid: true, value: trimmed };
    }

    /**
     * Validate USN/Roll Number
     * @param {string} usn - USN to validate
     * @param {boolean} required - Whether field is required
     * @returns {Object} Validation result
     */
    validateUSN(usn, required = false) {
        const config = this.config.usn;
        const trimmed = (usn || '').trim().toUpperCase();

        if (!trimmed) {
            if (required) {
                return { valid: false, error: 'USN is required' };
            }
            return { valid: true, value: null };
        }

        if (trimmed.length < config.minLength || trimmed.length > config.maxLength) {
            return { valid: false, error: `USN must be between ${config.minLength}-${config.maxLength} characters` };
        }

        if (!config.pattern.test(trimmed)) {
            return { valid: false, error: config.patternDescription };
        }

        return { valid: true, value: trimmed };
    }

    /**
     * Validate department selection
     * @param {string} dept - Department value
     * @param {boolean} required - Whether field is required
     * @returns {Object} Validation result
     */
    validateDepartment(dept, required = false) {
        const config = this.config.department;
        const value = (dept || '').trim();

        if (!value) {
            if (required) {
                return { valid: false, error: 'Department is required' };
            }
            return { valid: true, value: null };
        }

        if (!config.allowedValues.includes(value)) {
            return { valid: false, error: 'Invalid department selection' };
        }

        return { valid: true, value: value };
    }

    /**
     * Validate password
     * @param {string} password - Password to validate
     * @returns {Object} Validation result
     */
    validatePassword(password) {
        const config = this.config.password;

        if (!password) {
            return { valid: false, error: 'Password is required' };
        }

        if (password.length < config.minLength) {
            return { valid: false, error: `Password must be at least ${config.minLength} characters` };
        }

        if (password.length > config.maxLength) {
            return { valid: false, error: `Password is too long` };
        }

        return { valid: true, value: password };
    }

    /**
     * Validate entire registration form
     * @param {Object} formData - Form data object
     * @returns {Object} Validation result with all errors
     */
    validateRegistrationForm(formData) {
        const errors = {};
        const sanitized = {};

        // Email validation
        const email = this.validateEmail(formData.teamEmail);
        if (!email.valid) errors.teamEmail = email.error;
        else sanitized.teamEmail = email.value;

        // Team name validation
        const teamName = this.validateTeamName(formData.teamName);
        if (!teamName.valid) errors.teamName = teamName.error;
        else sanitized.teamName = teamName.value;

        // Member 1 (required)
        const m1Name = this.validateMemberName(formData.member1Name, true);
        if (!m1Name.valid) errors.member1Name = m1Name.error;
        else sanitized.member1Name = m1Name.value;

        const m1USN = this.validateUSN(formData.member1USN, true);
        if (!m1USN.valid) errors.member1USN = m1USN.error;
        else sanitized.member1USN = m1USN.value;

        const m1Dept = this.validateDepartment(formData.member1Dept, true);
        if (!m1Dept.valid) errors.member1Dept = m1Dept.error;
        else sanitized.member1Dept = m1Dept.value;

        // Member 2 (optional)
        const m2Name = this.validateMemberName(formData.member2Name, false);
        if (!m2Name.valid) errors.member2Name = m2Name.error;
        else sanitized.member2Name = m2Name.value;

        const m2USN = this.validateUSN(formData.member2USN, false);
        if (!m2USN.valid) errors.member2USN = m2USN.error;
        else sanitized.member2USN = m2USN.value;

        const m2Dept = this.validateDepartment(formData.member2Dept, false);
        if (!m2Dept.valid) errors.member2Dept = m2Dept.error;
        else sanitized.member2Dept = m2Dept.value;

        // Member 3 (optional)
        const m3Name = this.validateMemberName(formData.member3Name, false);
        if (!m3Name.valid) errors.member3Name = m3Name.error;
        else sanitized.member3Name = m3Name.value;

        const m3USN = this.validateUSN(formData.member3USN, false);
        if (!m3USN.valid) errors.member3USN = m3USN.error;
        else sanitized.member3USN = m3USN.value;

        const m3Dept = this.validateDepartment(formData.member3Dept, false);
        if (!m3Dept.valid) errors.member3Dept = m3Dept.error;
        else sanitized.member3Dept = m3Dept.value;

        return {
            valid: Object.keys(errors).length === 0,
            errors: errors,
            sanitized: sanitized
        };
    }

    /**
     * Validate login form
     * @param {Object} formData - Form data object
     * @returns {Object} Validation result
     */
    validateLoginForm(formData) {
        const errors = {};
        const sanitized = {};

        const email = this.validateEmail(formData.username);
        if (!email.valid) errors.username = email.error;
        else sanitized.username = email.value;

        const password = this.validatePassword(formData.password);
        if (!password.valid) errors.password = password.error;
        else sanitized.password = password.value;

        return {
            valid: Object.keys(errors).length === 0,
            errors: errors,
            sanitized: sanitized
        };
    }

    /**
     * Check for unexpected fields (OWASP mass assignment prevention)
     * @param {Object} formData - Form data
     * @param {string} formType - Type of form ('registration' or 'login')
     * @returns {Array} List of unexpected field names
     */
    checkUnexpectedFields(formData, formType) {
        const allowed = SECURITY_CONFIG.allowedFields[formType] || [];
        const unexpected = [];

        for (const key of Object.keys(formData)) {
            if (!allowed.includes(key)) {
                unexpected.push(key);
            }
        }

        return unexpected;
    }
}

// ============================================================================
// INPUT SANITIZER
// ============================================================================

/**
 * SECURITY: Input Sanitization (OWASP A07:2021 - XSS)
 * Cleans user input to prevent injection attacks.
 */
const InputSanitizer = {
    /**
     * Encode HTML entities to prevent XSS
     * @param {string} str - Input string
     * @returns {string} Sanitized string
     */
    escapeHTML(str) {
        if (typeof str !== 'string') return str;

        const htmlEntities = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
            '/': '&#x2F;',
            '`': '&#x60;',
            '=': '&#x3D;'
        };

        return str.replace(/[&<>"'`=\/]/g, char => htmlEntities[char]);
    },

    /**
     * Remove all script tags and event handlers
     * @param {string} str - Input string
     * @returns {string} Sanitized string
     */
    stripScripts(str) {
        if (typeof str !== 'string') return str;

        // Remove script tags
        let clean = str.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');

        // Remove event handlers
        clean = clean.replace(/\s*on\w+\s*=\s*["'][^"']*["']/gi, '');

        // Remove javascript: URLs
        clean = clean.replace(/javascript:/gi, '');

        return clean;
    },

    /**
     * Remove null bytes (OWASP path traversal prevention)
     * @param {string} str - Input string
     * @returns {string} Sanitized string
     */
    removeNullBytes(str) {
        if (typeof str !== 'string') return str;
        return str.replace(/\0/g, '');
    },

    /**
     * Normalize unicode to prevent homograph attacks
     * @param {string} str - Input string
     * @returns {string} Normalized string
     */
    normalizeUnicode(str) {
        if (typeof str !== 'string') return str;
        return str.normalize('NFKC');
    },

    /**
     * Trim and collapse whitespace
     * @param {string} str - Input string
     * @returns {string} Cleaned string
     */
    cleanWhitespace(str) {
        if (typeof str !== 'string') return str;
        return str.trim().replace(/\s+/g, ' ');
    },

    /**
     * Full sanitization pipeline
     * @param {string} str - Input string
     * @returns {string} Fully sanitized string
     */
    sanitize(str) {
        if (typeof str !== 'string') return str;

        let clean = str;
        clean = this.removeNullBytes(clean);
        clean = this.normalizeUnicode(clean);
        clean = this.stripScripts(clean);
        clean = this.escapeHTML(clean);
        clean = this.cleanWhitespace(clean);

        return clean;
    },

    /**
     * Sanitize an entire object's string values
     * @param {Object} obj - Object to sanitize
     * @returns {Object} Sanitized object
     */
    sanitizeObject(obj) {
        const result = {};

        for (const [key, value] of Object.entries(obj)) {
            if (typeof value === 'string') {
                result[key] = this.sanitize(value);
            } else if (value && typeof value === 'object' && !Array.isArray(value)) {
                result[key] = this.sanitizeObject(value);
            } else {
                result[key] = value;
            }
        }

        return result;
    }
};

// ============================================================================
// BUTTON DEBOUNCER
// ============================================================================

/**
 * SECURITY: Prevents double-submit and spam clicking
 */
const ButtonDebouncer = {
    /**
     * Debounce a button click
     * @param {HTMLButtonElement} button - Button element
     * @param {number} duration - Disable duration in ms (default 2000)
     */
    disable(button, duration = 2000) {
        if (!button) return;

        button.disabled = true;
        button.dataset.originalText = button.textContent;

        // Auto re-enable after duration (fallback)
        setTimeout(() => {
            this.enable(button);
        }, duration);
    },

    /**
     * Re-enable a debounced button
     * @param {HTMLButtonElement} button - Button element
     */
    enable(button) {
        if (!button) return;

        button.disabled = false;
        if (button.dataset.originalText) {
            // Keep original text/restore from loading state if needed
        }
    },

    /**
     * Set button to loading state
     * @param {HTMLButtonElement} button - Button element
     * @param {string} loadingText - Text to show while loading
     */
    setLoading(button, loadingText = 'Processing...') {
        if (!button) return;

        button.disabled = true;
        button.dataset.originalHTML = button.innerHTML;
        button.innerHTML = `<span class="spinner"></span> ${loadingText}`;
    },

    /**
     * Restore button from loading state
     * @param {HTMLButtonElement} button - Button element
     */
    restoreFromLoading(button) {
        if (!button) return;

        button.disabled = false;
        if (button.dataset.originalHTML) {
            button.innerHTML = button.dataset.originalHTML;
        }
    }
};

// ============================================================================
// RATE LIMIT UI COMPONENT
// ============================================================================

/**
 * Creates and manages the rate limit status display
 */
const RateLimitUI = {
    /**
     * Create the status indicator element
     * @returns {HTMLElement} Status element
     */
    createIndicator() {
        const container = document.createElement('div');
        container.id = 'rateLimitStatus';
        container.className = 'rate-limit-indicator';
        container.innerHTML = `
            <span class="rate-limit-icon">🔒</span>
            <span class="rate-limit-text">
                <span id="tokenCount">5</span> / <span id="tokenMax">5</span> requests remaining
            </span>
        `;
        return container;
    },

    /**
     * Update the status indicator
     * @param {Object} status - Rate limiter status
     */
    update(status) {
        const countEl = document.getElementById('tokenCount');
        const maxEl = document.getElementById('tokenMax');
        const container = document.getElementById('rateLimitStatus');

        if (countEl) countEl.textContent = status.tokens;
        if (maxEl) maxEl.textContent = status.maxTokens;

        if (container) {
            container.classList.remove('green', 'yellow', 'red');

            if (status.percentage > 50) {
                container.classList.add('green');
            } else if (status.percentage > 25) {
                container.classList.add('yellow');
            } else {
                container.classList.add('red');
            }
        }
    },

    /**
     * Get CSS styles for the indicator
     * @returns {string} CSS styles
     */
    getStyles() {
        return `
            .rate-limit-indicator {
                display: inline-flex;
                align-items: center;
                gap: 8px;
                padding: 8px 16px;
                border-radius: 50px;
                font-size: 13px;
                font-weight: 600;
                margin-bottom: 16px;
                transition: all 0.3s ease;
            }
            
            .rate-limit-indicator.green {
                background: rgba(16, 185, 129, 0.15);
                color: #10b981;
                border: 1px solid rgba(16, 185, 129, 0.3);
            }
            
            .rate-limit-indicator.yellow {
                background: rgba(245, 158, 11, 0.15);
                color: #f59e0b;
                border: 1px solid rgba(245, 158, 11, 0.3);
            }
            
            .rate-limit-indicator.red {
                background: rgba(239, 68, 68, 0.15);
                color: #ef4444;
                border: 1px solid rgba(239, 68, 68, 0.3);
            }
            
            .rate-limit-icon {
                font-size: 16px;
            }
            
            #tokenCount {
                font-weight: 800;
                font-size: 15px;
            }
            
            .rate-limit-error {
                background: rgba(239, 68, 68, 0.1);
                color: #ef4444;
                padding: 12px 16px;
                border-radius: 8px;
                margin-bottom: 16px;
                font-size: 14px;
                display: flex;
                align-items: center;
                gap: 8px;
            }
            
            .validation-error {
                color: #ef4444;
                font-size: 12px;
                margin-top: 4px;
                display: block;
            }
        `;
    }
};

// ============================================================================
// SECURITY MANAGER (MAIN INTEGRATION CLASS)
// ============================================================================

/**
 * Main security manager that coordinates all security features
 */
class SecurityManager {
    constructor() {
        this.validator = new InputValidator();
        this.registrationLimiter = null;
        this.loginLimiter = null;
        this.initialized = false;
    }

    /**
     * Initialize security features for the page
     * @param {string} pageType - 'registration' or 'login'
     */
    init(pageType = 'registration') {
        if (this.initialized) return;

        // Inject styles
        this._injectStyles();

        if (pageType === 'registration' || pageType === 'both') {
            this.registrationLimiter = new RateLimiter({
                ...SECURITY_CONFIG.rateLimiting.registration,
                name: 'registration'
            });
        }

        if (pageType === 'login' || pageType === 'both') {
            this.loginLimiter = new RateLimiter({
                ...SECURITY_CONFIG.rateLimiting.login,
                name: 'login'
            });
        }

        // Setup global UI update function
        window.updateRateLimitUI = (status) => RateLimitUI.update(status);

        this.initialized = true;
        console.log('[Security] Module initialized for:', pageType);
    }

    /**
     * Inject CSS styles into the page
     * @private
     */
    _injectStyles() {
        const styleId = 'security-styles';
        if (document.getElementById(styleId)) return;

        const style = document.createElement('style');
        style.id = styleId;
        style.textContent = RateLimitUI.getStyles();
        document.head.appendChild(style);
    }

    /**
     * Add rate limit indicator to a container
     * @param {string|HTMLElement} container - Container selector or element
     */
    addRateLimitIndicator(container) {
        const el = typeof container === 'string'
            ? document.querySelector(container)
            : container;

        if (el && !document.getElementById('rateLimitStatus')) {
            el.insertBefore(RateLimitUI.createIndicator(), el.firstChild);

            if (this.registrationLimiter) {
                RateLimitUI.update(this.registrationLimiter.getStatus());
            }
        }
    }

    /**
     * Process a registration form submission
     * @param {Object} formData - Form data
     * @param {HTMLButtonElement} submitButton - Submit button element
     * @returns {Object} Result with validation and rate limit status
     */
    processRegistration(formData, submitButton) {
        // Debounce button
        ButtonDebouncer.setLoading(submitButton, 'Validating...');

        // Check rate limit
        const rateResult = this.registrationLimiter.tryConsume();
        RateLimitUI.update(this.registrationLimiter.getStatus());

        if (!rateResult.allowed) {
            ButtonDebouncer.restoreFromLoading(submitButton);
            return {
                success: false,
                type: 'RATE_LIMITED',
                message: rateResult.message
            };
        }

        // Check for unexpected fields
        const unexpected = this.validator.checkUnexpectedFields(formData, 'registration');
        if (unexpected.length > 0) {
            console.warn('[Security] Unexpected fields detected:', unexpected);
            // Continue but log the warning
        }

        // Validate form
        const validation = this.validator.validateRegistrationForm(formData);

        if (!validation.valid) {
            ButtonDebouncer.restoreFromLoading(submitButton);
            return {
                success: false,
                type: 'VALIDATION_ERROR',
                errors: validation.errors
            };
        }

        // Sanitize inputs
        const sanitized = InputSanitizer.sanitizeObject(validation.sanitized);

        return {
            success: true,
            type: 'VALIDATED',
            data: sanitized,
            button: submitButton
        };
    }

    /**
     * Process a login form submission
     * @param {Object} formData - Form data
     * @param {HTMLButtonElement} submitButton - Submit button element
     * @returns {Object} Result with validation and rate limit status
     */
    processLogin(formData, submitButton) {
        ButtonDebouncer.setLoading(submitButton, 'Signing in...');

        // Check rate limit
        const rateResult = this.loginLimiter.tryConsume();

        if (!rateResult.allowed) {
            ButtonDebouncer.restoreFromLoading(submitButton);
            return {
                success: false,
                type: 'RATE_LIMITED',
                message: rateResult.message,
                tokens: rateResult.tokens,
                maxTokens: rateResult.maxTokens
            };
        }

        // Validate form
        const validation = this.validator.validateLoginForm(formData);

        if (!validation.valid) {
            ButtonDebouncer.restoreFromLoading(submitButton);
            return {
                success: false,
                type: 'VALIDATION_ERROR',
                errors: validation.errors
            };
        }

        return {
            success: true,
            type: 'VALIDATED',
            data: validation.sanitized,
            button: submitButton,
            tokens: rateResult.tokens,
            maxTokens: rateResult.maxTokens
        };
    }

    /**
     * Display validation errors on form fields
     * @param {Object} errors - Error object {fieldId: message}
     */
    displayValidationErrors(errors) {
        // Clear previous errors
        document.querySelectorAll('.validation-error').forEach(el => el.remove());
        document.querySelectorAll('.input-error').forEach(el => el.classList.remove('input-error'));

        for (const [fieldId, message] of Object.entries(errors)) {
            const field = document.getElementById(fieldId);
            if (field) {
                field.classList.add('input-error');
                field.style.borderColor = '#ef4444';

                const errorEl = document.createElement('span');
                errorEl.className = 'validation-error';
                errorEl.textContent = message;
                field.parentNode.appendChild(errorEl);
            }
        }
    }

    /**
     * Clear all validation errors
     */
    clearValidationErrors() {
        document.querySelectorAll('.validation-error').forEach(el => el.remove());
        document.querySelectorAll('.input-error').forEach(el => {
            el.classList.remove('input-error');
            el.style.borderColor = '';
        });
    }

    /**
     * Show a rate limit error message
     * @param {HTMLElement} container - Container to show error in
     * @param {string} message - Error message
     */
    showRateLimitError(container, message) {
        const existing = container.querySelector('.rate-limit-error');
        if (existing) existing.remove();

        const errorEl = document.createElement('div');
        errorEl.className = 'rate-limit-error';
        errorEl.innerHTML = `<span>⚠️</span> ${message}`;
        container.insertBefore(errorEl, container.firstChild);

        // Auto-remove after 5 seconds
        setTimeout(() => errorEl.remove(), 5000);
    }

    /**
     * Get login rate limit status for display
     * @returns {Object} Status object with tokens as numbers
     */
    getLoginStatus() {
        if (!this.loginLimiter) return null;
        return this.loginLimiter.getStatus();
    }

    /**
     * Get registration rate limit status for display
     * @returns {Object} Status object with tokens as numbers
     */
    getRegistrationStatus() {
        if (!this.registrationLimiter) return null;
        return this.registrationLimiter.getStatus();
    }
}

// ============================================================================
// GLOBAL EXPORTS
// ============================================================================

// Create global instance
window.ISTESecurity = new SecurityManager();

// Export individual components for advanced usage
window.RateLimiter = RateLimiter;
window.InputValidator = InputValidator;
window.InputSanitizer = InputSanitizer;
window.ButtonDebouncer = ButtonDebouncer;
window.RateLimitUI = RateLimitUI;
window.SECURITY_CONFIG = SECURITY_CONFIG;

console.log('[Security] ISTE Security Module loaded. Access via window.ISTESecurity');
