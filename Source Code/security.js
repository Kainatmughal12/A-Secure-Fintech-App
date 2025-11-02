/**
 * ============================================
 * Security Module - Debt Payoff Planner
 * ============================================
 * 
 * This module implements comprehensive security features for the FinTech application:
 * 1. User Registration & Login with Password Hashing
 * 2. Password Strength Validation
 * 3. Input Sanitization (XSS/Injection Prevention)
 * 4. Session Handling & Logout
 * 5. Secure Data Storage (Simulated Encryption)
 * 6. Error Handling & Audit Logging
 */

// ============================================
// Security Configuration
// ============================================

/**
 * Session timeout in milliseconds (30 minutes)
 * After this time, user will be automatically logged out for security
 */
const SESSION_TIMEOUT = 30 * 60 * 1000; // 30 minutes

/**
 * Maximum login attempts before account lockout
 * Prevents brute force attacks
 */
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes

/**
 * Storage keys for localStorage
 * Using namespaced keys to prevent conflicts
 */
const STORAGE_KEYS = {
    USERS: 'debtPlanner_users',
    CURRENT_USER: 'debtPlanner_currentUser',
    SESSION_TOKEN: 'debtPlanner_sessionToken',
    SESSION_EXPIRY: 'debtPlanner_sessionExpiry',
    AUDIT_LOG: 'debtPlanner_auditLog',
    ENCRYPTION_KEY: 'debtPlanner_encryptionKey'
};

// ============================================
// Password Hashing Module
// ============================================

/**
 * Simulates password hashing using a combination of techniques
 * In production, use proper libraries like bcrypt or crypto
 * 
 * This is a simple SHA-256 based hashing simulation for demonstration
 * 
 * @param {string} password - Plain text password
 * @param {string} salt - Salt for hashing (optional, will generate if not provided)
 * @returns {string} Hashed password with salt
 */
function hashPassword(password, salt = null) {
    // Generate salt if not provided
    // Salt adds randomness to prevent rainbow table attacks
    if (!salt) {
        salt = generateSalt();
    }
    
    // Simple hash function (simulating bcrypt/PBKDF2)
    // In production, use: crypto.subtle.digest('SHA-256', ...)
    let hash = '';
    const combined = password + salt;
    
    // Create a hash using a simple algorithm
    // Note: In real applications, use proper cryptographic libraries
    for (let i = 0; i < combined.length; i++) {
        const charCode = combined.charCodeAt(i);
        hash += charCode.toString(16);
    }
    
    // Add additional complexity (simulating multiple iterations)
    for (let i = 0; i < 10; i++) {
        hash = hash.split('').reverse().join('') + salt;
    }
    
    // Return salt and hash together (format: salt$hash)
    return `${salt}$${hash}`;
}

/**
 * Generate a random salt for password hashing
 * Salt ensures same password produces different hashes
 * 
 * @returns {string} Random salt string
 */
function generateSalt() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let salt = '';
    for (let i = 0; i < 16; i++) {
        salt += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return salt;
}

/**
 * Verify a password against a stored hash
 * 
 * @param {string} password - Plain text password to verify
 * @param {string} storedHash - Stored hash (format: salt$hash)
 * @returns {boolean} True if password matches
 */
function verifyPassword(password, storedHash) {
    const parts = storedHash.split('$');
    if (parts.length !== 2) {
        return false;
    }
    
    const [salt, originalHash] = parts;
    const newHash = hashPassword(password, salt);
    
    // Compare hashes
    return newHash === storedHash;
}

// ============================================
// Password Strength Validation Module
// ============================================

/**
 * Password strength requirements:
 * - Minimum 8 characters
 * - At least one uppercase letter
 * - At least one lowercase letter
 * - At least one number
 * - At least one special character
 */
const PASSWORD_REQUIREMENTS = {
    minLength: 8,
    requireUppercase: true,
    requireLowercase: true,
    requireNumber: true,
    requireSpecialChar: true
};

/**
 * Check password strength and return validation result
 * 
 * @param {string} password - Password to validate
 * @returns {Object} Validation result with strength, valid status, and requirements
 */
function validatePasswordStrength(password) {
    const checks = {
        length: password.length >= PASSWORD_REQUIREMENTS.minLength,
        uppercase: /[A-Z]/.test(password),
        lowercase: /[a-z]/.test(password),
        number: /[0-9]/.test(password),
        specialChar: /[!@#$%^&*(),.?":{}|<>]/.test(password)
    };
    
    // Count valid requirements
    const validChecks = Object.values(checks).filter(Boolean).length;
    
    // Determine strength level
    let strength = 'weak';
    let strengthScore = 0;
    
    if (checks.length) strengthScore += 1;
    if (checks.uppercase) strengthScore += 1;
    if (checks.lowercase) strengthScore += 1;
    if (checks.number) strengthScore += 1;
    if (checks.specialChar) strengthScore += 1;
    
    if (strengthScore >= 4 && checks.length) {
        strength = 'strong';
    } else if (strengthScore >= 3) {
        strength = 'medium';
    }
    
    // Password is valid if all requirements are met
    const isValid = Object.values(checks).every(Boolean);
    
    return {
        strength,
        isValid,
        checks,
        score: strengthScore
    };
}

// ============================================
// Input Sanitization Module (XSS/Injection Prevention)
// ============================================

/**
 * Sanitize user input to prevent XSS attacks
 * Removes or escapes potentially dangerous HTML/script tags
 * 
 * @param {string} input - User input to sanitize
 * @returns {string} Sanitized input
 */
function sanitizeInput(input) {
    if (typeof input !== 'string') {
        return String(input);
    }
    
    // Create a temporary div element to escape HTML
    const div = document.createElement('div');
    div.textContent = input;
    
    // Get the escaped content
    let sanitized = div.innerHTML;
    
    // Remove any remaining script tags (defense in depth)
    sanitized = sanitized.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
    
    // Remove event handlers (onclick, onerror, etc.)
    sanitized = sanitized.replace(/on\w+\s*=\s*["'][^"']*["']/gi, '');
    
    // Remove javascript: protocol
    sanitized = sanitized.replace(/javascript:/gi, '');
    
    return sanitized;
}

/**
 * Sanitize an object by sanitizing all string values
 * 
 * @param {Object} obj - Object to sanitize
 * @returns {Object} Sanitized object
 */
function sanitizeObject(obj) {
    if (typeof obj !== 'object' || obj === null) {
        return obj;
    }
    
    const sanitized = {};
    for (const key in obj) {
        if (obj.hasOwnProperty(key)) {
            const value = obj[key];
            if (typeof value === 'string') {
                sanitized[key] = sanitizeInput(value);
            } else if (typeof value === 'object') {
                sanitized[key] = sanitizeObject(value);
            } else {
                sanitized[key] = value;
            }
        }
    }
    return sanitized;
}

/**
 * Validate username format (alphanumeric, 3-20 characters)
 * Prevents injection through username field
 * 
 * @param {string} username - Username to validate
 * @returns {boolean} True if username is valid
 */
function validateUsername(username) {
    // Only allow alphanumeric characters and underscore
    // Length: 3-20 characters
    const usernameRegex = /^[a-zA-Z0-9_]{3,20}$/;
    return usernameRegex.test(username);
}

/**
 * Sanitize and validate numeric input
 * Prevents SQL injection and ensures type safety
 * 
 * @param {any} value - Value to sanitize
 * @param {number} min - Minimum allowed value
 * @param {number} max - Maximum allowed value
 * @returns {number|null} Sanitized number or null if invalid
 */
function sanitizeNumber(value, min = -Infinity, max = Infinity) {
    const num = parseFloat(value);
    if (isNaN(num) || num < min || num > max) {
        return null;
    }
    return num;
}

// ============================================
// Secure Data Storage Module (Simulated Encryption)
// ============================================

/**
 * Simulate encryption for sensitive data storage
 * In production, use proper encryption libraries like crypto-js or Web Crypto API
 * 
 * @param {string} data - Data to encrypt
 * @returns {string} Encrypted data
 */
function encryptData(data) {
    try {
        // Get or generate encryption key
        let key = localStorage.getItem(STORAGE_KEYS.ENCRYPTION_KEY);
        if (!key) {
            key = generateEncryptionKey();
            localStorage.setItem(STORAGE_KEYS.ENCRYPTION_KEY, key);
        }
        
        // Simple XOR cipher simulation (NOT secure for production)
        // In production, use AES encryption
        const encrypted = [];
        for (let i = 0; i < data.length; i++) {
            const charCode = data.charCodeAt(i);
            const keyChar = key.charCodeAt(i % key.length);
            encrypted.push(String.fromCharCode(charCode ^ keyChar));
        }
        
        // Base64 encode for storage
        return btoa(encrypted.join(''));
    } catch (error) {
        logSecurityEvent('error', 'Encryption failed', { error: error.message });
        return data; // Return unencrypted if encryption fails
    }
}

/**
 * Simulate decryption for sensitive data retrieval
 * 
 * @param {string} encryptedData - Encrypted data to decrypt
 * @returns {string} Decrypted data
 */
function decryptData(encryptedData) {
    try {
        const key = localStorage.getItem(STORAGE_KEYS.ENCRYPTION_KEY);
        if (!key) {
            throw new Error('Encryption key not found');
        }
        
        // Decode from Base64
        const decoded = atob(encryptedData);
        
        // Decrypt using XOR (reverse operation)
        const decrypted = [];
        for (let i = 0; i < decoded.length; i++) {
            const charCode = decoded.charCodeAt(i);
            const keyChar = key.charCodeAt(i % key.length);
            decrypted.push(String.fromCharCode(charCode ^ keyChar));
        }
        
        return decrypted.join('');
    } catch (error) {
        logSecurityEvent('error', 'Decryption failed', { error: error.message });
        return encryptedData; // Return encrypted data if decryption fails
    }
}

/**
 * Generate a random encryption key
 * 
 * @returns {string} Encryption key
 */
function generateEncryptionKey() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
    let key = '';
    for (let i = 0; i < 32; i++) {
        key += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return key;
}

/**
 * Store encrypted user data
 * 
 * @param {string} key - Storage key
 * @param {any} data - Data to store
 */
function storeSecureData(key, data) {
    try {
        const jsonData = JSON.stringify(data);
        const encrypted = encryptData(jsonData);
        localStorage.setItem(key, encrypted);
    } catch (error) {
        logSecurityEvent('error', 'Failed to store secure data', { key, error: error.message });
    }
}

/**
 * Retrieve and decrypt user data
 * 
 * @param {string} key - Storage key
 * @returns {any|null} Decrypted data or null if not found
 */
function retrieveSecureData(key) {
    try {
        const encrypted = localStorage.getItem(key);
        if (!encrypted) {
            return null;
        }
        
        const decrypted = decryptData(encrypted);
        return JSON.parse(decrypted);
    } catch (error) {
        logSecurityEvent('error', 'Failed to retrieve secure data', { key, error: error.message });
        return null;
    }
}

// ============================================
// Session Management Module
// ============================================

/**
 * Create a new session for authenticated user
 * 
 * @param {string} username - Username of authenticated user
 * @returns {string} Session token
 */
function createSession(username) {
    // Generate session token
    const sessionToken = generateSessionToken();
    const expiryTime = Date.now() + SESSION_TIMEOUT;
    
    // Store session information
    localStorage.setItem(STORAGE_KEYS.SESSION_TOKEN, sessionToken);
    localStorage.setItem(STORAGE_KEYS.SESSION_EXPIRY, expiryTime.toString());
    localStorage.setItem(STORAGE_KEYS.CURRENT_USER, username);
    
    logSecurityEvent('success', 'Session created', { username });
    
    return sessionToken;
}

/**
 * Generate a unique session token
 * 
 * @returns {string} Session token
 */
function generateSessionToken() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let token = '';
    for (let i = 0; i < 64; i++) {
        token += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return token;
}

/**
 * Check if current session is valid
 * 
 * @returns {boolean} True if session is valid
 */
function isSessionValid() {
    const sessionToken = localStorage.getItem(STORAGE_KEYS.SESSION_TOKEN);
    const expiryTime = localStorage.getItem(STORAGE_KEYS.SESSION_EXPIRY);
    const currentUser = localStorage.getItem(STORAGE_KEYS.CURRENT_USER);
    
    if (!sessionToken || !expiryTime || !currentUser) {
        return false;
    }
    
    // Check if session has expired
    if (Date.now() > parseInt(expiryTime)) {
        destroySession();
        logSecurityEvent('warning', 'Session expired', { username: currentUser });
        return false;
    }
    
    return true;
}

/**
 * Destroy current session (logout)
 */
function destroySession() {
    const username = localStorage.getItem(STORAGE_KEYS.CURRENT_USER);
    
    localStorage.removeItem(STORAGE_KEYS.SESSION_TOKEN);
    localStorage.removeItem(STORAGE_KEYS.SESSION_EXPIRY);
    localStorage.removeItem(STORAGE_KEYS.CURRENT_USER);
    
    logSecurityEvent('success', 'Session destroyed', { username });
}

/**
 * Get current authenticated user
 * 
 * @returns {string|null} Username or null if not authenticated
 */
function getCurrentUser() {
    if (isSessionValid()) {
        return localStorage.getItem(STORAGE_KEYS.CURRENT_USER);
    }
    return null;
}

// ============================================
// Audit Logging Module
// ============================================

/**
 * Log security events for audit purposes
 * Records all important security-related events
 * 
 * @param {string} level - Log level: 'success', 'warning', 'error'
 * @param {string} message - Log message
 * @param {Object} details - Additional details (optional)
 */
function logSecurityEvent(level, message, details = {}) {
    const logEntry = {
        timestamp: new Date().toISOString(),
        level,
        message,
        details: sanitizeObject(details),
        user: getCurrentUser() || 'anonymous',
        userAgent: navigator.userAgent,
        url: window.location.href
    };
    
    // Get existing audit log
    let auditLog = [];
    try {
        const stored = localStorage.getItem(STORAGE_KEYS.AUDIT_LOG);
        if (stored) {
            auditLog = JSON.parse(stored);
        }
    } catch (error) {
        console.error('Failed to load audit log:', error);
    }
    
    // Add new log entry
    auditLog.push(logEntry);
    
    // Keep only last 1000 entries (prevent localStorage overflow)
    if (auditLog.length > 1000) {
        auditLog = auditLog.slice(-1000);
    }
    
    // Store audit log
    try {
        localStorage.setItem(STORAGE_KEYS.AUDIT_LOG, JSON.stringify(auditLog));
    } catch (error) {
        console.error('Failed to save audit log:', error);
    }
    
    // Also log to console for debugging
    console.log(`[Security ${level.toUpperCase()}] ${message}`, details);
}

/**
 * Get audit log entries
 * 
 * @param {number} limit - Maximum number of entries to return
 * @returns {Array} Array of log entries
 */
function getAuditLog(limit = 100) {
    try {
        const stored = localStorage.getItem(STORAGE_KEYS.AUDIT_LOG);
        if (!stored) {
            return [];
        }
        
        const auditLog = JSON.parse(stored);
        return auditLog.slice(-limit).reverse(); // Most recent first
    } catch (error) {
        logSecurityEvent('error', 'Failed to retrieve audit log', { error: error.message });
        return [];
    }
}

// ============================================
// User Management Module
// ============================================

/**
 * Register a new user
 * 
 * @param {string} username - Username
 * @param {string} password - Plain text password
 * @returns {Object} Result object with success status and message
 */
function registerUser(username, password) {
    // Sanitize username input
    const sanitizedUsername = sanitizeInput(username).trim();
    
    // Validate username
    if (!validateUsername(sanitizedUsername)) {
        logSecurityEvent('warning', 'Invalid username format', { username: sanitizedUsername });
        return { success: false, message: 'Username must be 3-20 alphanumeric characters' };
    }
    
    // Validate password strength
    const passwordValidation = validatePasswordStrength(password);
    if (!passwordValidation.isValid) {
        logSecurityEvent('warning', 'Weak password attempted', { username: sanitizedUsername });
        return { success: false, message: 'Password does not meet strength requirements', validation: passwordValidation };
    }
    
    // Load existing users
    const users = retrieveSecureData(STORAGE_KEYS.USERS) || {};
    
    // Check if username already exists
    if (users[sanitizedUsername]) {
        logSecurityEvent('warning', 'Registration attempt with existing username', { username: sanitizedUsername });
        return { success: false, message: 'Username already exists' };
    }
    
    // Hash password
    const hashedPassword = hashPassword(password);
    
    // Store user
    users[sanitizedUsername] = {
        username: sanitizedUsername,
        passwordHash: hashedPassword,
        createdAt: new Date().toISOString(),
        loginAttempts: 0,
        lockedUntil: null
    };
    
    // Save encrypted users
    storeSecureData(STORAGE_KEYS.USERS, users);
    
    logSecurityEvent('success', 'User registered', { username: sanitizedUsername });
    
    return { success: true, message: 'Registration successful' };
}

/**
 * Authenticate user (login)
 * 
 * @param {string} username - Username
 * @param {string} password - Plain text password
 * @returns {Object} Result object with success status and message
 */
function loginUser(username, password) {
    // Sanitize username input
    const sanitizedUsername = sanitizeInput(username).trim();
    
    // Load users
    const users = retrieveSecureData(STORAGE_KEYS.USERS) || {};
    
    // Check if user exists
    const user = users[sanitizedUsername];
    if (!user) {
        logSecurityEvent('warning', 'Login attempt with non-existent username', { username: sanitizedUsername });
        // Return generic message (don't reveal if username exists - security best practice)
        return { success: false, message: 'Invalid username or password' };
    }
    
    // Check if account is locked
    if (user.lockedUntil && Date.now() < user.lockedUntil) {
        const minutesRemaining = Math.ceil((user.lockedUntil - Date.now()) / 60000);
        logSecurityEvent('warning', 'Login attempt on locked account', { username: sanitizedUsername });
        return { success: false, message: `Account locked. Try again in ${minutesRemaining} minute(s)` };
    }
    
    // Verify password
    if (!verifyPassword(password, user.passwordHash)) {
        // Increment failed login attempts
        user.loginAttempts = (user.loginAttempts || 0) + 1;
        
        // Lock account after max attempts
        if (user.loginAttempts >= MAX_LOGIN_ATTEMPTS) {
            user.lockedUntil = Date.now() + LOCKOUT_DURATION;
            user.loginAttempts = 0; // Reset after lockout
            logSecurityEvent('error', 'Account locked due to multiple failed attempts', { username: sanitizedUsername });
            storeSecureData(STORAGE_KEYS.USERS, users);
            return { success: false, message: 'Account locked due to multiple failed attempts' };
        }
        
        storeSecureData(STORAGE_KEYS.USERS, users);
        logSecurityEvent('warning', 'Failed login attempt', { username: sanitizedUsername, attempts: user.loginAttempts });
        return { success: false, message: 'Invalid username or password', attemptsRemaining: MAX_LOGIN_ATTEMPTS - user.loginAttempts };
    }
    
    // Successful login - reset login attempts
    user.loginAttempts = 0;
    user.lockedUntil = null;
    user.lastLogin = new Date().toISOString();
    storeSecureData(STORAGE_KEYS.USERS, users);
    
    // Create session
    createSession(sanitizedUsername);
    
    logSecurityEvent('success', 'User logged in', { username: sanitizedUsername });
    
    return { success: true, message: 'Login successful', username: sanitizedUsername };
}

/**
 * Logout current user
 */
function logoutUser() {
    const username = getCurrentUser();
    destroySession();
    logSecurityEvent('success', 'User logged out', { username });
}

// ============================================
// Error Handling Module
// ============================================

/**
 * Global error handler for security-related errors
 */
window.addEventListener('error', function(event) {
    logSecurityEvent('error', 'JavaScript error occurred', {
        message: event.message,
        filename: event.filename,
        lineno: event.lineno,
        colno: event.colno
    });
});

/**
 * Handle unhandled promise rejections
 */
window.addEventListener('unhandledrejection', function(event) {
    logSecurityEvent('error', 'Unhandled promise rejection', {
        reason: event.reason
    });
});

// ============================================
// Security Initialization
// ============================================

/**
 * Initialize security features on page load
 */
function initializeSecurity() {
    // Check if user is already logged in
    if (isSessionValid()) {
        const username = getCurrentUser();
        logSecurityEvent('success', 'Session restored', { username });
    } else {
        // Clear any stale session data
        destroySession();
    }
    
    // Set up session timeout check
    setInterval(() => {
        if (isSessionValid()) {
            // Session still valid, update UI if needed
        } else {
            // Session expired, redirect to login
            if (document.getElementById('app-container').style.display !== 'none') {
                showAuthContainer();
            }
        }
    }, 60000); // Check every minute
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeSecurity);
} else {
    initializeSecurity();
}

    