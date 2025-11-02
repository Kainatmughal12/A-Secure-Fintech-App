/**
 * ============================================
 * File Validation Module - Secure File Upload
 * ============================================
 * 
 * This module provides secure file upload validation for the FinTech app.
 * Features:
 * - Extension-based validation
 * - MIME type validation (strict)
 * - Security logging and audit trails
 * - Client-side validation only (no actual upload)
 */

// ============================================
// Configuration Constants
// ============================================

/**
 * Allowed MIME types for secure upload
 * Only these exact MIME types are permitted
 */
const ALLOWED_MIME_TYPES = {
    'image/jpeg': ['.jpg', '.jpeg'],
    'image/png': ['.png'],
    'application/pdf': ['.pdf']
};

/**
 * Allowed file extensions (case-insensitive)
 */
const ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.pdf'];

/**
 * Maximum file size: 10MB
 */
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB in bytes

/**
 * Disallowed file extensions (dangerous file types)
 */
const DISALLOWED_EXTENSIONS = [
    '.exe', '.bat', '.cmd', '.com', '.scr', '.vbs', '.js',
    '.jar', '.msi', '.dll', '.sh', '.ps1', '.py', '.php',
    '.html', '.htm', '.xml', '.zip', '.rar', '.7z', '.docx',
    '.doc', '.xls', '.xlsx', '.ppt', '.pptx'
];

/**
 * Disallowed MIME types (for security)
 */
const DISALLOWED_MIME_TYPES = [
    'application/x-msdownload',      // .exe
    'application/x-msdos-program',   // .exe
    'application/x-sh',              // .sh
    'application/x-shar',            // .shar
    'application/javascript',        // .js
    'text/javascript',               // .js
    'application/x-javascript',     // .js
    'application/x-executable',      // executables
    'application/x-bat',             // .bat
    'application/x-cmd',             // .cmd
    'application/zip',               // .zip
    'application/x-zip-compressed',  // .zip
    'application/x-rar-compressed',  // .rar
    'application/x-7z-compressed'   // .7z
];

// ============================================
// File Validation Functions
// ============================================

/**
 * Get file extension from filename (case-insensitive)
 * @param {string} filename - The file name
 * @returns {string} File extension in lowercase with dot (e.g., '.jpg')
 */
function getFileExtension(filename) {
    if (!filename || typeof filename !== 'string') {
        return '';
    }
    
    const lastDotIndex = filename.lastIndexOf('.');
    if (lastDotIndex === -1 || lastDotIndex === filename.length - 1) {
        return ''; // No extension found
    }
    
    return filename.substring(lastDotIndex).toLowerCase();
}

/**
 * Validate file extension
 * @param {string} extension - File extension (e.g., '.jpg')
 * @returns {Object} Validation result
 */
function validateExtension(extension) {
    const ext = extension.toLowerCase();
    
    // Check if extension is in disallowed list
    if (DISALLOWED_EXTENSIONS.includes(ext)) {
        return {
            isValid: false,
            reason: 'disallowed_extension',
            message: `Invalid file type. Only JPG, PNG, and PDF are allowed.`
        };
    }
    
    // Check if extension is in allowed list
    if (!ALLOWED_EXTENSIONS.includes(ext)) {
        return {
            isValid: false,
            reason: 'invalid_extension',
            message: `Invalid file type. Only JPG, PNG, and PDF are allowed.`
        };
    }
    
    return {
        isValid: true,
        reason: 'valid_extension'
    };
}

/**
 * Validate MIME type
 * @param {string} mimeType - MIME type (e.g., 'image/jpeg')
 * @returns {Object} Validation result
 */
function validateMimeType(mimeType) {
    if (!mimeType || typeof mimeType !== 'string' || mimeType.trim() === '') {
        return {
            isValid: false,
            reason: 'missing_mime_type',
            message: `Invalid file type. Only JPG, PNG, and PDF are allowed.`
        };
    }
    
    const mime = mimeType.toLowerCase().trim();
    
    // Check for generic/unknown MIME types that should be rejected
    if (mime === 'application/octet-stream' || 
        mime === 'application/x-unknown-content-type' ||
        mime === '' || 
        mime === 'unknown' ||
        mime === 'application/unknown') {
        return {
            isValid: false,
            reason: 'generic_mime_type',
            message: `Invalid file type. Only JPG, PNG, and PDF are allowed.`
        };
    }
    
    // Check if MIME type is in disallowed list
    if (DISALLOWED_MIME_TYPES.includes(mime)) {
        return {
            isValid: false,
            reason: 'disallowed_mime_type',
            message: `Invalid file type. Only JPG, PNG, and PDF are allowed.`
        };
    }
    
    // Check if MIME type is in allowed list (STRICT - must be exact match)
    if (!ALLOWED_MIME_TYPES[mime]) {
        return {
            isValid: false,
            reason: 'invalid_mime_type',
            message: `Invalid file type. Only JPG, PNG, and PDF are allowed.`
        };
    }
    
    return {
        isValid: true,
        reason: 'valid_mime_type'
    };
}

/**
 * Validate file size
 * @param {number} fileSize - File size in bytes
 * @returns {Object} Validation result
 */
function validateFileSize(fileSize) {
    if (fileSize === 0) {
        return {
            isValid: false,
            reason: 'empty_file',
            message: 'File is empty. Please select a valid file.'
        };
    }
    
    if (fileSize > MAX_FILE_SIZE) {
        const fileSizeMB = (fileSize / (1024 * 1024)).toFixed(2);
        return {
            isValid: false,
            reason: 'file_too_large',
            message: `File size too large. Maximum size is 10MB. Your file is ${fileSizeMB}MB.`
        };
    }
    
    return {
        isValid: true,
        reason: 'valid_size'
    };
}

/**
 * Check if MIME type matches file extension
 * @param {string} mimeType - MIME type
 * @param {string} extension - File extension
 * @returns {boolean} True if MIME type matches extension
 */
function mimeTypeMatchesExtension(mimeType, extension) {
    if (!mimeType || !extension) {
        return false;
    }
    
    const allowedExtensions = ALLOWED_MIME_TYPES[mimeType.toLowerCase()];
    if (!allowedExtensions) {
        return false;
    }
    
    return allowedExtensions.includes(extension.toLowerCase());
}

/**
 * Comprehensive file validation
 * Validates extension, MIME type, size, and ensures they match
 * 
 * @param {File} file - The file object to validate
 * @returns {Object} Validation result with isValid flag and message
 */
function validateFile(file) {
    // Audit log start
    console.log('🔍 [File Validation] Starting validation for file:', file.name);
    
    // Check if file exists
    if (!file) {
        console.error('❌ [File Validation] No file provided');
        return {
            isValid: false,
            message: 'No file selected. Please select a file to upload.'
        };
    }
    
    // Get file properties
    const fileName = file.name;
    const fileExtension = getFileExtension(fileName);
    const mimeType = file.type;
    const fileSize = file.size;
    
    // Log file properties
    console.log('📄 [File Validation] File properties:', {
        filename: fileName,
        extension: fileExtension,
        mimeType: mimeType,
        size: fileSize,
        sizeMB: (fileSize / (1024 * 1024)).toFixed(2) + ' MB'
    });
    
    // 1. Validate file extension
    console.log('🔍 [File Validation] Checking extension:', fileExtension);
    const extensionValidation = validateExtension(fileExtension);
    
    if (!extensionValidation.isValid) {
        const logMessage = `Rejected file: extension=${fileExtension}, reason=${extensionValidation.reason}`;
        console.error('❌ [File Validation]', logMessage);
        
        // Log security event if available
        if (typeof logSecurityEvent === 'function') {
            logSecurityEvent('warning', 'File upload rejected: invalid extension', {
                filename: fileName,
                extension: fileExtension,
                reason: extensionValidation.reason
            });
        }
        
        return {
            isValid: false,
            message: extensionValidation.message || 'Invalid file type. Only JPG, PNG, and PDF are allowed.'
        };
    }
    
    console.log('✅ [File Validation] Extension validation passed:', fileExtension);
    
    // 2. Validate MIME type (strict check - REQUIRED)
    console.log('🔍 [File Validation] Checking MIME type:', mimeType);
    
    // If MIME type is missing or empty, reject
    if (!mimeType || mimeType.trim() === '' || mimeType === 'application/octet-stream') {
        const logMessage = `Rejected file: Missing or invalid MIME type (${mimeType || 'empty'})`;
        console.error('❌ [File Validation]', logMessage);
        
        // Log security event if available
        if (typeof logSecurityEvent === 'function') {
            logSecurityEvent('warning', 'File upload rejected: missing MIME type', {
                filename: fileName,
                mimeType: mimeType,
                extension: fileExtension
            });
        }
        
        return {
            isValid: false,
            message: 'Invalid file type. Only JPG, PNG, and PDF are allowed.'
        };
    }
    
    const mimeValidation = validateMimeType(mimeType);
    
    if (!mimeValidation.isValid) {
        const logMessage = `Rejected file: type=${mimeType}, reason=${mimeValidation.reason}`;
        console.error('❌ [File Validation]', logMessage);
        
        // Log security event if available
        if (typeof logSecurityEvent === 'function') {
            logSecurityEvent('warning', 'File upload rejected: invalid MIME type', {
                filename: fileName,
                mimeType: mimeType,
                extension: fileExtension,
                reason: mimeValidation.reason
            });
        }
        
        return {
            isValid: false,
            message: mimeValidation.message || 'Invalid file type. Only JPG, PNG, and PDF are allowed.'
        };
    }
    
    console.log('✅ [File Validation] MIME type validation passed:', mimeType);
    
    // 3. Verify MIME type matches extension (additional security check - REQUIRED)
    console.log('🔍 [File Validation] Verifying MIME type matches extension');
    if (!mimeTypeMatchesExtension(mimeType, fileExtension)) {
        const logMessage = `Rejected file: MIME type (${mimeType}) does not match extension (${fileExtension})`;
        console.error('❌ [File Validation]', logMessage);
        
        // Log security event if available
        if (typeof logSecurityEvent === 'function') {
            logSecurityEvent('warning', 'File upload rejected: MIME type mismatch', {
                filename: fileName,
                mimeType: mimeType,
                extension: fileExtension
            });
        }
        
        return {
            isValid: false,
            message: 'Invalid file type. Only JPG, PNG, and PDF are allowed.'
        };
    }
    
    console.log('✅ [File Validation] MIME type matches extension');
    
    // 4. Validate file size
    console.log('🔍 [File Validation] Checking file size:', fileSize, 'bytes');
    const sizeValidation = validateFileSize(fileSize);
    
    if (!sizeValidation.isValid) {
        const logMessage = `Rejected file: size=${fileSize}, reason=${sizeValidation.reason}`;
        console.error('❌ [File Validation]', logMessage);
        
        // Log security event if available
        if (typeof logSecurityEvent === 'function') {
            logSecurityEvent('warning', 'File upload rejected: invalid size', {
                filename: fileName,
                size: fileSize,
                reason: sizeValidation.reason
            });
        }
        
        return {
            isValid: false,
            message: sizeValidation.message
        };
    }
    
    console.log('✅ [File Validation] File size validation passed');
    
    // All validations passed
    const successMessage = `File validation passed: filename=${fileName}, extension=${fileExtension}, type=${mimeType}, size=${(fileSize / (1024 * 1024)).toFixed(2)}MB`;
    console.log('✅ [File Validation]', successMessage);
    
    // Log security event if available
    if (typeof logSecurityEvent === 'function') {
        logSecurityEvent('success', 'File upload validation passed', {
            filename: fileName,
            extension: fileExtension,
            mimeType: mimeType,
            size: fileSize
        });
    }
    
    return {
        isValid: true,
        message: 'File validation passed.',
        fileInfo: {
            name: fileName,
            extension: fileExtension,
            mimeType: mimeType,
            size: fileSize,
            sizeMB: (fileSize / (1024 * 1024)).toFixed(2)
        }
    };
}

/**
 * Get file preview/confirmation information
 * @param {File} file - The validated file
 * @returns {Object} File preview information
 */
function getFilePreview(file) {
    if (!file) {
        return null;
    }
    
    const extension = getFileExtension(file.name);
    const sizeMB = (file.size / (1024 * 1024)).toFixed(2);
    
    return {
        name: file.name,
        extension: extension,
        mimeType: file.type,
        size: file.size,
        sizeMB: sizeMB,
        lastModified: new Date(file.lastModified).toLocaleString()
    };
}

// ============================================
// Export validation functions
// ============================================

// Make functions available globally (for use in app.js)
if (typeof window !== 'undefined') {
    window.FileValidation = {
        validateFile: validateFile,
        validateExtension: validateExtension,
        validateMimeType: validateMimeType,
        validateFileSize: validateFileSize,
        getFileExtension: getFileExtension,
        getFilePreview: getFilePreview,
        ALLOWED_MIME_TYPES: ALLOWED_MIME_TYPES,
        ALLOWED_EXTENSIONS: ALLOWED_EXTENSIONS,
        MAX_FILE_SIZE: MAX_FILE_SIZE
    };
    
    console.log('📦 [File Validation] Module loaded successfully');
    console.log('📦 [File Validation] Allowed types:', ALLOWED_EXTENSIONS);
    console.log('📦 [File Validation] Allowed MIME types:', Object.keys(ALLOWED_MIME_TYPES));
    
    // Verify module is accessible
    if (window.FileValidation && window.FileValidation.validateFile) {
        console.log('✅ [File Validation] Module exports verified');
    } else {
        console.error('❌ [File Validation] Module exports failed!');
    }
}

