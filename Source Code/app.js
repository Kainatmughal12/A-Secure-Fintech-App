/**
 * ============================================
 * Debt Payoff Planner - JavaScript Application
 * ============================================
 * 
 * A modular FinTech application for managing debt payments.
 * Features:
 * - CRUD operations (Create, Read, Update, Delete) for debts
 * - Advanced payoff calculations
 * - Visual progress indicators
 * - Summary statistics
 */

// ============================================
// Application State
// ============================================

/**
 * Array to store all debt objects
 * Structure: { id, name, amount, interestRate, monthlyPayment }
 */
let debts = [];

// Track if we're editing a debt
let editingDebtId = null;

// ============================================
// DOM Element References
// ============================================

// Authentication UI elements
const authContainer = document.getElementById('auth-container');
const appContainer = document.getElementById('app-container');
const loginForm = document.getElementById('login-form');
const registerForm = document.getElementById('register-form');
const loginSection = document.getElementById('login-section');
const registerSection = document.getElementById('register-section');
const showRegisterLink = document.getElementById('show-register');
const showLoginLink = document.getElementById('show-login');
const loginError = document.getElementById('login-error');
const registerError = document.getElementById('register-error');
const logoutBtn = document.getElementById('logout-btn');
const usernameDisplay = document.getElementById('username-display');
const registerPasswordInput = document.getElementById('register-password');
const confirmPasswordInput = document.getElementById('confirm-password');
const registerBtn = document.getElementById('register-btn');
const passwordStrengthBar = document.getElementById('strength-bar');
const passwordStrengthText = document.getElementById('strength-text');
const passwordStrengthRequirements = document.getElementById('strength-requirements');
const auditModal = document.getElementById('audit-modal');
const auditLogContent = document.getElementById('audit-log-content');
const showAuditLogLink = document.getElementById('show-audit-log');
const closeAuditModal = document.getElementById('close-audit-modal');

// Main application elements
const debtForm = document.getElementById('debt-form');
const debtIdInput = document.getElementById('debt-id');
const debtNameInput = document.getElementById('debt-name');
const debtAmountInput = document.getElementById('debt-amount');
const interestRateInput = document.getElementById('interest-rate');
const monthlyPaymentInput = document.getElementById('monthly-payment');
const debtsList = document.getElementById('debts-list');
const summaryContent = document.getElementById('summary-content');
const progressVisualization = document.getElementById('progress-visualization');
const progressBars = document.getElementById('progress-bars');
const formTitle = document.getElementById('form-title');
const submitBtn = document.getElementById('submit-btn');
const cancelBtn = document.getElementById('cancel-btn');

// File upload elements
const fileUploadForm = document.getElementById('file-upload-form');
const fileInput = document.getElementById('file-input');
const fileUploadError = document.getElementById('file-upload-error');
const fileUploadSuccess = document.getElementById('file-upload-success');
const uploadedFileInfo = document.getElementById('uploaded-file-info');
const fileInfoContent = document.getElementById('file-info-content');

// ============================================
// File Upload Validation Module
// Uses fileValidation.js module for validation
// ============================================

/**
 * Validate file when selected (before submission)
 * Uses FileValidation module for validation
 */
function validateFileOnSelect(event) {
    console.log('🔍 [File Upload] validateFileOnSelect called');
    
    const file = event.target.files[0];
    if (!file) {
        console.log('⚠️ [File Upload] No file selected');
        clearFileMessages();
        return;
    }
    
    console.log('📄 [File Upload] File detected:', file.name, 'Type:', file.type);
    
    // Hide previous messages
    clearFileMessages();
    
    // Check if FileValidation module is available
    if (!window.FileValidation || !window.FileValidation.validateFile) {
        console.error('❌ [File Upload] FileValidation module not available!');
        console.error('❌ [File Upload] window.FileValidation:', window.FileValidation);
        const errorMsg = 'File validation module not available. Please refresh the page.';
        showFileError(errorMsg);
        alert(errorMsg);
        event.target.value = '';
        return false;
    }
    
    console.log('✅ [File Upload] FileValidation module found, calling validateFile...');
    
    // Use FileValidation module
    try {
        const validation = window.FileValidation.validateFile(file);
        
        console.log('📊 [File Upload] Validation result:', validation);
        
        if (!validation.isValid) {
            // Show error message in UI
            showFileError(validation.message);
            
            // Show alert for visibility (REQUIRED for testing)
            alert(validation.message || 'Invalid file type. Only JPG, PNG, and PDF are allowed.');
            
            // Clear the file input
            event.target.value = '';
            
            console.error('❌ [File Upload] Validation failed:', validation.message);
            
            // Prevent form submission
            return false;
        } else {
            console.log('✅ [File Upload] File selected and validated:', file.name);
            // Clear any previous errors
            if (fileUploadError) fileUploadError.style.display = 'none';
            return true;
        }
    } catch (error) {
        console.error('❌ [File Upload] Validation error:', error);
        const errorMsg = 'Error validating file. Please try again.';
        showFileError(errorMsg);
        alert(errorMsg);
        event.target.value = '';
        return false;
    }
}

/**
 * Handle file upload form submission
 * Uses FileValidation module for strict validation
 */
function handleFileUpload(event) {
    event.preventDefault();
    event.stopPropagation();
    
    console.log('🔄 [File Upload] Form submission intercepted');
    
    // Clear previous messages
    clearFileMessages();
    
    // Get selected file
    const file = fileInput ? fileInput.files[0] : null;
    
    if (!file) {
        const errorMsg = 'Please select a file to upload.';
        console.error('❌ [File Upload]', errorMsg);
        showFileError(errorMsg);
        alert(errorMsg);
        return false;
    }
    
    console.log('📄 [File Upload] Processing file:', file.name, 'Type:', file.type);
    
    // Check if FileValidation module is available
    if (!window.FileValidation || !window.FileValidation.validateFile) {
        console.error('❌ [File Upload] FileValidation module not loaded!');
        console.error('❌ [File Upload] window.FileValidation exists:', !!window.FileValidation);
        const errorMsg = 'File validation module not available. Please refresh the page.';
        showFileError(errorMsg);
        alert(errorMsg);
        return false;
    }
    
    // Validate file using FileValidation module (STRICT VALIDATION)
    console.log('🔄 [File Upload] Starting strict validation for:', file.name);
    const validation = window.FileValidation.validateFile(file);
    
    console.log('📊 [File Upload] Validation result:', validation);
    
    if (!validation || !validation.isValid) {
        // Get error message
        const errorMessage = validation && validation.message 
            ? validation.message 
            : 'Invalid file type. Only JPG, PNG, and PDF are allowed.';
        
        console.error('❌ [File Upload] VALIDATION FAILED:', errorMessage);
        
        // Show error message in UI
        showFileError(errorMessage);
        
        // Show alert for visibility (REQUIRED - shows validation is working)
        alert('❌ ' + errorMessage);
        
        // Clear file input to prevent submission
        if (fileInput) fileInput.value = '';
        
        // Stop form submission
        return false;
    }
    
    // File is valid - show success message and preview
    console.log('✅ [File Upload] File validation PASSED');
    showFileSuccess(file, validation.fileInfo);
    
    // Show success alert
    alert('✅ File validated successfully!\nFile type: ' + file.type + '\nFilename: ' + file.name + '\n\nNote: This is a simulation - file was not actually stored.');
    
    // Don't reset form immediately - let user see the success
    setTimeout(() => {
        resetFileForm();
    }, 3000);
    
    return true;
}

/**
 * Show file upload error message
 */
function showFileError(message) {
    if (fileUploadError) {
        fileUploadError.textContent = message;
        fileUploadError.style.display = 'block';
        fileUploadSuccess.style.display = 'none';
        uploadedFileInfo.style.display = 'none';
    }
    
    // Log to console for testing
    console.error('❌ File Upload Error:', message);
}

/**
 * Show file upload success message with preview
 * @param {File} file - The validated file
 * @param {Object} fileInfo - File information from validation
 */
function showFileSuccess(file, fileInfo) {
    if (fileUploadSuccess) {
        fileUploadSuccess.textContent = '✅ File validated successfully! Upload simulation complete.';
        fileUploadSuccess.style.display = 'block';
        fileUploadError.style.display = 'none';
    }
    
    // Get file preview information
    let previewInfo = fileInfo;
    if (!previewInfo && window.FileValidation && window.FileValidation.getFilePreview) {
        previewInfo = window.FileValidation.getFilePreview(file);
    }
    
    // Display file information/preview
    if (uploadedFileInfo && fileInfoContent) {
        const fileSizeMB = previewInfo ? previewInfo.sizeMB : (file.size / (1024 * 1024)).toFixed(2);
        const fileExtension = previewInfo ? previewInfo.extension : file.name.substring(file.name.lastIndexOf('.'));
        const mimeType = previewInfo ? previewInfo.mimeType : file.type;
        
        fileInfoContent.innerHTML = `
            <div><strong>Filename:</strong> ${sanitizeInput(file.name)}</div>
            <div><strong>Type:</strong> ${mimeType || 'Unknown'}</div>
            <div><strong>Extension:</strong> ${fileExtension}</div>
            <div><strong>Size:</strong> ${fileSizeMB} MB</div>
            ${previewInfo && previewInfo.lastModified ? `<div><strong>Last Modified:</strong> ${previewInfo.lastModified}</div>` : ''}
            <div style="margin-top: 8px; padding-top: 8px; border-top: 1px solid rgba(148, 163, 184, 0.2);">
                <small style="color: var(--secondary-color);">
                    ✅ Validation Passed: Extension and MIME type verified. 
                    <br>Note: This is a simulation. File was not actually stored for security purposes.
                </small>
            </div>
        `;
        
        uploadedFileInfo.style.display = 'block';
    }
    
    // Log success to console
    console.log('✅ [File Upload] Success - File validated and preview displayed:', {
        filename: file.name,
        extension: fileExtension,
        mimeType: mimeType,
        size: file.size,
        sizeMB: fileSizeMB
    });
}

/**
 * Clear all file upload messages
 */
function clearFileMessages() {
    if (fileUploadError) fileUploadError.style.display = 'none';
    if (fileUploadSuccess) fileUploadSuccess.style.display = 'none';
    if (uploadedFileInfo) uploadedFileInfo.style.display = 'none';
}

/**
 * Reset file upload form
 */
function resetFileForm() {
    // Keep the form ready for next upload but clear after a delay
    setTimeout(() => {
        if (fileInput) fileInput.value = '';
        clearFileMessages();
    }, 5000); // Clear after 5 seconds
}

// ============================================
// Debt CRUD Operations Module
// ============================================

/**
 * Create a new debt
 * @param {Object} debtData - Debt information object
 * @returns {Object} The created debt object
 */
function createDebt(debtData) {
    // Sanitize all inputs to prevent XSS/injection attacks
    const sanitizedData = {
        name: sanitizeInput(debtData.name).trim(),
        amount: sanitizeNumber(debtData.amount, 0, 999999999),
        interestRate: sanitizeNumber(debtData.interestRate, 0, 100),
        monthlyPayment: sanitizeNumber(debtData.monthlyPayment, 0, 999999999)
    };
    
    // Validate sanitized data
    if (!sanitizedData.name || sanitizedData.amount === null || 
        sanitizedData.interestRate === null || sanitizedData.monthlyPayment === null) {
        logSecurityEvent('warning', 'Invalid debt data submitted', { data: debtData });
        throw new Error('Invalid debt data');
    }
    
    const debt = {
        id: Date.now(),
        name: sanitizedData.name,
        amount: sanitizedData.amount,
        interestRate: sanitizedData.interestRate,
        monthlyPayment: sanitizedData.monthlyPayment
    };
    
    debts.push(debt);
    saveDebtsToStorage();
    
    logSecurityEvent('success', 'Debt created', { debtId: debt.id });
    
    return debt;
}

/**
 * Read/Get all debts
 * @returns {Array} Array of all debts
 */
function readDebts() {
    return debts;
}

/**
 * Get a specific debt by ID
 * @param {number} debtId - The ID of the debt
 * @returns {Object|null} The debt object or null if not found
 */
function getDebtById(debtId) {
    return debts.find(debt => debt.id === debtId) || null;
}

/**
 * Update an existing debt
 * @param {number} debtId - The ID of the debt to update
 * @param {Object} updates - Object containing fields to update
 * @returns {boolean} True if update was successful, false otherwise
 */
function updateDebt(debtId, updates) {
    const debtIndex = debts.findIndex(debt => debt.id === debtId);
    
    if (debtIndex === -1) {
        logSecurityEvent('warning', 'Attempted to update non-existent debt', { debtId });
        return false;
    }
    
    // Sanitize all inputs
    const sanitizedData = {
        name: sanitizeInput(updates.name).trim(),
        amount: sanitizeNumber(updates.amount, 0, 999999999),
        interestRate: sanitizeNumber(updates.interestRate, 0, 100),
        monthlyPayment: sanitizeNumber(updates.monthlyPayment, 0, 999999999)
    };
    
    // Validate sanitized data
    if (!sanitizedData.name || sanitizedData.amount === null || 
        sanitizedData.interestRate === null || sanitizedData.monthlyPayment === null) {
        logSecurityEvent('warning', 'Invalid debt update data', { debtId, data: updates });
        return false;
    }
    
    // Update debt with sanitized values
    debts[debtIndex] = {
        ...debts[debtIndex],
        name: sanitizedData.name,
        amount: sanitizedData.amount,
        interestRate: sanitizedData.interestRate,
        monthlyPayment: sanitizedData.monthlyPayment
    };
    
    saveDebtsToStorage();
    
    logSecurityEvent('success', 'Debt updated', { debtId });
    
    return true;
}

/**
 * Delete a debt
 * @param {number} debtId - The ID of the debt to delete
 * @returns {boolean} True if deletion was successful, false otherwise
 */
function deleteDebt(debtId) {
    const initialLength = debts.length;
    debts = debts.filter(debt => debt.id !== debtId);
    const deleted = debts.length < initialLength;
    
    if (deleted) {
        saveDebtsToStorage();
        logSecurityEvent('success', 'Debt deleted', { debtId });
    } else {
        logSecurityEvent('warning', 'Attempted to delete non-existent debt', { debtId });
    }
    
    return deleted;
}

// ============================================
// Calculation Module
// ============================================

/**
 * Calculate months to payoff using amortization formula
 * @param {Object} debt - The debt object
 * @returns {number} Number of months to payoff (or Infinity if never)
 */
function calculateMonthsToPayoff(debt) {
    const { amount, interestRate, monthlyPayment } = debt;
    
    // Handle edge cases
    if (amount <= 0 || monthlyPayment <= 0) {
        return Infinity;
    }
    
    // Monthly interest rate
    const monthlyRate = interestRate / 100 / 12;
    
    // If no interest, simple division
    if (monthlyRate === 0) {
        return Math.ceil(amount / monthlyPayment);
    }
    
    // Check if payment covers at least the interest
    const monthlyInterest = amount * monthlyRate;
    if (monthlyPayment <= monthlyInterest) {
        return Infinity; // Debt will never be paid off
    }
    
    // Amortization formula: n = -log(1 - (P * r) / M) / log(1 + r)
    // Where: P = principal, r = monthly rate, M = monthly payment
    const numerator = -Math.log(1 - (amount * monthlyRate) / monthlyPayment);
    const denominator = Math.log(1 + monthlyRate);
    const months = numerator / denominator;
    
    return Math.ceil(months);
}

/**
 * Calculate total interest paid over the life of the debt
 * @param {Object} debt - The debt object
 * @returns {number} Total interest amount
 */
function calculateTotalInterest(debt) {
    const months = calculateMonthsToPayoff(debt);
    
    if (!isFinite(months)) {
        return Infinity;
    }
    
    const monthlyRate = debt.interestRate / 100 / 12;
    let balance = debt.amount;
    let totalInterest = 0;
    
    // Calculate interest month by month
    for (let i = 0; i < months; i++) {
        const interest = balance * monthlyRate;
        totalInterest += interest;
        balance = balance + interest - debt.monthlyPayment;
        
        if (balance <= 0) {
            break;
        }
    }
    
    return totalInterest;
}

/**
 * Calculate total amount to be paid (principal + interest)
 * @param {Object} debt - The debt object
 * @returns {number} Total amount
 */
function calculateTotalAmount(debt) {
    const months = calculateMonthsToPayoff(debt);
    
    if (!isFinite(months)) {
        return Infinity;
    }
    
    return debt.amount + calculateTotalInterest(debt);
}

/**
 * Calculate summary statistics for all debts
 * @returns {Object} Summary object with totals and averages
 */
function calculateSummary() {
    if (debts.length === 0) {
        return {
            totalDebt: 0,
            totalMonthlyPayment: 0,
            averageInterestRate: 0,
            longestPayoffMonths: 0,
            totalInterest: 0,
            estimatedTotalPayoff: 0
        };
    }
    
    const totalDebt = debts.reduce((sum, debt) => sum + debt.amount, 0);
    const totalMonthlyPayment = debts.reduce((sum, debt) => sum + debt.monthlyPayment, 0);
    const averageInterestRate = debts.reduce((sum, debt) => sum + debt.interestRate, 0) / debts.length;
    const longestPayoffMonths = Math.max(...debts.map(debt => calculateMonthsToPayoff(debt)).filter(m => isFinite(m)));
    
    // Calculate total interest across all debts
    let totalInterest = 0;
    let totalPayoff = 0;
    debts.forEach(debt => {
        const interest = calculateTotalInterest(debt);
        if (isFinite(interest)) {
            totalInterest += interest;
        }
        const payoff = calculateTotalAmount(debt);
        if (isFinite(payoff)) {
            totalPayoff += payoff;
        }
    });
    
    return {
        totalDebt,
        totalMonthlyPayment,
        averageInterestRate,
        longestPayoffMonths: isFinite(longestPayoffMonths) ? longestPayoffMonths : 0,
        totalInterest,
        estimatedTotalPayoff: totalPayoff
    };
}

// ============================================
// Rendering Module
// ============================================

/**
 * Render the list of debts
 */
function renderDebts() {
    debtsList.innerHTML = '';
    
    if (debts.length === 0) {
        debtsList.innerHTML = '<p class="empty-state">No debts added yet. Add your first debt above to get started.</p>';
        return;
    }
    
    // Sort debts by amount (largest first)
    const sortedDebts = [...debts].sort((a, b) => b.amount - a.amount);
    
    sortedDebts.forEach(debt => {
        const debtElement = createDebtElement(debt);
        debtsList.appendChild(debtElement);
    });
}

/**
 * Create a DOM element for a single debt item
 * @param {Object} debt - The debt object
 * @returns {HTMLElement} The created debt element
 */
function createDebtElement(debt) {
    const debtItem = document.createElement('div');
    debtItem.className = 'debt-item';
    debtItem.dataset.debtId = debt.id;
    
    // Calculate payoff metrics
    const monthsToPayoff = calculateMonthsToPayoff(debt);
    const totalInterest = calculateTotalInterest(debt);
    const totalAmount = calculateTotalAmount(debt);
    
    // Create debt info section
    const debtInfo = document.createElement('div');
    debtInfo.className = 'debt-info';
    
    const debtName = document.createElement('div');
    debtName.className = 'debt-name';
    debtName.textContent = debt.name;
    
    const debtDetails = document.createElement('div');
    debtDetails.className = 'debt-details';
    
    let detailsText = `Balance: $${debt.amount.toFixed(2)} | Rate: ${debt.interestRate}% APR | Payment: $${debt.monthlyPayment.toFixed(2)}/month`;
    
    if (isFinite(monthsToPayoff)) {
        const years = Math.floor(monthsToPayoff / 12);
        const months = monthsToPayoff % 12;
        let timeText = '';
        if (years > 0) {
            timeText = years === 1 ? '1 year' : `${years} years`;
            if (months > 0) {
                timeText += months === 1 ? ' 1 month' : ` ${months} months`;
            }
        } else {
            timeText = monthsToPayoff === 1 ? '1 month' : `${monthsToPayoff} months`;
        }
        detailsText += ` | Payoff: ${timeText}`;
        
        if (isFinite(totalInterest)) {
            detailsText += ` | Total Interest: $${totalInterest.toFixed(2)}`;
        }
    } else {
        detailsText += ' | ⚠️ Payment too low to pay off debt';
    }
    
    debtDetails.textContent = detailsText;
    
    debtInfo.appendChild(debtName);
    debtInfo.appendChild(debtDetails);
    
    // Create action buttons
    const debtActions = document.createElement('div');
    debtActions.className = 'debt-actions';
    
    const editButton = document.createElement('button');
    editButton.className = 'btn btn-edit';
    editButton.textContent = 'Edit';
    editButton.addEventListener('click', () => startEditDebt(debt.id));
    
    const deleteButton = document.createElement('button');
    deleteButton.className = 'btn btn-danger';
    deleteButton.textContent = 'Delete';
    deleteButton.addEventListener('click', () => handleDeleteDebt(debt.id));
    
    debtActions.appendChild(editButton);
    debtActions.appendChild(deleteButton);
    
    debtItem.appendChild(debtInfo);
    debtItem.appendChild(debtActions);
    
    return debtItem;
}

/**
 * Render the summary section
 */
function renderSummary() {
    summaryContent.innerHTML = '';
    
    if (debts.length === 0) {
        summaryContent.innerHTML = '<p class="empty-state">Add debts to see your payoff summary.</p>';
        progressVisualization.style.display = 'none';
        return;
    }
    
    const summary = calculateSummary();
    
    const summaries = [
        { label: 'Total Debt', value: `$${summary.totalDebt.toFixed(2)}`, icon: '💰' },
        { label: 'Total Monthly Payment', value: `$${summary.totalMonthlyPayment.toFixed(2)}`, icon: '📅' },
        { label: 'Average Interest Rate', value: `${summary.averageInterestRate.toFixed(2)}%`, icon: '📊' },
        { label: 'Longest Payoff Time', value: formatPayoffTime(summary.longestPayoffMonths), icon: '⏰' },
        { label: 'Total Interest', value: isFinite(summary.totalInterest) ? `$${summary.totalInterest.toFixed(2)}` : 'N/A', icon: '💸' },
        { label: 'Estimated Total Payoff', value: isFinite(summary.estimatedTotalPayoff) ? `$${summary.estimatedTotalPayoff.toFixed(2)}` : 'N/A', icon: '🎯' }
    ];
    
    summaries.forEach(summaryItem => {
        const item = document.createElement('div');
        item.className = 'summary-item';
        
        const label = document.createElement('div');
        label.className = 'summary-label';
        label.textContent = `${summaryItem.icon} ${summaryItem.label}`;
        
        const value = document.createElement('div');
        value.className = 'summary-value';
        value.textContent = summaryItem.value;
        
        item.appendChild(label);
        item.appendChild(value);
        summaryContent.appendChild(item);
    });
    
    // Render progress visualization
    renderProgressVisualization();
}

/**
 * Render progress bars for each debt
 */
function renderProgressVisualization() {
    if (debts.length === 0) {
        progressVisualization.style.display = 'none';
        return;
    }
    
    progressVisualization.style.display = 'block';
    progressBars.innerHTML = '';
    
    // Sort by amount (largest first) for visualization
    const sortedDebts = [...debts].sort((a, b) => b.amount - a.amount);
    const maxDebt = sortedDebts[0].amount;
    
    sortedDebts.forEach(debt => {
        const progressItem = document.createElement('div');
        progressItem.className = 'progress-item';
        
        const progressHeader = document.createElement('div');
        progressHeader.className = 'progress-header';
        
        const progressDebtName = document.createElement('span');
        progressDebtName.className = 'progress-debt-name';
        progressDebtName.textContent = debt.name;
        
        const progressAmount = document.createElement('span');
        progressAmount.className = 'progress-amount';
        progressAmount.textContent = `$${debt.amount.toFixed(2)}`;
        
        progressHeader.appendChild(progressDebtName);
        progressHeader.appendChild(progressAmount);
        
        const progressBarContainer = document.createElement('div');
        progressBarContainer.className = 'progress-bar-container';
        
        const progressBarLabel = document.createElement('span');
        progressBarLabel.className = 'progress-bar-label';
        const percentage = (debt.amount / maxDebt * 100).toFixed(0);
        progressBarLabel.textContent = `${percentage}%`;
        
        const progressBarFill = document.createElement('div');
        progressBarFill.className = 'progress-bar-fill';
        progressBarFill.style.width = `${(debt.amount / maxDebt * 100)}%`;
        
        // Add payoff info to progress bar
        const monthsToPayoff = calculateMonthsToPayoff(debt);
        if (isFinite(monthsToPayoff)) {
            const years = Math.floor(monthsToPayoff / 12);
            const months = monthsToPayoff % 12;
            let timeText = '';
            if (years > 0) {
                timeText = `${years}y`;
                if (months > 0) timeText += ` ${months}m`;
            } else {
                timeText = `${monthsToPayoff}m`;
            }
            progressBarFill.textContent = timeText;
        } else {
            progressBarFill.textContent = '∞';
        }
        
        progressBarContainer.appendChild(progressBarLabel);
        progressBarContainer.appendChild(progressBarFill);
        
        progressItem.appendChild(progressHeader);
        progressItem.appendChild(progressBarContainer);
        
        progressBars.appendChild(progressItem);
    });
}

/**
 * Format payoff time in a human-readable format
 * @param {number} months - Number of months
 * @returns {string} Formatted time string
 */
function formatPayoffTime(months) {
    if (!isFinite(months) || months === 0) {
        return 'N/A';
    }
    
    const years = Math.floor(months / 12);
    const remainingMonths = months % 12;
    
    let timeText = '';
    if (years > 0) {
        timeText = years === 1 ? '1 year' : `${years} years`;
        if (remainingMonths > 0) {
            timeText += remainingMonths === 1 ? ' 1 month' : ` ${remainingMonths} months`;
        }
    } else {
        timeText = months === 1 ? '1 month' : `${months} months`;
    }
    
    return timeText;
}

// ============================================
// Form Management Module
// ============================================

/**
 * Reset the form to add mode
 */
function resetForm() {
    editingDebtId = null;
    debtForm.reset();
    debtIdInput.value = '';
    formTitle.textContent = 'Add New Debt';
    submitBtn.textContent = 'Add Debt';
    cancelBtn.style.display = 'none';
}

/**
 * Populate form with debt data for editing
 * @param {Object} debt - The debt object to edit
 */
function populateForm(debt) {
    debtIdInput.value = debt.id;
    debtNameInput.value = debt.name;
    debtAmountInput.value = debt.amount;
    interestRateInput.value = debt.interestRate;
    monthlyPaymentInput.value = debt.monthlyPayment;
    
    editingDebtId = debt.id;
    formTitle.textContent = 'Edit Debt';
    submitBtn.textContent = 'Update Debt';
    cancelBtn.style.display = 'block';
    
    // Scroll to form
    document.getElementById('add-debt-section').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

/**
 * Start editing a debt
 * @param {number} debtId - The ID of the debt to edit
 */
function startEditDebt(debtId) {
    const debt = getDebtById(debtId);
    if (debt) {
        populateForm(debt);
    }
}

/**
 * Handle form submission (create or update)
 */
function handleFormSubmit(event) {
    event.preventDefault();
    
    // Get form values
    const formData = {
        name: debtNameInput.value.trim(),
        amount: debtAmountInput.value,
        interestRate: interestRateInput.value,
        monthlyPayment: monthlyPaymentInput.value
    };
    
    // Validate inputs
    if (!formData.name || 
        !formData.amount || 
        parseFloat(formData.amount) <= 0 ||
        parseFloat(formData.interestRate) < 0 ||
        !formData.monthlyPayment ||
        parseFloat(formData.monthlyPayment) <= 0) {
        alert('Please fill in all fields with valid values.');
        return;
    }
    
    // Create or update debt
    if (editingDebtId) {
        // Update existing debt
        const success = updateDebt(editingDebtId, formData);
        if (success) {
            console.log('Debt updated:', editingDebtId);
        }
    } else {
        // Create new debt
        const newDebt = createDebt(formData);
        console.log('Debt created:', newDebt);
    }
    
    // Reset form and update UI
    resetForm();
    renderDebts();
    renderSummary();
}

/**
 * Handle debt deletion
 * @param {number} debtId - The ID of the debt to delete
 */
function handleDeleteDebt(debtId) {
    const debt = getDebtById(debtId);
    if (!debt) return;
    
    if (!confirm(`Are you sure you want to delete "${debt.name}"?`)) {
        return;
    }
    
    const success = deleteDebt(debtId);
    if (success) {
        console.log('Debt deleted:', debtId);
        renderDebts();
        renderSummary();
    }
}

// ============================================
// Storage Module
// ============================================

/**
 * Save debts to secure storage (encrypted per user)
 */
function saveDebtsToStorage() {
    try {
        const currentUser = getCurrentUser();
        if (!currentUser) {
            return;
        }
        
        // Store debts encrypted per user
        const userDebtsKey = `debtPlanner_debts_${currentUser}`;
        storeSecureData(userDebtsKey, debts);
    } catch (error) {
        logSecurityEvent('error', 'Failed to save debts to storage', { error: error.message });
    }
}

/**
 * Load debts from secure storage (decrypted per user)
 */
function loadDebtsFromStorage() {
    try {
        const currentUser = getCurrentUser();
        if (!currentUser) {
            debts = [];
            return;
        }
        
        // Retrieve debts encrypted per user
        const userDebtsKey = `debtPlanner_debts_${currentUser}`;
        const storedDebts = retrieveSecureData(userDebtsKey);
        
        if (storedDebts && Array.isArray(storedDebts)) {
            debts = storedDebts;
        } else {
            debts = [];
        }
    } catch (error) {
        logSecurityEvent('error', 'Failed to load debts from storage', { error: error.message });
        debts = [];
    }
}

// ============================================
// Event Listeners
// ============================================

/**
 * Set up event listeners
 */
function setupEventListeners() {
    // Main application form submission
    if (debtForm) {
        debtForm.addEventListener('submit', handleFormSubmit);
    }
    
    // Cancel button
    if (cancelBtn) {
        cancelBtn.addEventListener('click', () => {
            resetForm();
        });
    }
    
    // Authentication event listeners
    setupAuthEventListeners();
}

/**
 * Set up authentication-related event listeners
 */
function setupAuthEventListeners() {
    // Login form submission
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }
    
    // Register form submission
    if (registerForm) {
        registerForm.addEventListener('submit', handleRegister);
    }
    
    // Show register form
    if (showRegisterLink) {
        showRegisterLink.addEventListener('click', (e) => {
            e.preventDefault();
            showRegisterForm();
        });
    }
    
    // Show login form
    if (showLoginLink) {
        showLoginLink.addEventListener('click', (e) => {
            e.preventDefault();
            showLoginForm();
        });
    }
    
    // Logout button
    if (logoutBtn) {
        logoutBtn.addEventListener('click', handleLogout);
    }
    
    // Password strength indicator
    if (registerPasswordInput) {
        registerPasswordInput.addEventListener('input', updatePasswordStrength);
    }
    
    // Password confirmation validation
    if (confirmPasswordInput && registerPasswordInput) {
        confirmPasswordInput.addEventListener('input', validatePasswordMatch);
    }
    
    // Audit log viewer
    if (showAuditLogLink) {
        showAuditLogLink.addEventListener('click', (e) => {
            e.preventDefault();
            showAuditLog();
        });
    }
    
    // Security tests viewer (handled by security-tests.js, but ensure it's available)
    const showSecurityTestsLink = document.getElementById('show-security-tests');
    if (showSecurityTestsLink && typeof showSecurityTests !== 'undefined') {
        showSecurityTestsLink.addEventListener('click', (e) => {
            e.preventDefault();
            showSecurityTests();
        });
    }
    
    // Close audit modal
    if (closeAuditModal) {
        closeAuditModal.addEventListener('click', () => {
            auditModal.style.display = 'none';
        });
    }
    
    // Close modal on outside click
    if (auditModal) {
        auditModal.addEventListener('click', (e) => {
            if (e.target === auditModal) {
                auditModal.style.display = 'none';
            }
        });
    }
    
    // File upload form submission
    if (fileUploadForm) {
        fileUploadForm.addEventListener('submit', function(event) {
            console.log('🔄 [File Upload] Form submit triggered, validating...');
            handleFileUpload(event);
        });
    }
    
    // File input change event for immediate validation
    if (fileInput) {
        fileInput.addEventListener('change', function(event) {
            console.log('📎 [File Upload] File selected, starting validation...');
            validateFileOnSelect(event);
        });
        
        // Also add input event for better compatibility
        fileInput.addEventListener('input', function(event) {
            console.log('📎 [File Upload] File input changed...');
            validateFileOnSelect(event);
        });
    }
}

// ============================================
// Authentication UI Functions
// ============================================

/**
 * Show authentication container (login/register)
 */
function showAuthContainer() {
    authContainer.style.display = 'flex';
    appContainer.style.display = 'none';
    showLoginForm();
}

/**
 * Show application container (main app)
 */
function showAppContainer() {
    authContainer.style.display = 'none';
    appContainer.style.display = 'block';
    
    const username = getCurrentUser();
    if (usernameDisplay && username) {
        usernameDisplay.textContent = `Logged in as: ${sanitizeInput(username)}`;
    }
}

/**
 * Show login form
 */
function showLoginForm() {
    loginSection.style.display = 'block';
    registerSection.style.display = 'none';
    clearAuthErrors();
}

/**
 * Show register form
 */
function showRegisterForm() {
    loginSection.style.display = 'none';
    registerSection.style.display = 'block';
    clearAuthErrors();
}

/**
 * Clear authentication error messages
 */
function clearAuthErrors() {
    if (loginError) loginError.style.display = 'none';
    if (registerError) registerError.style.display = 'none';
}

/**
 * Handle login form submission
 */
function handleLogin(e) {
    e.preventDefault();
    clearAuthErrors();
    
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;
    
    const result = loginUser(username, password);
    
    if (result.success) {
        // Load user's debts
        loadDebtsFromStorage();
        
        // Render application
        renderDebts();
        renderSummary();
        
        // Show application
        showAppContainer();
        
        // Clear form
        loginForm.reset();
    } else {
        // Show error message
        if (loginError) {
            loginError.textContent = result.message;
            loginError.style.display = 'block';
        }
    }
}

/**
 * Handle registration form submission
 */
function handleRegister(e) {
    e.preventDefault();
    clearAuthErrors();
    
    const username = document.getElementById('register-username').value;
    const password = document.getElementById('register-password').value;
    const confirmPassword = document.getElementById('confirm-password').value;
    
    // Validate password match
    if (password !== confirmPassword) {
        if (registerError) {
            registerError.textContent = 'Passwords do not match';
            registerError.style.display = 'block';
        }
        return;
    }
    
    const result = registerUser(username, password);
    
    if (result.success) {
        // Auto-login after registration
        const loginResult = loginUser(username, password);
        if (loginResult.success) {
            // Initialize empty debts for new user
            debts = [];
            saveDebtsToStorage();
            
            // Render application
            renderDebts();
            renderSummary();
            
            // Show application
            showAppContainer();
            
            // Clear form
            registerForm.reset();
            updatePasswordStrength(); // Reset strength indicator
        }
    } else {
        // Show error message
        if (registerError) {
            registerError.textContent = result.message;
            registerError.style.display = 'block';
        }
    }
}

/**
 * Handle logout
 */
function handleLogout() {
    if (confirm('Are you sure you want to logout?')) {
        logoutUser();
        debts = [];
        showAuthContainer();
        resetForm();
    }
}

/**
 * Update password strength indicator
 */
function updatePasswordStrength() {
    const password = registerPasswordInput.value;
    const validation = validatePasswordStrength(password);
    
    // Update strength bar
    passwordStrengthBar.className = 'strength-bar';
    if (password.length > 0) {
        passwordStrengthBar.classList.add(validation.strength);
    }
    
    // Update strength text
    const strengthMessages = {
        weak: 'Weak Password',
        medium: 'Medium Strength',
        strong: 'Strong Password'
    };
    passwordStrengthText.textContent = password.length > 0 ? strengthMessages[validation.strength] : '';
    passwordStrengthText.className = 'strength-text ' + (password.length > 0 ? validation.strength : '');
    
    // Update requirements checklist
    const requirements = [
        { check: validation.checks.length, text: 'At least 8 characters' },
        { check: validation.checks.uppercase, text: 'One uppercase letter' },
        { check: validation.checks.lowercase, text: 'One lowercase letter' },
        { check: validation.checks.number, text: 'One number' },
        { check: validation.checks.specialChar, text: 'One special character' }
    ];
    
    passwordStrengthRequirements.innerHTML = '';
    requirements.forEach(req => {
        const li = document.createElement('li');
        li.textContent = req.text;
        if (req.check) {
            li.classList.add('valid');
        }
        passwordStrengthRequirements.appendChild(li);
    });
    
    // Enable/disable register button
    if (registerBtn) {
        registerBtn.disabled = !validation.isValid;
    }
}

/**
 * Validate password match
 */
function validatePasswordMatch() {
    const password = registerPasswordInput.value;
    const confirmPassword = confirmPasswordInput.value;
    
    if (confirmPassword.length > 0 && password !== confirmPassword) {
        confirmPasswordInput.setCustomValidity('Passwords do not match');
    } else {
        confirmPasswordInput.setCustomValidity('');
    }
}

/**
 * Show audit log modal
 */
function showAuditLog() {
    const auditLog = getAuditLog(200);
    
    if (!auditLogContent) return;
    
    auditLogContent.innerHTML = '';
    
    if (auditLog.length === 0) {
        auditLogContent.innerHTML = '<p class="empty-state">No audit log entries found.</p>';
    } else {
        auditLog.forEach(entry => {
            const logItem = document.createElement('div');
            logItem.className = `audit-log-item ${entry.level}`;
            
            const timestamp = document.createElement('div');
            timestamp.className = 'audit-log-timestamp';
            timestamp.textContent = new Date(entry.timestamp).toLocaleString();
            
            const message = document.createElement('div');
            message.className = 'audit-log-message';
            message.textContent = entry.message;
            
            const details = document.createElement('div');
            details.className = 'audit-log-details';
            details.textContent = `User: ${entry.user} | Level: ${entry.level}`;
            
            logItem.appendChild(timestamp);
            logItem.appendChild(message);
            logItem.appendChild(details);
            
            auditLogContent.appendChild(logItem);
        });
    }
    
    auditModal.style.display = 'flex';
}

// ============================================
// Initialization
// ============================================

/**
 * Initialize the application
 */
function init() {
    console.log('Debt Payoff Planner initialized');
    
    // Check authentication status
    if (isSessionValid()) {
        // User is authenticated, show application
        const username = getCurrentUser();
        if (username) {
            // Load user's debts
            loadDebtsFromStorage();
            
            // Set up event listeners
            setupEventListeners();
            
            // Initial render
            resetForm();
            renderDebts();
            renderSummary();
            
            // Show application
            showAppContainer();
        } else {
            showAuthContainer();
        }
    } else {
        // User is not authenticated, show login
        showAuthContainer();
        setupAuthEventListeners();
    }
}

// Initialize app when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init(); // DOM is already ready
}
