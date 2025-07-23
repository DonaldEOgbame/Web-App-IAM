// Common utility functions used across the application

// CSRF token handling
function getCSRFToken() {
    const match = document.cookie.match(/csrftoken=([^;]+)/);
    return match ? match[1] : '';
}

// AJAX helpers
function makeAjaxRequest(url, options = {}) {
    options.headers = Object.assign({
        'X-CSRFToken': getCSRFToken(),
        'X-Requested-With': 'XMLHttpRequest'
    }, options.headers || {});
    return fetch(url, options).then(response => {
        if (!response.ok) throw new Error('Request failed');
        const ct = response.headers.get('Content-Type');
        return ct && ct.includes('application/json') ? response.json() : response.text();
    });
}

// Form validation utilities
function validateForm(form) {
    if (!form.checkValidity()) {
        form.reportValidity();
        return false;
    }
    return true;
}

// Date/time formatting
function formatDateTime(dateStr) {
    const date = new Date(dateStr);
    return date.toLocaleString();
}

// Local storage helpers
const manageLocalStorage = {
    set(key, value) { localStorage.setItem(key, JSON.stringify(value)); },
    get(key, def = null) { const v = localStorage.getItem(key); return v ? JSON.parse(v) : def; },
    remove(key) { localStorage.removeItem(key); }
};

// Error handling
function handleErrors(err) {
    console.error(err);
    showToast('An error occurred', 'error');
}

// Loading indicators
function showLoading(el) {
    if (!el) return;
    el.dataset.originalText = el.innerHTML;
    el.innerHTML = '...';
    el.disabled = true;
}

// Toast notifications
function hideLoading(el) {
    if (!el) return;
    el.innerHTML = el.dataset.originalText || el.innerHTML;
    el.disabled = false;
}

function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 3000);
}
