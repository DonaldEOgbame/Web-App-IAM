// Authentication JavaScript - Login, Register, Biometric authentication

// Face recognition functionality
function initFaceCapture() {
    // Face capture initialization will be added here
}

// WebAuthn functionality
function initWebAuthn() {
    // WebAuthn initialization will be added here
}

// Login form handling
function handleLogin() {
    const form = document.querySelector('form[action*="login"]');
    if (form) {
        form.addEventListener('submit', function(e) {
            sendKeystrokeData(form);
        });
    }
}

// Registration form handling
function handleRegistration() {
    // Registration form submission will be added here
}

// Biometric enrollment
function enrollBiometrics() {
    // Biometric enrollment functionality will be added here
}

// Password strength validation
function validatePassword() {
    // Password validation will be added here
}

// Keystroke Dynamics Capture for Login
let keystrokeEvents = [];
let lastKeyTime = null;

function captureKeystroke(event) {
    const now = Date.now();
    if (lastKeyTime === null) lastKeyTime = now;
    keystrokeEvents.push({
        key: event.key,
        type: event.type,
        time: now,
        delta: now - lastKeyTime
    });
    lastKeyTime = now;
}

function attachKeystrokeListeners() {
    const username = document.getElementById('username');
    const password = document.getElementById('password');
    if (username) {
        username.addEventListener('keydown', captureKeystroke);
        username.addEventListener('keyup', captureKeystroke);
    }
    if (password) {
        password.addEventListener('keydown', captureKeystroke);
        password.addEventListener('keyup', captureKeystroke);
    }
}

function sendKeystrokeData(form) {
    const input = document.createElement('input');
    input.type = 'hidden';
    input.name = 'keystroke_data';
    input.value = JSON.stringify(keystrokeEvents);
    form.appendChild(input);
}

// Initialize authentication
document.addEventListener('DOMContentLoaded', function() {
    initWebAuthn();
    attachKeystrokeListeners();
    handleLogin();
});
