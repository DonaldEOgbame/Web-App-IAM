

// Modern JS for biometric and adaptive authentication flows
// Smooth UI, modals, and feedback

function showRiskIndicator(level) {
    const indicator = document.getElementById('risk-indicator');
    if (!indicator) return;
    indicator.className = 'risk-indicator';
    if (level === 'LOW') indicator.classList.add('risk-low');
    else if (level === 'MEDIUM') indicator.classList.add('risk-medium');
    else if (level === 'HIGH') indicator.classList.add('risk-high');
}

// Show toast notifications (with animation, global container)
function showToast(message, type = 'info') {
    let container = document.getElementById('global-toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'global-toast-container';
        document.body.appendChild(container);
    }
    let toast = document.createElement('div');
    toast.className = 'toast toast-' + type;
    toast.innerText = message;
    container.appendChild(toast);
    setTimeout(() => { toast.classList.add('show'); }, 100);
    setTimeout(() => { toast.classList.remove('show'); toast.remove(); }, 4000);
}

// Modal dialog (glassmorphic)
function showModal(title, content) {
    let modal = document.createElement('div');
    modal.className = 'modal-overlay';
    modal.innerHTML = `<div class="modal glass" style="padding:2em 2.5em;max-width:420px;margin:10vh auto;">
        <h2 style="margin-bottom:1em;">${title}</h2>
        <div style="margin-bottom:1.5em;">${content}</div>
        <button class="btn" onclick="this.closest('.modal-overlay').remove()">Close</button>
    </div>`;
    document.body.appendChild(modal);
}

// Example: biometric feedback
function showBiometricFeedback(success, msg) {
    if (success) {
        showToast(msg || 'Biometric authentication successful!', 'success');
    } else {
        showToast(msg || 'Biometric authentication failed.', 'danger');
    }
}

// Micro-interaction: Animate cards on hover
document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('.card').forEach(card => {
        card.addEventListener('mouseenter', () => card.classList.add('hovered'));
        card.addEventListener('mouseleave', () => card.classList.remove('hovered'));
    });
});

// Add more JS as needed for biometric capture, WebAuthn, etc.
