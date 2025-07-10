// Show loading spinner on form submit or AJAX
function showLoadingSpinner() {
    let spinner = document.createElement('div');
    spinner.className = 'loading-spinner';
    spinner.id = 'global-loading-spinner';
    document.body.appendChild(spinner);
}
function hideLoadingSpinner() {
    let spinner = document.getElementById('global-loading-spinner');
    if (spinner) spinner.remove();
}
document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', function(e) {
            showLoadingSpinner();
        });
    });
});

// Responsive table: stack columns on mobile
document.addEventListener('DOMContentLoaded', function() {
  if (window.innerWidth < 600) {
    document.querySelectorAll('.modern-table').forEach(table => {
      table.classList.add('responsive-stack');
    });
  }
});

// Modern JS for biometric and adaptive authentication flows
// Smooth UI, modals, and feedback

// Profile/Settings: Show risk color on indicators
document.addEventListener('DOMContentLoaded', function() {
  document.querySelectorAll('.risk-indicator').forEach(function(el) {
    const level = el.textContent.trim().toUpperCase();
    el.classList.remove('risk-low', 'risk-medium', 'risk-high');
    if (level.startsWith('LOW')) el.classList.add('risk-low');
    else if (level.startsWith('MEDIUM')) el.classList.add('risk-medium');
    else if (level.startsWith('HIGH')) el.classList.add('risk-high');
  });
});

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

// --- Notification Center Enhancements ---
document.addEventListener('DOMContentLoaded', function() {
  // Scroll to first unread notification
  const firstUnread = document.querySelector('.notification-item.unread');
  if (firstUnread) {
    firstUnread.scrollIntoView({ behavior: 'smooth', block: 'center' });
    firstUnread.classList.add('highlight-unread');
    setTimeout(() => firstUnread.classList.remove('highlight-unread'), 2000);
  }

  // Animate mark-as-read
  document.querySelectorAll('.notification-item form').forEach(form => {
    form.addEventListener('submit', function(e) {
      const notifItem = form.closest('.notification-item');
      if (notifItem) {
        notifItem.classList.add('notification-fade-out');
        setTimeout(() => {
          notifItem.classList.remove('notification-fade-out');
          notifItem.classList.remove('unread');
          showToast('Notification marked as read', 'success');
        }, 600);
      }
    });
  });
});

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

// --- Drag & Drop Upload Logic ---
document.addEventListener('DOMContentLoaded', function() {
  const dndZone = document.querySelector('.dnd-upload-zone');
  if (dndZone) {
    const fileInput = document.getElementById('dnd-file-input');
    const preview = document.querySelector('.dnd-upload-preview');
    const progressBar = document.querySelector('.dnd-upload-progress-bar');
    dndZone.addEventListener('dragover', function(e) {
      e.preventDefault();
      dndZone.classList.add('dragover');
    });
    dndZone.addEventListener('dragleave', function(e) {
      dndZone.classList.remove('dragover');
    });
    dndZone.addEventListener('drop', function(e) {
      e.preventDefault();
      dndZone.classList.remove('dragover');
      if (e.dataTransfer.files.length > 0) {
        fileInput.files = e.dataTransfer.files;
        showFilePreview(fileInput.files, preview);
      }
    });
    dndZone.addEventListener('click', function() {
      fileInput.click();
    });
    fileInput.addEventListener('change', function() {
      showFilePreview(fileInput.files, preview);
    });
    function showFilePreview(files, preview) {
      preview.innerHTML = '';
      Array.from(files).forEach(file => {
        const item = document.createElement('div');
        item.className = 'file-item';
        item.innerHTML = `<span>📄</span> ${file.name} <span style="font-size:0.9em;color:#888;">(${(file.size/1024).toFixed(1)} KB)</span>`;
        preview.appendChild(item);
      });
    }
  }
});

// --- Watermark PDF (client-side preview only, not for download) ---
// For real watermarking, use server-side PDF processing (e.g., PyPDF2/reportlab)
