// Notifications JavaScript

// Notification center
function initNotificationCenter() {
    document.querySelectorAll('.notification-item form').forEach(form => {
        form.addEventListener('submit', e => {
            e.preventDefault();
            const btn = form.querySelector('button');
            showLoading(btn);
            makeAjaxRequest(form.action, {method: 'POST', body: new FormData(form)})
                .then(() => {
                    form.closest('.notification-item').classList.remove('unread');
                    form.remove();
                })
                .catch(err => { hideLoading(btn); handleErrors(err); });
        });
    });
}

// Real-time notifications
function setupRealTimeNotifications() {
    const notiCount = document.getElementById('notificationCount');
    if (!notiCount) return;
    setInterval(() => {
        fetch('/core/notifications/?ajax=1')
            .then(r => r.json())
            .then(data => { notiCount.textContent = data.unread; });
    }, 30000);
}

// Device notifications
function handleDeviceNotifications() {}

// Notification actions
function handleNotificationActions() {}

// Mark notifications as read
function markAsRead() {}

// Notification preferences
function manageNotificationPreferences() {}

// Initialize notifications
document.addEventListener('DOMContentLoaded', function() {
    initNotificationCenter();
    setupRealTimeNotifications();
});
