// Dashboard functionality
function initDashboard() {
    const toggle = document.getElementById('sidebarToggle');
    const sidebar = document.getElementById('sidebar');
    if (toggle && sidebar) {
        toggle.addEventListener('click', function() {
            sidebar.classList.toggle('open');
        });
    }
}

document.addEventListener('DOMContentLoaded', initDashboard);

