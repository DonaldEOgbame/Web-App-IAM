// Profile Management JavaScript

// Profile form handling
function initProfileForm() {
    const profileForm = document.querySelector('#profileForm');
    if (!profileForm) return;
    profileForm.addEventListener('submit', () => {
        const btn = profileForm.querySelector('button[type="submit"]');
        showLoading(btn);
    });
}

// Device management
function initDeviceManagement() {
    document.querySelectorAll('.device-actions form').forEach(form => {
        form.addEventListener('submit', e => {
            e.preventDefault();
            const btn = form.querySelector('button');
            showLoading(btn);
            makeAjaxRequest(form.action, {method: 'POST', body: new FormData(form)})
                .then(() => window.location.reload())
                .catch(err => { hideLoading(btn); handleErrors(err); });
        });
    });
}

// Profile picture upload
function handleProfilePictureUpload() {
    const input = document.querySelector('#id_profile_picture');
    const preview = document.querySelector('#picturePreview');
    if (!input || !preview) return;
    input.addEventListener('change', () => {
        const file = input.files[0];
        if (file) preview.src = URL.createObjectURL(file);
    });
}

// Device trust management
function handleDeviceTrust() {}

// Profile preferences
function managePreferences() {}

// Form validation
function validateProfileForm() {}

// Initialize profile management
document.addEventListener('DOMContentLoaded', function() {
    initProfileForm();
    initDeviceManagement();
    handleProfilePictureUpload();
});
