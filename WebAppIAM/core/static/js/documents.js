// Document Management JavaScript

// File upload progress indicator
function initFileUpload() {
    const uploadForm = document.querySelector('#documentUploadForm');
    if (!uploadForm) return;
    uploadForm.addEventListener('submit', () => {
        const btn = uploadForm.querySelector('button[type="submit"]');
        showLoading(btn);
    });
}

// Document viewer
function initDocumentViewer() {
    const previewLinks = document.querySelectorAll('[data-preview-url]');
    previewLinks.forEach(link => {
        link.addEventListener('click', e => {
            e.preventDefault();
            window.open(link.dataset.previewUrl, '_blank');
        });
    });
}

// Version management
function manageVersions() {
    document.querySelectorAll('.restore-form').forEach(form => {
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

// Document search
function initDocumentSearch() {
    const form = document.querySelector('.version-filters');
    if (!form) return;
    form.addEventListener('change', () => form.submit());
}

// Access control handling
function handleAccessControls() {
    document.querySelectorAll('[data-checksum-url]').forEach(btn => {
        btn.addEventListener('click', () => {
            const url = btn.dataset.checksumUrl;
            showLoading(btn);
            makeAjaxRequest(url, {method: 'POST'})
                .then(res => {
                    hideLoading(btn);
                    if (res.status === 'success') {
                        showToast('Checksum: ' + res.checksum, 'success');
                    }
                }).catch(err => { hideLoading(btn); handleErrors(err); });
        });
    });
}

// Download protection
function secureDownload() {}

// Initialize document management
document.addEventListener('DOMContentLoaded', function() {
    initFileUpload();
    initDocumentSearch();
    manageVersions();
    handleAccessControls();
});
