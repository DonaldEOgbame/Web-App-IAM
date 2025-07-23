// Shared authentication logic for NeumorphicAuth
const keystrokeEvents = [];
let lastKeyTime = null;

function recordKeystroke(event) {
    const now = Date.now();
    if (lastKeyTime === null) lastKeyTime = now;
    keystrokeEvents.push({key: event.key, type: event.type, time: now, delta: now - lastKeyTime});
    lastKeyTime = now;
}

function attachKeystrokeListeners(form) {
    const username = form.querySelector('input[name="username"], input[name="email"]');
    const password = form.querySelector('input[type="password"]');
    if (username) {
        username.addEventListener('keydown', recordKeystroke);
        username.addEventListener('keyup', recordKeystroke);
    }
    if (password) {
        password.addEventListener('keydown', recordKeystroke);
        password.addEventListener('keyup', recordKeystroke);
    }
    form.addEventListener('submit', () => {
        const input = document.createElement('input');
        input.type = 'hidden';
        input.name = 'keystroke_data';
        input.value = JSON.stringify(keystrokeEvents);
        form.appendChild(input);
    });
}

function validatePasswords(form) {
    const p1 = form.querySelector('input[name="password1"]');
    const p2 = form.querySelector('input[name="password2"]');
    if (!p1 || !p2) return;
    function check() {
        if (p1.value !== p2.value) {
            p2.setCustomValidity('Passwords do not match');
        } else {
            p2.setCustomValidity('');
        }
    }
    p1.addEventListener('input', check);
    p2.addEventListener('input', check);
}

function checkAvailability(input, url) {
    input.addEventListener('blur', () => {
        fetch(url + '?value=' + encodeURIComponent(input.value))
            .then(r => r.json())
            .then(data => {
                if (!data.available) {
                    input.setCustomValidity('Not available');
                } else {
                    input.setCustomValidity('');
                }
            })
            .catch(() => {});
    });
}

function initWebAuthn(optionsUrl, verifyUrl) {
    const btn = document.getElementById('webauthnBtn');
    if (!btn || !window.PublicKeyCredential) return;
    btn.addEventListener('click', () => {
        fetch(optionsUrl, {headers: {'X-CSRFToken': getCSRFToken()}})
            .then(r => r.json())
            .then(async options => {
                options.challenge = Uint8Array.from(atob(options.challenge), c => c.charCodeAt(0));
                options.user.id = Uint8Array.from(atob(options.user.id), c => c.charCodeAt(0));
                const cred = await navigator.credentials.create({publicKey: options});
                const data = {
                    id: cred.id,
                    rawId: btoa(String.fromCharCode.apply(null, new Uint8Array(cred.rawId))),
                    type: cred.type,
                    response: {
                        clientDataJSON: btoa(String.fromCharCode.apply(null, new Uint8Array(cred.response.clientDataJSON))),
                        attestationObject: btoa(String.fromCharCode.apply(null, new Uint8Array(cred.response.attestationObject)))
                    }
                };
                return fetch(verifyUrl, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json', 'X-CSRFToken': getCSRFToken()},
                    body: JSON.stringify(data)
                });
            })
            .then(r => r.json())
            .then(res => {
                if (res.status === 'success' && res.redirect) {
                    window.location.href = res.redirect;
                }
            })
            .catch(console.error);
    });
}

function initFaceCapture() {
    const video = document.getElementById('faceVideo');
    const canvas = document.getElementById('faceCanvas');
    const captureBtn = document.getElementById('captureFace');
    const form = document.getElementById('faceForm');
    if (!video || !canvas || !captureBtn) return;
    navigator.mediaDevices.getUserMedia({video: true}).then(stream => {
        video.srcObject = stream;
    });
    captureBtn.addEventListener('click', () => {
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        canvas.getContext('2d').drawImage(video, 0, 0);
        canvas.toBlob(blob => {
            const file = new File([blob], 'face.png', {type: 'image/png'});
            const data = new FormData(form);
            data.set('face_data', file);
            fetch(form.action, {method: 'POST', headers: {'X-CSRFToken': getCSRFToken()}, body: data})
                .then(r => r.json())
                .then(res => { if(res.status === 'success' && res.redirect){ window.location.href = res.redirect; }});
        });
    });
}

function getCSRFToken() {
    const cookieValue = document.cookie.split('; ').find(row => row.startsWith('csrftoken='));
    return cookieValue ? cookieValue.split('=')[1] : '';
}

document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('form[data-auth]').forEach(form => {
        attachKeystrokeListeners(form);
        validatePasswords(form);
    });
    const username = document.querySelector('#id_username');
    if (username) checkAvailability(username, '/api/validate-username/');
    const email = document.querySelector('#id_email');
    if (email) checkAvailability(email, '/api/validate-email/');
    initWebAuthn('/register/webauthn/options/', '/register/webauthn/verify/');
    initFaceCapture();
});
