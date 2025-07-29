# WebAppIAM

## Local Development

Run the server on `localhost:8000` and configure WebAuthn and Face API settings.
If you choose a different port, update `WEBAUTHN_EXPECTED_ORIGIN` accordingly so
the origin matches the server. For example when running on port `8001`:

```bash
export WEBAUTHN_EXPECTED_ORIGIN=http://localhost:8001
```
And for the default `localhost:8000` setup:

```bash
export WEBAUTHN_RP_ID=localhost
export WEBAUTHN_EXPECTED_ORIGIN=http://localhost:8000
export FACE_API_ENABLED=True
export FACE_ENROLL_DIR=/path/to/enrolled_faces
# Optional DeepFace tuning
export DEEPFACE_MODEL_NAME=ArcFace
export DEEPFACE_DISTANCE_METRIC=cosine
export DEEPFACE_DETECTOR_BACKEND=retinaface
```

Then start Django:

```bash
python manage.py runserver localhost:8000
```

## Production

Set `WEBAUTHN_RP_ID` and `WEBAUTHN_EXPECTED_ORIGIN` to your public domain and
ensure the site is served over HTTPS. `WEBAUTHN_RP_ID` **must** contain only the
host name (no scheme or port). It also needs to match or be a suffix of the
host serving the page. When developing locally you should use `localhost` and
not `127.0.0.1`, otherwise WebAuthn will fail with an "invalid domain"
message.
