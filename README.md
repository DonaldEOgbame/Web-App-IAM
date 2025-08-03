# WebAppIAM

WebAppIAM is a Django-based identity and access management demo that combines WebAuthn and optional facial verification with a risk engine.

## Requirements

- Python 3.11+
- pip

## Installation

```bash
git clone <repo-url>
cd Web-App-IAM
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt          # core web application
# optional: model training utilities
pip install -r ml_pipeline/requirements.txt
```

## Configuration

Environment variables configure WebAuthn and facial recognition. For a default `localhost:8000` setup:

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

If you choose a different port, update `WEBAUTHN_EXPECTED_ORIGIN` so the origin matches the server.

## Database setup

```bash
python manage.py migrate
python manage.py createsuperuser
```

## Running

```bash
python manage.py runserver localhost:8000
```

## Testing

Run the unit tests with:

```bash
pytest
```

## Production

For production deployments set `WEBAUTHN_RP_ID` and `WEBAUTHN_EXPECTED_ORIGIN` to your public domain and serve the site over HTTPS. `WEBAUTHN_RP_ID` must contain only the host name and match or be a suffix of the host serving the page. When developing locally use `localhost` instead of `127.0.0.1`; otherwise WebAuthn will fail with an "invalid domain" message.
