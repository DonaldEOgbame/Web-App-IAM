# WebAppIAM

## Local Development

Run the server on `localhost:8000` and configure WebAuthn and Face API settings:

```bash
export WEBAUTHN_RP_ID=localhost
export WEBAUTHN_EXPECTED_ORIGIN=http://localhost:8000
export FACE_API_ENABLED=True
export AZURE_FACE_API_ENDPOINT=https://<resource>.cognitiveservices.azure.com/
export AZURE_FACE_API_KEY=<your-key>
export AZURE_FACE_PERSON_GROUP_ID=<group-id>
```

Then start Django:

```bash
python manage.py runserver localhost:8000
```

## Production

Set `WEBAUTHN_RP_ID` and `WEBAUTHN_EXPECTED_ORIGIN` to your public domain and
ensure the site is served over HTTPS.
