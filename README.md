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
ensure the site is served over HTTPS. `WEBAUTHN_RP_ID` **must** contain only the
host name (no scheme or port). It also needs to match or be a suffix of the
host serving the page. When developing locally you should use `localhost` and
not `127.0.0.1`, otherwise WebAuthn will fail with an "invalid domain"
message.
