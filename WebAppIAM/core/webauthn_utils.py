import json
import base64
# Import WebAuthn library functions under distinct names to avoid
# colliding with the wrapper helpers defined in this module. Without
# aliasing, calls inside the wrappers would recursively invoke the
# wrappers themselves leading to unexpected errors.
from webauthn import (
    generate_registration_options as wa_generate_registration_options,
    verify_registration_response as wa_verify_registration_response,
    generate_authentication_options as wa_generate_authentication_options,
    verify_authentication_response as wa_verify_authentication_response,
    options_to_json,
)
from webauthn.helpers import (
    bytes_to_base64url,
    base64url_to_bytes,
    parse_authentication_credential_json,
    parse_registration_credential_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    RegistrationCredential,
    AuthenticationCredential,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialType,
    AuthenticatorTransport,
)
from django.conf import settings

def generate_registration_options(user):
    """Generate WebAuthn registration options for a user"""
    return wa_generate_registration_options(
        rp_id=settings.WEBAUTHN_RP_ID,
        rp_name=settings.WEBAUTHN_RP_NAME,
        # The WebAuthn library expects the user identifier as bytes.
        # Convert the database ID to a UTF-8 encoded byte string.
        user_id=str(user.id).encode(),
        user_name=user.username,
        user_display_name=user.get_full_name() or user.username,
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.PREFERRED
        ),
    )

def verify_registration_response(user, data, expected_challenge):
    """Verify WebAuthn registration response"""
    credential = parse_registration_credential_json(json.dumps(data))

    verification = wa_verify_registration_response(
        credential=RegistrationCredential(
            id=credential.id,
            raw_id=credential.raw_id,
            response=credential.response,
            type=credential.type,
            client_extension_results=credential.client_extension_results,
            transports=credential.transports,
        ),
        expected_challenge=expected_challenge,
        expected_rp_id=settings.WEBAUTHN_RP_ID,
        expected_origin=settings.WEBAUTHN_EXPECTED_ORIGIN,
    )
    
    return verification.credential

def generate_authentication_options(user):
    """Generate WebAuthn authentication options for a user"""
    allow_credentials = [
        PublicKeyCredentialDescriptor(
            id=base64url_to_bytes(cred.credential_id),
            type=PublicKeyCredentialType.PUBLIC_KEY,
            transports=[AuthenticatorTransport.INTERNAL],
        )
        for cred in user.webauthn_credentials.all()
    ]

    return wa_generate_authentication_options(
        rp_id=settings.WEBAUTHN_RP_ID,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.PREFERRED,
    )

def verify_authentication_response(user, data, expected_challenge):
    """Verify WebAuthn authentication response"""
    credential = parse_authentication_credential_json(json.dumps(data))
    
    # Get the stored credential
    stored_credential = user.webauthn_credentials.get(credential_id=credential.id)
    
    verification = wa_verify_authentication_response(
        credential=AuthenticationCredential(
            id=credential.id,
            raw_id=credential.raw_id,
            response=credential.response,
            type=credential.type,
            client_extension_results=credential.client_extension_results,
        ),
        expected_challenge=expected_challenge,
        expected_rp_id=settings.WEBAUTHN_RP_ID,
        expected_origin=settings.WEBAUTHN_EXPECTED_ORIGIN,
        credential_public_key=base64url_to_bytes(stored_credential.public_key),
        credential_current_sign_count=stored_credential.sign_count,
        require_user_verification=True,
    )
    
    return stored_credential
