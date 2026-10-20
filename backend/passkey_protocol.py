"""WebAuthn protocol foundation; not an authentication route or vault unlock.

Callers must own the challenge lifecycle and credential-to-user lookup. No
client-supplied expected challenge, key, origin or counter may be trusted.
"""
import base64
import ipaddress
import json
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from webauthn import (generate_registration_options, generate_authentication_options,
                      verify_registration_response, verify_authentication_response, options_to_json)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (AuthenticatorSelectionCriteria, ResidentKeyRequirement,
                                    UserVerificationRequirement, PublicKeyCredentialDescriptor)


ALGORITHMS=[COSEAlgorithmIdentifier.ECDSA_SHA_256,COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256]


class PasskeyError(ValueError):
    pass


def decode(value, maximum=65536):
    if not isinstance(value,str) or not value or len(value)>maximum*2 or not re.fullmatch(r'[A-Za-z0-9_-]+',value):
        raise PasskeyError('Invalid passkey response.')
    try:raw=base64.urlsafe_b64decode(value+'='*((-len(value))%4))
    except ValueError:raise PasskeyError('Invalid passkey response.') from None
    if len(raw)>maximum or base64.urlsafe_b64encode(raw).decode().rstrip('=')!=value:
        raise PasskeyError('Invalid passkey response.')
    return raw


def top_level(credential):
    # The library checks challenge/type/origin/RP hash/signature/UP/UV. Our
    # product additionally refuses framed/related-origin ceremonies entirely.
    try:
        if not isinstance(credential,dict) or len(json.dumps(credential))>100000:
            raise ValueError()
        client=json.loads(decode(credential['response']['clientDataJSON'],4096))
        if not isinstance(client,dict) or client.get('crossOrigin',False) is not False or 'topOrigin' in client:
            raise ValueError()
        decode(credential['id'],1024)
    except (KeyError,ValueError,TypeError):
        raise PasskeyError('Invalid passkey response.') from None


@dataclass(frozen=True)
class RelyingParty:
    origin: str
    rp_id: str

    @classmethod
    def from_origin(cls,origin):
        try:
            p=urlsplit(origin)
            host=p.hostname or ''
            if not host or p.username or p.password or p.path or p.query or p.fragment or p.port==0:
                raise ValueError()
            if p.scheme!='https' and not (p.scheme=='http' and host=='localhost'):
                raise ValueError()
            if not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',host) or len(host)>253:
                raise ValueError()
            try:ipaddress.ip_address(host)
            except ValueError:pass
            else:raise ValueError()
            port='' if p.port is None or p.port==(443 if p.scheme=='https' else 80) else ':'+str(p.port)
            if origin!=p.scheme+'://'+host+port:raise ValueError()
        except (ValueError,TypeError,AttributeError):
            raise PasskeyError('Passkeys require a canonical HTTPS domain origin, or http://localhost with its configured port.') from None
        return cls(origin,host)

    def registration_options(self,user_id,email,credential_ids=()):
        if not isinstance(user_id,bytes) or not 1<=len(user_id)<=64 or len(credential_ids)>10:
            raise PasskeyError('Invalid account credential scope.')
        return json.loads(options_to_json(generate_registration_options(
            rp_id=self.rp_id,rp_name='SentinelOps',user_id=user_id,user_name=email,timeout=120000,
            supported_pub_key_algs=ALGORITHMS,
            authenticator_selection=AuthenticatorSelectionCriteria(resident_key=ResidentKeyRequirement.REQUIRED,user_verification=UserVerificationRequirement.REQUIRED),
            exclude_credentials=[PublicKeyCredentialDescriptor(id=value) for value in credential_ids])))

    def authentication_options(self,credential_ids):
        if not 1<=len(credential_ids)<=10:raise PasskeyError('Invalid account credential scope.')
        return json.loads(options_to_json(generate_authentication_options(
            rp_id=self.rp_id,timeout=120000,user_verification=UserVerificationRequirement.REQUIRED,
            allow_credentials=[PublicKeyCredentialDescriptor(id=value) for value in credential_ids])))

    def register(self,credential,challenge):
        top_level(credential)
        if not isinstance(challenge,bytes) or len(challenge)<32:raise PasskeyError('Invalid server challenge.')
        try:
            return verify_registration_response(credential=credential,expected_challenge=challenge,
                expected_origin=self.origin,expected_rp_id=self.rp_id,require_user_presence=True,
                require_user_verification=True,supported_pub_key_algs=ALGORITHMS)
        except (ValueError,TypeError,KeyError,WebAuthnException):
            raise PasskeyError('Passkey registration could not be verified.') from None

    def authenticate(self,credential,challenge,credential_id,public_key,sign_count,user_id):
        top_level(credential)
        if not isinstance(challenge,bytes) or len(challenge)<32:raise PasskeyError('Invalid server challenge.')
        try:
            if decode(credential['id'],1024)!=credential_id:raise ValueError()
            handle=credential['response'].get('userHandle')
            if handle is not None and decode(handle,64)!=user_id:raise ValueError()
            return verify_authentication_response(credential=credential,expected_challenge=challenge,
                expected_origin=self.origin,expected_rp_id=self.rp_id,credential_public_key=public_key,
                credential_current_sign_count=sign_count,require_user_verification=True)
        except (ValueError,TypeError,KeyError,WebAuthnException):
            raise PasskeyError('Passkey sign-in could not be verified.') from None
