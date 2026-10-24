"""Real protocol crypto through two registered accounts; not browser acceptance."""
import base64
import hashlib
import json
import os

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from fastapi.testclient import TestClient

from backend.store import Store, canonical, uid
from test_platform import system, invited, post
from test_shared_companions import pair
from test_sharing import sign


def b64(value):
    return base64.b64encode(value).decode()


def identity(client):
    user = client.get('/api/me').json()['id']
    encryption = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    signing = ec.generate_private_key(ec.SECP256R1())
    public = {name: b64(key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
              for name, key in [('encryption', encryption), ('signing', signing)]}
    private = {name: b64(key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
               for name, key in [('encryption', encryption), ('signing', signing)]}
    salt, iv = os.urandom(16), os.urandom(12)
    wrapping = Argon2id(salt=salt, length=32, iterations=3, lanes=1, memory_cost=65536).derive(b'Public-test-sharing-passphrase-only-2026!')
    encrypted = {'version': 1, 'salt': b64(salt), 'iv': b64(iv), 'ciphertext': b64(AESGCM(wrapping).encrypt(iv, canonical(private).encode(), ('SentinelOps sharing identity v1:' + user).encode()))}
    response = post(client, '/sharing/identity', {'public': public, 'encrypted': encrypted})
    assert response.status_code == 200, response.text
    return {'id': user, 'public': public, 'fingerprint': hashlib.sha256(canonical(public).encode()).hexdigest(), 'private': signing, 'encryption': encryption}


def grant(sender, recipient, vault, key, role, epoch):
    document = {'version': 1, 'vault_id': vault, 'recipient': recipient['id'], 'issuer': sender['id'], 'epoch': epoch,
                'role': role, 'recipient_fingerprint': recipient['fingerprint'], 'issuer_fingerprint': sender['fingerprint']}
    label = f"SentinelOps team grant v1:{vault}:{epoch}:{recipient['id']}".encode()
    document['wrapped_key'] = b64(recipient['encryption'].public_key().encrypt(key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=label)))
    return {**document, 'signature': sign(sender, document)}


def seal(vault, epoch, key, entries):
    iv = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(iv, canonical({'entries': entries}).encode(), f'SentinelOps team vault v1:{vault}:{epoch}'.encode())
    return {'version': 1, 'context': vault, 'epoch': epoch, 'iv': b64(iv), 'ciphertext': b64(ciphertext)}


def open_payload(payload, key, epoch=None):
    aad = f"SentinelOps team vault v1:{payload['context']}:{epoch or payload['epoch']}".encode()
    return json.loads(AESGCM(key).decrypt(base64.b64decode(payload['iv']), base64.b64decode(payload['ciphertext']), aad))['entries']


def test_removed_account_and_cached_key_cannot_read_next_epoch(system):
    app, client, _ = system
    other = invited(app, client)
    try:
        owner, member = identity(client), identity(other)
        vault, key = uid(), os.urandom(32)
        workspace = client.get('/api/me').json()['workspace']
        manifest = {'id': vault, 'workspace': workspace, 'owner': owner['id'], 'owner_fingerprint': owner['fingerprint']}
        entries = [{'id': 'public-fixture', 'type': 'login', 'title': 'Disposable client', 'origin': 'https://example.test', 'username': 'fixture-only', 'password': 'public-fixture-before-removal-only'}]
        created = post(client, '/team-vaults', {'id': vault, 'name': 'Offboarding crypto fixture', 'manifest_signature': sign(owner, manifest),
                       'grant': grant(owner, owner, vault, key, 'owner', 1), 'payload': seal(vault, 1, key, entries)})
        assert created.status_code == 200, created.text
        assert post(client, f'/team-vaults/{vault}/invite', grant(owner, member, vault, key, 'editor', 1)).status_code == 200
        assert post(other, f'/team-vaults/{vault}/accept', {}).status_code == 200
        cached = other.get(f'/api/team-vaults/{vault}').json()
        label = f"SentinelOps team grant v1:{vault}:1:{member['id']}".encode()
        cached_key = member['encryption'].decrypt(base64.b64decode(cached['grant']['wrapped_key']), padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=label))
        assert open_payload(cached['payload'], cached_key) == entries
        stale_token = pair(other, vault)
        with TestClient(app) as browser:
            assert browser.get('/api/companion/vault', headers=stale_token).status_code == 200
            assert post(client, f'/team-vaults/{vault}/revoke/{member["id"]}', {}).status_code == 200
            assert other.get(f'/api/team-vaults/{vault}').status_code == 404
            assert browser.get('/api/companion/vault', headers=stale_token).status_code == 401
            assert post(client, f'/team-vaults/{vault}/save', {'revision': 1, 'payload': seal(vault, 1, key, entries)}).status_code == 409
            # Cached old data remains readable; offboarding cannot erase copies.
            assert open_payload(cached['payload'], cached_key) == entries
            next_key = os.urandom(32)
            rotated = {'revision': 1, 'payload': seal(vault, 2, next_key, entries), 'grants': [grant(owner, owner, vault, next_key, 'owner', 2)]}
            assert post(client, f'/team-vaults/{vault}/rotate', rotated).status_code == 200
            next_entries = [{**entries[0], 'password': 'public-fixture-after-removal-new-secret'}]
            assert post(client, f'/team-vaults/{vault}/save', {'revision': 2, 'payload': seal(vault, 2, next_key, next_entries)}).status_code == 200
            current = client.get(f'/api/team-vaults/{vault}').json()
            assert open_payload(current['payload'], next_key) == next_entries
            for aad_epoch in [1, 2]:
                with pytest.raises(InvalidTag):
                    open_payload(current['payload'], cached_key, epoch=aad_epoch)
            assert browser.get('/api/companion/vault', headers=stale_token).status_code == 401
        with app.state.store.connect() as c:
            dump = '\n'.join(c.iterdump())
            for secret in [entries[0]['password'], next_entries[0]['password'], b64(key), b64(next_key), b64(cached_key)]:
                assert secret not in dump
            assert Store.audit(c, workspace)['valid']
    finally:
        other.close()
