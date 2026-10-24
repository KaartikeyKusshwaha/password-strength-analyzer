"""Reproduce the public recovery vector with Python cryptography, not WebCrypto.

Run python tests/recovery_vector.py to verify the committed fixture. All keys
and passwords below are public test values; no user store or environment is read.
"""
import base64
import json
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id


def fixture():
    b64=lambda raw:base64.b64encode(raw).decode()
    context='c'*24;identifier='d'*24;stamp='2026-10-21T00:00:00.000Z'
    data_key=b'd'*32;recovery=bytes(range(32));salt=bytes(range(16));wrap_iv=b'w'*12;data_iv=b'v'*12
    master=Argon2id(salt=salt,length=32,iterations=3,lanes=1,memory_cost=65536).derive(b'Fixture-native-recovery-only-79')
    snapshot=dict(version=2,context=context,kdf=dict(algorithm='argon2id',memory_kib=65536,iterations=3,parallelism=1),salt=b64(salt),wrap_iv=b64(wrap_iv),wrapped_key=b64(AESGCM(master).encrypt(wrap_iv,data_key,('SentinelOps vault v2 wrap:'+context).encode())),iv=b64(data_iv),ciphertext=b64(AESGCM(data_key).encrypt(data_iv,b'{"entries":[]}',('SentinelOps vault v2 data:'+context).encode())))
    return dict(format='sentinelops-recovery-kit',version=1,vault_id=context,recovery_id=identifier,created_at=stamp,key_wrap=dict(iv=b64(b'r'*12),wrapped_key=b64(AESGCM(recovery).encrypt(b'r'*12,data_key,('SentinelOps recovery kit v1:'+context+':'+identifier+':'+stamp).encode()))),snapshot=snapshot)


if __name__=='__main__':
    expected=json.loads((Path(__file__).resolve().parents[1]/'frontend/src/recovery-native.fixture.json').read_text(encoding='utf-8'))
    if fixture()!=expected:raise SystemExit('Native recovery fixture differs; review the protocol and test data.')
    print('Committed recovery vector matches independent Python cryptography.')
