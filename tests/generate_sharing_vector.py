"""Regenerate a PUBLIC test vector using Python cryptography, independently of JS.

All material here is synthetic, with a published fixture passphrase. Never put
real credentials in this file or its generated JSON.
"""
import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id


def generate():
    encode=lambda b:base64.b64encode(b).decode()
    canonical=lambda d:json.dumps(d,sort_keys=True,separators=(',',':')).encode()
    user,workspace,vault='1'*24,'2'*24,'3'*24
    password='Fixture-only!native-sharing-vector-79'
    private=rsa.generate_private_key(public_exponent=65537,key_size=3072)
    signing=ec.generate_private_key(ec.SECP256R1())
    public={'encryption':encode(private.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)),'signing':encode(signing.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo))}
    fingerprint=hashlib.sha256(canonical(public)).hexdigest()
    keyformat=(serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
    raw_identity=canonical({'encryption':encode(private.private_bytes(*keyformat)),'signing':encode(signing.private_bytes(*keyformat))})
    # Fixed nonces/salts are only for this fixture, with independently random keys.
    salt=b's'*16;iv=b'i'*12;raw=bytes(range(32));data_iv=b'd'*12
    wrap=Argon2id(salt=salt,length=32,iterations=3,lanes=1,memory_cost=65536).derive(password.encode())
    identity={'public':public,'fingerprint':fingerprint,'encrypted':{'version':1,'salt':encode(salt),'iv':encode(iv),'ciphertext':encode(AESGCM(wrap).encrypt(iv,raw_identity,('SentinelOps sharing identity v1:'+user).encode()))}}
    def sign(document):
        r,s=decode_dss_signature(signing.sign(canonical(document),ec.ECDSA(hashes.SHA256())))
        return encode(r.to_bytes(32,'big')+s.to_bytes(32,'big'))
    manifest={'id':vault,'workspace':workspace,'owner':user,'owner_fingerprint':fingerprint}
    grant={'version':1,'vault_id':vault,'recipient':user,'issuer':user,'epoch':1,'role':'owner','recipient_fingerprint':fingerprint,'issuer_fingerprint':fingerprint,'wrapped_key':encode(private.public_key().encrypt(raw,padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=('SentinelOps team grant v1:'+vault+':1:'+user).encode())))}
    grant.update(signature=sign(grant),issuer_public=public,issuer_grant=None)
    entry={'id':'native-fixture','type':'login','title':'Native fixture','origin':'https://example.test','username':'fixture','password':'fixture-only-never-real'}
    payload={'version':1,'context':vault,'epoch':1,'iv':encode(data_iv),'ciphertext':encode(AESGCM(raw).encrypt(data_iv,canonical({'entries':[entry]}),('SentinelOps team vault v1:'+vault+':1').encode()))}
    team={'id':vault,'workspace':workspace,'owner':user,'owner_public':public,'owner_fingerprint':fingerprint,'manifest':{'document':manifest,'signature':sign(manifest)},'epoch':1,'revision':1,'rotation_required':False,'role':'owner','accepted':True,'grant':grant,'grants':[{'user_id':user,'role':'owner','envelope':grant,'accepted':True}],'payload':payload}
    path=Path(__file__).resolve().parents[1]/'frontend/src/fixtures/native-sharing.json'
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps({'user':user,'password':password,'identity':identity,'team':team,'entry':entry},indent=2)+'\n',encoding='utf-8')


if __name__=='__main__':
    generate()
