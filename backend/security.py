import base64
import hashlib
import hmac
import json
import secrets
import struct
import time


def digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def hash_password(password):
    salt = secrets.token_bytes(16)
    key = hashlib.scrypt(password.encode(), salt=salt, n=32768, r=8, p=1, maxmem=64 * 1024 * 1024)
    return salt.hex() + ":" + key.hex()


def verify_password(password, encoded):
    salt, expected = encoded.split(":")
    actual = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=32768, r=8, p=1, maxmem=64 * 1024 * 1024)
    return hmac.compare_digest(actual.hex(), expected)


def password_policy(password):
    from zxcvbn import zxcvbn
    if not 15 <= len(password) <= 128 or zxcvbn(password, max_length=128)["score"] < 3:
        raise ValueError("Use 15–128 characters and avoid common or predictable phrases. A password manager can generate one.")


def totp(secret, step):
    key = base64.b32decode(secret, casefold=True)
    code = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = code[-1] & 15
    return f"{(struct.unpack('>I', code[offset:offset+4])[0] & 0x7fffffff) % 1000000:06d}"


def check_totp(secret, code, last_step=-1, at=None):
    current = int((time.time() if at is None else at) // 30)
    for step in (current, current - 1, current + 1):
        if step > last_step and hmac.compare_digest(totp(secret, step), code):
            return step
    return None


def consume_factor(c, user, code, cipher):
    if not user["mfa"]:
        return False
    step = check_totp(cipher.decrypt(user["mfa"].encode()).decode(), code, user["mfa_step"])
    if step is not None:
        c.execute("UPDATE users SET mfa_step=? WHERE id=?", (step, user["id"]))
        return True
    recovery = json.loads(user["recovery"])
    token_hash = digest(code)
    if token_hash in recovery:
        recovery.remove(token_hash)
        c.execute("UPDATE users SET recovery=? WHERE id=?", (json.dumps(recovery), user["id"]))
        return True
    return False
