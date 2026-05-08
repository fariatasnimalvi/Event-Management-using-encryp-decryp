import hashlib, secrets, hmac, time

def sha256(data: bytes): return hashlib.sha256(data).digest()

def hash_password(password: str, salt_hex=None, rounds=120000):
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    data = password.encode() + salt
    for _ in range(rounds):
        data = sha256(data + password.encode() + salt)
    return salt.hex(), data.hex()

def verify_password(password, salt_hex, digest_hex):
    _, d = hash_password(password, salt_hex)
    return hmac.compare_digest(d, digest_hex)

def hmac_sha256(key: bytes, message: bytes):
    block=64
    if len(key)>block: key=sha256(key)
    key=key.ljust(block,b'\x00')
    o=bytes([x^0x5c for x in key]); i=bytes([x^0x36 for x in key])
    return sha256(o + sha256(i + message)).hex()

def make_otp(secret: str, step=None):
    if step is None: step=int(time.time()//30)
    mac=hmac_sha256(secret.encode(), str(step).encode())
    return str(int(mac[:12],16)%1000000).zfill(6)

def verify_otp(secret, code):
    now=int(time.time()//30)
    return any(hmac.compare_digest(make_otp(secret, now+off), code) for off in (-1,0,1))
