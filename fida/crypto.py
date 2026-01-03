from __future__ import annotations
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import secrets
from fida.util import b64u_encode, b64u_decode, sha256_hex

@dataclass
class KeyPair:
    kid: str
    priv: Ed25519PrivateKey
    pub: Ed25519PublicKey

def new_ed25519_kid() -> str:
    return sha256_hex(secrets.token_bytes(32))[:32]

def generate_keypair() -> KeyPair:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    kid = new_ed25519_kid()
    return KeyPair(kid=kid, priv=priv, pub=pub)

def pub_b64u(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes_raw()
    return b64u_encode(raw)

def pub_from_b64u(s: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(b64u_decode(s))

def sign_b64u(priv: Ed25519PrivateKey, msg: bytes) -> str:
    sig = priv.sign(msg)
    return b64u_encode(sig)

def verify(pub: Ed25519PublicKey, msg: bytes, sig_b64u: str) -> bool:
    try:
        pub.verify(b64u_decode(sig_b64u), msg)
        return True
    except Exception:
        return False

def envelope_encrypt(master_key_b64u: str, plaintext: bytes) -> str:
    mk = b64u_decode(master_key_b64u)
    if len(mk) != 32:
        raise ValueError("FIDA_MASTER_KEY_B64 must be 32 bytes (base64url)")
    nonce = os.urandom(12)
    aes = AESGCM(mk)
    ct = aes.encrypt(nonce, plaintext, None)
    return b64u_encode(nonce + ct)

def envelope_decrypt(master_key_b64u: str, blob_b64u: str) -> bytes:
    mk = b64u_decode(master_key_b64u)
    raw = b64u_decode(blob_b64u)
    nonce, ct = raw[:12], raw[12:]
    aes = AESGCM(mk)
    return aes.decrypt(nonce, ct, None)
