import base64
import hashlib
import os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization


def b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_decode(s: str) -> bytes:
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode((s + pad).encode())


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def new_kid() -> str:
    return b64u_encode(os.urandom(16))


def ed25519_from_seed_b64(seed_b64: str) -> Ed25519PrivateKey:
    seed = base64.b64decode(seed_b64)
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes base64")
    return Ed25519PrivateKey.from_private_bytes(seed)


def ed25519_seed_b64(priv: Ed25519PrivateKey) -> str:
    seed = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    return base64.b64encode(seed).decode()


def ed25519_public_jwk(kid: str, pub: Ed25519PublicKey) -> dict:
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "kid": kid,
        "x": b64u_encode(raw),
        "use": "sig",
        "alg": "EdDSA",
    }


def sign_b64u(priv: Ed25519PrivateKey, msg: bytes) -> str:
    sig = priv.sign(msg)
    return b64u_encode(sig)


def verify_sig(pub: Ed25519PublicKey, msg: bytes, sig_b64u: str) -> bool:
    try:
        pub.verify(b64u_decode(sig_b64u), msg)
        return True
    except Exception:
        return False
