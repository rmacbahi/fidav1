from typing import Any
import rfc8785
from fida.util import sha256_hex

def canonicalize(payload: Any) -> str:
    # RFC8785 canonical JSON bytes -> decode to UTF-8 string
    b = rfc8785.dumps(payload)
    return b.decode("utf-8")

def hash_canon(canon: str) -> str:
    return sha256_hex(canon.encode("utf-8"))
