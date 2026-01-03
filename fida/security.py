import base64
import hashlib
import os
import secrets
import time
from typing import Optional, Tuple
from fastapi import Header, HTTPException, Depends
from sqlalchemy.orm import Session
from fida.db import get_db
from fida.models import ApiKey
from fida.config import settings

ROLE_ADMIN = "admin"
ROLE_ISSUER = "issuer"
ROLE_VERIFIER = "verifier"
ROLE_EXPORTER = "exporter"

VALID_ROLES = {ROLE_ADMIN, ROLE_ISSUER, ROLE_VERIFIER, ROLE_EXPORTER}


def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()


def mint_api_key() -> str:
    # long random token
    return "fida_" + secrets.token_urlsafe(48)


def require_api_key(
    x_api_key: Optional[str] = Header(default=None, alias="x-api-key"),
    db: Session = Depends(get_db),
) -> Tuple[ApiKey, str]:
    if not x_api_key:
        raise HTTPException(status_code=401, detail="missing_api_key")

    h = hash_api_key(x_api_key)
    rec = db.query(ApiKey).filter(ApiKey.key_hash_hex == h, ApiKey.active == True).first()
    if not rec:
        raise HTTPException(status_code=403, detail="invalid_api_key")

    # expiry check if set
    if rec.expires_at is not None:
        import datetime as dt
        if rec.expires_at < dt.datetime.utcnow():
            raise HTTPException(status_code=403, detail="expired_api_key")

    return rec, x_api_key


def require_role(required: str):
    def _dep(pair=Depends(require_api_key)):
        rec, raw = pair
        if rec.role != required:
            raise HTTPException(status_code=403, detail="insufficient_role")
        return rec, raw
    return _dep


# --- Rate limiting (best-effort) ---
# Tier-0 would use Redis with token bucket. Here we support Redis if available and fallback to memory.
_mem = {}


def rate_limit_or_429(key: str, rps: int):
    if rps <= 0:
        return
    now = time.time()
    bucket = _mem.get(key)
    if not bucket:
        _mem[key] = {"t": now, "n": 1}
        return
    # simple fixed window 1s
    if now - bucket["t"] >= 1.0:
        bucket["t"] = now
        bucket["n"] = 1
        return
    bucket["n"] += 1
    if bucket["n"] > rps:
        raise HTTPException(status_code=429, detail="rate_limited")
