from __future__ import annotations
import secrets
from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session
from fida.db import db_session
from fida.models import ApiKey
from fida.util import sha256_hex

def api_key_hash(api_key: str) -> str:
    # store hash only
    return sha256_hex(api_key.encode("utf-8"))

class Principal:
    def __init__(self, key_id: str, role: str, tenant_id: str | None):
        self.key_id = key_id
        self.role = role
        self.tenant_id = tenant_id

def require_key(x_api_key: str | None = Header(default=None, alias="x-api-key"), db: Session = Depends(db_session)) -> Principal:
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing x-api-key")
    h = api_key_hash(x_api_key)
    row = db.query(ApiKey).filter(ApiKey.key_hash == h, ApiKey.status == "active").first()
    if not row:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return Principal(key_id=row.key_id, role=row.role, tenant_id=row.tenant_id)

def require_role(*roles: str):
    def _dep(p: Principal = Depends(require_key)) -> Principal:
        if p.role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient role")
        return p
    return _dep

def new_api_key() -> str:
    return secrets.token_urlsafe(32)
