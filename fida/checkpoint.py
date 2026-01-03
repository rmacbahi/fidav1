import datetime as dt
import hashlib
from sqlalchemy.orm import Session
from fastapi import HTTPException
from fida.models import TenantState
from fida.crypto import sign_b64u, ed25519_from_seed_b64
from fida.config import settings
from fida.crypto import sha256_hex
from fida.canonical import canonical_json_bytes


def make_export_integrity(items: list[dict]) -> dict:
    # page_hash over concatenated event_hashes
    h = hashlib.sha256()
    for it in items:
        h.update(bytes.fromhex(it["event_hash"]))
    return {"page_hash": h.hexdigest()}


def make_checkpoint(db: Session, tenant_id: str, platform_kid: str) -> dict:
    st = db.query(TenantState).filter(TenantState.tenant_id == tenant_id).first()
    if not st:
        return None
    issued_at = dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    body = {
        "tenant_id": tenant_id,
        "size": int(st.size),
        "root_hash": st.root_hash,
        "issued_at": issued_at,
        "platform_kid": platform_kid,
    }
    priv = ed25519_from_seed_b64(settings.platform_signing_key_b64)
    sig = sign_b64u(priv, canonical_json_bytes(body))
    body["signature_b64u"] = sig
    return body
