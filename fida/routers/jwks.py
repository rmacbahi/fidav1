from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from fida.db import get_db
from fida.models import PlatformState, TenantKey
from fida.crypto import ed25519_from_seed_b64, ed25519_public_jwk
from fida.config import settings

router = APIRouter()


@router.get("/.well-known/platform.jwks.json")
def platform_jwks(db: Session = Depends(get_db)):
    ps = db.query(PlatformState).filter(PlatformState.id == 1).first()
    if not ps or not ps.bootstrapped:
        return {"keys": []}
    # Platform public key derived from env signing seed (baseline)
    pub = ed25519_from_seed_b64(settings.platform_signing_key_b64).public_key()
    return {"keys": [ed25519_public_jwk(ps.platform_kid, pub)]}


@router.get("/tenants/{tenant_id}/.well-known/jwks.json")
def tenant_jwks(tenant_id: str, db: Session = Depends(get_db)):
    keys = db.query(TenantKey).filter(TenantKey.tenant_id == tenant_id, TenantKey.active == True).all()
    out = []
    for k in keys:
        pub = ed25519_from_seed_b64(k.seed_b64).public_key()
        out.append(ed25519_public_jwk(k.key_id, pub))
    return {"keys": out}
