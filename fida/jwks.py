from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from fida.db import db_session
from fida.models import PlatformState, Tenant

router = APIRouter(tags=["jwks"])

@router.get("/.well-known/platform.jwks.json")
def platform_jwks(db: Session = Depends(db_session)):
    ps = db.query(PlatformState).filter(PlatformState.id == 1).first()
    if not ps or not ps.platform_kid or not ps.platform_pub_b64u:
        raise HTTPException(status_code=404, detail="Not bootstrapped")
    # Minimal JWKS-like object for Ed25519 (OKP)
    return {"keys":[{"kty":"OKP","crv":"Ed25519","kid":ps.platform_kid,"x":ps.platform_pub_b64u}]}

@router.get("/tenants/{tenant_id}/.well-known/jwks.json")
def tenant_jwks(tenant_id: str, db: Session = Depends(db_session)):
    t = db.query(Tenant).filter(Tenant.tenant_id == tenant_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Unknown tenant")
    return {"keys":[{"kty":"OKP","crv":"Ed25519","kid":t.active_kid,"x":t.pub_b64u}]}
