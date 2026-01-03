import base64
import os
from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.orm import Session

from fida.config import settings
from fida.db import get_db
from fida.models import PlatformState, Tenant, TenantKey, ApiKey, TenantState
from fida.schemas import BootstrapRequest, BootstrapResponse, TenantCreateRequest, TenantCreateResponse, ApiKeyIssueRequest, ApiKeyIssueResponse
from fida.crypto import new_kid, ed25519_from_seed_b64, ed25519_seed_b64, b64u_encode
from fida.security import mint_api_key, hash_api_key, require_role, ROLE_ADMIN, VALID_ROLES
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

router = APIRouter(prefix="/admin")


@router.post("/bootstrap", response_model=BootstrapResponse)
def bootstrap(body: BootstrapRequest, x_bootstrap_token: str | None = Header(default=None, alias="x-bootstrap-token"), db: Session = Depends(get_db)):
    # Tier-0 baseline: bootstrap token MUST be provided and MUST match, and bootstrap must not be locked.
    if not x_bootstrap_token or x_bootstrap_token != settings.bootstrap_token:
        raise HTTPException(status_code=403, detail="invalid_bootstrap_token")

    ps = db.query(PlatformState).filter(PlatformState.id == 1).first()
    if not ps:
        ps = PlatformState(id=1)
        db.add(ps)
        db.flush()

    if ps.bootstrap_locked:
        raise HTTPException(status_code=403, detail="bootstrap_locked")

    if ps.bootstrapped:
        # already bootstrapped; return 409 to prevent reissue
        raise HTTPException(status_code=409, detail="already_bootstrapped")

    # platform kid
    platform_kid = new_kid()
    ps.platform_kid = platform_kid
    ps.platform_admin_name = body.platform_admin_name
    ps.bootstrapped = True

    # mint platform admin api key
    raw_key = mint_api_key()
    api = ApiKey(
        key_id=new_kid(),
        tenant_id="__platform__",
        role="admin",
        active=True,
        key_hash_hex=hash_api_key(raw_key),
        label="platform_admin"
    )
    db.add(api)
    db.commit()

    # publish platform public key as b64u(x)
    pub = ed25519_from_seed_b64(settings.platform_signing_key_b64).public_key()
    raw = pub.public_bytes(
        encoding=__import__("cryptography.hazmat.primitives.serialization").hazmat.primitives.serialization.Encoding.Raw,
        format=__import__("cryptography.hazmat.primitives.serialization").hazmat.primitives.serialization.PublicFormat.Raw,
    )
    platform_public_key_b64u = b64u_encode(raw)

    return {"platform_kid": platform_kid, "platform_public_key_b64u": platform_public_key_b64u, "platform_admin_api_key": raw_key}


@router.post("/bootstrap/lock")
def bootstrap_lock(pair=Depends(require_role("admin")), db: Session = Depends(get_db)):
    ps = db.query(PlatformState).filter(PlatformState.id == 1).first()
    if not ps or not ps.bootstrapped:
        raise HTTPException(status_code=400, detail="not_bootstrapped")
    ps.bootstrap_locked = True
    db.commit()
    return {"ok": True}


@router.post("/tenants", response_model=TenantCreateResponse)
def create_tenant(body: TenantCreateRequest, pair=Depends(require_role("admin")), db: Session = Depends(get_db)):
    # Create tenant id
    import uuid
    tenant_id = uuid.uuid4().hex[:24]
    t = Tenant(tenant_id=tenant_id, name=body.name, active=True, monthly_event_cap=settings.default_monthly_event_cap)
    db.add(t)

    # create tenant signing key
    kid = new_kid()
    priv = Ed25519PrivateKey.generate()
    seed_b64 = ed25519_seed_b64(priv)
    tk = TenantKey(key_id=kid, tenant_id=tenant_id, active=True, seed_b64=seed_b64)
    db.add(tk)

    # init tenant state
    db.add(TenantState(tenant_id=tenant_id, next_seq=1, last_event_hash="", root_hash="", size=0))

    # issue role keys
    def issue(role: str, label: str):
        raw = mint_api_key()
        ak = ApiKey(key_id=new_kid(), tenant_id=tenant_id, role=role, active=True, key_hash_hex=hash_api_key(raw), label=label)
        db.add(ak)
        return raw

    issuer = issue("issuer", "issuer")
    verifier = issue("verifier", "verifier")
    exporter = issue("exporter", "exporter")
    admin = issue("admin", "tenant_admin")

    db.commit()

    # tenant public key b64u
    pub = ed25519_from_seed_b64(seed_b64).public_key()
    raw_pub = pub.public_bytes(
        encoding=__import__("cryptography.hazmat.primitives.serialization").hazmat.primitives.serialization.Encoding.Raw,
        format=__import__("cryptography.hazmat.primitives.serialization").hazmat.primitives.serialization.PublicFormat.Raw,
    )
    public_key_b64u = b64u_encode(raw_pub)

    return {
        "tenant_id": tenant_id,
        "issuer_api_key": issuer,
        "verifier_api_key": verifier,
        "exporter_api_key": exporter,
        "admin_api_key": admin,
        "active_kid": kid,
        "public_key_b64u": public_key_b64u,
    }


@router.post("/apikeys/issue", response_model=ApiKeyIssueResponse)
def issue_api_key(body: ApiKeyIssueRequest, pair=Depends(require_role("admin")), db: Session = Depends(get_db)):
    if body.role not in ("issuer", "verifier", "exporter", "admin"):
        raise HTTPException(status_code=400, detail="bad_role")
    # ensure tenant exists (allow platform)
    if body.tenant_id != "__platform__":
        t = db.query(Tenant).filter(Tenant.tenant_id == body.tenant_id).first()
        if not t:
            raise HTTPException(status_code=404, detail="unknown_tenant")
    raw = mint_api_key()
    key_id = new_kid()
    ak = ApiKey(key_id=key_id, tenant_id=body.tenant_id, role=body.role, active=True, key_hash_hex=hash_api_key(raw), label=f"issued:{body.role}")
    db.add(ak)
    db.commit()
    return {"key_id": key_id, "tenant_id": body.tenant_id, "role": body.role, "api_key": raw}


# ---- EXTRA Tier-0 hygiene endpoints (non-breaking additions) ----
@router.post("/tenants/{tenant_id}/limits")
def set_tenant_limits(tenant_id: str, monthly_event_cap: int, pair=Depends(require_role("admin")), db: Session = Depends(get_db)):
    t = db.query(Tenant).filter(Tenant.tenant_id == tenant_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="unknown_tenant")
    if monthly_event_cap < 0:
        raise HTTPException(status_code=400, detail="bad_cap")
    t.monthly_event_cap = int(monthly_event_cap)
    db.commit()
    return {"ok": True, "tenant_id": tenant_id, "monthly_event_cap": t.monthly_event_cap}


@router.post("/tenants/{tenant_id}/keys/rotate")
def rotate_tenant_key(tenant_id: str, pair=Depends(require_role("admin")), db: Session = Depends(get_db)):
    # deactivate old keys and create a new active key (baseline approach)
    keys = db.query(TenantKey).filter(TenantKey.tenant_id == tenant_id, TenantKey.active == True).all()
    for k in keys:
        k.active = False
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from fida.crypto import ed25519_seed_b64, new_kid
    kid = new_kid()
    priv = Ed25519PrivateKey.generate()
    seed_b64 = ed25519_seed_b64(priv)
    db.add(TenantKey(key_id=kid, tenant_id=tenant_id, active=True, seed_b64=seed_b64))
    db.commit()
    return {"ok": True, "tenant_id": tenant_id, "new_kid": kid}


@router.post("/apikeys/{key_id}/revoke")
def revoke_api_key(key_id: str, pair=Depends(require_role("admin")), db: Session = Depends(get_db)):
    k = db.query(ApiKey).filter(ApiKey.key_id == key_id).first()
    if not k:
        raise HTTPException(status_code=404, detail="unknown_key")
    k.active = False
    db.commit()
    return {"ok": True}
