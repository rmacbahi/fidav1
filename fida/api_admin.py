from __future__ import annotations
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session
from datetime import datetime, timezone
import secrets

from fida.db import db_session
from fida.models import PlatformState, Tenant, ApiKey
from fida.schemas import BootstrapRequest, BootstrapResponse, TenantCreateRequest, TenantCreateResponse, ApiKeyIssueRequest, ApiKeyIssueResponse
from fida.config import settings
from fida.crypto import generate_keypair, pub_b64u, envelope_encrypt, envelope_decrypt
from fida.auth import require_role, Principal, new_api_key, api_key_hash
from fida.audit import audit
from fida.util import json_dumps, sha256_hex

router = APIRouter(prefix="/admin", tags=["admin"])

def _get_platform(db: Session) -> PlatformState:
    row = db.query(PlatformState).filter(PlatformState.id == 1).first()
    if not row:
        row = PlatformState(id=1, bootstrapped=False, bootstrap_locked=False)
        db.add(row)
        db.flush()
    return row

@router.post("/bootstrap", response_model=BootstrapResponse)
def bootstrap(req: BootstrapRequest, request: Request, x_bootstrap_token: str | None = Header(default=None, alias="x-bootstrap-token"), db: Session = Depends(db_session)):
    ps = _get_platform(db)
    if ps.bootstrap_locked:
        raise HTTPException(status_code=409, detail="Bootstrap locked")
    if settings.fida_bootstrap_token:
        if not x_bootstrap_token or x_bootstrap_token != settings.fida_bootstrap_token:
            raise HTTPException(status_code=403, detail="Invalid bootstrap token")

    if ps.bootstrapped and ps.platform_kid and ps.platform_pub_b64u:
        # Already bootstrapped: issue a fresh admin key? Tier-0 posture: avoid re-bootstrap.
        raise HTTPException(status_code=409, detail="Already bootstrapped")

    kp = generate_keypair()
    # Store platform private seed encrypted (v1 envelope). Later swap to KMS.
    # NOTE: We store the raw private bytes (not ideal long-term); this is to enable platform signing of checkpoints.
    priv_raw = kp.priv.private_bytes_raw()
    ps.platform_kid = kp.kid
    ps.platform_pub_b64u = pub_b64u(kp.pub)
    ps.platform_seed_enc_b64u = envelope_encrypt(settings.fida_master_key_b64, priv_raw)
    ps.bootstrapped = True

    admin_api_key = new_api_key()
    db.add(ApiKey(key_id="platform-admin", key_hash=api_key_hash(admin_api_key), tenant_id=None, role="admin", status="active"))

    audit(db, actor=req.platform_admin_name, action="platform_bootstrap", tenant_id=None, meta={"platform_kid":kp.kid}, ip=request.client.host if request.client else None, ua=request.headers.get("user-agent"))
    db.commit()

    return BootstrapResponse(platform_kid=kp.kid, platform_public_key_b64u=ps.platform_pub_b64u, platform_admin_api_key=admin_api_key)

@router.post("/bootstrap/lock", dependencies=[Depends(require_role("admin"))])
def bootstrap_lock(request: Request, p: Principal = Depends(require_role("admin")), db: Session = Depends(db_session)):
    ps = _get_platform(db)
    ps.bootstrap_locked = True
    audit(db, actor=p.key_id, action="bootstrap_lock", tenant_id=None, meta={}, ip=request.client.host if request.client else None, ua=request.headers.get("user-agent"))
    db.commit()
    return {"ok": True}

@router.post("/tenants", response_model=TenantCreateResponse, dependencies=[Depends(require_role("admin"))])
def create_tenant(req: TenantCreateRequest, request: Request, p: Principal = Depends(require_role("admin")), db: Session = Depends(db_session)):
    tenant_id = sha256_hex(secrets.token_bytes(16))[:16]
    kp = generate_keypair()
    # tenant private key stored encrypted
    tenant_priv_raw = kp.priv.private_bytes_raw()
    seed_enc = envelope_encrypt(settings.fida_master_key_b64, tenant_priv_raw)

    tenant = Tenant(tenant_id=tenant_id, name=req.name, active_kid=kp.kid, pub_b64u=pub_b64u(kp.pub), seed_enc_b64u=seed_enc)
    db.add(tenant)

    issuer = new_api_key(); verifier = new_api_key(); exporter = new_api_key(); admin = new_api_key()
    db.add(ApiKey(key_id=f"{tenant_id}-issuer", key_hash=api_key_hash(issuer), tenant_id=tenant_id, role="issuer"))
    db.add(ApiKey(key_id=f"{tenant_id}-verifier", key_hash=api_key_hash(verifier), tenant_id=tenant_id, role="verifier"))
    db.add(ApiKey(key_id=f"{tenant_id}-exporter", key_hash=api_key_hash(exporter), tenant_id=tenant_id, role="exporter"))
    db.add(ApiKey(key_id=f"{tenant_id}-admin", key_hash=api_key_hash(admin), tenant_id=tenant_id, role="admin"))

    audit(db, actor=p.key_id, action="tenant_create", tenant_id=tenant_id, meta={"name":req.name,"kid":kp.kid}, ip=request.client.host if request.client else None, ua=request.headers.get("user-agent"))
    db.commit()

    return TenantCreateResponse(
        tenant_id=tenant_id,
        issuer_api_key=issuer,
        verifier_api_key=verifier,
        exporter_api_key=exporter,
        admin_api_key=admin,
        active_kid=kp.kid,
        public_key_b64u=tenant.pub_b64u
    )

@router.post("/apikeys/issue", response_model=ApiKeyIssueResponse, dependencies=[Depends(require_role("admin"))])
def issue_api_key(req: ApiKeyIssueRequest, request: Request, p: Principal = Depends(require_role("admin")), db: Session = Depends(db_session)):
    tenant = db.query(Tenant).filter(Tenant.tenant_id == req.tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Unknown tenant")
    api_key = new_api_key()
    key_id = f"{req.tenant_id}-{req.role}-{sha256_hex(secrets.token_bytes(8))[:8]}"
    db.add(ApiKey(key_id=key_id, key_hash=api_key_hash(api_key), tenant_id=req.tenant_id, role=req.role, status="active"))
    audit(db, actor=p.key_id, action="apikey_issue", tenant_id=req.tenant_id, meta={"role":req.role,"key_id":key_id}, ip=request.client.host if request.client else None, ua=request.headers.get("user-agent"))
    db.commit()
    return ApiKeyIssueResponse(key_id=key_id, tenant_id=req.tenant_id, role=req.role, api_key=api_key)
