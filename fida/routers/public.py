from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from fida.db import get_db, engine
from fida.schemas import IssueRequest, Receipt, VerifyRequest, VerifyResult, ExportEnvelope
from fida.security import require_api_key, ROLE_ISSUER, ROLE_VERIFIER, ROLE_EXPORTER, rate_limit_or_429
from fida.ledger import issue_event, export_ledger
from fida.checkpoint import make_export_integrity, make_checkpoint
from fida.models import TenantState, PlatformState, TenantKey
from fida.crypto import ed25519_from_seed_b64, verify_sig, sha256_hex
from fida.canonical import canonical_json_bytes
from fida.config import settings

router = APIRouter()


@router.get("/")
def root():
    return {"ok": True, "service": "fida-rail-v1"}


@router.get("/health")
def health():
    return {"ok": True}


@router.get("/ready")
def ready(db: Session = Depends(get_db)):
    # verify DB
    db.execute("SELECT 1")
    return {"ok": True}


@router.post("/issue", response_model=Receipt)
def issue(req: Request, body: IssueRequest, idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"), pair=Depends(require_api_key), db: Session = Depends(get_db)):
    api_rec, raw = pair
    if api_rec.role != ROLE_ISSUER:
        raise HTTPException(status_code=403, detail="insufficient_role")
    rate_limit_or_429(api_rec.key_id, settings.default_rps_limit)

    # payload size guard (Tier-0 hygiene)
    raw_body = req.scope.get("body_bytes")
    if raw_body and len(raw_body) > settings.max_payload_bytes:
        raise HTTPException(status_code=413, detail="payload_too_large")

    receipt = issue_event(
        db=db,
        tenant_id=body.tenant_id,
        profile_id=body.profile_id,
        event_type=body.event_type,
        actor_role=body.actor_role,
        object_ref=body.object_ref,
        payload=body.payload,
        idempotency_key=idempotency_key,
    )
    db.commit()
    return receipt


@router.post("/verify", response_model=VerifyResult)
def verify(body: VerifyRequest, pair=Depends(require_api_key), db: Session = Depends(get_db)):
    api_rec, raw = pair
    if api_rec.role not in (ROLE_VERIFIER, ROLE_ADMIN, ROLE_EXPORTER, ROLE_ISSUER):
        raise HTTPException(status_code=403, detail="insufficient_role")
    rate_limit_or_429(api_rec.key_id, settings.default_rps_limit)

    r = body.receipt.model_dump()
    reasons = []
    # recompute event hash from receipt fields
    header = {
        "version": r["version"],
        "tenant_id": r["tenant_id"],
        "event_id": r["event_id"],
        "seq": r["seq"],
        "issued_at": r["issued_at"],
        "profile_id": r["profile_id"],
        "event_type": r["event_type"],
        "actor_role": r["actor_role"],
        "object_ref": r["object_ref"],
        "payload_hash": r["payload_hash"],
        "prev_event_hash": r.get("prev_event_hash", None),
        "kid": r["kid"],
        "canon_alg": r.get("canon_alg", "RFC8785"),
        "hash_alg": r.get("hash_alg", "SHA-256"),
    }
    computed = sha256_hex(canonical_json_bytes(header))
    hash_valid = (computed == r["event_hash"])
    if not hash_valid:
        reasons.append("event_hash_mismatch")

    # find tenant key for kid
    tk = db.query(TenantKey).filter(TenantKey.key_id == r["kid"], TenantKey.tenant_id == r["tenant_id"]).first()
    if not tk:
        reasons.append("unknown_kid")
        return {"valid": False, "reason_codes": reasons, "signature_valid": False, "hash_valid": hash_valid, "chain_hint_ok": False, "computed_event_hash": computed}

    pub = ed25519_from_seed_b64(tk.seed_b64).public_key()
    sig_ok = verify_sig(pub, bytes.fromhex(r["event_hash"]), r["signature_b64u"])
    if not sig_ok:
        reasons.append("bad_signature")

    # chain hint: if prev_event_hash exists, we can check it exists in DB (soft)
    chain_ok = True
    prev = r.get("prev_event_hash")
    if prev:
        from fida.models import LedgerEvent
        exists = db.query(LedgerEvent).filter(LedgerEvent.event_hash == prev, LedgerEvent.tenant_id == r["tenant_id"]).first()
        if not exists:
            chain_ok = False
            reasons.append("prev_hash_missing")

    valid = bool(hash_valid and sig_ok)
    return {"valid": valid, "reason_codes": reasons, "signature_valid": sig_ok, "hash_valid": hash_valid, "chain_hint_ok": chain_ok, "computed_event_hash": computed}


@router.get("/export/{tenant_id}", response_model=ExportEnvelope)
def export(tenant_id: str, cursor: str | None = None, limit: int = 500, fmt: str = "json", pair=Depends(require_api_key), db: Session = Depends(get_db)):
    api_rec, raw = pair
    if api_rec.role not in (ROLE_EXPORTER, ROLE_ADMIN):
        raise HTTPException(status_code=403, detail="insufficient_role")
    rate_limit_or_429(api_rec.key_id, settings.default_rps_limit)

    if limit < 1 or limit > 5000:
        raise HTTPException(status_code=400, detail="bad_limit")

    items, next_cursor = export_ledger(db, tenant_id, cursor, limit)
    st = db.query(TenantState).filter(TenantState.tenant_id == tenant_id).first()

    # Integrity envelope
    if not st:
        integrity = {"from_root": "", "to_root": "", "size": 0, "page_hash": ""}
    else:
        # from_root is root before this page is applied; we can approximate using cursor boundary.
        # For baseline, include page_hash + current root + size.
        page = make_export_integrity(items) if items else {"page_hash": ""}
        integrity = {"from_root": "", "to_root": st.root_hash, "size": int(st.size), "page_hash": page["page_hash"]}

    ps = db.query(PlatformState).filter(PlatformState.id == 1).first()
    checkpoint = make_checkpoint(db, tenant_id, ps.platform_kid) if ps and ps.bootstrapped else None

    return {"tenant_id": tenant_id, "items": items, "next_cursor": next_cursor, "checkpoint": checkpoint, "integrity": integrity}
