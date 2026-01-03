from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, Header, Request
from sqlalchemy.orm import Session
from sqlalchemy import and_
from datetime import datetime, timezone

from fida.db import db_session
from fida.models import Tenant, Event, Checkpoint, MerkleNode, PlatformState
from fida.schemas import IssueRequest, Receipt, VerifyRequest, VerifyResult, ExportEnvelope, ExportItem, ExportIntegrity, CheckpointOut, MerkleProofOut
from fida.auth import require_key, require_role, Principal
from fida.rate_limit import enforce_rl
from fida.audit import audit
from fida.config import settings
from fida.crypto import envelope_decrypt
from fida.ledger import issue_event, verify_receipt, maybe_checkpoint
from fida.merkle import verify_proof, MerkleProof

from fida.util import json_dumps, sha256_hex

router = APIRouter(tags=["public"])

@router.get("/")
def root():
    return {"name":"FIDA Rail V1","version":"1.0.0","fes":"FES-1.0"}

@router.get("/health")
def health():
    return {"ok": True}

@router.get("/ready")
def ready(db: Session = Depends(db_session)):
    # readiness means DB reachable and platform state exists
    ps = db.query(PlatformState).filter(PlatformState.id == 1).first()
    return {"ok": True, "bootstrapped": bool(ps and ps.bootstrapped), "locked": bool(ps and ps.bootstrap_locked)}

@router.post("/issue", response_model=Receipt)
def issue(req: IssueRequest, request: Request, idem: str | None = Header(default=None, alias="Idempotency-Key"), p: Principal = Depends(require_role("issuer","admin")), db: Session = Depends(db_session)):
    enforce_rl(request, p.tenant_id, p.key_id)
    if not p.tenant_id or p.tenant_id != req.tenant_id:
        raise HTTPException(status_code=403, detail="Tenant mismatch")
    tenant = db.query(Tenant).filter(Tenant.tenant_id == req.tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Unknown tenant")

    # decrypt tenant private seed
    tenant_seed = envelope_decrypt(settings.fida_master_key_b64, tenant.seed_enc_b64u)
    receipt_json, idem_hit = issue_event(db, tenant, req.payload, req.profile_id, req.event_type, req.actor_role, req.object_ref, idem, tenant_seed)

    audit(db, actor=p.key_id, action="issue_event", tenant_id=req.tenant_id, meta={"idem":bool(idem),"idem_hit":idem_hit}, ip=request.client.host if request.client else None, ua=request.headers.get("user-agent"))

    # maybe checkpoint batch in background-ish (sync here; for prod, move to worker)
    ps = db.query(PlatformState).filter(PlatformState.id == 1).first()
    if ps and ps.platform_seed_enc_b64u and ps.platform_kid:
        platform_seed = envelope_decrypt(settings.fida_master_key_b64, ps.platform_seed_enc_b64u)
        maybe_checkpoint(db, tenant.tenant_id, platform_seed, ps.platform_kid)

    db.commit()
    return Receipt.model_validate_json(receipt_json)

@router.post("/verify", response_model=VerifyResult)
def verify(req: VerifyRequest, request: Request, p: Principal = Depends(require_role("verifier","admin","issuer","exporter")), db: Session = Depends(db_session)):
    enforce_rl(request, p.tenant_id or "platform", p.key_id)
    tenant_id = req.receipt.tenant_id
    if p.tenant_id and p.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Tenant mismatch")
    tenant = db.query(Tenant).filter(Tenant.tenant_id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Unknown tenant")
    out = verify_receipt(db, tenant, req.receipt.model_dump())
    audit(db, actor=p.key_id, action="verify_receipt", tenant_id=tenant_id, meta={"valid":out["valid"]}, ip=request.client.host if request.client else None, ua=request.headers.get("user-agent"))
    db.commit()
    return VerifyResult(**out)

@router.get("/export/{tenant_id}", response_model=ExportEnvelope)
def export_ledger(tenant_id: str, cursor: str | None = None, limit: int = 500, fmt: str = "json", request: Request = None, p: Principal = Depends(require_role("exporter","admin")), db: Session = Depends(db_session)):
    if p.tenant_id and p.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Tenant mismatch")
    enforce_rl(request, tenant_id, p.key_id)

    q = db.query(Event).filter(Event.tenant_id == tenant_id).order_by(Event.seq.asc())
    if cursor:
        q = q.filter(Event.seq > int(cursor))
    rows = q.limit(min(limit, 5000)).all()
    next_cursor = str(rows[-1].seq) if rows else None

    items = []
    for e in rows:
        items.append(ExportItem(
            seq=int(e.seq),
            event_id=e.event_id,
            issued_at=e.issued_at.isoformat(),
            event_type=e.event_type,
            payload_hash=e.payload_hash,
            event_hash=e.event_hash,
            tenant_id=e.tenant_id,
            profile_id=e.profile_id,
            actor_role=e.actor_role,
            object_ref=e.object_ref,
            prev_event_hash=e.prev_event_hash,
            kid=e.kid,
            signature_b64u=e.signature_b64u,
            payload_canon=e.payload_canon,
            checkpoint_id=e.checkpoint_id,
            leaf_index=e.leaf_index,
        ))

    from_root = rows[0].prev_event_hash or "" if rows else ""
    to_root = rows[-1].event_hash if rows else ""
    page_hash = sha256_hex(("|".join([x.event_hash for x in rows])).encode("utf-8")) if rows else sha256_hex(b"")
    integrity = ExportIntegrity(from_root=from_root, to_root=to_root, size=len(rows), page_hash=page_hash)

    # attach latest checkpoint for tenant (if exists)
    cp = db.query(Checkpoint).filter(Checkpoint.tenant_id == tenant_id).order_by(Checkpoint.id.desc()).first()
    cp_out = None
    if cp:
        cp_out = CheckpointOut(
            tenant_id=tenant_id,
            size=cp.leaf_count,
            root_hash=cp.merkle_root,
            issued_at=cp.issued_at.isoformat(),
            platform_kid=cp.platform_kid,
            signature_b64u=cp.signature_b64u
        )

    audit(db, actor=p.key_id, action="export_ledger", tenant_id=tenant_id, meta={"count":len(rows)}, ip=request.client.host if request.client else None, ua=request.headers.get("user-agent"))
    db.commit()

    return ExportEnvelope(tenant_id=tenant_id, items=items, next_cursor=next_cursor, checkpoint=cp_out, integrity=integrity)

@router.get("/proof/{tenant_id}/{event_id}", response_model=MerkleProofOut)
def proof(tenant_id: str, event_id: str, request: Request, p: Principal = Depends(require_role("verifier","exporter","admin")), db: Session = Depends(db_session)):
    if p.tenant_id and p.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Tenant mismatch")
    enforce_rl(request, tenant_id, p.key_id)

    e = db.query(Event).filter(and_(Event.tenant_id == tenant_id, Event.event_id == event_id)).first()
    if not e or not e.checkpoint_id or e.leaf_index is None:
        raise HTTPException(status_code=404, detail="Event not checkpointed yet (proof unavailable)")

    cp = db.query(Checkpoint).filter(Checkpoint.id == e.checkpoint_id).first()
    if not cp:
        raise HTTPException(status_code=404, detail="Checkpoint missing")

    # Rebuild layers from stored merkle_nodes
    # Read nodes grouped by level
    nodes = db.query(MerkleNode).filter(MerkleNode.checkpoint_id == cp.id).all()
    by_level = {}
    for n in nodes:
        by_level.setdefault(n.level, {})[n.idx] = n.hash_hex
    max_level = max(by_level.keys())
    layers = []
    for lvl in range(0, max_level+1):
        d = by_level.get(lvl, {})
        layer = [d[i] for i in range(0, len(d))]
        layers.append(layer)

    from fida.merkle import prove
    pr = prove(layers, int(e.leaf_index))
    ok = verify_proof(pr)

    audit(db, actor=p.key_id, action="merkle_proof", tenant_id=tenant_id, meta={"checkpoint_id":cp.id,"ok":ok}, ip=request.client.host if request.client else None, ua=request.headers.get("user-agent"))
    db.commit()

    return MerkleProofOut(
        tenant_id=tenant_id,
        checkpoint_id=cp.id,
        event_id=event_id,
        leaf_index=int(e.leaf_index),
        leaf=pr.leaf,
        root=pr.root,
        siblings=[[s,h] for (s,h) in pr.siblings],
        proof_valid=ok
    )
