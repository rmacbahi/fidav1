import datetime as dt
import uuid
from sqlalchemy.orm import Session
from sqlalchemy import text
from fastapi import HTTPException

from fida.models import Tenant, TenantKey, TenantState, LedgerEvent, IdempotencyRecord, UsageCounter
from fida.crypto import sha256_hex, sign_b64u, ed25519_from_seed_b64
from fida.canonical import canonical_json_bytes

FES_VERSION = "FES-1.0"


def yyyymm_now() -> str:
    return dt.datetime.utcnow().strftime("%Y%m")


def bump_usage(db: Session, tenant_id: str, inc: int = 1):
    ym = yyyymm_now()
    row = db.query(UsageCounter).filter(UsageCounter.tenant_id == tenant_id, UsageCounter.yyyymm == ym).first()
    if not row:
        row = UsageCounter(tenant_id=tenant_id, yyyymm=ym, count=0)
        db.add(row)
        db.flush()
    row.count += inc


def get_usage(db: Session, tenant_id: str) -> int:
    ym = yyyymm_now()
    row = db.query(UsageCounter).filter(UsageCounter.tenant_id == tenant_id, UsageCounter.yyyymm == ym).first()
    return int(row.count) if row else 0


def enforce_cap(db: Session, tenant: Tenant):
    used = get_usage(db, tenant.tenant_id)
    if used >= int(tenant.monthly_event_cap):
        raise HTTPException(status_code=402, detail="tenant_monthly_cap_exceeded")


def compute_event_hash(fields: dict) -> str:
    # event hash over canonical JSON of the event "header fields" (not including signature)
    b = canonical_json_bytes(fields)
    return sha256_hex(b)


def issue_event(
    db: Session,
    tenant_id: str,
    profile_id: str,
    event_type: str,
    actor_role: str,
    object_ref: str,
    payload: dict,
    idempotency_key: str | None,
) -> dict:
    tenant = db.query(Tenant).filter(Tenant.tenant_id == tenant_id, Tenant.active == True).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="unknown_tenant")

    enforce_cap(db, tenant)

    if idempotency_key:
        idem = db.query(IdempotencyRecord).filter(
            IdempotencyRecord.tenant_id == tenant_id,
            IdempotencyRecord.idem_key == idempotency_key
        ).first()
        if idem:
            import orjson
            return orjson.loads(idem.receipt_json)

    # Ensure tenant state exists
    st = db.query(TenantState).filter(TenantState.tenant_id == tenant_id).with_for_update().first()
    if not st:
        st = TenantState(tenant_id=tenant_id, next_seq=1, last_event_hash="", root_hash="", size=0)
        db.add(st)
        db.flush()
        st = db.query(TenantState).filter(TenantState.tenant_id == tenant_id).with_for_update().first()

    # Active tenant signing key
    tkey = db.query(TenantKey).filter(TenantKey.tenant_id == tenant_id, TenantKey.active == True).order_by(TenantKey.created_at.desc()).first()
    if not tkey:
        raise HTTPException(status_code=500, detail="tenant_missing_signing_key")

    priv = ed25519_from_seed_b64(tkey.seed_b64)

    issued_at = dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    event_id = uuid.uuid4().hex
    seq = int(st.next_seq)
    prev_event_hash = st.last_event_hash or None

    payload_canon = canonical_json_bytes(payload)
    payload_hash = sha256_hex(payload_canon)

    # header fields for hash
    header = {
        "version": FES_VERSION,
        "tenant_id": tenant_id,
        "event_id": event_id,
        "seq": seq,
        "issued_at": issued_at,
        "profile_id": profile_id,
        "event_type": event_type,
        "actor_role": actor_role,
        "object_ref": object_ref,
        "payload_hash": payload_hash,
        "prev_event_hash": prev_event_hash,
        "kid": tkey.key_id,
        "canon_alg": "RFC8785",
        "hash_alg": "SHA-256",
    }
    event_hash = compute_event_hash(header)
    signature_b64u = sign_b64u(priv, bytes.fromhex(event_hash))

    receipt = {
        "version": FES_VERSION,
        "tenant_id": tenant_id,
        "event_id": event_id,
        "seq": seq,
        "issued_at": issued_at,
        "profile_id": profile_id,
        "event_type": event_type,
        "actor_role": actor_role,
        "object_ref": object_ref,
        "payload_hash": payload_hash,
        "prev_event_hash": prev_event_hash,
        "event_hash": event_hash,
        "kid": tkey.key_id,
        "signature_b64u": signature_b64u,
        "canon_alg": "RFC8785",
        "hash_alg": "SHA-256",
    }

    # Persist event (append-only)
    ev = LedgerEvent(
        tenant_id=tenant_id,
        seq=seq,
        event_id=event_id,
        issued_at=issued_at,
        event_type=event_type,
        profile_id=profile_id,
        actor_role=actor_role,
        object_ref=object_ref,
        payload_hash=payload_hash,
        prev_event_hash=prev_event_hash or "",
        event_hash=event_hash,
        kid=tkey.key_id,
        signature_b64u=signature_b64u,
        payload_canon=payload_canon.decode("utf-8") if len(payload_canon) <= 8192 else None,
    )
    db.add(ev)

    # Update tenant state: next_seq, last_event_hash, root_hash, size
    import hashlib
    prev_root = st.root_hash.encode() if st.root_hash else b""
    new_root = hashlib.sha256(prev_root + bytes.fromhex(event_hash)).hexdigest()
    st.root_hash = new_root
    st.last_event_hash = event_hash
    st.size = int(st.size) + 1
    st.next_seq = int(st.next_seq) + 1
    st.updated_at = dt.datetime.utcnow()

    bump_usage(db, tenant_id, 1)

    if idempotency_key:
        import orjson
        db.add(IdempotencyRecord(tenant_id=tenant_id, idem_key=idempotency_key, receipt_json=orjson.dumps(receipt).decode("utf-8")))

    return receipt


def export_ledger(db: Session, tenant_id: str, cursor: str | None, limit: int) -> tuple[list[dict], str | None]:
    q = db.query(LedgerEvent).filter(LedgerEvent.tenant_id == tenant_id).order_by(LedgerEvent.seq.asc())
    if cursor:
        try:
            cseq = int(cursor)
            q = q.filter(LedgerEvent.seq > cseq)
        except Exception:
            raise HTTPException(status_code=400, detail="bad_cursor")
    items = q.limit(limit).all()
    if not items:
        return [], None
    next_cursor = str(items[-1].seq)
    out = []
    for it in items:
        out.append({
            "seq": int(it.seq),
            "event_id": it.event_id,
            "issued_at": it.issued_at,
            "event_type": it.event_type,
            "payload_hash": it.payload_hash,
            "event_hash": it.event_hash,
            "tenant_id": it.tenant_id,
            "profile_id": it.profile_id,
            "actor_role": it.actor_role,
            "object_ref": it.object_ref,
            "prev_event_hash": (it.prev_event_hash if it.prev_event_hash else None),
            "kid": it.kid,
            "signature_b64u": it.signature_b64u,
            "payload_canon": it.payload_canon,
        })
    return out, next_cursor
