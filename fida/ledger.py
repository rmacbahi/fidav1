from __future__ import annotations
from datetime import datetime, timezone
import secrets
from sqlalchemy.orm import Session
from sqlalchemy import func, and_
from fida.models import Event, Tenant, Idempotency, Checkpoint, MerkleNode, PlatformState
from fida.config import settings
from fida.canonical import canonicalize, hash_canon
from fida.util import sha256_hex, json_dumps
from fida.crypto import pub_from_b64u, sign_b64u, verify as sig_verify, envelope_decrypt
from fida.merkle import build_merkle
from fida.util import b64u_decode

def compute_event_hash(tenant_id: str, seq: int, issued_at: str, profile_id: str, event_type: str, actor_role: str, object_ref: str, payload_hash: str, prev_event_hash: str | None) -> str:
    parts = [tenant_id, str(seq), issued_at, profile_id, event_type, actor_role, object_ref, payload_hash, prev_event_hash or ""]
    return sha256_hex("|".join(parts).encode("utf-8"))

def issue_event(db: Session, tenant: Tenant, payload: dict, profile_id: str, event_type: str, actor_role: str, object_ref: str, idem_key: str | None, tenant_priv_seed: bytes):
    # idempotency
    if idem_key:
        found = db.query(Idempotency).filter(and_(Idempotency.tenant_id == tenant.tenant_id, Idempotency.idem_key == idem_key)).first()
        if found:
            return found.receipt_json, True

    canon = canonicalize(payload)
    payload_hash = hash_canon(canon)

    last = db.query(func.max(Event.seq)).filter(Event.tenant_id == tenant.tenant_id).scalar()
    seq = int(last or 0) + 1

    prev = db.query(Event).filter(and_(Event.tenant_id == tenant.tenant_id, Event.seq == seq - 1)).first()
    prev_event_hash = prev.event_hash if prev else None

    issued_at_dt = datetime.now(timezone.utc)
    issued_at = issued_at_dt.isoformat()

    event_hash = compute_event_hash(
        tenant_id=tenant.tenant_id,
        seq=seq,
        issued_at=issued_at,
        profile_id=profile_id,
        event_type=event_type,
        actor_role=actor_role,
        object_ref=object_ref,
        payload_hash=payload_hash,
        prev_event_hash=prev_event_hash
    )

    # derive ed25519 key from seed (simple deterministic derivation for v1; in tier0 you can store encrypted seed and rehydrate)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    import hashlib
    seed32 = hashlib.sha256(tenant_priv_seed).digest()[:32]
    priv = Ed25519PrivateKey.from_private_bytes(seed32)

    msg = json_dumps({
        "version":"FES-1.0",
        "tenant_id": tenant.tenant_id,
        "event_id": "", # filled below
        "seq": seq,
        "issued_at": issued_at,
        "profile_id": profile_id,
        "event_type": event_type,
        "actor_role": actor_role,
        "object_ref": object_ref,
        "payload_hash": payload_hash,
        "prev_event_hash": prev_event_hash,
        "event_hash": event_hash,
        "kid": tenant.active_kid,
        "canon_alg": "RFC8785",
        "hash_alg": "SHA-256",
    }).encode("utf-8")

    event_id = sha256_hex(secrets.token_bytes(32))[:32]
    msg = msg.replace(b"\"event_id\":\"\"", f"\"event_id\":\"{event_id}\"".encode("utf-8"))

    signature_b64u = sign_b64u(priv, msg)

    row = Event(
        tenant_id=tenant.tenant_id,
        seq=seq,
        event_id=event_id,
        issued_at=issued_at_dt,
        profile_id=profile_id,
        event_type=event_type,
        actor_role=actor_role,
        object_ref=object_ref or "",
        payload_canon=canon,
        payload_hash=payload_hash,
        prev_event_hash=prev_event_hash,
        event_hash=event_hash,
        kid=tenant.active_kid,
        signature_b64u=signature_b64u,
        checkpoint_id=None,
        leaf_index=None,
    )
    db.add(row)

    receipt = {
        "version":"FES-1.0",
        "tenant_id": tenant.tenant_id,
        "event_id": event_id,
        "seq": seq,
        "issued_at": issued_at,
        "profile_id": profile_id,
        "event_type": event_type,
        "actor_role": actor_role,
        "object_ref": object_ref or "",
        "payload_hash": payload_hash,
        "prev_event_hash": prev_event_hash,
        "event_hash": event_hash,
        "kid": tenant.active_kid,
        "signature_b64u": signature_b64u,
        "canon_alg": "RFC8785",
        "hash_alg": "SHA-256",
    }
    receipt_json = json_dumps(receipt)

    if idem_key:
        db.add(Idempotency(tenant_id=tenant.tenant_id, idem_key=idem_key, receipt_json=receipt_json))

    return receipt_json, False

def verify_receipt(db: Session, tenant: Tenant, receipt: dict) -> dict:
    # recompute hash validity
    # signature validity uses tenant pub key from tenant record
    pub = pub_from_b64u(tenant.pub_b64u)

    required = ["tenant_id","event_id","seq","issued_at","profile_id","event_type","actor_role","object_ref","payload_hash","event_hash","kid","signature_b64u"]
    missing = [k for k in required if k not in receipt]
    if missing:
        return {"valid": False, "reason_codes":[f"missing:{','.join(missing)}"], "signature_valid": False, "hash_valid": False, "chain_hint_ok": False, "computed_event_hash": None}

    computed = compute_event_hash(
        tenant_id=receipt["tenant_id"],
        seq=int(receipt["seq"]),
        issued_at=str(receipt["issued_at"]),
        profile_id=str(receipt["profile_id"]),
        event_type=str(receipt["event_type"]),
        actor_role=str(receipt["actor_role"]),
        object_ref=str(receipt["object_ref"]),
        payload_hash=str(receipt["payload_hash"]),
        prev_event_hash=receipt.get("prev_event_hash")
    )
    hash_valid = (computed == receipt["event_hash"])

    msg = json_dumps({
        "version":receipt.get("version","FES-1.0"),
        "tenant_id":receipt["tenant_id"],
        "event_id":receipt["event_id"],
        "seq":receipt["seq"],
        "issued_at":receipt["issued_at"],
        "profile_id":receipt["profile_id"],
        "event_type":receipt["event_type"],
        "actor_role":receipt["actor_role"],
        "object_ref":receipt["object_ref"],
        "payload_hash":receipt["payload_hash"],
        "prev_event_hash":receipt.get("prev_event_hash"),
        "event_hash":receipt["event_hash"],
        "kid":receipt["kid"],
        "canon_alg":receipt.get("canon_alg","RFC8785"),
        "hash_alg":receipt.get("hash_alg","SHA-256"),
    }).encode("utf-8")

    signature_valid = sig_verify(pub, msg, receipt["signature_b64u"])
    chain_hint_ok = True

    valid = bool(signature_valid and hash_valid and chain_hint_ok)
    reasons = []
    if not signature_valid: reasons.append("sig_invalid")
    if not hash_valid: reasons.append("hash_invalid")
    return {
        "valid": valid,
        "reason_codes": reasons,
        "signature_valid": signature_valid,
        "hash_valid": hash_valid,
        "chain_hint_ok": chain_hint_ok,
        "computed_event_hash": computed,
    }

def maybe_checkpoint(db: Session, tenant_id: str, platform_priv_seed: bytes, platform_kid: str):
    # create checkpoint every N events without checkpoint
    pending = db.query(Event).filter(Event.tenant_id == tenant_id, Event.checkpoint_id.is_(None)).order_by(Event.seq.asc()).limit(settings.checkpoint_batch_size).all()
    if len(pending) < settings.checkpoint_batch_size:
        return None

    from_seq = int(pending[0].seq)
    to_seq = int(pending[-1].seq)

    leaves = [e.event_hash for e in pending]
    root, layers = build_merkle(leaves)

    # page hash = hash of concatenated event_hashes (simple integrity of export page)
    page_hash = sha256_hex(("|".join(leaves)).encode("utf-8"))

    # sign checkpoint with platform key derived from seed
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    import hashlib
    seed32 = hashlib.sha256(platform_priv_seed).digest()[:32]
    priv = Ed25519PrivateKey.from_private_bytes(seed32)

    issued_at_dt = datetime.now(timezone.utc)
    issued_at = issued_at_dt.isoformat()
    msg = json_dumps({
        "tenant_id": tenant_id,
        "from_seq": from_seq,
        "to_seq": to_seq,
        "leaf_count": len(leaves),
        "root_hash": root,
        "page_hash": page_hash,
        "issued_at": issued_at,
        "platform_kid": platform_kid,
    }).encode("utf-8")
    sig = sign_b64u(priv, msg)

    cp = Checkpoint(
        tenant_id=tenant_id,
        from_seq=from_seq,
        to_seq=to_seq,
        leaf_count=len(leaves),
        merkle_root=root,
        page_hash=page_hash,
        platform_kid=platform_kid,
        signature_b64u=sig,
        issued_at=issued_at_dt,
    )
    db.add(cp)
    db.flush()  # get cp.id

    # store merkle layers as nodes for proofs
    for lvl, layer in enumerate(layers):
        for idx, h in enumerate(layer):
            db.add(MerkleNode(checkpoint_id=cp.id, level=lvl, idx=idx, hash_hex=h))

    # assign checkpoint_id + leaf_index
    for i, e in enumerate(pending):
        e.checkpoint_id = cp.id
        e.leaf_index = i

    return cp.id
