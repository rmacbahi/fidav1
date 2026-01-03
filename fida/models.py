from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import String, Text, Boolean, DateTime, Integer, BigInteger
from sqlalchemy.sql import func

class Base(DeclarativeBase):
    pass

class PlatformState(Base):
    __tablename__ = "platform_state"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    bootstrapped: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    bootstrap_locked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    platform_kid: Mapped[str | None] = mapped_column(String(64), nullable=True)
    platform_pub_b64u: Mapped[str | None] = mapped_column(Text, nullable=True)
    platform_seed_enc_b64u: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[object] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

class ApiKey(Base):
    __tablename__ = "api_keys"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key_id: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    key_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    tenant_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), server_default=func.now())
    revoked_at: Mapped[object | None] = mapped_column(DateTime(timezone=True), nullable=True)

class Tenant(Base):
    __tablename__ = "tenants"
    tenant_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    active_kid: Mapped[str] = mapped_column(String(64), nullable=False)
    pub_b64u: Mapped[str] = mapped_column(Text, nullable=False)
    seed_enc_b64u: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), server_default=func.now())

class Idempotency(Base):
    __tablename__ = "idempotency"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(80), nullable=False)
    idem_key: Mapped[str] = mapped_column(String(120), nullable=False)
    receipt_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), server_default=func.now())

class Event(Base):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(80), nullable=False)
    seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    event_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    issued_at: Mapped[object] = mapped_column(DateTime(timezone=True), nullable=False)
    profile_id: Mapped[str] = mapped_column(String(80), nullable=False)
    event_type: Mapped[str] = mapped_column(String(40), nullable=False)
    actor_role: Mapped[str] = mapped_column(String(40), nullable=False)
    object_ref: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    payload_canon: Mapped[str] = mapped_column(Text, nullable=False)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    prev_event_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    kid: Mapped[str] = mapped_column(String(64), nullable=False)
    signature_b64u: Mapped[str] = mapped_column(Text, nullable=False)
    checkpoint_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    leaf_index: Mapped[int | None] = mapped_column(Integer, nullable=True)

class Checkpoint(Base):
    __tablename__ = "checkpoints"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(80), nullable=False)
    from_seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    to_seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    leaf_count: Mapped[int] = mapped_column(Integer, nullable=False)
    merkle_root: Mapped[str] = mapped_column(String(64), nullable=False)
    page_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    platform_kid: Mapped[str] = mapped_column(String(64), nullable=False)
    signature_b64u: Mapped[str] = mapped_column(Text, nullable=False)
    issued_at: Mapped[object] = mapped_column(DateTime(timezone=True), nullable=False)

class MerkleNode(Base):
    __tablename__ = "merkle_nodes"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    checkpoint_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    level: Mapped[int] = mapped_column(Integer, nullable=False)
    idx: Mapped[int] = mapped_column(Integer, nullable=False)
    hash_hex: Mapped[str] = mapped_column(String(64), nullable=False)

class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ts: Mapped[object] = mapped_column(DateTime(timezone=True), server_default=func.now())
    actor: Mapped[str] = mapped_column(String(120), nullable=False)
    tenant_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    action: Mapped[str] = mapped_column(String(80), nullable=False)
    meta_json: Mapped[str] = mapped_column(Text, nullable=False)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ua: Mapped[str | None] = mapped_column(String(200), nullable=True)
