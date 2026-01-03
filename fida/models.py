import datetime as dt
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import String, Integer, BigInteger, Boolean, DateTime, Text, ForeignKey, UniqueConstraint, Index


class Base(DeclarativeBase):
    pass


class PlatformState(Base):
    __tablename__ = "platform_state"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    bootstrapped: Mapped[bool] = mapped_column(Boolean, default=False)
    bootstrap_locked: Mapped[bool] = mapped_column(Boolean, default=False)
    platform_kid: Mapped[str] = mapped_column(String(64), default="")
    platform_admin_name: Mapped[str] = mapped_column(String(120), default="Owner")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=dt.datetime.utcnow)


class Tenant(Base):
    __tablename__ = "tenants"
    tenant_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), default="Unnamed Tenant")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    monthly_event_cap: Mapped[int] = mapped_column(Integer, default=100000)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=dt.datetime.utcnow)


class TenantKey(Base):
    __tablename__ = "tenant_keys"
    key_id: Mapped[str] = mapped_column(String(64), primary_key=True)  # kid
    tenant_id: Mapped[str] = mapped_column(String(80), ForeignKey("tenants.tenant_id", ondelete="CASCADE"))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=dt.datetime.utcnow)
    # store private seed encrypted? for baseline we store seed as base64 in DB; production should use KMS/HSM
    seed_b64: Mapped[str] = mapped_column(Text)

    __table_args__ = (
        Index("ix_tenant_keys_tenant_active", "tenant_id", "active"),
    )


class ApiKey(Base):
    __tablename__ = "api_keys"
    key_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(80), index=True)
    role: Mapped[str] = mapped_column(String(20), index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    # store SHA-256 hash of api key
    key_hash_hex: Mapped[str] = mapped_column(String(64), unique=True)
    label: Mapped[str] = mapped_column(String(120), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=dt.datetime.utcnow)
    expires_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)


class TenantState(Base):
    __tablename__ = "tenant_state"
    tenant_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    next_seq: Mapped[int] = mapped_column(BigInteger, default=1)
    last_event_hash: Mapped[str] = mapped_column(String(64), default="")
    # rolling root hash for integrity (sha256(prev_root || event_hash))
    root_hash: Mapped[str] = mapped_column(String(64), default="")
    size: Mapped[int] = mapped_column(BigInteger, default=0)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=dt.datetime.utcnow)


class LedgerEvent(Base):
    __tablename__ = "ledger_events"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(80), index=True)
    seq: Mapped[int] = mapped_column(BigInteger, index=True)
    event_id: Mapped[str] = mapped_column(String(64), index=True)
    issued_at: Mapped[str] = mapped_column(String(40))
    event_type: Mapped[str] = mapped_column(String(40))
    profile_id: Mapped[str] = mapped_column(String(80))
    actor_role: Mapped[str] = mapped_column(String(40))
    object_ref: Mapped[str] = mapped_column(String(200))
    payload_hash: Mapped[str] = mapped_column(String(64))
    prev_event_hash: Mapped[str] = mapped_column(String(64), default="")
    event_hash: Mapped[str] = mapped_column(String(64), unique=True)
    kid: Mapped[str] = mapped_column(String(64))
    signature_b64u: Mapped[str] = mapped_column(Text)
    payload_canon: Mapped[str | None] = mapped_column(Text, default=None)

    __table_args__ = (
        UniqueConstraint("tenant_id", "seq", name="uq_tenant_seq"),
        Index("ix_ledger_tenant_seq", "tenant_id", "seq"),
    )


class IdempotencyRecord(Base):
    __tablename__ = "idempotency"
    tenant_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    idem_key: Mapped[str] = mapped_column(String(128), primary_key=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=dt.datetime.utcnow)
    receipt_json: Mapped[str] = mapped_column(Text)


class UsageCounter(Base):
    __tablename__ = "usage_counters"
    tenant_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    yyyymm: Mapped[str] = mapped_column(String(6), primary_key=True)
    count: Mapped[int] = mapped_column(BigInteger, default=0)
