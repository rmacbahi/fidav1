"""init

Revision ID: 0001_init
Revises:
Create Date: 2026-01-03
"""
from alembic import op
import sqlalchemy as sa

revision = "0001_init"
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    op.create_table(
        "platform_state",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("bootstrapped", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("bootstrap_locked", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("platform_kid", sa.String(length=64), nullable=True),
        sa.Column("platform_pub_b64u", sa.Text(), nullable=True),
        sa.Column("platform_seed_enc_b64u", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_table(
        "api_keys",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("key_id", sa.String(length=80), nullable=False, unique=True),
        sa.Column("key_hash", sa.String(length=128), nullable=False),
        sa.Column("tenant_id", sa.String(length=80), nullable=True),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "tenants",
        sa.Column("tenant_id", sa.String(length=80), primary_key=True),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("active_kid", sa.String(length=64), nullable=False),
        sa.Column("pub_b64u", sa.Text(), nullable=False),
        sa.Column("seed_enc_b64u", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_table(
        "idempotency",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.String(length=80), nullable=False),
        sa.Column("idem_key", sa.String(length=120), nullable=False),
        sa.Column("receipt_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("tenant_id", "idem_key", name="uq_idem_tenant_key"),
    )
    op.create_table(
        "events",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.String(length=80), nullable=False, index=True),
        sa.Column("seq", sa.BigInteger(), nullable=False),
        sa.Column("event_id", sa.String(length=64), nullable=False, unique=True),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("profile_id", sa.String(length=80), nullable=False),
        sa.Column("event_type", sa.String(length=40), nullable=False),
        sa.Column("actor_role", sa.String(length=40), nullable=False),
        sa.Column("object_ref", sa.String(length=200), nullable=False, server_default=""),
        sa.Column("payload_canon", sa.Text(), nullable=False),
        sa.Column("payload_hash", sa.String(length=64), nullable=False),
        sa.Column("prev_event_hash", sa.String(length=64), nullable=True),
        sa.Column("event_hash", sa.String(length=64), nullable=False),
        sa.Column("kid", sa.String(length=64), nullable=False),
        sa.Column("signature_b64u", sa.Text(), nullable=False),
        sa.Column("checkpoint_id", sa.BigInteger(), nullable=True, index=True),
        sa.Column("leaf_index", sa.Integer(), nullable=True),
        sa.UniqueConstraint("tenant_id", "seq", name="uq_tenant_seq"),
    )
    op.create_table(
        "checkpoints",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.String(length=80), nullable=False, index=True),
        sa.Column("from_seq", sa.BigInteger(), nullable=False),
        sa.Column("to_seq", sa.BigInteger(), nullable=False),
        sa.Column("leaf_count", sa.Integer(), nullable=False),
        sa.Column("merkle_root", sa.String(length=64), nullable=False),
        sa.Column("page_hash", sa.String(length=64), nullable=False),
        sa.Column("platform_kid", sa.String(length=64), nullable=False),
        sa.Column("signature_b64u", sa.Text(), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "merkle_nodes",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("checkpoint_id", sa.BigInteger(), nullable=False, index=True),
        sa.Column("level", sa.Integer(), nullable=False),
        sa.Column("idx", sa.Integer(), nullable=False),
        sa.Column("hash_hex", sa.String(length=64), nullable=False),
        sa.UniqueConstraint("checkpoint_id", "level", "idx", name="uq_merkle_node"),
    )
    op.create_table(
        "audit_log",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("actor", sa.String(length=120), nullable=False),
        sa.Column("tenant_id", sa.String(length=80), nullable=True),
        sa.Column("action", sa.String(length=80), nullable=False),
        sa.Column("meta_json", sa.Text(), nullable=False),
        sa.Column("ip", sa.String(length=64), nullable=True),
        sa.Column("ua", sa.String(length=200), nullable=True),
    )

def downgrade():
    op.drop_table("audit_log")
    op.drop_table("merkle_nodes")
    op.drop_table("checkpoints")
    op.drop_table("events")
    op.drop_table("idempotency")
    op.drop_table("tenants")
    op.drop_table("api_keys")
    op.drop_table("platform_state")
