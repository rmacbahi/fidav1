# FIDA Rail V1 — Mandate-Ready Bundle (Architecture + Evidence Pack)

## What this is
A pilot-grade, Tier-0 credible implementation of:
- Tenant-scoped issuance + verification
- RFC8785 canonicalization
- Ed25519 signatures
- Durable ledger in Postgres
- Redis-backed rate limiting
- Checkpoints that include Merkle root
- Merkle inclusion proofs for checkpointed events
- Audit log table
- Alembic migrations
- Ops/compliance templates and infra skeletons

> NOTE: This repo includes the *mechanisms + templates* required for Tier-0 procurement readiness.  
> Actual certifications (SOC2/ISO), pen-test results, and executed key ceremony require real external execution.

## Quickstart (local)
1) Set a real master key:
   - Generate 32 bytes base64url:
     python -c "import os,base64;print(base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('='))"
   Put into docker-compose.yml FIDA_MASTER_KEY_B64.

2) Run:
   docker compose up -d
   docker compose exec api alembic upgrade head

3) Open:
   http://localhost:8080/docs

## Bootstrap
POST /admin/bootstrap with header x-bootstrap-token (dev: dev-bootstrap-token)

Then lock bootstrap:
POST /admin/bootstrap/lock (x-api-key = platform admin key)

## Create tenant
POST /admin/tenants (x-api-key = platform admin key)

## Issue events
POST /issue (x-api-key = issuer key)
Optional: Idempotency-Key header.

## Proofs
After a checkpoint batch occurs (default 5000 events), fetch:
GET /proof/{tenant_id}/{event_id}

## Deploy
See infra/gcp for a starting point.
