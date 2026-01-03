# FIDA Rail V1 (Mandate-aligned baseline)

This service implements:
- Multi-tenant append-only ledger
- Ed25519 receipt signing per tenant (and platform checkpoint signing)
- Idempotent issuance
- Export integrity + checkpoints
- API-key roles (issuer/verifier/exporter/admin)
- Bootstrap token (one-time) + bootstrap lock
- Tenant quotas + rate limiting (Redis if provided)

## Run
Replit uses `.replit` command.

## Required env
- DATABASE_URL
- FIDA_BOOTSTRAP_TOKEN
- FIDA_PLATFORM_SIGNING_KEY_B64

## First bootstrap (ONE TIME)
POST /admin/bootstrap with header:
- x-bootstrap-token: $FIDA_BOOTSTRAP_TOKEN
Body: {"platform_admin_name":"Owner"}

Then immediately:
POST /admin/bootstrap/lock with header:
- x-api-key: <platform_admin_api_key>

---
