# GCP Infra Skeleton (Draft)
This folder is a starting point for:
- Cloud Run service for API
- Cloud SQL Postgres (PITR)
- Memorystore Redis
- Cloud KMS key for master key / signing key operations (future swap)
- Cloud Storage bucket for immutable exports/checkpoints
- Cloud Armor / LB (edge rate limiting + WAF)

Use Terraform in `infra/gcp` as a scaffold and wire your org/project.
