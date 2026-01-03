# Security Questionnaire (Draft)
- Data storage: Postgres (encrypted at rest via cloud provider)
- Key storage: envelope encrypted seeds; upgrade path to Cloud KMS
- Access: tenant-scoped API keys; rotation + revocation supported
- Logging: audit_log table + export hooks
- Backups: PITR + restore drills (see scripts)
