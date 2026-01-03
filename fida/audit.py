from __future__ import annotations
from sqlalchemy.orm import Session
from fida.models import AuditLog
from fida.util import json_dumps

def audit(db: Session, actor: str, action: str, tenant_id: str | None, meta: dict, ip: str | None, ua: str | None):
    row = AuditLog(actor=actor, action=action, tenant_id=tenant_id, meta_json=json_dumps(meta), ip=ip, ua=ua)
    db.add(row)
