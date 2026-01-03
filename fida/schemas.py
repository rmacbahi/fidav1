from pydantic import BaseModel, Field
from typing import Any, Optional, Literal, List, Dict

class BootstrapRequest(BaseModel):
    platform_admin_name: str = Field(default="Owner", max_length=120, min_length=1)

class BootstrapResponse(BaseModel):
    platform_kid: str
    platform_public_key_b64u: str
    platform_admin_api_key: str

class TenantCreateRequest(BaseModel):
    name: str = Field(default="Unnamed Tenant", max_length=120, min_length=1)

class TenantCreateResponse(BaseModel):
    tenant_id: str
    issuer_api_key: str
    verifier_api_key: str
    exporter_api_key: str
    admin_api_key: str
    active_kid: str
    public_key_b64u: str

class ApiKeyIssueRequest(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=80)
    role: Literal["issuer","verifier","exporter","admin"]

class ApiKeyIssueResponse(BaseModel):
    key_id: str
    tenant_id: str
    role: str
    api_key: str

class IssueRequest(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=80)
    profile_id: str = Field(default="HUMAN-MSP-01", min_length=1, max_length=80)
    event_type: str = Field(default="CHANGE", min_length=1, max_length=40)
    actor_role: str = Field(default="agent", min_length=1, max_length=40)
    object_ref: str = Field(default="", max_length=200)
    payload: Dict[str, Any] = Field(default_factory=dict)

class Receipt(BaseModel):
    version: Literal["FES-1.0"] = "FES-1.0"
    tenant_id: str
    event_id: str
    seq: int
    issued_at: str
    profile_id: str
    event_type: str
    actor_role: str
    object_ref: str
    payload_hash: str
    prev_event_hash: Optional[str] = None
    event_hash: str
    kid: str
    signature_b64u: str
    canon_alg: str = "RFC8785"
    hash_alg: str = "SHA-256"

class VerifyRequest(BaseModel):
    receipt: Receipt

class VerifyResult(BaseModel):
    valid: bool
    reason_codes: List[str] = Field(default_factory=list)
    signature_valid: bool
    hash_valid: bool
    chain_hint_ok: bool
    computed_event_hash: Optional[str] = None

class ExportItem(BaseModel):
    seq: int
    event_id: str
    issued_at: str
    event_type: str
    payload_hash: str
    event_hash: str
    tenant_id: str
    profile_id: str
    actor_role: str
    object_ref: str
    prev_event_hash: Optional[str] = None
    kid: str
    signature_b64u: str
    payload_canon: Optional[str] = None
    checkpoint_id: Optional[int] = None
    leaf_index: Optional[int] = None

class ExportIntegrity(BaseModel):
    from_root: str
    to_root: str
    size: int
    page_hash: str

class CheckpointOut(BaseModel):
    tenant_id: str
    size: int
    root_hash: str
    issued_at: str
    platform_kid: str
    signature_b64u: str

class ExportEnvelope(BaseModel):
    tenant_id: str
    items: List[ExportItem]
    next_cursor: Optional[str]
    checkpoint: Optional[CheckpointOut]
    integrity: ExportIntegrity

class MerkleProofOut(BaseModel):
    tenant_id: str
    checkpoint_id: int
    event_id: str
    leaf_index: int
    leaf: str
    root: str
    siblings: List[List[str]]  # [side, hash]
    proof_valid: bool
