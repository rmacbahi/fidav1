from pydantic_settings import BaseSettings
from pydantic import Field

class Settings(BaseSettings):
    fida_env: str = Field(default="dev", alias="FIDA_ENV")
    database_url: str = Field(alias="DATABASE_URL")
    redis_url: str = Field(alias="REDIS_URL")
    fida_master_key_b64: str = Field(alias="FIDA_MASTER_KEY_B64")
    fida_bootstrap_token: str = Field(default="", alias="FIDA_BOOTSTRAP_TOKEN")
    rate_limit_rps: int = Field(default=20, alias="FIDA_RATE_LIMIT_RPS")
    rate_limit_burst: int = Field(default=40, alias="FIDA_RATE_LIMIT_BURST")
    checkpoint_batch_size: int = Field(default=5000, alias="FIDA_CHECKPOINT_BATCH")
    max_body_bytes: int = Field(default=200_000, alias="FIDA_MAX_BODY_BYTES")

settings = Settings()
