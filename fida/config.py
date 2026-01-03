from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    # Core
    env: str = Field(default="prod", alias="FIDA_ENV")
    database_url: str = Field(alias="DATABASE_URL")

    # Bootstrap (one-time)
    bootstrap_token: str = Field(alias="FIDA_BOOTSTRAP_TOKEN")

    # Platform signing key (Ed25519 seed, base64)
    platform_signing_key_b64: str = Field(alias="FIDA_PLATFORM_SIGNING_KEY_B64")

    # Optional
    redis_url: str | None = Field(default=None, alias="REDIS_URL")
    allowed_origins: str = Field(default="*", alias="FIDA_ALLOWED_ORIGINS")

    # Security controls (tune for production)
    max_payload_bytes: int = 64_000
    default_monthly_event_cap: int = 100_000
    default_rps_limit: int = 20  # per api key

    @property
    def allowed_origins_list(self):
        v = (self.allowed_origins or "*").strip()
        if v == "*" or v == "":
            return ["*"]
        return [x.strip() for x in v.split(",") if x.strip()]


settings = Settings()
