from __future__ import annotations
import time
import redis
from fastapi import HTTPException, Request
from fida.config import settings

r = redis.from_url(settings.redis_url, decode_responses=True)

def enforce_rl(request: Request, tenant_id: str | None, key_id: str):
    # Token bucket per API key (or tenant). Simple Redis-based limiter.
    now = int(time.time())
    bucket = f"rl:{key_id}:{now}"
    count = r.incr(bucket)
    if count == 1:
        r.expire(bucket, 2)
    if count > settings.rate_limit_burst:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
