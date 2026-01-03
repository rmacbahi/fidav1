from __future__ import annotations
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from fida.config import settings
from fida.metrics import REQS, LAT
import time

class BodySizeMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # hard cap via Content-Length if present
        cl = request.headers.get("content-length")
        if cl and int(cl) > settings.max_body_bytes:
            return Response("Payload too large", status_code=413)
        # measure actual read body bytes safely for canonical hashing + DoS cap
        body = await request.body()
        if len(body) > settings.max_body_bytes:
            return Response("Payload too large", status_code=413)
        request.state.body_bytes = body  # available to handlers if needed
        # re-inject body for downstream
        async def receive():
            return {"type":"http.request","body":body,"more_body":False}
        request._receive = receive  # type: ignore
        start = time.time()
        resp = await call_next(request)
        dur = time.time() - start
        LAT.labels(path=request.url.path, method=request.method).observe(dur)
        REQS.labels(path=request.url.path, method=request.method, status=str(resp.status_code)).inc()
        return resp
