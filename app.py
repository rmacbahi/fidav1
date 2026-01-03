from fastapi import FastAPI
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from starlette.responses import Response

from fida.middleware import BodySizeMiddleware
from fida.api_admin import router as admin_router
from fida.api_public import router as public_router
from fida.jwks import router as jwks_router

app = FastAPI(title="FIDA Rail V1", version="1.0.0")

app.add_middleware(BodySizeMiddleware)

app.include_router(public_router)
app.include_router(admin_router)
app.include_router(jwks_router)

@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
