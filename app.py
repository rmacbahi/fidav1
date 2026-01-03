from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fida.config import settings
from fida.routers.public import router as public_router
from fida.routers.admin import router as admin_router
from fida.routers.jwks import router as jwks_router
from fida.db import init_db
from fida.middleware import RequestIdMiddleware

app = FastAPI(
    title="FIDA Rail V1",
    version="1.0.0",
    docs_url="/docs",
    redoc_url=None,
)

app.add_middleware(RequestIdMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins_list,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(public_router)
app.include_router(admin_router)
app.include_router(jwks_router)


@app.on_event("startup")
def _startup():
    init_db()
