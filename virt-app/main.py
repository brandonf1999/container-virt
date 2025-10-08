import time
import logging
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

# Local imports
from .core.config import (
    APP_NAME,
    APP_VERSION,
    CORS_ORIGINS,
    CORS_ALLOW_CREDENTIALS,
    CORS_ALLOW_METHODS,
    CORS_ALLOW_HEADERS,
)
from .core.logging import setup_logging
from .api import health, hosts, cluster as cluster_api, system_logs

# Initialize Logging
setup_logging()
logger = logging.getLogger(APP_NAME)

# FastAPI Initialize
app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description="REST API for managing libvirt virtualization hosts via SSH",
)

# Configure CORES
if CORS_ORIGINS:
    logger.info("Enabling CORS for origins: %s", CORS_ORIGINS)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ORIGINS,
        allow_credentials=CORS_ALLOW_CREDENTIALS,
        allow_methods=CORS_ALLOW_METHODS,
        allow_headers=CORS_ALLOW_HEADERS,
    )
else:
    logger.warning("No CORS origins defined in config.yaml; CORS disabled.")


# Simple request timing middleware for visibility
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    duration_ms = int((time.time() - start) * 1000)
    logger.info(
        "%s %s -> %d (%d ms)",
        request.method,
        request.url.path,
        response.status_code,
        duration_ms,
    )
    return response

# Routers
app.include_router(health.router, prefix='/api')
app.include_router(hosts.router, prefix='/api')
app.include_router(cluster_api.router, prefix='/api')
app.include_router(system_logs.router, prefix='/api')

# Optional: lifecycle events
@app.on_event("startup")
async def on_startup():
    logger.info("Starting %s v%s", APP_NAME, APP_VERSION)

@app.on_event("shutdown")
async def on_shutdown():
    logger.info("Shutting down %s", APP_NAME)

@app.get("/", tags=["Root"])
async def root():
    return {
        "message": f"{APP_NAME} API is running",
        "version": APP_VERSION,
        "docs": "/docs",
    }
