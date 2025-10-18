from fastapi import APIRouter

from . import base, console, domains, storage

router = APIRouter(prefix="/hosts", tags=["Hosts"])
router.include_router(base.router)
router.include_router(domains.router)
router.include_router(storage.router)
router.include_router(console.router)

__all__ = ["router"]
