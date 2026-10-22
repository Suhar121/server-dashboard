import os
from fastapi import APIRouter
from fastapi.responses import FileResponse, HTMLResponse

router = APIRouter(tags=["public-status"])

STATUS_HTML_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "frontend", "status.html")

@router.get("/status")
def get_public_status_default():
    """Serves the standalone public status page for default slug."""
    if os.path.exists(STATUS_HTML_PATH):
        return FileResponse(STATUS_HTML_PATH)
    return HTMLResponse("<h1>Status Page Under Construction</h1>", status_code=200)

@router.get("/status/{slug}")
def get_public_status_page(slug: str):
    """Serves the standalone public status page for a specific slug."""
    if os.path.exists(STATUS_HTML_PATH):
        return FileResponse(STATUS_HTML_PATH)
    return HTMLResponse("<h1>Status Page Under Construction</h1>", status_code=200)
