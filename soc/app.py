"""
PRAMAAN SOC — FastAPI sub-app mounted at /soc.

Serves the analyst command center UI (HTML pages, not JSON APIs).
Uses Jinja2 for templates, HTMX for dynamic panels, Alpine.js for
lightweight client-side interactivity.

Ref: Issue #75
"""
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates


SOC_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = SOC_DIR / "templates"
STATIC_DIR = SOC_DIR / "static"

TEMPLATES_DIR.mkdir(exist_ok=True)
(TEMPLATES_DIR / "panels").mkdir(exist_ok=True)

soc_app = FastAPI(
    title="PRAMAAN SOC",
    description="Analyst Command Center",
    docs_url=None,
    redoc_url=None,
)

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
soc_app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="soc-static")


@soc_app.get("/", response_class=HTMLResponse)
async def soc_index(request: Request):
    """Main SOC command center page."""
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"title": "PRAMAAN SOC"},
    )

@soc_app.get("/panels/{name}", response_class=HTMLResponse)
async def soc_panel(request: Request, name: str):
    """
    HTMX partial endpoint. Returns a small HTML fragment that the
    client can swap into the page without a full reload.

    Template lookup: templates/panels/{name}.html
    """
    template_name = f"panels/{name}.html"
    return templates.TemplateResponse(
        request=request,
        name=template_name,
    )