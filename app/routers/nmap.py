"""Nmap scanning routes"""
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from pathlib import Path

from app.db.session import get_db
from app.services.scanner import NmapScanner
from app.db.models import Asset, Service

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))

@router.post("/scan", response_class=HTMLResponse)
async def perform_scan(
    request: Request,
    target: str = Form(...),
    scan_level: str = Form("intense"),
    db: Session = Depends(get_db)
):
    """Initiate an Nmap scan and return formatted results for HTMX"""
    scanner = NmapScanner(db)
    result = await scanner.scan_target(target, scan_level=scan_level)
    
    if not result["success"]:
        return templates.TemplateResponse(
            "nmap/scan_error.html",
            {"request": request, "error": result["error"], "target": target}
        )
    
    # Fetch the assets and services discovered in this scan to display
    # We can filter by engagement_id and source_tool = 'nmap'
    # For a more precise result, we'd need to track the specific import session
    assets = db.query(Asset).filter(
        Asset.engagement_id == result["engagement_id"],
        Asset.ip_address == result["target"]
    ).all()
    
    return templates.TemplateResponse(
        "nmap/scan_results.html",
        {
            "request": request,
            "target": target,
            "assets": assets,
            "success": True
        }
    )
