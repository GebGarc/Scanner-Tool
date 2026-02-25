from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from pathlib import Path
from typing import Optional

from app.db.session import get_db
from app.db.models import Engagement
from app.services.security import SecurityAnalysisService

router = APIRouter()
security_service = SecurityAnalysisService()
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))

@router.post("/{engagement_id}/ssl")
async def analyze_ssl(
    request: Request,
    engagement_id: int,
    url: str = Form(...),
    db: Session = Depends(get_db)
):
    """Analyze SSL/TLS certificate."""
    engagement = db.query(Engagement).filter(Engagement.id == engagement_id).first()
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")
    
    result = await security_service.analyze_ssl(url)
    return templates.TemplateResponse(
        "security/results.html",
        {"request": request, "tool": "ssl", "data": result}
    )

@router.post("/{engagement_id}/headers")
async def check_headers(
    request: Request,
    engagement_id: int,
    url: str = Form(...),
    db: Session = Depends(get_db)
):
    """Check security headers."""
    engagement = db.query(Engagement).filter(Engagement.id == engagement_id).first()
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")
    
    result = await security_service.check_headers(url)
    return templates.TemplateResponse(
        "security/results.html", 
        {"request": request, "tool": "headers", "data": result}
    )

@router.post("/{engagement_id}/subdomains")
async def enumerate_subdomains(
    request: Request,
    engagement_id: int,
    domain: str = Form(...),
    db: Session = Depends(get_db)
):
    """Enumerate subdomains."""
    engagement = db.query(Engagement).filter(Engagement.id == engagement_id).first()
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")
    
    result = await security_service.enumerate_subdomains(domain)
    return templates.TemplateResponse(
        "security/results.html",
        {"request": request, "tool": "subdomains", "data": result}
    )

@router.post("/{engagement_id}/tech")
async def detect_tech(
    request: Request,
    engagement_id: int,
    url: str = Form(...),
    db: Session = Depends(get_db)
):
    """Detect tech stack."""
    engagement = db.query(Engagement).filter(Engagement.id == engagement_id).first()
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")
    
    result = await security_service.detect_tech_stack(url)
    return templates.TemplateResponse(
        "security/results.html",
        {"request": request, "tool": "tech", "data": result}
    )

@router.post("/{engagement_id}/email")
async def email_security(
    request: Request,
    engagement_id: int,
    domain: str = Form(...),
    db: Session = Depends(get_db)
):
    """Check email security."""
    engagement = db.query(Engagement).filter(Engagement.id == engagement_id).first()
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")
    
    result = await security_service.check_email_security(domain)
    return templates.TemplateResponse(
        "security/results.html",
        {"request": request, "tool": "email", "data": result}
    )

@router.post("/{engagement_id}/dirs")
async def scan_dirs(
    request: Request,
    engagement_id: int,
    url: str = Form(...),
    db: Session = Depends(get_db)
):
    """Scan for directories."""
    engagement = db.query(Engagement).filter(Engagement.id == engagement_id).first()
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")
    
    result = await security_service.scan_directories(url)
    return templates.TemplateResponse(
        "security/results.html",
        {"request": request, "tool": "dirs", "data": result}
    )
