import asyncio
import logging
import sys
from fastapi import FastAPI, Request

# Custom logging filter to suppress noisy Nmap probes hitting localhost
class ProbeFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        # Silence access logs (GET/OPTIONS/etc) that result in 404/405 from localhost probes
        if record.name == "uvicorn.access" and isinstance(record.args, (list, tuple)) and len(record.args) >= 5:
            client_addr = record.args[0]
            status_code = record.args[4]
            if client_addr == "127.0.0.1" and status_code in [400, 404, 405]:
                return False
        
        # Silence uvicorn's internal warnings for "Invalid HTTP" which Nmap triggers during version detection
        if record.name == "uvicorn.error":
            msg = record.getMessage()
            noise_markers = [
                "Invalid HTTP request received",
                "Unsupported upgrade request",
                "No supported WebSocket library detected"
            ]
            if any(marker in msg for marker in noise_markers):
                return False
                
        return True

# Apply the filter to both uvicorn loggers
for logger_name in ["uvicorn.access", "uvicorn.error"]:
    logging.getLogger(logger_name).addFilter(ProbeFilter())

from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from contextlib import asynccontextmanager
from pathlib import Path

# Fix for Windows asyncio subprocess (NotImplementedError)
if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from app.core.config import settings
from app.db.session import init_db
from app.routers import nmap, security


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    # Startup
    print(f"🚀 Starting {settings.app_name} v{settings.app_version}")
    settings.ensure_directories()
    init_db()
    print("✅ Database initialized")
    
    yield
    
    # Shutdown
    print("👋 Shutting down...")


# Create FastAPI app
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Recon App - Advanced reconnaissance and analysis suite",
    lifespan=lifespan
)

# Mount static files
static_path = Path(__file__).parent / "static"
static_path.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_path)), name="static")

# Templates
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

# Include routers
app.include_router(nmap.router, prefix="/nmap", tags=["Nmap"])
app.include_router(security.router, prefix="/security", tags=["Security"])


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    """Home page - dashboard"""
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "title": "Dashboard"}
    )


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "app": settings.app_name,
        "version": settings.app_version
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug
    )
