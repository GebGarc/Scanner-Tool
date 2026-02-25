import asyncio
import logging
import tempfile
import os
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from concurrent.futures import ThreadPoolExecutor

from app.modules.nmap_importer import NmapImporter
from app.db.models import Engagement, ImportLog
from app.core.config import settings
from app.services.hashing import calculate_sha256

logger = logging.getLogger(__name__)

# Global executor for running synchronous subprocesses
executor = ThreadPoolExecutor(max_workers=5)

class NmapScanner:
    """Service to execute nmap scans and import results"""
    
    def __init__(self, db: Session):
        self.db = db
    
    def _execute_nmap_sync(self, nmap_path: str, xml_path: str, target: str, scan_level: str = "intense") -> subprocess.CompletedProcess:
        """Helper to run nmap synchronously (to be called in an executor)"""
        
        # Base flags
        flags = [nmap_path, "-Pn", "-oX", xml_path]
        
        if scan_level == "quick":
            # Fast scan: -F (top 100 ports), -T4 (fast)
            flags.extend(["-F", "-T4"])
        elif scan_level == "stealth":
            # Balanced/Stealth: -sT (Connect scan, no Admin req), -T3 (normal timing)
            # We use -sT on Windows for reliability without needing raw socket privileges
            flags.extend(["-sT", "-T3"])
        else: # intense (default)
            # Intense: -sV (service versions), -sC (default scripts), -T4 (fast)
            flags.extend(["-sV", "-sC", "-T4"])
            
        logger.info(f"🖥️ [Sync Thread] Executing: {' '.join(flags)} {target}")
        flags.append(target)
        
        return subprocess.run(
            flags,
            capture_output=True,
            text=True,
            check=True
        )

    async def scan_target(self, target: str, engagement_id: Optional[int] = None, scan_level: str = "intense") -> Dict[str, Any]:
        """
        Execute nmap scan against a target and import results
        """
        logger.info(f"🚀 Starting Nmap scan for target: {target} (Level: {scan_level})")
        
        if not engagement_id:
            engagement_id = self._get_or_create_default_engagement()
            logger.info(f"📅 Using engagement ID: {engagement_id}")
        
        # Create a temporary file for Nmap XML output
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            xml_path = Path(tmp.name)
        
        try:
            # Full path to nmap discovered during installation
            nmap_path = r"C:\Program Files (x86)\Nmap\nmap.exe"
            
            # Run nmap in a thread pool
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                executor, 
                self._execute_nmap_sync, 
                nmap_path, str(xml_path), target, scan_level
            )
            
            logger.info(f"✅ Nmap scan completed. Importing results...")
            
            # Calculate file hash for ImportLog
            file_hash = calculate_sha256(xml_path)
            
            # Use existing NmapImporter to parse and import results
            importer = NmapImporter(self.db)
            import_log = importer.import_to_db(
                engagement_id=engagement_id,
                xml_path=xml_path,
                file_hash=file_hash
            )
            
            logger.info(f"📊 Imported {import_log.imported_assets} assets and {import_log.imported_services} services.")
            
            return {
                "success": True,
                "target": target,
                "imported_assets": import_log.imported_assets,
                "imported_services": import_log.imported_services,
                "engagement_id": engagement_id,
                "import_log_id": import_log.id
            }
            
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr or str(e)
            logger.error(f"❌ Nmap failed: {error_msg}")
            return {
                "success": False,
                "error": f"Nmap command failed: {error_msg}",
                "target": target
            }
        except Exception as e:
            logger.exception(f"💥 Scan execution failed: {str(e)}")
            return {
                "success": False,
                "error": f"Scan execution failed: {str(e)}",
                "target": target
            }
        finally:
            # Clean up temp file
            if xml_path.exists():
                os.unlink(xml_path)
    
    def _get_or_create_default_engagement(self) -> int:
        """Get or create the 'Default Dashboard' engagement"""
        default_name = "Default Dashboard Engagement"
        engagement = self.db.query(Engagement).filter(Engagement.name == default_name).first()
        
        if not engagement:
            engagement = Engagement(
                name=default_name,
                client_name="Self",
                status="active"
            )
            self.db.add(engagement)
            self.db.commit()
            self.db.refresh(engagement)
        
        return engagement.id
