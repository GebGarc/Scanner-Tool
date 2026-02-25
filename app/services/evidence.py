"""Evidence storage and management service"""
import shutil
from pathlib import Path
from datetime import datetime
from typing import Optional
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import Evidence, EvidenceType
from app.services.hashing import calculate_sha256


class EvidenceService:
    """Service for managing evidence files"""
    
    def __init__(self, db: Session):
        self.db = db
        self.evidence_dir = settings.evidence_dir
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
    
    def store_evidence(
        self,
        engagement_id: int,
        file_path: Path,
        original_filename: str,
        evidence_type: EvidenceType = EvidenceType.OTHER,
        description: Optional[str] = None,
        uploaded_by: Optional[str] = None
    ) -> Evidence:
        """
        Store evidence file and create database record
        
        Args:
            engagement_id: ID of engagement
            file_path: Path to source file
            original_filename: Original filename
            evidence_type: Type of evidence
            description: Optional description
            uploaded_by: Optional user identifier
            
        Returns:
            Evidence model instance
        """
        # Calculate hash
        file_hash = calculate_sha256(file_path)
        
        # Generate storage filename (hash-based to ensure uniqueness)
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        file_extension = Path(original_filename).suffix
        storage_filename = f"{engagement_id}_{timestamp}_{file_hash[:16]}{file_extension}"
        storage_path = self.evidence_dir / storage_filename
        
        # Copy file to evidence directory
        shutil.copy2(file_path, storage_path)
        
        # Get file size
        file_size = storage_path.stat().st_size
        
        # Create database record
        evidence = Evidence(
            engagement_id=engagement_id,
            filename=storage_filename,
            original_filename=original_filename,
            file_path=str(storage_path),
            file_size=file_size,
            sha256_hash=file_hash,
            evidence_type=evidence_type,
            description=description,
            uploaded_by=uploaded_by
        )
        
        self.db.add(evidence)
        self.db.commit()
        self.db.refresh(evidence)
        
        return evidence
    
    def store_evidence_from_bytes(
        self,
        engagement_id: int,
        file_data: bytes,
        filename: str,
        evidence_type: EvidenceType = EvidenceType.OTHER,
        description: Optional[str] = None,
        uploaded_by: Optional[str] = None
    ) -> Evidence:
        """
        Store evidence from bytes and create database record
        
        Args:
            engagement_id: ID of engagement
            file_data: File bytes
            filename: Filename
            evidence_type: Type of evidence
            description: Optional description
            uploaded_by: Optional user identifier
            
        Returns:
            Evidence model instance
        """
        # Write to temp file first
        temp_path = self.evidence_dir / f"temp_{datetime.utcnow().timestamp()}"
        temp_path.write_bytes(file_data)
        
        try:
            evidence = self.store_evidence(
                engagement_id=engagement_id,
                file_path=temp_path,
                original_filename=filename,
                evidence_type=evidence_type,
                description=description,
                uploaded_by=uploaded_by
            )
            return evidence
        finally:
            # Clean up temp file
            if temp_path.exists():
                temp_path.unlink()
    
    def get_evidence_path(self, evidence: Evidence) -> Path:
        """Get filesystem path for evidence"""
        # Type checker may see file_path as Column[str] instead of str
        # Cast to str to resolve type checking issue
        return Path(str(evidence.file_path))
    
    def delete_evidence(self, evidence_id: int) -> bool:
        """
        Delete evidence file and database record
        
        Args:
            evidence_id: Evidence ID
            
        Returns:
            True if deleted, False if not found
        """
        evidence = self.db.query(Evidence).filter(Evidence.id == evidence_id).first()
        if not evidence:
            return False
        
        # Delete file
        file_path = self.get_evidence_path(evidence)
        if file_path.exists():
            file_path.unlink()
        
        # Delete database record
        self.db.delete(evidence)
        self.db.commit()
        
        return True
