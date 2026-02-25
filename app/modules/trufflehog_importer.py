"""TruffleHog JSON parser and importer"""
import json
from pathlib import Path
from typing import Dict, List, Optional
from sqlalchemy.orm import Session

from app.db.models import Finding, FindingSeverity, FindingStatus, ImportLog


class TruffleHogImporter:
    """Parse and import TruffleHog secret scanning results"""
    
    def __init__(self, db: Session):
        self.db = db
        self.warnings = []
    
    def parse_json(self, json_path: Path) -> List[Dict]:
        """
        Parse TruffleHog JSON output
        
        Args:
            json_path: Path to TruffleHog JSON file
            
        Returns:
            List of finding dictionaries
        """
        findings_data = []
        
        with open(json_path, 'r', encoding='utf-8') as f:
            # TruffleHog outputs one JSON object per line
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                
                try:
                    result = json.loads(line)
                except json.JSONDecodeError:
                    self.warnings.append(f"Failed to parse line {line_num}")
                    continue
                
                # Extract relevant fields
                detector_name = result.get('DetectorName', 'Unknown')
                source_name = result.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('file', 'Unknown')
                raw_data = result.get('Raw', '')
                verified = result.get('Verified', False)
                
                # Build title
                title = f"Exposed Secret: {detector_name}"
                if verified:
                    title += " (Verified)"
                
                # Build description
                description = f"**Detector:** {detector_name}\n\n"
                description += f"**Source File:** {source_name}\n\n"
                if verified:
                    description += "**Status:** This secret was verified and is likely valid.\n\n"
                else:
                    description += "**Status:** Unverified potential secret.\n\n"
                
                # Truncate raw data for PoC
                proof = raw_data[:500] + "..." if len(raw_data) > 500 else raw_data
                
                finding_data = {
                    'title': title,
                    'description': description,
                    'remediation': 'Rotate the exposed secret immediately. Review access logs to determine if it was compromised. Implement secret management solutions.',
                    'severity': FindingSeverity.HIGH if verified else FindingSeverity.MEDIUM,
                    'source_tool': 'trufflehog',
                    'proof_of_concept': proof,
                    'category': 'Secrets Exposure',
                    'tags': ['secrets', 'credentials', detector_name.lower()],
                    'external_references': []
                }
                findings_data.append(finding_data)
        
        return findings_data
    
    def import_to_db(
        self,
        engagement_id: int,
        json_path: Path,
        file_hash: str
    ) -> ImportLog:
        """
        Import TruffleHog JSON into database
        
        Args:
            engagement_id: Engagement ID
            json_path: Path to JSON file
            file_hash: SHA-256 hash of file
            
        Returns:
            ImportLog record
        """
        self.warnings = []
        
        try:
            # Parse JSON
            findings_data = self.parse_json(json_path)
            
            # Import findings
            for finding_data in findings_data:
                finding = Finding(
                    engagement_id=engagement_id,
                    **finding_data
                )
                self.db.add(finding)
            
            # Create import log
            import_log = ImportLog(
                engagement_id=engagement_id,
                tool_name='trufflehog',
                file_name=json_path.name,
                file_hash=file_hash,
                imported_findings=len(findings_data),
                success=True,
                warnings=self.warnings
            )
            self.db.add(import_log)
            self.db.commit()
            
            return import_log
            
        except Exception as e:
            self.db.rollback()
            
            import_log = ImportLog(
                engagement_id=engagement_id,
                tool_name='trufflehog',
                file_name=json_path.name,
                file_hash=file_hash,
                success=False,
                error_message=str(e)
            )
            self.db.add(import_log)
            self.db.commit()
            
            raise
