"""OWASP ZAP JSON/XML parser and importer"""
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional
from sqlalchemy.orm import Session

from app.db.models import Finding, FindingSeverity, FindingStatus, ImportLog
from app.services.scope import ScopeValidator


class ZAPImporter:
    """Parse and import OWASP ZAP scan results"""
    
    # Risk level mapping
    RISK_MAP = {
        'Informational': FindingSeverity.INFO,
        'Low': FindingSeverity.LOW,
        'Medium': FindingSeverity.MEDIUM,
        'High': FindingSeverity.HIGH,
        'Critical': FindingSeverity.CRITICAL
    }
    
    def __init__(self, db: Session, scope_validator: Optional[ScopeValidator] = None):
        self.db = db
        self.scope_validator = scope_validator
        self.warnings = []
        self.out_of_scope_count = 0
    
    def parse_json(self, json_path: Path) -> List[Dict]:
        """Parse ZAP JSON report"""
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        findings_data = []
        
        # ZAP JSON structure: site -> alerts
        sites = data.get('site', [])
        if not isinstance(sites, list):
            sites = [sites]
        
        for site in sites:
            alerts = site.get('alerts', [])
            
            for alert in alerts:
                url = alert.get('url', '')
                
                # Check scope
                in_scope = True
                if self.scope_validator and url:
                    in_scope, _ = self.scope_validator.is_url_in_scope(url)
                    if not in_scope:
                        self.out_of_scope_count += 1
                        self.warnings.append(f"Out of scope URL: {url}")
                        continue  # Skip out of scope
                
                finding_data = {
                    'title': alert.get('alert', 'Unknown Alert'),
                    'description': alert.get('desc', ''),
                    'remediation': alert.get('solution', ''),
                    'severity': self.RISK_MAP.get(alert.get('riskdesc', '').split()[0], FindingSeverity.INFO),
                    'affected_url': url,
                    'affected_parameter': alert.get('param', ''),
                    'proof_of_concept': alert.get('evidence', ''),
                    'source_tool': 'zap',
                    'plugin_id': str(alert.get('pluginid', '')),
                    'external_references': [ref.strip() for ref in alert.get('reference', '').split('\n') if ref.strip()],
                    'cwe_ids': [f"CWE-{alert.get('cweid')}"] if alert.get('cweid') else [],
                    'tags': ['web', 'zap']
                }
                findings_data.append(finding_data)
        
        return findings_data
    
    def parse_xml(self, xml_path: Path) -> List[Dict]:
        """Parse ZAP XML report"""
        tree = ET.parse(xml_path)
        root = tree.getroot()
        
        findings_data = []
        
        for alert_item in root.findall('.//alertitem'):
            url = self._get_text(alert_item, 'uri')
            
            # Check scope
            in_scope = True
            if self.scope_validator and url:
                in_scope, _ = self.scope_validator.is_url_in_scope(url)
                if not in_scope:
                    self.out_of_scope_count += 1
                    self.warnings.append(f"Out of scope URL: {url}")
                    continue
            
            risk_desc = self._get_text(alert_item, 'riskdesc', '')
            risk = risk_desc.split()[0] if risk_desc else 'Informational'
            
            finding_data = {
                'title': self._get_text(alert_item, 'alert', 'Unknown Alert'),
                'description': self._get_text(alert_item, 'desc', ''),
                'remediation': self._get_text(alert_item, 'solution', ''),
                'severity': self.RISK_MAP.get(risk, FindingSeverity.INFO),
                'affected_url': url,
                'affected_parameter': self._get_text(alert_item, 'param', ''),
                'proof_of_concept': self._get_text(alert_item, 'evidence', ''),
                'source_tool': 'zap',
                'plugin_id': self._get_text(alert_item, 'pluginid', ''),
                'external_references': [ref.strip() for ref in self._get_text(alert_item, 'reference', '').split('\n') if ref.strip()],
                'cwe_ids': [f"CWE-{self._get_text(alert_item, 'cweid')}"] if self._get_text(alert_item, 'cweid') else [],
                'tags': ['web', 'zap']
            }
            findings_data.append(finding_data)
        
        return findings_data
    
    def _get_text(self, element, tag_name: str, default: str = '') -> str:
        """Get text content of a child element"""
        child = element.find(tag_name)
        return child.text if child is not None and child.text else default
    
    def import_to_db(
        self,
        engagement_id: int,
        file_path: Path,
        file_hash: str
    ) -> ImportLog:
        """
        Import ZAP report into database
        
        Args:
            engagement_id: Engagement ID
            file_path: Path to ZAP file (JSON or XML)
            file_hash: SHA-256 hash of file
            
        Returns:
            ImportLog record
        """
        self.warnings = []
        self.out_of_scope_count = 0
        
        try:
            # Detect format and parse
            if file_path.suffix.lower() == '.json':
                findings_data = self.parse_json(file_path)
            elif file_path.suffix.lower() in ['.xml', '.html']:
                findings_data = self.parse_xml(file_path)
            else:
                raise ValueError(f"Unsupported file format: {file_path.suffix}")
            
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
                tool_name='zap',
                file_name=file_path.name,
                file_hash=file_hash,
                imported_findings=len(findings_data),
                out_of_scope_count=self.out_of_scope_count,
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
                tool_name='zap',
                file_name=file_path.name,
                file_hash=file_hash,
                success=False,
                error_message=str(e)
            )
            self.db.add(import_log)
            self.db.commit()
            
            raise
