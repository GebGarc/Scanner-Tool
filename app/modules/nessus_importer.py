"""Nessus .nessus XML parser and importer"""
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from sqlalchemy.orm import Session

from app.db.models import Asset, Finding, FindingSeverity, FindingStatus, ImportLog
from app.services.scope import ScopeValidator


class NessusImporter:
    """Parse and import Nessus .nessus XML scan results"""
    
    # Severity mapping
    SEVERITY_MAP = {
        '0': FindingSeverity.INFO,
        '1': FindingSeverity.LOW,
        '2': FindingSeverity.MEDIUM,
        '3': FindingSeverity.HIGH,
        '4': FindingSeverity.CRITICAL
    }
    
    def __init__(self, db: Session, scope_validator: Optional[ScopeValidator] = None):
        self.db = db
        self.scope_validator = scope_validator
        self.warnings = []
        self.out_of_scope_count = 0
    
    def parse_xml(self, xml_path: Path) -> Tuple[List[Dict], List[Dict]]:
        """
        Parse Nessus XML file
        
        Args:
            xml_path: Path to .nessus XML file
            
        Returns:
            Tuple of (assets_data, findings_data)
        """
        tree = ET.parse(xml_path)
        root = tree.getroot()
        
        assets_data = []
        findings_data = []
        
        # Iterate through report hosts
        for host_elem in root.findall('.//ReportHost'):
            host_name = host_elem.get('name')
            
            # Extract host properties
            host_properties = {}
            for prop in host_elem.findall('.//HostProperties/tag'):
                prop_name = prop.get('name')
                host_properties[prop_name] = prop.text
            
            # Get IP and hostname
            ip_address = host_properties.get('host-ip', host_name)
            hostname = host_properties.get('host-fqdn') or host_properties.get('hostname')
            os_name = host_properties.get('operating-system')
            mac_address = host_properties.get('mac-address')
            
            # Check scope
            in_scope = True
            scope_check_notes = None
            if self.scope_validator:
                ip_in_scope, ip_reason = self.scope_validator.is_ip_in_scope(ip_address)
                hostname_in_scope = True
                if hostname:
                    hostname_in_scope, _ = self.scope_validator.is_domain_in_scope(hostname)
                
                in_scope = ip_in_scope or hostname_in_scope
                if not in_scope:
                    scope_check_notes = ip_reason
                    self.out_of_scope_count += 1
                    self.warnings.append(f"Out of scope host: {ip_address}")
            
            asset_data = {
                'ip_address': ip_address,
                'hostname': hostname,
                'mac_address': mac_address,
                'os_name': os_name,
                'in_scope': in_scope,
                'scope_check_notes': scope_check_notes,
                'source_tool': 'nessus'
            }
            assets_data.append(asset_data)
            
            # Parse findings (ReportItem elements)
            for item in host_elem.findall('.//ReportItem'):
                plugin_id = item.get('pluginID')
                plugin_name = item.get('pluginName')
                severity = item.get('severity', '0')
                port = item.get('port')
                protocol = item.get('protocol')
                service_name = item.get('svc_name')
                
                # Extract detailed info
                description = self._get_text(item, 'description')
                solution = self._get_text(item, 'solution')
                synopsis = self._get_text(item, 'synopsis')
                plugin_output = self._get_text(item, 'plugin_output')
                
                # CVSS info
                cvss_score = self._get_text(item, 'cvss_base_score')
                cvss_vector = self._get_text(item, 'cvss_vector')
                cvss3_score = self._get_text(item, 'cvss3_base_score')
                cvss3_vector = self._get_text(item, 'cvss3_vector')
                
                # Use CVSS v3 if available, otherwise v2
                final_cvss_score = cvss3_score or cvss_score
                final_cvss_vector = cvss3_vector or cvss_vector
                
                # CVE references
                cve_ids = [cve.text for cve in item.findall('.//cve') if cve.text]
                
                # External references
                see_also = self._get_text(item, 'see_also')
                references = see_also.split('\n') if see_also else []
                
                # Skip informational plugins with severity 0 unless they have CVEs
                if severity == '0' and not cve_ids:
                    continue
                
                finding_data = {
                    'ip_address': ip_address,
                    'title': plugin_name,
                    'description': description or synopsis,
                    'remediation': solution,
                    'severity': self.SEVERITY_MAP.get(severity, FindingSeverity.INFO),
                    'cvss_score': float(final_cvss_score) if final_cvss_score else None,
                    'cvss_vector': final_cvss_vector,
                    'cve_ids': cve_ids,
                    'external_references': references,
                    'source_tool': 'nessus',
                    'plugin_id': plugin_id,
                    'proof_of_concept': plugin_output,
                    'port': port,
                    'protocol': protocol,
                    'service': service_name
                }
                findings_data.append(finding_data)
        
        return assets_data, findings_data
    
    def _get_text(self, element, tag_name: str) -> Optional[str]:
        """Get text content of a child element"""
        child = element.find(tag_name)
        return child.text if child is not None and child.text else None
    
    def import_to_db(
        self,
        engagement_id: int,
        xml_path: Path,
        file_hash: str
    ) -> ImportLog:
        """
        Import Nessus XML into database
        
        Args:
            engagement_id: Engagement ID
            xml_path: Path to XML file
            file_hash: SHA-256 hash of file
            
        Returns:
            ImportLog record
        """
        self.warnings = []
        self.out_of_scope_count = 0
        
        try:
            # Parse XML
            assets_data, findings_data = self.parse_xml(xml_path)
            
            # Import assets (same logic as Nmap)
            asset_map = {}
            for asset_data in assets_data:
                existing_asset = self.db.query(Asset).filter(
                    Asset.engagement_id == engagement_id,
                    Asset.ip_address == asset_data['ip_address']
                ).first()
                
                if existing_asset:
                    for key, value in asset_data.items():
                        if key != 'ip_address':
                            setattr(existing_asset, key, value)
                    asset = existing_asset
                else:
                    asset = Asset(
                        engagement_id=engagement_id,
                        **asset_data
                    )
                    self.db.add(asset)
                
                self.db.flush()
                asset_map[asset_data['ip_address']] = asset
            
            # Import findings
            for finding_data in findings_data:
                ip_address = finding_data.pop('ip_address')
                port = finding_data.pop('port', None)
                protocol = finding_data.pop('protocol', None)
                service = finding_data.pop('service', None)
                
                asset = asset_map.get(ip_address)
                if not asset:
                    continue
                
                # Create or update finding
                finding = Finding(
                    engagement_id=engagement_id,
                    **finding_data
                )
                self.db.add(finding)
                self.db.flush()
                
                # Link to asset
                finding.assets.append(asset)
            
            # Create import log
            import_log = ImportLog(
                engagement_id=engagement_id,
                tool_name='nessus',
                file_name=xml_path.name,
                file_hash=file_hash,
                imported_assets=len(assets_data),
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
                tool_name='nessus',
                file_name=xml_path.name,
                file_hash=file_hash,
                success=False,
                error_message=str(e)
            )
            self.db.add(import_log)
            self.db.commit()
            
            raise
