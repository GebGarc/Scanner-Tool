"""Nmap XML parser and importer"""
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from sqlalchemy.orm import Session

from app.db.models import Asset, Service, ImportLog
from app.services.scope import ScopeValidator


class NmapImporter:
    """Parse and import Nmap XML scan results"""
    
    def __init__(self, db: Session, scope_validator: Optional[ScopeValidator] = None):
        self.db = db
        self.scope_validator = scope_validator
        self.warnings = []
        self.out_of_scope_count = 0
    
    def parse_xml(self, xml_path: Path) -> Tuple[List[Dict], List[Dict]]:
        """
        Parse Nmap XML file
        
        Args:
            xml_path: Path to Nmap XML file
            
        Returns:
            Tuple of (assets_data, services_data)
        """
        tree = ET.parse(xml_path)
        root = tree.getroot()
        
        assets_data = []
        services_data = []
        
        # Iterate through hosts
        for host_elem in root.findall('.//host'):
            # Skip hosts that are down
            status = host_elem.find('status')
            if status is not None and status.get('state') != 'up':
                continue
            
            # Extract IP address
            address_elem = host_elem.find("address[@addrtype='ipv4']")
            if address_elem is None:
                address_elem = host_elem.find("address[@addrtype='ipv6']")
            
            if address_elem is None:
                continue
            
            ip_address = address_elem.get('addr')
            if not ip_address:
                continue
            
            # Extract MAC address
            mac_elem = host_elem.find("address[@addrtype='mac']")
            mac_address = mac_elem.get('addr') if mac_elem is not None else None
            
            # Extract hostname
            hostname = None
            hostnames_elem = host_elem.find('hostnames')
            if hostnames_elem is not None:
                hostname_elem = hostnames_elem.find('hostname')
                if hostname_elem is not None:
                    hostname = hostname_elem.get('name')
            
            # Extract OS info
            os_name = None
            os_version = None
            os_elem = host_elem.find('.//osmatch')
            if os_elem is not None:
                os_name = os_elem.get('name')
                # Try to extract version from osclass
                osclass_elem = os_elem.find('osclass')
                if osclass_elem is not None:
                    os_version = osclass_elem.get('osgen')
            
            # Check scope
            in_scope = True
            scope_check_notes = None
            if self.scope_validator:
                # Check IP
                ip_in_scope, ip_reason = self.scope_validator.is_ip_in_scope(ip_address)
                # Check hostname if present
                hostname_in_scope = True
                hostname_reason = None
                if hostname:
                    hostname_in_scope, hostname_reason = self.scope_validator.is_domain_in_scope(hostname)
                
                # Asset is in scope if either IP or hostname matches
                in_scope = ip_in_scope or hostname_in_scope
                if not in_scope:
                    scope_check_notes = f"IP: {ip_reason}; Hostname: {hostname_reason or 'N/A'}"
                    self.out_of_scope_count += 1
                    self.warnings.append(f"Out of scope host: {ip_address} ({hostname or 'no hostname'})")
            
            asset_data = {
                'ip_address': ip_address,
                'hostname': hostname,
                'mac_address': mac_address,
                'os_name': os_name,
                'os_version': os_version,
                'in_scope': in_scope,
                'scope_check_notes': scope_check_notes,
                'source_tool': 'nmap'
            }
            assets_data.append(asset_data)
            
            # Parse ports/services
            ports_elem = host_elem.find('ports')
            if ports_elem is not None:
                for port_elem in ports_elem.findall('port'):
                    port_id_str = port_elem.get('portid')
                    if not port_id_str:
                        continue
                    port_id = int(port_id_str)
                    protocol = port_elem.get('protocol', 'tcp')
                    
                    # Port state
                    state_elem = port_elem.find('state')
                    state = state_elem.get('state') if state_elem is not None else None
                    
                    # Service info
                    service_elem = port_elem.find('service')
                    service_name = None
                    service_product = None
                    service_version = None
                    service_extrainfo = None
                    
                    if service_elem is not None:
                        service_name = service_elem.get('name')
                        service_product = service_elem.get('product')
                        service_version = service_elem.get('version')
                        service_extrainfo = service_elem.get('extrainfo')
                    
                    service_data = {
                        'ip_address': ip_address,  # Link to asset
                        'port': port_id,
                        'protocol': protocol,
                        'state': state,
                        'service_name': service_name,
                        'service_product': service_product,
                        'service_version': service_version,
                        'service_extrainfo': service_extrainfo,
                        'source_tool': 'nmap'
                    }
                    services_data.append(service_data)
        
        return assets_data, services_data
    
    def import_to_db(
        self,
        engagement_id: int,
        xml_path: Path,
        file_hash: str
    ) -> ImportLog:
        """
        Import Nmap XML into database
        
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
            assets_data, services_data = self.parse_xml(xml_path)
            
            # Import assets
            asset_map = {}  # ip -> Asset object
            for asset_data in assets_data:
                # Check if asset already exists
                existing_asset = self.db.query(Asset).filter(
                    Asset.engagement_id == engagement_id,
                    Asset.ip_address == asset_data['ip_address']
                ).first()
                
                if existing_asset:
                    # Update existing
                    for key, value in asset_data.items():
                        if key != 'ip_address':  # Don't update primary identifier
                            setattr(existing_asset, key, value)
                    existing_asset.last_seen = datetime.utcnow()
                    asset = existing_asset
                else:
                    # Create new
                    asset = Asset(
                        engagement_id=engagement_id,
                        **asset_data
                    )
                    self.db.add(asset)
                
                self.db.flush()  # Get ID
                asset_map[asset_data['ip_address']] = asset
            
            # Import services
            for service_data in services_data:
                ip_address = service_data.pop('ip_address')
                asset = asset_map.get(ip_address)
                
                if not asset:
                    continue
                
                # Check if service already exists
                existing_service = self.db.query(Service).filter(
                    Service.asset_id == asset.id,
                    Service.port == service_data['port'],
                    Service.protocol == service_data['protocol']
                ).first()
                
                if existing_service:
                    # Update existing
                    for key, value in service_data.items():
                        setattr(existing_service, key, value)
                else:
                    # Create new
                    service = Service(
                        asset_id=asset.id,
                        **service_data
                    )
                    self.db.add(service)
            
            # Create import log
            import_log = ImportLog(
                engagement_id=engagement_id,
                tool_name='nmap',
                file_name=xml_path.name,
                file_hash=file_hash,
                imported_assets=len(assets_data),
                imported_services=len(services_data),
                out_of_scope_count=self.out_of_scope_count,
                success=True,
                warnings=self.warnings
            )
            self.db.add(import_log)
            self.db.commit()
            
            return import_log
            
        except Exception as e:
            self.db.rollback()
            
            # Create failed import log
            import_log = ImportLog(
                engagement_id=engagement_id,
                tool_name='nmap',
                file_name=xml_path.name,
                file_hash=file_hash,
                success=False,
                error_message=str(e)
            )
            self.db.add(import_log)
            self.db.commit()
            
            raise
