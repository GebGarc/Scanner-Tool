"""OSINT services - Wayback Machine, WHOIS, Hunter.io"""
import httpx
import json
from typing import Optional, Dict, List
from datetime import datetime
from sqlalchemy.orm import Session

from app.db.models import OSINTResult
from app.core.config import settings


class WaybackService:
    """Wayback Machine API service"""
    
    BASE_URL = "https://web.archive.org/cdx/search/cdx"
    
    async def lookup_snapshots(
        self,
        url: str,
        limit: int = 100
    ) -> List[Dict]:
        """
        Fetch Wayback Machine snapshots for a URL
        
        Args:
            url: Target URL or domain
            limit: Maximum number of snapshots
            
        Returns:
            List of snapshot dictionaries
        """
        params = {
            'url': url,
            'output': 'json',
            'limit': limit,
            'fl': 'timestamp,original,statuscode,mimetype'
        }
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(self.BASE_URL, params=params)
            response.raise_for_status()
            
            data = response.json()
            
            # First row is headers
            if len(data) < 2:
                return []
            
            headers = data[0]
            snapshots = []
            
            for row in data[1:]:
                snapshot = dict(zip(headers, row))
                # Build snapshot URL
                timestamp = snapshot.get('timestamp', '')
                original = snapshot.get('original', '')
                snapshot['snapshot_url'] = f"https://web.archive.org/web/{timestamp}/{original}"
                snapshots.append(snapshot)
            
            return snapshots
    
    async def store_lookup(
        self,
        db: Session,
        engagement_id: int,
        url: str,
        limit: int = 100
    ) -> OSINTResult:
        """Store Wayback lookup in database"""
        snapshots = await self.lookup_snapshots(url, limit)
        
        result = OSINTResult(
            engagement_id=engagement_id,
            lookup_type='wayback',
            target=url,
            raw_data={'snapshots': snapshots},
            parsed_data={
                'count': len(snapshots),
                'latest_snapshot': snapshots[0] if snapshots else None
            }
        )
        
        db.add(result)
        db.commit()
        db.refresh(result)
        
        return result


class WHOISService:
    """WHOIS lookup service"""
    
    async def lookup_domain(self, domain: str) -> Dict:
        """
        Perform WHOIS lookup
        
        Args:
            domain: Domain name
            
        Returns:
            WHOIS data dictionary
        """
        try:
            import whois
            
            # Perform WHOIS lookup
            w = whois.whois(domain)
            
            # Convert to dict
            data = {
                'domain_name': w.get('domain_name'),
                'registrar': w.get('registrar'),
                'whois_server': w.get('whois_server'),
                'creation_date': str(w.get('creation_date')) if w.get('creation_date') else None,
                'expiration_date': str(w.get('expiration_date')) if w.get('expiration_date') else None,
                'updated_date': str(w.get('updated_date')) if w.get('updated_date') else None,
                'status': w.get('status'),
                'name_servers': w.get('name_servers'),
                'emails': w.get('emails'),
                'org': w.get('org'),
                'address': w.get('address'),
                'city': w.get('city'),
                'state': w.get('state'),
                'country': w.get('country')
            }
            
            return data
            
        except Exception as e:
            return {'error': str(e)}
    
    async def store_lookup(
        self,
        db: Session,
        engagement_id: int,
        domain: str
    ) -> OSINTResult:
        """Store WHOIS lookup in database"""
        whois_data = await self.lookup_domain(domain)
        
        result = OSINTResult(
            engagement_id=engagement_id,
            lookup_type='whois',
            target=domain,
            raw_data=whois_data,
            parsed_data={
                'registrar': whois_data.get('registrar'),
                'creation_date': whois_data.get('creation_date'),
                'expiration_date': whois_data.get('expiration_date')
            }
        )
        
        db.add(result)
        db.commit()
        db.refresh(result)
        
        return result


class HunterIOService:
    """Hunter.io email discovery service (optional, requires API key)"""
    
    BASE_URL = "https://api.hunter.io/v2"
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or settings.hunter_io_api_key
    
    async def domain_search(
        self,
        domain: str,
        limit: int = 10
    ) -> Dict:
        """
        Search for emails associated with a domain
        
        Args:
            domain: Target domain
            limit: Maximum results
            
        Returns:
            Hunter.io API response
        """
        if not self.api_key:
            return {'error': 'Hunter.io API key not configured'}
        
        params = {
            'domain': domain,
            'api_key': self.api_key,
            'limit': limit
        }
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(f"{self.BASE_URL}/domain-search", params=params)
            response.raise_for_status()
            
            return response.json()
    
    async def store_lookup(
        self,
        db: Session,
        engagement_id: int,
        domain: str,
        limit: int = 10
    ) -> OSINTResult:
        """Store Hunter.io lookup in database with audit logging"""
        hunter_data = await self.domain_search(domain, limit)
        
        # Extract emails
        emails = []
        if 'data' in hunter_data and 'emails' in hunter_data['data']:
            emails = [email['value'] for email in hunter_data['data']['emails']]
        
        result = OSINTResult(
            engagement_id=engagement_id,
            lookup_type='hunter',
            target=domain,
            raw_data=hunter_data,
            parsed_data={
                'email_count': len(emails),
                'emails': emails
            }
        )
        
        db.add(result)
        db.commit()
        db.refresh(result)
        
        return result
