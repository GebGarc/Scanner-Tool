"""Scope validation service"""
import re
import ipaddress
from typing import List, Tuple, Optional
from urllib.parse import urlparse


class ScopeValidator:
    """Validates targets against engagement scope allowlist"""
    
    def __init__(
        self,
        domains: Optional[List[str]] = None,
        ips: Optional[List[str]] = None,
        urls: Optional[List[str]] = None
    ):
        """
        Initialize validator with scope allowlists
        
        Args:
            domains: List of allowed domains (exact or wildcard like *.example.com)
            ips: List of allowed IPs/CIDRs (e.g., 192.168.1.0/24, 10.0.0.1)
            urls: List of allowed base URLs
        """
        self.domains = domains or []
        self.ips = ips or []
        self.urls = urls or []
        
        # Parse IP networks for efficient matching
        self.ip_networks = []
        for ip_str in self.ips:
            try:
                # Try parsing as network (with CIDR)
                network = ipaddress.ip_network(ip_str, strict=False)
                self.ip_networks.append(network)
            except ValueError:
                # Skip invalid entries
                continue
    
    def is_domain_in_scope(self, domain: str) -> Tuple[bool, str]:
        """
        Check if domain is in scope
        
        Args:
            domain: Domain to check
            
        Returns:
            Tuple of (is_in_scope, reason)
        """
        if not domain:
            return False, "Empty domain"
        
        domain_lower = domain.lower().strip()
        
        # Check exact matches
        for allowed in self.domains:
            allowed_lower = allowed.lower().strip()
            
            # Wildcard match (*.example.com)
            if allowed_lower.startswith("*."):
                suffix = allowed_lower[2:]  # Remove *.
                if domain_lower == suffix or domain_lower.endswith("." + suffix):
                    return True, f"Matches wildcard: {allowed}"
            
            # Exact match
            elif domain_lower == allowed_lower:
                return True, f"Exact match: {allowed}"
        
        return False, "Domain not in allowlist"
    
    def is_ip_in_scope(self, ip: str) -> Tuple[bool, str]:
        """
        Check if IP address is in scope
        
        Args:
            ip: IP address to check
            
        Returns:
            Tuple of (is_in_scope, reason)
        """
        if not ip:
            return False, "Empty IP"
        
        try:
            ip_obj = ipaddress.ip_address(ip.strip())
        except ValueError:
            return False, f"Invalid IP address: {ip}"
        
        # Check against all allowed networks
        for network in self.ip_networks:
            if ip_obj in network:
                return True, f"Matches network: {network}"
        
        return False, "IP not in allowlist"
    
    def is_url_in_scope(self, url: str) -> Tuple[bool, str]:
        """
        Check if URL is in scope
        
        Args:
            url: URL to check
            
        Returns:
            Tuple of (is_in_scope, reason)
        """
        if not url:
            return False, "Empty URL"
        
        try:
            parsed = urlparse(url)
            
            # Check if domain is in scope
            if parsed.hostname:
                domain_in_scope, domain_reason = self.is_domain_in_scope(parsed.hostname)
                if domain_in_scope:
                    return True, f"Domain in scope: {domain_reason}"
            
            # Check against URL allowlist (base URL matching)
            for allowed_url in self.urls:
                allowed_parsed = urlparse(allowed_url)
                
                # Match scheme and hostname
                if (parsed.scheme == allowed_parsed.scheme and 
                    parsed.hostname == allowed_parsed.hostname and
                    parsed.port == allowed_parsed.port):
                    
                    # Check if path starts with allowed path
                    allowed_path = allowed_parsed.path.rstrip('/')
                    target_path = parsed.path.rstrip('/')
                    
                    if target_path.startswith(allowed_path):
                        return True, f"Matches base URL: {allowed_url}"
            
            return False, "URL not in allowlist"
            
        except Exception as e:
            return False, f"Error parsing URL: {str(e)}"
    
    def check_target(self, target: str) -> Tuple[bool, str, str]:
        """
        Auto-detect target type and validate
        
        Args:
            target: IP, domain, or URL
            
        Returns:
            Tuple of (is_in_scope, target_type, reason)
        """
        target = target.strip()
        
        # Try IP first
        try:
            ipaddress.ip_address(target)
            in_scope, reason = self.is_ip_in_scope(target)
            return in_scope, "ip", reason
        except ValueError:
            pass
        
        # Try URL (has scheme)
        if "://" in target:
            in_scope, reason = self.is_url_in_scope(target)
            return in_scope, "url", reason
        
        # Assume domain
        in_scope, reason = self.is_domain_in_scope(target)
        return in_scope, "domain", reason
    
    @staticmethod
    def from_engagement(engagement) -> "ScopeValidator":
        """Create validator from Engagement model"""
        return ScopeValidator(
            domains=engagement.scope_domains or [],
            ips=engagement.scope_ips or [],
            urls=engagement.scope_urls or []
        )
