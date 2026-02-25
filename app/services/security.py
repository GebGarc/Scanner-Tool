import socket
import ssl
import httpx
import re
from datetime import datetime
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

class SecurityAnalysisService:
    """Consolidated service for advanced security analysis features."""

    def __init__(self):
        self.timeout = 10.0
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) GabeApp/1.0 Security Scanner"

    def _get_hostname(self, target: str) -> str:
        """Extract hostname from a string that might be a URL."""
        if not target:
            return ""
        if "://" in target:
            parsed = urlparse(target)
            return parsed.hostname or ""
        return target.split('/')[0].split(':')[0]

    async def analyze_ssl(self, target: str, port: int = 443) -> Dict[str, Any]:
        """Analyze SSL/TLS certificate of a target."""
        hostname = self._get_hostname(target)
        if not hostname:
            return {"error": "Invalid hostname"}
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    if not cert:
                        return {"error": "No certificate found"}

                    # Safely extract subject and issuer info
                    def parse_rdns(rdns) -> Dict[str, str]:
                        data = {}
                        if rdns:
                            for rdn in rdns:
                                for entry in rdn:
                                    if len(entry) >= 2:
                                        data[entry[0]] = entry[1]
                        return data

                    subject_info = parse_rdns(cert.get('subject'))
                    issuer_info = parse_rdns(cert.get('issuer'))
                    
                    # Parse dates - Nmap/SSL format: '%b %d %H:%M:%S %Y %Z'
                    # Note: cert dates are strings like 'Feb 23 20:53:05 2026 GMT'
                    try:
                        not_before = datetime.strptime(str(cert.get('notBefore')), '%b %d %H:%M:%S %Y %Z')
                        not_after = datetime.strptime(str(cert.get('notAfter')), '%b %d %H:%M:%S %Y %Z')
                    except (ValueError, TypeError):
                        # Fallback for different formats
                        return {"error": "Could not parse certificate dates"}
                    
                    now = datetime.utcnow()
                    days_left = (not_after - now).days

                    return {
                        "issuer": issuer_info.get('commonName'),
                        "subject": subject_info.get('commonName'),
                        "not_before": not_before.isoformat(),
                        "not_after": not_after.isoformat(),
                        "expired": now > not_after,
                        "days_left": days_left,
                        "version": cert.get('version'),
                        "serial_number": cert.get('serialNumber'),
                        "cipher": ssock.cipher()
                    }
        except Exception as e:
            return {"error": str(e)}

    async def check_headers(self, url: str) -> Dict[str, Any]:
        """Check for security headers on a given URL."""
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"

        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                response = await client.get(url, headers={"User-Agent": self.user_agent})
                headers = response.headers
                
                results = {}
                security_headers = {
                    "Strict-Transport-Security": "Protects against MITM and cookie hijacking.",
                    "Content-Security-Policy": "Mitigates XSS and data injection attacks.",
                    "X-Frame-Options": "Prevents Clickjacking.",
                    "X-Content-Type-Options": "Prevents MIME sniffing.",
                    "Referrer-Policy": "Controls how much referrer information is shared.",
                    "Permissions-Policy": "Controls which browser features can be used.",
                    "X-XSS-Protection": "Legacy header for XSS filtering (often redundant now)."
                }

                for header, description in security_headers.items():
                    value = headers.get(header)
                    results[header] = {
                        "present": value is not None,
                        "value": value,
                        "description": description
                    }

                return {
                    "url": str(response.url),
                    "status_code": response.status_code,
                    "headers": results,
                    "server": headers.get("Server"),
                    "powered_by": headers.get("X-Powered-By")
                }
        except Exception as e:
            return {"error": str(e)}

    async def enumerate_subdomains(self, domain: str) -> List[str]:
        """Enumerate subdomains using crt.sh Certificate Transparency logs."""
        domain = self._get_hostname(domain)
        if not domain:
            return []
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(url)
                if response.status_code != 200:
                    return []
                
                data = response.json()
                subdomains = set()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    for sub in name_value.split('\n'):
                        if sub.endswith(domain) and not sub.startswith('*.'):
                            subdomains.add(sub.strip().lower())
                
                return sorted(list(subdomains))
        except Exception:
            return []

    async def detect_tech_stack(self, url: str) -> Dict[str, Any]:
        """Fingerprint technology stack based on headers and HTML content."""
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"

        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                response = await client.get(url, headers={"User-Agent": self.user_agent})
                html = response.text
                headers = response.headers
                
                stack = []
                
                # Header checks
                tech_headers = {
                    "X-Powered-By": "Platform",
                    "Server": "Web Server",
                    "X-AspNet-Version": "ASP.NET",
                    "X-Generator": "CMS"
                }
                for h, label in tech_headers.items():
                    if val := headers.get(h):
                        stack.append({"name": val, "type": label})

                # HTML Content Signatures
                signatures = {
                    "WordPress": r"wp-content|wp-includes",
                    "Drupal": r"Drupal.settings",
                    "Joomla": r"content=\"Joomla!",
                    "React": r"data-reactid|react-root",
                    "Angular": r"ng-app|ng-version",
                    "Vue.js": r"vue\.js|Vue",
                    "jQuery": r"jquery\.min\.js",
                    "Bootstrap": r"bootstrap\.min\.css",
                    "Tailwind": r"tailwind\.min\.css"
                }

                for name, pattern in signatures.items():
                    if re.search(pattern, html, re.I):
                        stack.append({"name": name, "type": "Framework/Library/CMS"})

                return {"stack": stack}
        except Exception as e:
            return {"error": str(e)}

    async def check_email_security(self, domain: str) -> Dict[str, Any]:
        """Check DNS records for email security (SPF, DMARC, DKIM)."""
        domain = self._get_hostname(domain)
        if not domain:
            return {"spf": None, "dmarc": None}
        # Note: In a production app, use dnspython. For now, we'll try to use 'nslookup' or similar if available,
        # or implement a basic DNS query if possible. Since we have httpx, we can use a DNS-over-HTTPS provider!
        
        results: Dict[str, Optional[str]] = {"spf": None, "dmarc": None}
        
        # Using Cloudflare DNS-over-HTTPS for DNS lookups
        doh_url = "https://cloudflare-dns.com/query"
        
        async def query_dns(name: str, type: str) -> Optional[str]:
            params = {"name": name, "type": type}
            headers = {"Accept": "application/dns-json"}
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(doh_url, params=params, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    if "Answer" in data:
                        # Return the first TXT record content
                        for answer in data["Answer"]:
                            if answer["type"] == 16: # TXT
                                return answer["data"].strip('"')
            return None

        results["spf"] = await query_dns(domain, "TXT")
        results["dmarc"] = await query_dns(f"_dmarc.{domain}", "TXT")
        
        return results

    async def scan_directories(self, url: str) -> List[Dict[str, Any]]:
        """Scan for common directories and sensitive files."""
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        
        common_paths = [
            ".git/config", ".env", "phpinfo.php", "config.php",
            "wp-admin", "admin", "login", "api", "v1", "backup",
            "db.sql", "dump.sql", ".ssh/id_rsa", "server-status"
        ]
        
        found = []
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
            # First, ensure base URL is accessible
            target_url = url
            try:
                base_resp = await client.get(url)
                target_url = str(base_resp.url).rstrip('/')
            except Exception:
                pass

            for path in common_paths:
                try:
                    target = f"{target_url}/{path}"
                    response = await client.get(target, headers={"User-Agent": self.user_agent})
                    if response.status_code in [200, 301, 302, 403]:
                        found.append({
                            "path": path,
                            "status": response.status_code,
                            "url": target
                        })
                except Exception:
                    continue
        return found
