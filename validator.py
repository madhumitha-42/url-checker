import re
import requests
import whois
import dns.resolver
from urllib.parse import urlparse

class URLValidator:
    def __init__(self):
        self.blacklists = [
            'https://urlhaus-api.abuse.ch/v1/urls/recent/',
            'https://www.phishtank.com/developer_info.php'
        ]
        self.suspicious_patterns = [
            r'ip[s]?://', r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',  # IP addresses
            r'bit\.ly|tinyurl|t\.co|goo\.gl',  # URL shorteners
            r'login|sign-in|bank|paypal|amazon',  # Common phishing keywords
            r'\%[0-9a-z]{2}',  # Double encoding
            r'[^\w\s-./?=&%+]',  # Unusual characters
        ]
    
    def is_suspicious_domain(self, domain):
        # Check for common suspicious TLDs and patterns
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            return True
        
        # Multiple subdomains (phishing tactic)
        if domain.count('.') > 3:
            return True
        return False
    
    def check_blacklists(self, url):
        try:
            # Check URLhaus blacklist
            response = requests.get(f'https://urlhaus-api.abuse.ch/v1/url/{url}/', timeout=5)
            if response.json().get('query_status') == 'hit':
                return True
        except:
            pass
        return False
    
    def validate_url(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Basic checks
        if len(domain) > 100 or len(parsed.path) > 200:
            return {'safe': False, 'reason': 'Unusually long URL'}
        
        # Pattern checks
        for pattern in self.suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return {'safe': False, 'reason': 'Suspicious pattern detected'}
        
        # Domain checks
        if self.is_suspicious_domain(domain):
            return {'safe': False, 'reason': 'Suspicious domain'}
        
        # Blacklist check
        if self.check_blacklists(url):
            return {'safe': False, 'reason': 'Found in blacklist'}
        
        return {'safe': True, 'reason': 'URL appears safe'}