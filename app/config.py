import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    HACKERONE_API_TOKEN = os.getenv("HACKERONE_API_TOKEN", "")
    SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key")
    RECON_TOOLS = {
        "subdomain": "dnsresolver",
        "port_scan": "nmap"
    }
    SCAN_TIMEOUT = 3600  # Seconds
    ALLOWED_DOMAINS = https://www.kayak.com  # Populated by HackerOne program scope
    VULN_CHECKS = [
        "xss", "sqli", "lfi", "rfi", "idor", "csrf", "ssrf",
        "open_redirect", "misconfig", "insecure_deserialization"
    ]  # Comprehensive vulnerability checks
