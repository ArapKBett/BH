import requests
import subprocess
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from typing import List, Dict
import re
import pickle
import base64

class Scanner:
    def __init__(self, target: str):
        self.target = target
        self.vulnerabilities: List[Dict] = []
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "BountyHunter/1.0"})

    def check_xss(self, url: str) -> bool:
        """Check for XSS vulnerabilities."""
        payloads = [
            "<script>alert('xss')</script>",
            "'><img src=x onerror=alert('xss')>",
            "<svg onload=alert('xss')>"
        ]
        for payload in payloads:
            try:
                test_url = f"{url}?q={payload}"
                response = self.session.get(test_url, timeout=5)
                if payload in response.text:
                    self.vulnerabilities.append({
                        "type": "XSS",
                        "url": test_url,
                        "payload": payload
                    })
                    return True
            except requests.RequestException:
                continue
        return False

    def check_sqli(self, url: str) -> bool:
        """Check for SQL injection using sqlmap."""
        try:
            result = subprocess.run(
                ["sqlmap", "-u", url, "--batch", "--level=1", "--risk=1"],
                capture_output=True, text=True, timeout=60
            )
            if "vulnerable" in result.stdout.lower():
                self.vulnerabilities.append({
                    "type": "SQLi",
                    "url": url,
                    "payload": "sqlmap detected vulnerability"
                })
                return True
            return False
        except Exception as e:
            print(f"SQLi scan failed: {e}")
            return False

    def check_lfi(self, url: str) -> bool:
        """Check for Local File Inclusion."""
        payloads = ["../../etc/passwd", "/proc/self/environ"]
        for payload in payloads:
            try:
                test_url = f"{url}?file={payload}"
                response = self.session.get(test_url, timeout=5)
                if "root:x" in response.text or "HOME=" in response.text:
                    self.vulnerabilities.append({
                        "type": "LFI",
                        "url": test_url,
                        "payload": payload
                    })
                    return True
            except requests.RequestException:
                continue
        return False

    def check_rfi(self, url: str) -> bool:
        """Check for Remote File Inclusion."""
        test_file = "https://example.com/malicious.php"
        try:
            test_url = f"{url}?include={test_file}"
            response = self.session.get(test_url, timeout=5)
            if "example.com" in response.text:
                self.vulnerabilities.append({
                    "type": "RFI",
                    "url": test_url,
                    "payload": test_file
                })
                return True
        except requests.RequestException:
            return False
        return False

    def check_idor(self, url: str) -> bool:
        """Check for Insecure Direct Object References."""
        try:
            parsed = urlparse(url)
            if "id=" in parsed.query:
                test_id = str(int(re.search(r"id=(\d+)", url).group(1)) + 1)
                test_url = url.replace(re.search(r"id=\d+", url).group(0), f"id={test_id}")
                response = self.session.get(test_url, timeout=5)
                if response.status_code == 200 and "unauthorized" not in response.text.lower():
                    self.vulnerabilities.append({
                        "type": "IDOR",
                        "url": test_url,
                        "payload": test_id
                    })
                    return True
        except requests.RequestException:
            return False
        return False

    def check_csrf(self, url: str) -> bool:
        """Check for CSRF vulnerabilities."""
        try:
            response = self.session.get(url, timeout=5)
            soup = BeautifulSoup(response.text, "html.parser")
            forms = soup.find_all("form")
            for form in forms:
                if not form.find("input", {"name": re.compile(r"csrf|token", re.I)}):
                    self.vulnerabilities.append({
                        "type": "CSRF",
                        "url": url,
                        "payload": "Missing CSRF token"
                    })
                    return True
        except requests.RequestException:
            return False
        return False

    def check_ssrf(self, url: str) -> bool:
        """Check for Server-Side Request Forgery."""
        test_url = "http://169.254.169.254/latest/meta-data/"  # AWS metadata endpoint
        try:
            test_param = f"{url}?url={test_url}"
            response = self.session.get(test_param, timeout=5)
            if "ami-id" in response.text or "instance-id" in response.text:
                self.vulnerabilities.append({
                    "type": "SSRF",
                    "url": test_param,
                    "payload": test_url
                })
                return True
        except requests.RequestException:
            return False
        return False

    def check_open_redirect(self, url: str) -> bool:
        """Check for open redirect vulnerabilities."""
        test_redirect = "http://evil.com"
        try:
            test_url = f"{url}?redirect={test_redirect}"
            response = self.session.get(test_url, allow_redirects=False, timeout=5)
            if response.status_code in [301, 302] and test_redirect in response.headers.get("Location", ""):
                self.vulnerabilities.append({
                    "type": "Open Redirect",
                    "url": test_url,
                    "payload": test_redirect
                })
                return True
        except requests.RequestException:
            return False
        return False

    def check_misconfig(self, url: str) -> bool:
        """Check for server misconfigurations."""
        headers_to_check = ["Server", "X-Powered-By", "X-AspNet-Version"]
        try:
            response = self.session.get(url, timeout=5)
            for header in headers_to_check:
                if header in response.headers:
                    self.vulnerabilities.append({
                        "type": "Misconfiguration",
                        "url": url,
                        "payload": f"Exposed header: {header} = {response.headers[header]}"
                    })
                    return True
        except requests.RequestException:
            return False
        return False

    def check_insecure_deserialization(self, url: str) -> bool:
        """Check for insecure deserialization vulnerabilities."""
        try:
            payload = base64.b64encode(pickle.dumps({"test": "vulnerable"})).decode()
            test_url = f"{url}?data={payload}"
            response = self.session.get(test_url, timeout=5)
            if response.status_code == 500 or "pickle" in response.text.lower():
                self.vulnerabilities.append({
                    "type": "Insecure Deserialization",
                    "url": test_url,
                    "payload": payload
                })
                return True
        except requests.RequestException:
            return False
        return False

    def scan(self) -> List[Dict]:
        """Run all vulnerability scans on the target."""
        try:
            response = self.session.get(self.target, timeout=5)
            soup = BeautifulSoup(response.text, "html.parser")
            forms = soup.find_all("form")
            links = [urljoin(self.target, a.get("href")) for a in soup.find_all("a", href=True)]
            endpoints = [self.target] + [urljoin(self.target, form.get("action")) for form in forms] + links

            for url in endpoints:
                for check in Config.VULN_CHECKS:
                    method = getattr(self, f"check_{check}", None)
                    if method and method(url):
                        print(f"Potential {check.upper()} found at {url}")
            return self.vulnerabilities
        except Exception as e:
            print(f"Scan failed: {e}")
            return []
