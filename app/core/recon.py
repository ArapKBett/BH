import dns.resolver
import nmap
from typing import List, Dict

class Recon:
    def __init__(self, target: str):
        self.target = target
        self.subdomains: List[str] = []
        self.ports: Dict[str, str] = {}

    def enumerate_subdomains(self) -> List[str]:
        try:
            resolver = dns.resolver.Resolver()
            answers = resolver.resolve(self.target, "NS")
            for rdata in answers:
                common_subdomains = ["www", "api", "dev", "staging", "test"]
                for sub in common_subdomains:
                    try:
                        subdomain = f"{sub}.{self.target}"
                        resolver.resolve(subdomain, "A")
                        self.subdomains.append(subdomain)
                    except dns.resolver.NXDOMAIN:
                        continue
            return self.subdomains
        except Exception as e:
            print(f"Subdomain enumeration failed: {e}")
            return []

    def scan_ports(self) -> Dict[str, str]:
        try:
            nm = nmap.PortScanner()
            nm.scan(self.target, arguments="-sS -p 1-65535 --open")
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        self.ports[port] = nm[host][proto][port]["state"]
            return self.ports
        except Exception as e:
            print(f"Port scan failed: {e}")
            return {}
