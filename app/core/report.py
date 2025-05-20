from typing import List, Dict
import json
from datetime import datetime

class Report:
    def __init__(self, vulnerabilities: List[Dict]):
        self.vulnerabilities = vulnerabilities
        self.timestamp = datetime.utcnow().isoformat()

    def generate_json(self) -> str:
        report = {
            "timestamp": self.timestamp,
            "vulnerabilities": self.vulnerabilities,
            "count": len(self.vulnerabilities)
        }
        return json.dumps(report, indent=2)

    def generate_html(self) -> str:
        html = """
        <html>
        <head>
            <link rel="stylesheet" href="/static/css/style.css">
        </head>
        <body>
            <h1>Bug Bounty Report</h1>
            <p>Generated: {}</p>
            <table>
                <tr><th>Type</th><th>URL</th><th>Payload</th></tr>
                {}
            </table>
        </body>
        </html>
        """.format(self.timestamp, "".join(
            f"<tr><td>{vuln['type']}</td><td>{vuln['url']}</td><td>{vuln['payload']}</td></tr>"
            for vuln in self.vulnerabilities
        ))
        return html
