from flask import Blueprint, render_template, request
from app.core.recon import Recon
from app.core.scanner import Scanner
from app.core.report import Report

main = Blueprint("main", __name__)

@main.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        target = request.form.get("target")
        recon = Recon(target)
        subdomains = recon.enumerate_subdomains()
        ports = recon.scan_ports()
        scanner = Scanner(target)
        vulnerabilities = scanner.scan()
        report = Report(vulnerabilities)
        html_report = report.generate_html()
        return render_template("report.html", report=html_report, subdomains=subdomains, ports=ports)
    return render_template("index.html")
