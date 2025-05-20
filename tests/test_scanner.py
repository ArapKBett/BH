import pytest
from app.core.scanner import Scanner

@pytest.fixture
def scanner():
    return Scanner("http://example.com")

def test_xss(scanner):
    assert isinstance(scanner.check_xss("http://example.com"), bool)

def test_sqli(scanner):
    assert isinstance(scanner.check_sqli("http://example.com"), bool)

def test_lfi(scanner):
    assert isinstance(scanner.check_lfi("http://example.com"), bool)

def test_full_scan(scanner):
    vulnerabilities = scanner.scan()
    assert isinstance(vulnerabilities, list)
