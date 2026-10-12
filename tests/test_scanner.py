"""Unit tests for the scanner module."""
from scanner import check_missing_security_headers, SECURITY_HEADERS, LEAKY_HEADERS


def test_check_missing_security_headers_all_missing():
    """Verify all expected security headers are reported missing when none provided."""
    findings = check_missing_security_headers({})
    assert "missing" in findings
    assert "leaky_disclosure" in findings
    assert len(findings["missing"]) == len(SECURITY_HEADERS)
    assert findings["leaky_disclosure"] == {}


def test_check_missing_security_headers_detects_present():
    """Verify headers present in response are excluded from the missing list."""
    mock_headers = {
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Server": "nginx/1.24.0",
        "X-Powered-By": "PHP/8.2.0",
    }
    findings = check_missing_security_headers(mock_headers)
    assert "content-security-policy" not in findings["missing"]
    assert "strict-transport-security" not in findings["missing"]
    assert "x-frame-options" in findings["missing"]
    assert findings["leaky_disclosure"].get("server") == "nginx/1.24.0"
    assert findings["leaky_disclosure"].get("x-powered-by") == "PHP/8.2.0"
