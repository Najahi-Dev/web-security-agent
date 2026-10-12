"""Unit tests for agent helper functions."""
from agent import keywords_from_scan, build_system_prompt


def test_keywords_from_scan_extracts_expected():
    """Verify keywords are derived properly from scanner output."""
    mock_scan = {
        "header_findings": {
            "missing": ["content-security-policy", "strict-transport-security"],
            "leaky_disclosure": {"server": "Apache"},
        },
        "exposed_paths": [{"path": "/.env", "status_code": 200}],
        "tls": {"days_until_expiry": 10},
        "http": {
            "cookies": [{"name": "session", "secure": False, "httponly": False}]
        },
    }
    kws = keywords_from_scan(mock_scan)
    assert "security headers audit" in kws
    assert "content security policy" in kws
    assert "misconfiguration" in kws
    assert "secrets scanning" in kws
    assert "certificate lifecycle" in kws
    assert "cookie" in kws


def test_build_system_prompt_filters_exploits():
    """Verify build_system_prompt excludes offensive/exploit procedures."""
    sample_skills = [
        {
            "name": "performing-security-headers-audit",
            "description": "Header audit",
            "body": "Remediation step 1",
        },
        {
            "name": "exploiting-sql-injection",
            "description": "Exploit skill",
            "body": "Attack payload",
        },
    ]
    prompt = build_system_prompt(sample_skills, "")
    assert "performing-security-headers-audit" in prompt
    assert "exploiting-sql-injection" not in prompt
    assert "defensive cybersecurity engineer" in prompt


def test_sanitize_and_validate_url():
    """Verify URL normalization and validation."""
    from agent import sanitize_url, is_valid_url

    assert sanitize_url("example.com") == "https://example.com"
    assert sanitize_url("http://example.com") == "http://example.com"
    assert sanitize_url("https://example.com/path") == "https://example.com/path"

    assert is_valid_url("https://example.com") is True
    assert is_valid_url("http://test.co.uk") is True
    assert is_valid_url("not_a_url") is False
    assert is_valid_url("") is False
