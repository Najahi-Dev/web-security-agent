"""Unit tests for HTML export functionality."""
from html_exporter import generate_html_report, _render_markdown_to_html


def test_render_markdown_to_html():
    md = "# Heading\n\n- Item 1\n\n| A | B |\n|---|---|\n| 1 | 2 |"
    html = _render_markdown_to_html(md)
    assert "Heading" in html
    assert "<table>" in html
    assert "Item 1" in html


def test_generate_html_report_structure():
    mock_scan = {
        "header_findings": {
            "missing": ["content-security-policy"],
            "leaky_disclosure": {"server": "Apache"},
        },
        "tls": {"tls_version": "TLSv1.3", "days_until_expiry": 120},
        "exposed_paths": [],
    }
    mock_skills = [{"name": "security-headers-audit"}]
    html = generate_html_report("https://target.local", mock_scan, "# Findings\nEverything looks good.", mock_skills)

    assert "<!DOCTYPE html>" in html
    assert "target.local" in html
    assert "TLSv1.3" in html
    assert "Findings" in html
    assert "security-headers-audit" or "Skills Engaged" in html
