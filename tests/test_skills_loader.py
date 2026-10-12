"""Unit tests for skills loading and matching engine."""
from skills_loader import load_all_skills, pick_relevant_skills, build_catalog_summary


def test_load_all_skills():
    """Verify skills are discovered and parsed with proper fields."""
    skills = load_all_skills()
    assert isinstance(skills, list)
    assert len(skills) > 0, "Expected at least one skill to be loaded from skills directory"

    first = skills[0]
    assert "name" in first
    assert "description" in first
    assert "body" in first
    assert "tags" in first
    assert isinstance(first["tags"], list)


def test_pick_relevant_skills():
    """Verify keyword scoring returns relevant security skills."""
    skills = load_all_skills()
    keywords = ["security headers", "ssl", "tls"]
    relevant = pick_relevant_skills(skills, keywords, max_skills=5)

    assert isinstance(relevant, list)
    assert len(relevant) <= 5
    # Should find skills matching headers or ssl/tls
    names = [s["name"].lower() for s in relevant]
    has_match = any("header" in n or "ssl" in n or "tls" in n for n in names)
    assert has_match, f"Expected relevant skills matching keywords, got: {names}"


def test_build_catalog_summary():
    """Verify catalog summary formats skill names and descriptions."""
    sample_skills = [
        {"name": "test-skill-1", "description": "Audit headers."},
        {"name": "test-skill-2", "description": "Inspect TLS cert."},
    ]
    summary = build_catalog_summary(sample_skills)
    assert "- test-skill-1: Audit headers." in summary
    assert "- test-skill-2: Inspect TLS cert." in summary
