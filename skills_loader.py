"""
Loads the curated cybersecurity skills (from mukul975/Anthropic-Cybersecurity-Skills)
that live under ./skills/<skill-name>/SKILL.md

Each SKILL.md is YAML frontmatter + a markdown procedure, following the
agentskills.io standard used by that repo.
"""
import os
import yaml

SKILLS_DIR = os.path.join(os.path.dirname(__file__), "skills")


def load_all_skills():
    """Returns a list of dicts: {name, description, tags, body, path}."""
    skills = []
    if not os.path.isdir(SKILLS_DIR):
        return skills

    for skill_name in sorted(os.listdir(SKILLS_DIR)):
        skill_path = os.path.join(SKILLS_DIR, skill_name, "SKILL.md")
        if not os.path.isfile(skill_path):
            continue

        with open(skill_path, "r", encoding="utf-8") as f:
            raw = f.read()

        if raw.startswith("---"):
            parts = raw.split("---", 2)
            frontmatter = yaml.safe_load(parts[1]) or {}
            body = parts[2].strip()
        else:
            frontmatter = {}
            body = raw

        skills.append({
            "name": frontmatter.get("name", skill_name),
            "description": frontmatter.get("description", ""),
            "tags": frontmatter.get("tags", []),
            "subdomain": frontmatter.get("subdomain", ""),
            "body": body,
            "path": skill_path,
        })

    return skills


def pick_relevant_skills(skills, keywords, max_skills=8):
    """
    Very simple keyword matcher: scores each skill by how many of the
    given keywords appear in its name/description/tags, returns the
    top matches. Good enough for routing a finding to the right
    skill procedure without needing embeddings.
    """
    scored = []
    for skill in skills:
        haystack = " ".join([
            skill["name"],
            skill["description"],
            " ".join(skill["tags"]),
        ]).lower()
        score = sum(1 for kw in keywords if kw.lower() in haystack)
        if score > 0:
            scored.append((score, skill))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [s for _, s in scored[:max_skills]]


def build_catalog_summary(skills):
    """One line per skill - name + description. Used as the system prompt's skill index."""
    lines = []
    for s in skills:
        lines.append(f"- {s['name']}: {s['description']}")
    return "\n".join(lines)
