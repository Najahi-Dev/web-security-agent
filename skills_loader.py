"""
Loads and organizes the curated cybersecurity skills (from mukul975/Anthropic-Cybersecurity-Skills)
that live under ./skills/<skill-name>/SKILL.md

Each SKILL.md is YAML frontmatter + a markdown procedure, following the
agentskills.io standard.
"""
import os
import yaml

SKILLS_DIR = os.path.join(os.path.dirname(__file__), "skills")

SKILL_METADATA = {
    # 1. Web & Headers (Order 1)
    "performing-security-headers-audit": {
        "category": "Web & Headers",
        "category_order": 1,
        "display_title": "HTTP Security Headers Audit",
        "short_desc": "Evaluates HSTS, CSP, X-Frame-Options, and referrer policies",
    },
    "testing-cors-misconfiguration": {
        "category": "Web & Headers",
        "category_order": 1,
        "display_title": "CORS Misconfiguration Audit",
        "short_desc": "Tests cross-origin resource sharing, wildcards, and origin trust",
    },
    "performing-clickjacking-attack-test": {
        "category": "Web & Headers",
        "category_order": 1,
        "display_title": "Clickjacking & UI Redressing Defense",
        "short_desc": "Assesses framing restrictions, X-Frame-Options, and CSP frame-ancestors",
    },
    "testing-for-host-header-injection": {
        "category": "Web & Headers",
        "category_order": 1,
        "display_title": "Host Header Injection Testing",
        "short_desc": "Audits cache poisoning, password reset poisoning, and vhost routing",
    },
    "testing-for-email-header-injection": {
        "category": "Web & Headers",
        "category_order": 1,
        "display_title": "Email / SMTP Header Injection",
        "short_desc": "Tests input fields and mail gateways for CRLF and SMTP relay injection",
    },

    # 2. SSL & TLS (Order 2)
    "performing-ssl-tls-security-assessment": {
        "category": "SSL & TLS",
        "category_order": 2,
        "display_title": "SSL/TLS Server Configuration Assessment",
        "short_desc": "Evaluates cipher suite strength, protocol versions, and TLS flaws",
    },
    "configuring-tls-1-3-for-secure-communications": {
        "category": "SSL & TLS",
        "category_order": 2,
        "display_title": "TLS 1.3 Modern Configuration",
        "short_desc": "Verifies modern TLS 1.3 ciphers, forward secrecy, and 0-RTT security",
    },
    "performing-ssl-certificate-lifecycle-management": {
        "category": "SSL & TLS",
        "category_order": 2,
        "display_title": "Certificate Lifecycle & Expiry Audit",
        "short_desc": "Monitors certificate validity, renewal automation, and PKI health",
    },

    # 3. Injections & Web Attacks (Order 3)
    "testing-for-xss-vulnerabilities": {
        "category": "Injections & Vulns",
        "category_order": 3,
        "display_title": "Cross-Site Scripting (XSS) Vulnerability Audit",
        "short_desc": "Tests reflected, stored, and DOM XSS protections and output encoding",
    },
    "exploiting-sql-injection-vulnerabilities": {
        "category": "Injections & Vulns",
        "category_order": 3,
        "display_title": "SQL Injection (SQLi) Vulnerability Audit",
        "short_desc": "Audits database queries for parameterization and SQLi prevention",
    },
    "performing-second-order-sql-injection": {
        "category": "Injections & Vulns",
        "category_order": 3,
        "display_title": "Second-Order SQL Injection Defense",
        "short_desc": "Evaluates stored payloads executed in secondary application queries",
    },
    "exploiting-nosql-injection-vulnerabilities": {
        "category": "Injections & Vulns",
        "category_order": 3,
        "display_title": "NoSQL Injection Vulnerability Audit",
        "short_desc": "Audits MongoDB and document database query operator sanitization",
    },
    "exploiting-template-injection-vulnerabilities": {
        "category": "Injections & Vulns",
        "category_order": 3,
        "display_title": "Server-Side Template Injection (SSTI)",
        "short_desc": "Checks Jinja2, Twig, and template engines for code execution vulnerabilities",
    },
    "performing-ssrf-vulnerability-exploitation": {
        "category": "Injections & Vulns",
        "category_order": 3,
        "display_title": "Server-Side Request Forgery (SSRF)",
        "short_desc": "Audits URL parameters against cloud metadata endpoints and internal IPs",
    },
    "performing-blind-ssrf-exploitation": {
        "category": "Injections & Vulns",
        "category_order": 3,
        "display_title": "Blind SSRF & Out-of-Band Audit",
        "short_desc": "Tests webhooks, document parsers, and asynchronous network fetching",
    },
    "testing-for-xml-injection-vulnerabilities": {
        "category": "Injections & Vulns",
        "category_order": 3,
        "display_title": "XML Injection Vulnerability Defense",
        "short_desc": "Audits XML parser security, entity expansion, and XPath queries",
    },
    "testing-for-xxe-injection-vulnerabilities": {
        "category": "Injections & Vulns",
        "category_order": 3,
        "display_title": "XML External Entity (XXE) Injection Defense",
        "short_desc": "Verifies disabling of external DTDs and remote entity resolution",
    },
    "exploiting-api-injection-vulnerabilities": {
        "category": "Injections & Vulns",
        "category_order": 3,
        "display_title": "API Injection Vulnerability Defense",
        "short_desc": "Tests REST & GraphQL payloads for injection and deserialization flaws",
    },

    # 4. API Security (Order 4)
    "conducting-api-security-testing": {
        "category": "API Security",
        "category_order": 4,
        "display_title": "API Security & OWASP API Top 10 Testing",
        "short_desc": "Comprehensive audit of REST API authorization, exposure, and tokens",
    },
    "performing-api-security-testing-with-postman": {
        "category": "API Security",
        "category_order": 4,
        "display_title": "API Security Testing Suite (Postman)",
        "short_desc": "Automated regression testing collection for API vulnerabilities",
    },
    "implementing-api-rate-limiting-and-throttling": {
        "category": "API Security",
        "category_order": 4,
        "display_title": "API Rate Limiting & Throttling Hardening",
        "short_desc": "Implements rate limit rules, burst quotas, and DoS mitigation",
    },
    "performing-api-rate-limiting-bypass": {
        "category": "API Security",
        "category_order": 4,
        "display_title": "API Rate Limiting Bypass & Boundary Audit",
        "short_desc": "Audits header spoofing (X-Forwarded-For) and method rotation bypasses",
    },
    "implementing-api-security-posture-management": {
        "category": "API Security",
        "category_order": 4,
        "display_title": "API Security Posture Management (ASPM)",
        "short_desc": "Tracks API inventory drift, shadow endpoints, and sensitive data flow",
    },
    "implementing-api-security-testing-with-42crunch": {
        "category": "API Security",
        "category_order": 4,
        "display_title": "API Conformance Audit (42Crunch)",
        "short_desc": "Validates OpenAPI schemas, contract conformance, and security rules",
    },
    "integrating-dast-with-owasp-zap-in-pipeline": {
        "category": "API Security",
        "category_order": 4,
        "display_title": "OWASP ZAP Dynamic Scanning (DAST)",
        "short_desc": "Full runtime dynamic web and API scanning using OWASP ZAP",
    },

    # 5. Auth & OAuth (Order 5)
    "configuring-oauth2-authorization-flow": {
        "category": "Auth & OAuth",
        "category_order": 5,
        "display_title": "OAuth 2.0 Authorization Flow Hardening",
        "short_desc": "Hardens PKCE, state validation, authorization code flow, and tokens",
    },
    "exploiting-oauth-misconfiguration": {
        "category": "Auth & OAuth",
        "category_order": 5,
        "display_title": "OAuth 2.0 Misconfiguration Audit",
        "short_desc": "Audits redirect URI validation, CSRF state bypass, and token leakage",
    },
    "detecting-oauth-token-theft": {
        "category": "Auth & OAuth",
        "category_order": 5,
        "display_title": "OAuth Token Theft & Replay Detection",
        "short_desc": "Detects token exfiltration, replay attacks, and excessive lifetimes",
    },
    "performing-oauth-scope-minimization-review": {
        "category": "Auth & OAuth",
        "category_order": 5,
        "display_title": "OAuth Scope Minimization & Permission Audit",
        "short_desc": "Audits over-scoped third-party permissions and consent grants",
    },
    "exploiting-idor-vulnerabilities": {
        "category": "Auth & OAuth",
        "category_order": 5,
        "display_title": "IDOR / Broken Object Level Authorization",
        "short_desc": "Tests user data isolation and object-level permission enforcement",
    },
    "exploiting-broken-function-level-authorization": {
        "category": "Auth & OAuth",
        "category_order": 5,
        "display_title": "BFLA Function Level Authorization Audit",
        "short_desc": "Audits role-based access control on administrative and privileged APIs",
    },
    "detecting-broken-object-property-level-authorization": {
        "category": "Auth & OAuth",
        "category_order": 5,
        "display_title": "BOPLA Object Property Level Authorization",
        "short_desc": "Tests mass assignment and unauthorized modification of object attributes",
    },

    # 6. DevSecOps & Supply Chain (Order 6)
    "implementing-secrets-scanning-in-ci-cd": {
        "category": "DevSecOps & Code",
        "category_order": 6,
        "display_title": "Secrets & Credentials Leakage Scanning",
        "short_desc": "Scans for committed API keys, tokens, passwords, and private certs",
    },
    "implementing-semgrep-for-custom-sast-rules": {
        "category": "DevSecOps & Code",
        "category_order": 6,
        "display_title": "Semgrep Custom SAST Rules & Analysis",
        "short_desc": "Integrates static code analysis rules to catch insecure code patterns",
    },
    "integrating-sast-into-github-actions-pipeline": {
        "category": "DevSecOps & Code",
        "category_order": 6,
        "display_title": "SAST Pipeline Integration (CodeQL/Semgrep)",
        "short_desc": "Automates continuous static security testing in CI/CD pull requests",
    },
    "performing-sca-dependency-scanning-with-snyk": {
        "category": "DevSecOps & Code",
        "category_order": 6,
        "display_title": "SCA Dependency Vulnerability Scanning (Snyk)",
        "short_desc": "Scans open-source packages for known CVEs and license compliance",
    },
    "detecting-dependency-confusion": {
        "category": "DevSecOps & Code",
        "category_order": 6,
        "display_title": "Dependency Confusion & Supply Chain Audit",
        "short_desc": "Audits private package registries against public namespace hijacking",
    },

    # 7. Cloud & Containers (Order 7)
    "hardening-docker-containers-for-production": {
        "category": "Cloud & Infra",
        "category_order": 7,
        "display_title": "Production Docker Container Hardening",
        "short_desc": "Enforces non-root users, read-only file systems, and minimal runtimes",
    },
    "performing-container-image-hardening": {
        "category": "Cloud & Infra",
        "category_order": 7,
        "display_title": "Container Image CIS Benchmark Hardening",
        "short_desc": "Shrinks image attack surface and applies CIS Docker benchmarks",
    },
    "detecting-azure-storage-account-misconfigurations": {
        "category": "Cloud & Infra",
        "category_order": 7,
        "display_title": "Azure Storage Account Misconfiguration Audit",
        "short_desc": "Audits storage accounts for public access, unencrypted transfers, and keys",
    },
    "detecting-misconfigured-azure-storage": {
        "category": "Cloud & Infra",
        "category_order": 7,
        "display_title": "Azure Blob & Public Storage Exposure Review",
        "short_desc": "Checks public container access policies and anonymous read permissions",
    },
}


def load_all_skills():
    """Returns a list of dicts: {name, description, tags, subdomain, category, category_order, display_title, short_desc, body, path}."""
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

        meta = SKILL_METADATA.get(skill_name, {
            "category": frontmatter.get("subdomain") or "General Security",
            "category_order": 99,
            "display_title": frontmatter.get("name", skill_name).replace("-", " ").title(),
            "short_desc": frontmatter.get("description", "")[:80],
        })

        skills.append({
            "name": frontmatter.get("name", skill_name),
            "description": frontmatter.get("description", ""),
            "tags": frontmatter.get("tags", []),
            "subdomain": frontmatter.get("subdomain", ""),
            "category": meta["category"],
            "category_order": meta["category_order"],
            "display_title": meta["display_title"],
            "short_desc": meta["short_desc"],
            "body": body,
            "path": skill_path,
        })

    return skills


def pick_relevant_skills(skills, keywords, max_skills=8):
    """Keyword matcher fallback."""
    scored = []
    for skill in skills:
        haystack = " ".join([
            skill["name"],
            skill["display_title"],
            skill["description"],
            " ".join(skill["tags"]),
        ]).lower()
        score = sum(1 for kw in keywords if kw.lower() in haystack)
        if score > 0:
            scored.append((score, skill))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [s for _, s in scored[:max_skills]]


def build_catalog_summary(skills):
    """One line per skill - name + description."""
    lines = []
    for s in skills:
        lines.append(f"- {s['name']}: {s['description']}")
    return "\n".join(lines)


def interactive_select_skills(skills, min_skills=1, max_skills=5):
    """
    Renders an interactive terminal checkbox menu using questionary.
    Allows navigating with Up/Down arrow keys, selecting with Space (min 1, max 5),
    and confirming with Enter.
    """
    import questionary
    from questionary import Style

    custom_style = Style([
        ("qmark", "fg:#38bdf8 bold"),
        ("question", "fg:#ffffff bold"),
        ("answer", "fg:#22c55e bold"),
        ("pointer", "fg:#38bdf8 bold"),
        ("highlighted", "fg:#38bdf8 bold"),
        ("selected", "fg:#22c55e bold"),
        ("separator", "fg:#64748b"),
        ("instruction", "fg:#94a3b8 italic"),
    ])

    sorted_skills = sorted(
        skills,
        key=lambda s: (s.get("category_order", 99), s.get("category", ""), s.get("display_title", s["name"]))
    )

    choices = []
    current_category = None
    default_preselected = ["performing-security-headers-audit", "performing-ssl-tls-security-assessment"]

    for s in sorted_skills:
        cat = s.get("category", "General Security")
        if cat != current_category:
            current_category = cat
            choices.append(questionary.Separator(f"\n  ─── {current_category.upper()} ───"))

        title_str = f"{s['display_title']:<46} | {s['short_desc']}"
        is_checked = s["name"] in default_preselected
        choices.append(questionary.Choice(
            title=title_str,
            value=s,
            checked=is_checked
        ))

    def validate_selection(selected):
        count = len(selected)
        if count < min_skills:
            return f"Please select at least {min_skills} skill (currently selected: {count})."
        if count > max_skills:
            return f"Maximum {max_skills} skills allowed (currently selected: {count}). Press Space to deselect."
        return True

    question_text = (
        f"Select {min_skills} to {max_skills} Security Skills to Audit:\n"
        f"  (Navigate: ↑/↓ | Toggle: Space | Confirm: Enter)\n"
    )

    return questionary.checkbox(
        question_text,
        choices=choices,
        validate=validate_selection,
        style=custom_style
    ).ask()
