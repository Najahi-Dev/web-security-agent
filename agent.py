"""
Website Security Check Agent
=============================

A small AI agent that checks a website YOU OWN (or are authorized to test)
against a curated set of cybersecurity skills from:
  https://github.com/mukul975/Anthropic-Cybersecurity-Skills

It does three things:
  1. Runs a read-only recon pass against your site (scanner.py) - headers,
     TLS config, cookie flags, a few commonly-leaked paths.
  2. Routes the findings to the most relevant skill procedures from the
     curated library (skills_loader.py).
  3. Sends both to Claude, which writes a prioritized, plain-English
     report with concrete fixes.

Setup:
    pip install -r requirements.txt
    export ANTHROPIC_API_KEY=sk-ant-...
    python agent.py https://your-own-site.com

Only point this at sites you own or have written permission to test.
"""
import json
import sys
import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from scanner import run_full_scan
from skills_loader import load_all_skills, pick_relevant_skills, build_catalog_summary

DEFAULT_ANTHROPIC_MODEL = "claude-3-5-sonnet-20241022"
DEFAULT_GEMINI_MODEL = "gemini-3.1-flash-lite"


def keywords_from_scan(scan):
    """Turn scan findings into keywords so we can pull the right skills."""
    kws = ["security headers audit", "ssl tls"]

    header_findings = scan.get("header_findings", {})
    for h in header_findings.get("missing", []):
        kws.append(h.replace("-", " "))

    if header_findings.get("leaky_disclosure"):
        kws.append("misconfiguration")

    if scan.get("exposed_paths"):
        kws += ["secrets scanning", "misconfigured", "dependency"]

    tls = scan.get("tls", {})
    if isinstance(tls, dict) and tls.get("days_until_expiry", 999) < 30:
        kws.append("certificate lifecycle")

    cookies = scan.get("http", {}).get("cookies", [])
    if any(not c.get("secure") or not c.get("httponly") for c in cookies):
        kws += ["cookie", "session"]

    return kws


def build_system_prompt(relevant_skills, full_catalog):
    # Focus on defensive, hardening and remediation skills
    defensive_skills = [
        s for s in relevant_skills if not s.get("name", "").startswith("exploiting-")
    ]
    skill_procedures = "\n\n---\n\n".join(
        f"## Skill: {s['name']}\n{s['description']}\n\n{s['body']}"
        for s in defensive_skills
    )

    return f"""You are a defensive cybersecurity engineer and server hardening assistant.
You help a developer audit and harden web applications THEY OWN and manage.
You only provide defensive guidance, configuration snippets (e.g. Nginx, Apache, Cloudflare), and remediation steps.
Never provide exploit payloads or attack steps.

RELEVANT DEFENSIVE SKILL PROCEDURES:
{skill_procedures}

Using the server configuration audit data provided, write a structured hardening report with:
1. A short summary (2-3 sentences) of overall risk level.
2. A prioritized findings list (Critical / High / Medium / Low), each with:
   - What was found
   - Why it matters
   - Concrete configuration fix or directive, citing relevant skills where applicable.
3. Hardening recommendations for additional defense-in-depth."""


def generate_report_gemini(api_key, system_prompt, scan, model=None):
    from google import genai
    from google.genai import types

    client = genai.Client(api_key=api_key)
    
    # Sanitize scan data to emphasize defensive audit context
    clean_scan = dict(scan)
    clean_scan["target"] = "Application Server (Authorized Local Configuration Audit)"
    
    prompt = f"Here is the defensive configuration audit data as JSON:\n\n{json.dumps(clean_scan, indent=2, default=str)}\n\nWrite the defensive security and hardening report."

    preferred_model = model or os.environ.get("GEMINI_MODEL") or DEFAULT_GEMINI_MODEL
    candidates = [preferred_model, "gemini-3.5-flash-lite", "gemini-3-flash-preview", "gemini-3.5-flash"]
    models_to_try = []
    for m in candidates:
        if m and m not in models_to_try:
            models_to_try.append(m)

    last_error = None
    for m in models_to_try:
        try:
            print(f"Generating report using Gemini ({m}) ...")
            response = client.models.generate_content(
                model=m,
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=system_prompt,
                    max_output_tokens=4000,
                ),
            )
            return response.text
        except Exception as e:
            last_error = e
            print(f"Notice: Model {m} encountered an issue ({e}). Trying fallback...")
    if last_error:
        raise last_error
    raise RuntimeError("Failed to generate report: no models were tried or succeeded.")


def generate_report_anthropic(api_key, system_prompt, scan, model=None):
    import anthropic

    client = anthropic.Anthropic(api_key=api_key)
    chosen_model = model or os.environ.get("ANTHROPIC_MODEL") or DEFAULT_ANTHROPIC_MODEL
    print(f"Generating report using Claude ({chosen_model}) ...")
    response = client.messages.create(
        model=chosen_model,
        max_tokens=2000,
        system=system_prompt,
        messages=[{
            "role": "user",
            "content": f"Here is the raw scan data as JSON:\n\n{json.dumps(scan, indent=2, default=str)}\n\nWrite the report.",
        }],
    )
    return "".join(block.text for block in response.content if block.type == "text")


def main():
    if len(sys.argv) < 2:
        print("Usage: python agent.py https://your-own-site.com")
        sys.exit(1)

    target = sys.argv[1]
    gemini_key = os.environ.get("GEMINI_API_KEY")
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY")

    provider = os.environ.get("LLM_PROVIDER", "").lower()
    if not provider:
        if gemini_key:
            provider = "gemini"
        elif anthropic_key:
            provider = "anthropic"
        else:
            print("Error: Please set GEMINI_API_KEY or ANTHROPIC_API_KEY.")
            sys.exit(1)

    print(f"Scanning {target} ...")
    scan = run_full_scan(target)

    print("Loading skill library ...")
    skills = load_all_skills()
    full_catalog = build_catalog_summary(skills)

    kws = keywords_from_scan(scan)
    relevant = pick_relevant_skills(skills, kws, max_skills=6)
    print(f"Matched skills: {[s['name'] for s in relevant]}")

    system_prompt = build_system_prompt(relevant, full_catalog)

    if provider == "gemini":
        report_text = generate_report_gemini(gemini_key, system_prompt, scan)
    elif provider == "anthropic":
        report_text = generate_report_anthropic(anthropic_key, system_prompt, scan)
    else:
        print(f"Unknown LLM_PROVIDER: {provider}")
        sys.exit(1)

    print("\n" + "=" * 70)
    print(report_text)
    print("=" * 70)

    out_file = "security_report.md"
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(f"# Security Report for {target}\n\n{report_text}\n")
    print(f"\nSaved to {out_file}")


if __name__ == "__main__":
    main()
