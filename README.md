# Website Security Check Agent

A small AI agent for checking websites **you own or are authorized to
test**. It's built on a curated slice of the open-source
[Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills)
library (818 skills total).

## Why only some skills, not all 818

That repo covers a huge range: malware reverse engineering, Active
Directory attacks, ransomware forensics, OT/ICS security, red-team C2
infrastructure, and more. Loading all of it would bloat the agent with
things that have nothing to do with "is my website configured safely" -
and some of it (credential-dumping techniques, AD privilege escalation,
C2 tradecraft) isn't relevant or appropriate for a tool whose job is to
audit your own site's config.

This agent ships with **41 skills** from the domains that actually
apply to web app checks: `web-application-security`, `api-security`,
`devsecops`, and a few `cryptography`/`cloud-security` skills for TLS
and storage misconfig. They live under `skills/`. You can add more by
copying any other `skills/<name>/SKILL.md` folder from the source repo
into this project's `skills/` directory - `skills_loader.py` picks up
anything that's there.

## What it checks

`scanner.py` does **read-only** recon against your target - it never
sends attack payloads or tries to bypass anything:
- Missing/misconfigured security headers (CSP, HSTS, X-Frame-Options, etc.)
- Information-leaking headers (`Server`, `X-Powered-By`)
- TLS version and certificate expiry
- Cookie flags (`Secure`, `HttpOnly`, `SameSite`)
- A handful of commonly-exposed paths (`.env`, `.git/config`, backup files)

## Setup

```bash
pip install -r requirements.txt

# Option A: Using Google Gemini (Free / Fast)
# Either create a .env file with GEMINI_API_KEY=... or set in shell:
# PowerShell: $env:GEMINI_API_KEY="your-gemini-key"
# Linux/macOS: export GEMINI_API_KEY="your-gemini-key"

# Option B: Using Anthropic Claude
# PowerShell: $env:ANTHROPIC_API_KEY="sk-ant-..."
# Linux/macOS: export ANTHROPIC_API_KEY="sk-ant-..."

python agent.py https://your-own-site.com
```

It prints a prioritized report (Critical/High/Medium/Low) and saves it
to `security_report.md`.

## Extending it

- **Add more skills**: copy more `skills/<name>/` folders from the
  source repo. Good next additions if you deploy with Docker: the
  container-hardening skills; if you have a CI/CD pipeline: the
  SAST/DAST/secrets-scanning skills (`implementing-secrets-scanning-in-ci-cd`,
  `integrating-sast-into-github-actions-pipeline`).
- **Add more checks**: `scanner.py` is plain Python + `requests`/`ssl` -
  add functions for whatever else you want measured, then add matching
  keywords in `agent.py`'s `keywords_from_scan()` so the right skill
  gets pulled in.

## Scope note

This only ever points at sites you control. The underlying skill
library includes offensive/dual-use material meant for *authorized*
penetration testing - use it only against your own systems or systems
you have explicit written permission to test.
