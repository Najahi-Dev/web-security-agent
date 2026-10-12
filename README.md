<p align="center">
  <img src="assets/banner.jpg" alt="Web Security Agent Banner" width="100%" />
</p>

<h1 align="center">🛡️ Web Security Agent</h1>

<p align="center">
  <strong>Autonomous AI-powered defensive auditor for web infrastructure, TLS posture, and application hardening.</strong>
</p>

<p align="center">
  <a href="https://github.com/Najahi-Dev/web-security-agent/actions/workflows/python-app.yml"><img src="https://github.com/Najahi-Dev/web-security-agent/actions/workflows/python-app.yml/badge.svg" alt="Build Status" /></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-blue?logo=python&logoColor=white" alt="Python Version" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License: MIT" /></a>
  <a href="https://ai.google.dev/"><img src="https://img.shields.io/badge/AI-Google%20Gemini-4285F4?logo=google&logoColor=white" alt="Gemini Powered" /></a>
  <a href="https://www.anthropic.com/"><img src="https://img.shields.io/badge/AI-Anthropic%20Claude-D97706?logo=anthropic&logoColor=white" alt="Claude Powered" /></a>
</p>

---

## 📌 Overview

**Web Security Agent** is an automated, defensive cybersecurity auditor designed for developers, DevOps teams, and security engineers to assess sites **they own or are authorized to test**.

Unlike invasive penetration testing scanners that spray aggressive payloads, Web Security Agent performs **safe, read-only reconnaissance** on your target. It parses configuration hygiene, SSL/TLS certificates, response headers, and exposed endpoints, matches findings against a **curated library of 41 specialized cybersecurity skills**, and uses LLMs (Google Gemini or Anthropic Claude) to synthesize a prioritized, actionable hardening report with drop-in configuration directives (Nginx, Apache, Cloudflare).

---

## ⚡ Key Features

* **🔍 Non-Invasive, Read-Only Recon**: Audits attack surface without injecting payloads, triggering WAF bans, or degrading site availability.
* **🧠 Curated Skills Reasoning Engine**: Synthesizes real-world defense patterns sourced and adapted from the open-source *Anthropic Cybersecurity Skills* catalog.
* **🤖 Multi-LLM Provider Support**: Fully compatible with both **Google Gemini** (Gemini 2.5/3.x Flash) and **Anthropic Claude** (Claude 3.5 Sonnet).
* **📋 Prioritized Risk Reporting**: Groups findings into `Critical`, `High`, `Medium`, and `Low` with severity context, impact breakdowns, and remediation directives.
* **🔧 Concrete Hardening Snippets**: Provides copy-pasteable configuration directives for Nginx, Apache, Cloudflare edge rules, and HTTP servers.
* **🚀 CI/CD & Automation Ready**: Easily integrates into GitHub Actions, nightly cron jobs, or pre-deployment verification scripts.

---

## 🔄 Architecture & Workflow

```mermaid
flowchart LR
    A[Target URL] --> B[scanner.py<br/>Read-Only Recon]
    B --> C{Finding Extractor<br/>& Keywords}
    C --> D[skills_loader.py<br/>Curated Skills Catalog]
    D --> E[LLM Reasoning Engine<br/>Gemini / Claude]
    E --> F[security_report.md<br/>Prioritized Hardening Report]
```

1. **Reconnaissance (`scanner.py`)**: Executes non-intrusive HTTP/HTTPS probes, inspecting headers, TLS handshakes, cookies, and standard paths.
2. **Context Matching (`skills_loader.py`)**: Filters identified weaknesses against 41 curated defensive procedures.
3. **Synthesis (`agent.py`)**: Prompts the LLM with structured audit findings and defensive skill standards.
4. **Deliverable (`security_report.md`)**: Generates a clean Markdown audit report with remediation code and defense-in-depth recommendations.

---

## 🔬 Reconnaissance Capabilities

| Category | Checks Performed | Detection Scope |
| :--- | :--- | :--- |
| **Security Headers** | Content Security Policy (CSP), Strict-Transport-Security (HSTS), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy | Missing headers, improper directives, weak configurations |
| **Information Disclosure** | Server Banner, `X-Powered-By`, framework telemetry | Leaked technology stacks, server version disclosures |
| **SSL / TLS Health** | Certificate expiration, protocol support, TLS handshake validation | Imminent certificate expiries (< 30 days), weak handshakes |
| **Cookie Hardening** | `Secure`, `HttpOnly`, `SameSite` flags | Insecure session tokens vulnerable to XSS or MITM |
| **Exposed Endpoints** | Read-only verification of `.env`, `.git/config`, backup files (`.bak`), etc. | Accidentally public sensitive configuration files |

---

## 📚 Curated Skills Engine (41 Skills)

Rather than ingesting bloated libraries containing irrelevant offensive attack material (e.g., Active Directory privilege escalation, ransomware tradecraft, or rootkits), Web Security Agent bundles **41 high-yield, web-focused defense skills** under `skills/`:

* **Web Application Security**: CORS misconfigurations, CSRF defenses, XSS mitigation, second-order SQLi prevention, host/email header injection hardening.
* **API Security & Resiliency**: API rate limiting bypass defenses, OpenAPI/REST validation, JWT security, auth bypass defenses.
* **DevSecOps & Supply Chain**: Container image hardening, secrets scanning in CI/CD, SAST/DAST pipeline integration (OWASP ZAP, Snyk).
* **TLS & Cryptography**: SSL/TLS certificate lifecycle management, cipher suite hardening, edge security.

> Need extra skills? Drop any compliant skill folder (`skills/<name>/SKILL.md`) into `skills/`—`skills_loader.py` dynamically auto-indexes them on startup!

---

## 🚀 Quick Start

### 1. Clone & Set Up Environment

```bash
# Clone the repository
git clone https://github.com/Najahi-Dev/web-security-agent.git
cd web-security-agent

# Create and activate virtual environment
python -m venv .venv

# On Linux / macOS:
source .venv/bin/activate

# On Windows (PowerShell):
.venv\Scripts\Activate.ps1
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure API Credentials

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

Set your preferred provider:

#### Option A: Google Gemini *(Recommended for speed & cost)*
Get an API key from [Google AI Studio](https://aistudio.google.com/):
```env
GEMINI_API_KEY=your_gemini_api_key_here
```

#### Option B: Anthropic Claude
Get an API key from [Anthropic Console](https://console.anthropic.com/):
```env
ANTHROPIC_API_KEY=sk-ant-your_anthropic_api_key_here
```

---

## 💻 Usage

### 🎮 Interactive Console Mode *(Recommended)*

Simply run `agent.py` to launch the interactive terminal console application:

```bash
python agent.py
```

The interactive console application provides:
* 🌟 **Stylized Welcome Banner & Diagnostics**: Displays active LLM provider, skill library status, and scope policy.
* ⌨️ **Smart URL Input & Normalization**: Automatically validates target URL format (e.g. typing `mysite.com` automatically normalizes to `https://mysite.com`).
* ⏳ **Real-Time Animated Spinners**: Live loading indicators for every reconnaissance phase (HTTP headers, SSL/TLS audit, exposed file probes, skill matching, and AI synthesis).
* 📊 **Reconnaissance Findings Matrix**: Formatted summary table of status codes, missing headers, TLS lifecycle, and cookies.
* 🛡️ **Terminal Markdown Presentation**: Syntax-highlighted, rich-bordered report display directly in your console.
* 💾 **Multi-Format Report Export Menu**:
  * `[1]` Save as Markdown (`.md`)
  * `[2]` Export as standalone dark-mode HTML (`.html`)
  * `[3]` Export raw scan data as JSON (`.json`)
  * `[4]` Save all formats at once (`.md`, `.html`, `.json`)
  * `[5]` Open interactive HTML report in default browser
  * `[6]` Audit another website in continuous loop

### ⚡ Direct Target Mode

You can also pass a target URL directly:

```bash
python agent.py https://your-site.com
```

---

## 📑 Sample Report Output

```markdown
# Security Report for https://example.com

### Security Hardening Report: Application Server Infrastructure

#### 1. Summary of Risk Level
**Risk Level: Medium**
The server is accessible and TLS is active, but lacks essential defense-in-depth
headers and exposes server software version telemetry.

#### 2. Prioritized Findings
* **Finding 1: Missing Content Security Policy (High Priority)**
  * **Risk**: High exposure to Cross-Site Scripting (XSS) and data injection.
  * **Remediation**: Deploy a strict `Content-Security-Policy` header.
  * **Config Directive (Nginx)**:
    ```nginx
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none';" always;
    ```
```

---

## 🛠️ Extending the Agent

* **Adding New Checks**: Extend `scanner.py` with custom checks (e.g., DNSSEC validation, subdomain takeover recon, HTTP/2 or HTTP/3 checks).
* **Adding New Skills**: Add procedure documentation to `skills/<skill-name>/SKILL.md`. Map associated keywords in `agent.py::keywords_from_scan()` so relevant procedures are auto-injected into the prompt.
* **CI/CD Integration**: Web Security Agent ships with a GitHub Actions workflow in [`.github/workflows/python-app.yml`](file:///.github/workflows/python-app.yml) for automated linting and tests.

---

## ⚖️ Scope & Ethical Use Policy

> [!CAUTION]
> **Strictly for Authorized Testing**:
> This agent is designed solely for defensive audits and authorized hardening. You must **only** scan domain names and endpoints that you own or for which you have explicit, documented authorization. Unauthorized security testing may violate local and international cyber laws.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE). Curated skills are adapted from the open-source community under their respective upstream open-source licenses.
