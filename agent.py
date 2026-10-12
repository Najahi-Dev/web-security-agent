"""
Website Security Check Agent - Interactive Console Application
==============================================================

An AI-driven security auditing assistant that conducts non-intrusive,
read-only reconnaissance on websites you own (or are authorized to audit),
matches findings against defensive cybersecurity skill procedures, and synthesizes
a prioritized hardening report with Gemini or Claude.

Features:
  - Interactive Console Application with Rich terminal UI
  - Real-time animated loading spinners during recon & AI synthesis
  - Diagnostic reconnaissance summary dashboard
  - Beautiful terminal Markdown rendering
  - Multi-format report export: Markdown (.md), HTML (.html), JSON (.json)
  - Direct in-browser report preview
"""

import datetime
import json
import os
import re
import sys
import webbrowser
from urllib.parse import urlparse

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.markdown import Markdown
from rich.prompt import Prompt, Confirm
from rich import box

console = Console(highlight=False)

from scanner import (
    fetch_headers,
    check_missing_security_headers,
    check_tls,
    check_exposed_paths,
    run_targeted_skill_probes,
    SECURITY_HEADERS,
)
from skills_loader import (
    load_all_skills,
    pick_relevant_skills,
    build_catalog_summary,
    interactive_select_skills,
)
from html_exporter import generate_html_report

console = Console()

DEFAULT_ANTHROPIC_MODEL = "claude-3-5-sonnet-20241022"
DEFAULT_GEMINI_MODEL = "gemini-3.5-flash-lite"
REPORTS_DIR = "reports"


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


def build_system_prompt(relevant_skills, full_catalog=""):
    """Focus on defensive, hardening and remediation skills for user-selected domains."""
    defensive_skills = [
        s for s in relevant_skills if not s.get("name", "").startswith("exploiting-")
    ]
    exploit_skills = [
        s for s in relevant_skills if s.get("name", "").startswith("exploiting-")
    ]

    skill_blocks = []
    for s in defensive_skills:
        title = s.get("display_title") or s.get("name")
        cat = s.get("category", "SecOps")
        body = s.get("body", "")
        skill_blocks.append(f"### Skill Procedure [{cat}]: {title}\nDescription: {s.get('description', '')}\n\n{body}")

    for s in exploit_skills:
        title = s.get("display_title") or s.get("name", "").replace("exploiting-", "Defending Against ")
        cat = s.get("category", "Vulnerability Defense")
        skill_blocks.append(
            f"### Defensive Audit Focus [{cat}]: {title}\n"
            f"Audit Objective: Evaluate application and server configuration resilience against {s.get('description', '')}. "
            f"Provide concrete input sanitization, WAF rules, and defensive architecture to prevent this vulnerability class."
        )

    skill_procedures = "\n\n---\n\n".join(skill_blocks)

    skill_names_list = []
    for i, s in enumerate(relevant_skills, 1):
        name = s.get("name", "")
        if name.startswith("exploiting-"):
            clean_title = s.get("display_title") or name.replace("exploiting-", "Defending Against ").replace("-", " ").title()
        else:
            clean_title = s.get("display_title") or name
        skill_names_list.append(f"{i}. [{s.get('category', 'SecOps')}] {clean_title}")
    skill_names_str = "\n".join(skill_names_list)

    return f"""You are a defensive cybersecurity engineer and server hardening assistant.
You help a developer audit and harden web applications THEY OWN and manage.
You only provide defensive guidance, configuration snippets (e.g. Nginx, Apache, Cloudflare), and remediation steps.
Never provide exploit payloads or attack steps.

MANDATORY AUDIT SCOPE:
The user has specifically chosen the following {len(relevant_skills)} cybersecurity skills to audit this system against:
{skill_names_str}

PROCEDURES & BENCHMARKS FOR CHOSEN SKILLS:
{skill_procedures}

CRITICAL REPORT STRUCTURE REQUIREMENTS:
Your audit report MUST be structured directly around the chosen skills. Do NOT output a generic report. Follow this exact format:

# Security Audit & Hardening Report

## 1. Executive Summary & Posture Rating
- Overall risk level for the audited domains (Critical / High / Medium / Low / Hardened).
- Summary (3-4 sentences) evaluating the application against the user's chosen audit scope.

## 2. In-Depth Analysis of Selected Security Skills
(You MUST include a dedicated, detailed subsection for EACH of the {len(relevant_skills)} chosen skills above!)
For EACH chosen skill:
### [Skill Number & Title]
- **Current Assessment Status:** [Critical / High / Medium / Low / Hardened / Warning]
- **Reconnaissance & Probe Observations:** Specific technical evidence observed (headers, cookies, TLS ciphers, probe responses). If the probe data confirms that defenses are already active (e.g. CI/CD secret scanning workflows, pre-commit hooks, or hardened security headers), cite them clearly as active and verified.
- **Vulnerability & Threat Analysis:** Real-world impact if an attacker attempts this vector against this application.
- **Production Remediation Directives:** If the probe indicates missing controls, provide concrete configuration blocks. If the probe confirms the defense is ALREADY hardened and configured (e.g., automated secrets scanning in CI/CD and pre-commit hooks are detected), mark the status as 'Hardened', acknowledge the existing implementation, and provide maintenance or operational best practices rather than falsely claiming it is missing.

## 3. Defense-in-Depth & Architectural Recommendations
- Prioritized hardening roadmap for long-term server posture."""


def generate_report_gemini(api_key, system_prompt, scan, selected_skills=None, model=None, status_updater=None):
    from google import genai
    from google.genai import types

    client = genai.Client(api_key=api_key)

    clean_scan = dict(scan)
    clean_scan["target"] = "Application Server (Authorized Local Configuration Audit)"

    skills_summary = "\n".join(
        f"{idx}. [{s.get('category', 'SecOps')}] {s.get('display_title', s.get('name'))}: {s.get('short_desc', s.get('description', ''))}"
        for idx, s in enumerate(selected_skills or [], 1)
    )

    prompt = (
        f"TARGET ASSET: {clean_scan.get('target')}\n\n"
        f"AUDIT SCOPE: The user has chosen these {len(selected_skills or [])} specific security skills to test:\n"
        f"{skills_summary}\n\n"
        "RECONNAISSANCE, CONFIGURATION AUDIT, AND TARGETED SKILL PROBE DATA (JSON):\n"
        f"{json.dumps(clean_scan, indent=2, default=str)}\n\n"
        "INSTRUCTIONS:\n"
        f"Write a thorough, professional security audit report. YOU MUST dedicate a separate subsection under 'Section 2: In-Depth Analysis of Selected Security Skills' for EACH of the {len(selected_skills or [])} skills chosen above.\n"
        "Analyze the reconnaissance data and skill probe results for each domain, and provide concrete remediation directives."
    )

    preferred_model = model or os.environ.get("GEMINI_MODEL") or DEFAULT_GEMINI_MODEL
    candidates = [preferred_model, "gemini-2.5-flash", "gemini-2.0-flash", "gemini-1.5-flash", "gemini-3.5-flash-lite"]
    models_to_try = []
    for m in candidates:
        if m and m not in models_to_try:
            models_to_try.append(m)

    last_error = None
    for m in models_to_try:
        try:
            if status_updater:
                status_updater(f"Consulting Gemini reasoning engine ({m})...")
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
            if status_updater:
                status_updater(f"Model {m} fallback, trying alternative...")
    if last_error:
        raise last_error
    raise RuntimeError("Failed to generate report: no models were tried or succeeded.")


def generate_report_anthropic(api_key, system_prompt, scan, selected_skills=None, model=None, status_updater=None):
    import anthropic

    client = anthropic.Anthropic(api_key=api_key)
    chosen_model = model or os.environ.get("ANTHROPIC_MODEL") or DEFAULT_ANTHROPIC_MODEL
    if status_updater:
        status_updater(f"Consulting Claude reasoning engine ({chosen_model})...")

    skills_summary = "\n".join(
        f"{idx}. [{s.get('category', 'SecOps')}] {s.get('display_title', s.get('name'))}: {s.get('short_desc', s.get('description', ''))}"
        for idx, s in enumerate(selected_skills or [], 1)
    )

    user_prompt = (
        f"TARGET ASSET: {scan.get('target')}\n\n"
        f"AUDIT SCOPE: The user has chosen these {len(selected_skills or [])} specific security skills to test:\n"
        f"{skills_summary}\n\n"
        "RECONNAISSANCE, CONFIGURATION AUDIT, AND TARGETED SKILL PROBE DATA (JSON):\n"
        f"{json.dumps(scan, indent=2, default=str)}\n\n"
        "INSTRUCTIONS:\n"
        f"Write a thorough, professional security audit report. YOU MUST dedicate a separate subsection under 'Section 2: In-Depth Analysis of Selected Security Skills' for EACH of the {len(selected_skills or [])} skills chosen above.\n"
        "Analyze the reconnaissance data and skill probe results for each domain, and provide concrete remediation directives."
    )

    response = client.messages.create(
        model=chosen_model,
        max_tokens=3000,
        system=system_prompt,
        messages=[{
            "role": "user",
            "content": user_prompt,
        }],
    )
    return "".join(block.text for block in response.content if block.type == "text")


def sanitize_url(raw_url: str) -> str:
    """Normalize input into a valid URL with protocol."""
    target = raw_url.strip()
    if not target:
        return ""
    if not re.match(r"^https?://", target, re.IGNORECASE):
        target = f"https://{target}"
    return target


def is_valid_url(url: str) -> bool:
    """Validate that the URL has a valid scheme and netloc."""
    try:
        parsed = urlparse(url)
        return bool(parsed.scheme in ("http", "https") and parsed.netloc and "." in parsed.netloc)
    except Exception:
        return False


def get_active_provider_info():
    """Determine currently configured LLM provider and API keys."""
    gemini_key = os.environ.get("GEMINI_API_KEY")
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
    env_provider = os.environ.get("LLM_PROVIDER", "").lower()

    if env_provider == "anthropic" and anthropic_key:
        return "anthropic", anthropic_key
    if env_provider == "gemini" and gemini_key:
        return "gemini", gemini_key

    if gemini_key:
        return "gemini", gemini_key
    if anthropic_key:
        return "anthropic", anthropic_key

    return None, None


def display_welcome_banner():
    """Print high-impact, modern welcome banner and system diagnostics."""
    banner_ascii = """[bold bright_cyan]
  __          __  _        _____                      _ _         
  \\ \\        / / | |      / ____|                    (_) |        
   \\ \\  /\\  / /__| |__   | (___   ___  ___ _   _ _ __ _| |_ _   _ 
    \\ \\/  \\/ / _ \\ '_ \\   \\___ \\ / _ \\/ __| | | | '__| | __| | | |
     \\  /\\  /  __/ |_) |  ____) |  __/ (__| |_| | |  | | |_| |_| |
      \\/  \\/ \\___|_.__/  |_____/ \\___|\\___|\\__,_|_|  |_|\\__|\\__, |
                                                             __/ |
    [bold cyan]-- DEFENSIVE WEB SECURITY & SERVER HARDENING AGENT --[/bold cyan]   |___/ 
[/bold bright_cyan]"""
    console.print(banner_ascii)

    provider, _ = get_active_provider_info()
    provider_badge = f"[bold green]● {provider.upper()}[/bold green]" if provider else "[bold red]● None Configured[/bold red]"

    skills_count = len(load_all_skills())
    skills_badge = f"[bold cyan]{skills_count} Defensive Procedures[/bold cyan]"

    info_table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    info_table.add_row("[bold white]Role:[/bold white]", "[cyan]Autonomous Defensive Recon & Server Hardening Agent[/cyan]")
    info_table.add_row("[bold white]Active AI Model:[/bold white]", provider_badge)
    info_table.add_row("[bold white]Skill Catalog:[/bold white]", skills_badge)
    info_table.add_row("[bold white]Scope & Policy:[/bold white]", "[yellow]Audits authorized systems you own or have permission to test.[/yellow]")

    panel = Panel(
        info_table,
        title="[bold bright_white]System Diagnostics & Capabilities[/bold bright_white]",
        border_style="bright_blue",
        padding=(1, 2),
    )
    console.print(panel)
    console.print()


def display_recon_summary(scan: dict, matched_skills: list):
    """Render a clean summary dashboard of reconnaissance findings."""
    table = Table(
        title="[bold bright_white]📊 Reconnaissance Findings Matrix[/bold bright_white]",
        box=box.ROUNDED,
        header_style="bold bright_blue",
    )
    table.add_column("Category", style="cyan", width=22)
    table.add_column("Status / Observation", style="white")

    # HTTP Status & Server
    http_data = scan.get("http", {})
    status_code = http_data.get("status_code", "N/A")
    headers = http_data.get("headers", {})
    server_hdr = headers.get("server") or headers.get("Server") or "Hidden / None"
    table.add_row("HTTP Status Code", f"[bold green]{status_code}[/bold green]" if status_code == 200 else f"[yellow]{status_code}[/yellow]")
    table.add_row("Server Header", f"[yellow]{server_hdr}[/yellow]" if server_hdr != "Hidden / None" else "[green]Hidden / Obscured[/green]")

    # Security Headers Check
    header_findings = scan.get("header_findings", {})
    missing_hdrs = header_findings.get("missing", [])
    if missing_hdrs:
        table.add_row(
            f"Missing Headers ({len(missing_hdrs)})",
            f"[bold red]{', '.join(missing_hdrs[:4])}{' ...' if len(missing_hdrs) > 4 else ''}[/bold red]",
        )
    else:
        table.add_row("Security Headers", "[bold green]All standard security headers present[/bold green]")

    # TLS Status
    tls = scan.get("tls", {})
    if isinstance(tls, dict) and "tls_version" in tls:
        days = tls.get("days_until_expiry", 0)
        days_style = "green" if days > 30 else "red"
        table.add_row("TLS Protocol", f"{tls.get('tls_version', 'Unknown')} (Expires in [{days_style}]{days} days[/{days_style}])")
    else:
        table.add_row("TLS Protocol", "[yellow]Not accessible / Plain HTTP[/yellow]")

    # Cookies
    cookies = http_data.get("cookies", [])
    if cookies:
        insecure_cookies = [c["name"] for c in cookies if not c.get("secure") or not c.get("httponly")]
        if insecure_cookies:
            table.add_row("Cookie Flags", f"[bold yellow]{len(insecure_cookies)}/{len(cookies)} lacking Secure/HttpOnly[/bold yellow]")
        else:
            table.add_row("Cookie Flags", f"[bold green]{len(cookies)} cookies protected (Secure/HttpOnly)[/bold green]")
    else:
        table.add_row("Cookie Flags", "[dim]No cookies detected in root response[/dim]")

    # Exposed Paths
    exposed = scan.get("exposed_paths", [])
    if exposed:
        exposed_str = ", ".join(f"{e['path']} ({e['status_code']})" for e in exposed)
        table.add_row("Sensitive Paths Exposed", f"[bold red]{exposed_str}[/bold red]")
    else:
        table.add_row("Sensitive Paths", "[bold green]0 sensitive/backup paths accessible[/bold green]")

    # Targeted Skill Probes Telemetry
    skill_probes = scan.get("skill_probes", {})
    if skill_probes:
        probe_items = []
        for s_key, s_data in skill_probes.items():
            if isinstance(s_data, dict) and "verdict" in s_data:
                verdict = s_data["verdict"]
                color = "green" if any(w in verdict for w in ["Secure", "Protected", "Hardened"]) else "yellow" if "No" in verdict else "red"
                probe_items.append(f"[{color}]{verdict}[/{color}] ([dim]{s_key}[/dim])")
        if probe_items:
            table.add_row("Skill Probe Telemetry", "\n".join(f"• {p}" for p in probe_items))

    # Active Skills
    skills_names = [f"[{s.get('category', 'SecOps')}] {s.get('display_title', s.get('name'))}" for s in matched_skills]
    table.add_row("Active Audit Skills", "\n".join(f"• [cyan]{name}[/cyan]" for name in skills_names))

    console.print(table)
    console.print()


def execute_scan_workflow(target_url: str, selected_skills: list = None):
    """Run full reconnaissance and report generation with live animated spinners."""
    parsed = urlparse(target_url)
    hostname = parsed.hostname or target_url

    scan_result = {"target": target_url}

    # Animated Loading Steps
    with console.status("[bold cyan]Initiating multi-stage defensive audit...[/bold cyan]", spinner="dots") as status:
        # Step 1: HTTP Headers & Recon
        status.update(f"[bold cyan]Stage 1/5:[/] Probing [bold white]{target_url}[/] HTTP response & headers...")
        scan_result["http"] = fetch_headers(target_url)
        if "headers" in scan_result["http"]:
            scan_result["header_findings"] = check_missing_security_headers(scan_result["http"]["headers"])
        console.print(" [bold green]✓[/bold green] HTTP headers captured & evaluated")

        # Step 2: TLS Audit
        status.update("[bold cyan]Stage 2/5:[/] Inspecting SSL/TLS certificates and protocol parameters...")
        if parsed.scheme == "https" and hostname:
            scan_result["tls"] = check_tls(hostname)
            console.print(" [bold green]✓[/bold green] SSL/TLS configuration verified")
        else:
            scan_result["tls"] = {"notice": "Target is not HTTPS"}
            console.print(" [bold yellow]![/bold yellow] Skipped TLS inspection (HTTP target)")

        # Step 3: Exposed sensitive paths
        status.update("[bold cyan]Stage 3/5:[/] Scanning for commonly exposed files (.env, .git, backups)...")
        scan_result["exposed_paths"] = check_exposed_paths(target_url)
        console.print(" [bold green]✓[/bold green] Sensitive configuration exposure scan complete")

        # Step 4: Loading & matching skills and running targeted probes
        status.update("[bold cyan]Stage 4/5:[/] Running targeted skill probes & activating defensive procedures...")
        if not selected_skills:
            skills = load_all_skills()
            kws = keywords_from_scan(scan_result)
            selected_skills = pick_relevant_skills(skills, kws, max_skills=5)
        
        # Execute safe, targeted diagnostic probes based directly on user-selected skills
        scan_result["skill_probes"] = run_targeted_skill_probes(target_url, selected_skills, scan_result.get("http"))
        full_catalog = build_catalog_summary(selected_skills)
        console.print(f" [bold green]✓[/bold green] Executed targeted probes for {len(selected_skills)} active skills")

        # Step 5: AI Hardening Report Synthesis
        provider, api_key = get_active_provider_info()
        if not provider:
            console.print("[bold red]Error: No LLM API key detected.[/bold red]")
            api_key = Prompt.ask("Please enter your GEMINI_API_KEY or ANTHROPIC_API_KEY", password=True)
            if api_key.startswith("sk-ant-"):
                provider = "anthropic"
            else:
                provider = "gemini"

        status.update(f"[bold cyan]Stage 5/5:[/] Synthesizing hardening report using [bold white]{provider.capitalize()}[/]...")
        system_prompt = build_system_prompt(selected_skills, full_catalog)

        def update_msg(msg):
            status.update(f"[bold cyan]Stage 5/5:[/] {msg}")

        if provider == "gemini":
            report_text = generate_report_gemini(api_key, system_prompt, scan_result, selected_skills=selected_skills, status_updater=update_msg)
        else:
            report_text = generate_report_anthropic(api_key, system_prompt, scan_result, selected_skills=selected_skills, status_updater=update_msg)

        console.print(f" [bold green]✓[/bold green] Hardening report generated successfully via {provider.capitalize()}")

    console.print()
    # Display Recon Table
    display_recon_summary(scan_result, selected_skills)

    # Render Report in Terminal
    console.print(
        Panel(
            Markdown(report_text),
            title=f"[bold bright_white]🛡️ AI Hardening & Remediation Report: {hostname}[/bold bright_white]",
            border_style="cyan",
            padding=(1, 2),
        )
    )

    return scan_result, report_text, selected_skills


def handle_export_menu(target_url: str, scan_data: dict, report_text: str, matched_skills: list):
    """Present interactive export, download, and file opening options."""
    parsed = urlparse(target_url)
    hostname = (parsed.hostname or "audit").replace(":", "_")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(REPORTS_DIR, exist_ok=True)

    default_base = os.path.join(REPORTS_DIR, f"security_report_{hostname}_{timestamp}")
    last_saved_html = None

    while True:
        console.print()
        menu_table = Table(show_header=False, box=box.ROUNDED, border_style="bright_blue")
        menu_table.add_column("Option", style="bold cyan", width=6)
        menu_table.add_column("Action", style="white")

        menu_table.add_row("[1]", "📄 Save report as Markdown (.md)")
        menu_table.add_row("[2]", "🌐 Export report as Interactive HTML (.html)")
        menu_table.add_row("[3]", "📦 Export raw scan data as JSON (.json)")
        menu_table.add_row("[4]", "🚀 Save all formats (.md, .html, .json) & root security_report.md")
        menu_table.add_row("[5]", "🔎 Open HTML report in default web browser")
        menu_table.add_row("[6]", "🔄 Scan another website target")
        menu_table.add_row("[0]", "🚪 Exit console application")

        console.print(Panel(menu_table, title="[bold bright_white]💾 Report Export & Options[/bold bright_white]", border_style="bright_blue"))

        choice = Prompt.ask("[bold cyan]Select an option[/bold cyan]", choices=["1", "2", "3", "4", "5", "6", "0"], default="4")

        if choice == "1":
            file_path = f"{default_base}.md"
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(f"# Security Report for {target_url}\n\n{report_text}\n")
            console.print(f"[bold green]✓ Saved Markdown report to:[/bold green] [underline]{os.path.abspath(file_path)}[/underline]")

        elif choice == "2":
            html_content = generate_html_report(target_url, scan_data, report_text, matched_skills)
            file_path = f"{default_base}.html"
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            last_saved_html = file_path
            console.print(f"[bold green]✓ Saved HTML report to:[/bold green] [underline]{os.path.abspath(file_path)}[/underline]")

        elif choice == "3":
            file_path = f"{default_base}.json"
            export_payload = {
                "target": target_url,
                "timestamp": timestamp,
                "scan": scan_data,
                "report_markdown": report_text,
                "matched_skills": [s["name"] for s in matched_skills],
            }
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(export_payload, f, indent=2, default=str)
            console.print(f"[bold green]✓ Saved JSON scan data to:[/bold green] [underline]{os.path.abspath(file_path)}[/underline]")

        elif choice == "4":
            # Markdown
            md_path = f"{default_base}.md"
            with open(md_path, "w", encoding="utf-8") as f:
                f.write(f"# Security Report for {target_url}\n\n{report_text}\n")
            # Root security_report.md for direct access
            with open("security_report.md", "w", encoding="utf-8") as f:
                f.write(f"# Security Report for {target_url}\n\n{report_text}\n")

            # HTML
            html_content = generate_html_report(target_url, scan_data, report_text, matched_skills)
            html_path = f"{default_base}.html"
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            last_saved_html = html_path

            # JSON
            json_path = f"{default_base}.json"
            export_payload = {
                "target": target_url,
                "timestamp": timestamp,
                "scan": scan_data,
                "report_markdown": report_text,
                "matched_skills": [s["name"] for s in matched_skills],
            }
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(export_payload, f, indent=2, default=str)

            console.print(Panel(
                f"[bold green]✓ All reports exported successfully![/bold green]\n\n"
                f"• [cyan]Markdown:[/] [underline]{os.path.abspath(md_path)}[/underline]\n"
                f"• [cyan]Markdown (Root):[/cyan] [underline]{os.path.abspath('security_report.md')}[/underline]\n"
                f"• [cyan]HTML Report:[/] [underline]{os.path.abspath(html_path)}[/underline]\n"
                f"• [cyan]Raw JSON Data:[/] [underline]{os.path.abspath(json_path)}[/underline]",
                title="[bold bright_green]Export Complete[/bold bright_green]",
                border_style="green",
            ))

        elif choice == "5":
            if not last_saved_html or not os.path.exists(last_saved_html):
                html_content = generate_html_report(target_url, scan_data, report_text, matched_skills)
                last_saved_html = f"{default_base}.html"
                with open(last_saved_html, "w", encoding="utf-8") as f:
                    f.write(html_content)
            abs_path = os.path.abspath(last_saved_html)
            console.print(f"[bold cyan]Opening in web browser:[/] [underline]{abs_path}[/underline]")
            webbrowser.open(f"file://{abs_path}")

        elif choice == "6":
            return True  # Scan another target

        elif choice == "0":
            console.print("\n[bold cyan]Thank you for using Web Security Agent. Stay safe![/bold cyan]")
            return False


def main():
    """Main application loop."""
    display_welcome_banner()

    # Check if a target URL was passed as command-line argument
    cli_target = None
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        cli_target = sanitize_url(sys.argv[1])

    while True:
        if cli_target:
            target = cli_target
            cli_target = None  # Use once
            console.print(f"[bold cyan]Target specified via command line:[/] [bold bright_white]{target}[/bold bright_white]\n")
        else:
            raw_target = Prompt.ask("[bold cyan]Enter website target URL[/bold cyan] [dim](or 'q' to quit)[/dim]").strip()
            if raw_target.lower() in ("q", "quit", "exit"):
                console.print("\n[bold cyan]Goodbye![/bold cyan]")
                break
            target = sanitize_url(raw_target)

        if not target or not is_valid_url(target):
            console.print("[bold red]Invalid URL format. Please provide a valid address (e.g. https://example.com or example.com)[/bold red]\n")
            continue

        # Interactive Skill Selection
        all_skills = load_all_skills()
        console.print("\n[bold cyan]Choose the security audit focus for this target...[/bold cyan]")
        try:
            selected_skills = interactive_select_skills(all_skills, min_skills=1, max_skills=5)
        except (KeyboardInterrupt, EOFError):
            console.print("\n[bold yellow]Selection interrupted. Exiting...[/bold yellow]")
            break

        if not selected_skills:
            console.print("[bold yellow]No skills selected. Returning to target prompt...[/bold yellow]\n")
            continue

        # Render Selected Skills Confirmation Badge Panel
        selected_table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
        for idx, s in enumerate(selected_skills, 1):
            selected_table.add_row(
                f"[bold cyan]{idx}.[/bold cyan]",
                f"[bold white][{s['category']}][/bold white] [bright_cyan]{s['display_title']}[/bright_cyan]",
                f"[dim]{s['short_desc']}[/dim]"
            )

        console.print(Panel(
            selected_table,
            title=f"[bold bright_green]🎯 Active Audit Scope ({len(selected_skills)}/5 Skills Selected)[/bold bright_green]",
            border_style="green",
            padding=(1, 2)
        ))
        console.print()

        try:
            scan_data, report_text, matched_skills = execute_scan_workflow(target, selected_skills=selected_skills)
            keep_running = handle_export_menu(target, scan_data, report_text, matched_skills)
            if not keep_running:
                break
        except KeyboardInterrupt:
            console.print("\n[bold yellow]Scan interrupted by user. Exiting...[/bold yellow]")
            break
        except Exception as e:
            from rich.markup import escape
            console.print(f"\n[bold red]Error during audit execution:[/] {escape(str(e))}")
            if not Confirm.ask("Would you like to try auditing another URL?"):
                break


if __name__ == "__main__":
    main()
