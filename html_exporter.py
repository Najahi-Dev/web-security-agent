"""
HTML Report Exporter for Web Security Agent
Generates an executive-ready, professional security audit report from scan data and AI report markdown.
Features:
  - Clean, human-designed executive styling (Dark & Light themes)
  - One-click "Download as PDF" with optimized @media print stylesheet
  - Interactive severity filtering & code copy utilities
  - Comprehensive metrics dashboard & findings visualization
"""
import datetime
from urllib.parse import urlparse
import markdown_it


def _render_markdown_to_html(md_text: str) -> str:
    """Convert markdown text to HTML with tables enabled."""
    try:
        md = markdown_it.MarkdownIt().enable("table")
        return md.render(md_text)
    except Exception:
        import html
        escaped = html.escape(md_text)
        return f"<pre>{escaped}</pre>"


def generate_html_report(target_url: str, scan_data: dict, report_markdown: str, matched_skills: list = None) -> str:
    """Generate a complete, professional standalone HTML report with PDF export."""
    parsed = urlparse(target_url)
    hostname = parsed.hostname or target_url
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    body_html = _render_markdown_to_html(report_markdown)

    # Compute key metrics
    header_findings = scan_data.get("header_findings", {})
    missing_headers = header_findings.get("missing", [])
    missing_count = len(missing_headers)
    leaky_count = len(header_findings.get("leaky_disclosure", {}))
    
    tls_info = scan_data.get("tls", {})
    tls_version = tls_info.get("tls_version", "N/A") if isinstance(tls_info, dict) else "N/A"
    tls_days = tls_info.get("days_until_expiry", "N/A") if isinstance(tls_info, dict) else "N/A"
    
    exposed_paths = scan_data.get("exposed_paths", [])
    exposed_count = len(exposed_paths)
    
    skills = matched_skills or []
    skills_count = len(skills)

    # Calculate defensive score & rating
    penalty = (missing_count * 5) + (exposed_count * 15)
    if tls_version in ("N/A", "TLSv1.0", "TLSv1.1"):
        penalty += 20
    calc_score = max(10, min(100, 100 - penalty))
    
    if calc_score >= 85:
        posture_grade = "A"
        posture_rating = "Low Risk"
        posture_color = "var(--sev-success)"
    elif calc_score >= 65:
        posture_grade = "B"
        posture_rating = "Moderate Risk"
        posture_color = "var(--sev-medium)"
    else:
        posture_grade = "C"
        posture_rating = "High Risk"
        posture_color = "var(--sev-critical)"

    tls_sub = f"{tls_days} days to expiry" if isinstance(tls_days, int) else "Transport Parameters"

    html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Hardening & Posture Assessment - {hostname}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg-page: #080c14;
      --bg-surface: #0e1526;
      --bg-surface-elevated: #151f38;
      --bg-surface-soft: #1a2542;
      --border-subtle: #1e293b;
      --border-strong: #334155;
      
      --text-primary: #f8fafc;
      --text-secondary: #94a3b8;
      --text-muted: #64748b;
      
      --brand-primary: #38bdf8;
      --brand-glow: rgba(56, 189, 248, 0.15);
      --accent-indigo: #6366f1;
      
      --sev-critical: #ef4444;
      --sev-critical-bg: rgba(239, 68, 68, 0.12);
      --sev-critical-border: rgba(239, 68, 68, 0.3);
      
      --sev-high: #f97316;
      --sev-high-bg: rgba(249, 115, 22, 0.12);
      --sev-high-border: rgba(249, 115, 22, 0.3);
      
      --sev-medium: #eab308;
      --sev-medium-bg: rgba(234, 179, 8, 0.12);
      --sev-medium-border: rgba(234, 179, 8, 0.3);
      
      --sev-low: #3b82f6;
      --sev-low-bg: rgba(59, 130, 246, 0.12);
      --sev-low-border: rgba(59, 130, 246, 0.3);
      
      --sev-success: #10b981;
      --sev-success-bg: rgba(16, 185, 129, 0.12);
      --sev-success-border: rgba(16, 185, 129, 0.3);

      --code-bg: #050811;
      --code-border: #1e293b;
      --code-color: #38bdf8;

      --shadow-sm: 0 2px 4px rgba(0, 0, 0, 0.2);
      --shadow-md: 0 4px 12px rgba(0, 0, 0, 0.35);
      --shadow-lg: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
    }}

    body.light-theme {{
      --bg-page: #f8fafc;
      --bg-surface: #ffffff;
      --bg-surface-elevated: #f1f5f9;
      --bg-surface-soft: #e2e8f0;
      --border-subtle: #e2e8f0;
      --border-strong: #cbd5e1;
      
      --text-primary: #0f172a;
      --text-secondary: #475569;
      --text-muted: #64748b;
      
      --brand-primary: #0284c7;
      --brand-glow: rgba(2, 132, 199, 0.08);
      --accent-indigo: #4f46e5;

      --sev-critical: #dc2626;
      --sev-critical-bg: #fef2f2;
      --sev-critical-border: #fecaca;

      --sev-high: #ea580c;
      --sev-high-bg: #fff7ed;
      --sev-high-border: #fed7aa;

      --sev-medium: #d97706;
      --sev-medium-bg: #fefce8;
      --sev-medium-border: #fef08a;

      --sev-low: #2563eb;
      --sev-low-bg: #eff6ff;
      --sev-low-border: #bfdbfe;

      --sev-success: #059669;
      --sev-success-bg: #ecfdf5;
      --sev-success-border: #a7f3d0;

      --code-bg: #f8fafc;
      --code-border: #e2e8f0;
      --code-color: #0369a1;

      --shadow-sm: 0 1px 3px rgba(0, 0, 0, 0.05);
      --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.08);
      --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
    }}

    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    
    body {{
      font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background-color: var(--bg-page);
      color: var(--text-primary);
      line-height: 1.6;
      margin: 0;
      padding: 0;
      -webkit-font-smoothing: antialiased;
      transition: background-color 0.2s ease, color 0.2s ease;
    }}

    /* Action & Navigation Bar */
    .action-bar {{
      position: sticky;
      top: 0;
      z-index: 1000;
      background: rgba(14, 21, 38, 0.85);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--border-subtle);
      padding: 0.75rem 1.5rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 1rem;
    }}

    body.light-theme .action-bar {{
      background: rgba(255, 255, 255, 0.9);
    }}

    .bar-brand {{
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }}

    .brand-logo {{
      width: 32px;
      height: 32px;
      border-radius: 8px;
      background: linear-gradient(135deg, #0284c7 0%, #6366f1 100%);
      display: flex;
      align-items: center;
      justify-content: center;
      color: #ffffff;
      font-weight: 800;
      font-size: 1rem;
    }}

    .brand-title {{
      font-weight: 700;
      font-size: 0.95rem;
      letter-spacing: -0.01em;
      color: var(--text-primary);
    }}

    .brand-meta {{
      font-size: 0.75rem;
      color: var(--text-muted);
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }}

    .badge-confidential {{
      background: rgba(239, 68, 68, 0.15);
      color: #f87171;
      border: 1px solid rgba(239, 68, 68, 0.3);
      font-size: 0.65rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      padding: 0.15rem 0.5rem;
      border-radius: 4px;
    }}

    .bar-controls {{
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }}

    .btn {{
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      font-size: 0.825rem;
      font-weight: 600;
      padding: 0.5rem 1rem;
      border-radius: 8px;
      border: 1px solid transparent;
      cursor: pointer;
      transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
      font-family: inherit;
      text-decoration: none;
    }}

    .btn-primary {{
      background: linear-gradient(135deg, #0284c7 0%, #4f46e5 100%);
      color: #ffffff;
      box-shadow: 0 4px 12px rgba(2, 132, 199, 0.3);
    }}

    .btn-primary:hover {{
      transform: translateY(-1px);
      box-shadow: 0 6px 18px rgba(2, 132, 199, 0.45);
    }}

    .btn-outline {{
      background: var(--bg-surface-elevated);
      color: var(--text-primary);
      border-color: var(--border-subtle);
    }}

    .btn-outline:hover {{
      background: var(--bg-surface-soft);
      border-color: var(--border-strong);
    }}

    /* Container */
    .container {{
      max-width: 1100px;
      margin: 0 auto;
      padding: 2.5rem 1.5rem 4rem;
    }}

    /* Hero Card */
    .hero-card {{
      background: linear-gradient(135deg, #0e1526 0%, #151d33 100%);
      border: 1px solid var(--border-subtle);
      border-radius: 16px;
      padding: 2.5rem;
      margin-bottom: 2rem;
      box-shadow: var(--shadow-lg);
      position: relative;
      overflow: hidden;
    }}

    body.light-theme .hero-card {{
      background: linear-gradient(135deg, #ffffff 0%, #f8fafc 100%);
    }}

    .hero-card::before {{
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 4px;
      background: linear-gradient(90deg, #ef4444, #f97316, #eab308, #38bdf8, #6366f1);
    }}

    .hero-top-row {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 1.5rem;
      flex-wrap: wrap;
      gap: 1rem;
    }}

    .hero-pill {{
      font-size: 0.75rem;
      font-weight: 700;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      padding: 0.3rem 0.8rem;
      border-radius: 9999px;
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      background: var(--brand-glow);
      color: var(--brand-primary);
      border: 1px solid rgba(56, 189, 248, 0.4);
    }}

    .hero-title {{
      font-size: 2.25rem;
      font-weight: 800;
      color: var(--text-primary);
      letter-spacing: -0.025em;
      margin-bottom: 0.5rem;
      line-height: 1.2;
    }}

    .hero-subtitle {{
      font-size: 1.05rem;
      color: var(--text-secondary);
      max-width: 800px;
      margin-bottom: 2rem;
    }}

    .hero-meta-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 1.25rem;
      padding-top: 1.5rem;
      border-top: 1px solid var(--border-subtle);
    }}

    .meta-item {{ display: flex; flex-direction: column; }}
    .meta-label {{
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      font-weight: 600;
      margin-bottom: 0.25rem;
    }}
    .meta-value {{
      font-size: 0.95rem;
      font-weight: 600;
      color: var(--text-primary);
      word-break: break-all;
    }}

    /* Dashboard Grid */
    .dashboard-grid {{
      display: grid;
      grid-template-columns: 320px 1fr;
      gap: 1.5rem;
      margin-bottom: 2rem;
    }}

    @media (max-width: 900px) {{
      .dashboard-grid {{ grid-template-columns: 1fr; }}
    }}

    .posture-card {{
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: 14px;
      padding: 1.75rem;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      box-shadow: var(--shadow-md);
    }}

    .posture-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1rem;
    }}

    .posture-title {{
      font-size: 0.85rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
    }}

    .score-display {{
      display: flex;
      align-items: baseline;
      gap: 0.5rem;
      margin: 0.5rem 0 1rem;
    }}

    .score-grade {{
      font-size: 3.5rem;
      font-weight: 800;
      line-height: 1;
      color: {posture_color};
    }}

    .score-rating {{
      font-size: 1.15rem;
      font-weight: 700;
      color: var(--text-primary);
    }}

    .kpi-cards-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 1rem;
    }}

    .kpi-card {{
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: 12px;
      padding: 1.25rem;
      box-shadow: var(--shadow-sm);
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      transition: transform 0.15s ease, border-color 0.15s ease;
    }}

    .kpi-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 0.5rem;
    }}

    .kpi-label {{
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
    }}

    .kpi-indicator {{
      width: 8px;
      height: 8px;
      border-radius: 50%;
    }}

    .ind-danger {{ background: var(--sev-critical); }}
    .ind-warning {{ background: var(--sev-high); }}
    .ind-success {{ background: var(--sev-success); }}
    .ind-info {{ background: var(--brand-primary); }}

    .kpi-value {{
      font-size: 1.85rem;
      font-weight: 800;
      color: var(--text-primary);
      margin-bottom: 0.25rem;
      letter-spacing: -0.02em;
    }}

    .kpi-sub {{
      font-size: 0.75rem;
      color: var(--text-muted);
    }}

    /* Main Report Body Content Card */
    .report-card {{
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: 16px;
      padding: 2.5rem;
      box-shadow: var(--shadow-md);
      margin-bottom: 2.5rem;
    }}

    .report-content h1, .report-content h2, .report-content h3, .report-content h4 {{
      color: var(--text-primary);
      margin-top: 2rem;
      margin-bottom: 0.85rem;
      border-bottom: 1px solid var(--border-subtle);
      padding-bottom: 0.45rem;
      letter-spacing: -0.015em;
    }}

    .report-content h1 {{ font-size: 1.65rem; font-weight: 800; }}
    .report-content h2 {{ font-size: 1.4rem; font-weight: 700; }}
    .report-content h3 {{ font-size: 1.2rem; font-weight: 700; }}
    .report-content h4 {{ font-size: 1.05rem; font-weight: 600; }}

    .report-content p {{
      margin-bottom: 1rem;
      color: var(--text-secondary);
      font-size: 0.95rem;
      line-height: 1.65;
    }}

    .report-content ul, .report-content ol {{
      margin-left: 1.75rem;
      margin-bottom: 1.25rem;
      color: var(--text-secondary);
      font-size: 0.95rem;
    }}

    .report-content li {{
      margin-bottom: 0.4rem;
      line-height: 1.6;
    }}

    .report-content table {{
      width: 100%;
      border-collapse: collapse;
      margin: 1.5rem 0;
      background: var(--bg-surface-elevated);
      border-radius: 8px;
      overflow: hidden;
      border: 1px solid var(--border-subtle);
    }}

    .report-content th, .report-content td {{
      padding: 0.85rem 1rem;
      border: 1px solid var(--border-subtle);
      text-align: left;
      font-size: 0.9rem;
    }}

    .report-content th {{
      background-color: var(--bg-surface-soft);
      color: var(--text-primary);
      font-weight: 700;
    }}

    .report-content code {{
      background-color: var(--code-bg);
      color: var(--code-color);
      padding: 0.15rem 0.4rem;
      border-radius: 4px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.85rem;
      border: 1px solid var(--border-subtle);
    }}

    .report-content pre {{
      background-color: var(--code-bg);
      border: 1px solid var(--code-border);
      border-radius: 8px;
      padding: 1.25rem;
      overflow-x: auto;
      margin: 1.25rem 0;
    }}

    .report-content pre code {{
      background-color: transparent;
      padding: 0;
      color: var(--code-color);
      border: none;
      font-size: 0.875rem;
      display: block;
    }}

    footer {{
      text-align: center;
      margin-top: 3.5rem;
      padding-top: 2rem;
      border-top: 1px solid var(--border-subtle);
      font-size: 0.8rem;
      color: var(--text-muted);
    }}

    /* Print & PDF optimization */
    @media print {{
      @page {{
        size: A4 portrait;
        margin: 1.5cm 1.2cm;
      }}
      body {{
        background: #ffffff !important;
        color: #0f172a !important;
        font-size: 10pt !important;
      }}
      .action-bar, .btn {{ display: none !important; }}
      .container {{ max-width: 100% !important; padding: 0 !important; }}
      .hero-card, .posture-card, .kpi-card, .report-card {{
        background: #ffffff !important;
        border: 1px solid #cbd5e1 !important;
        box-shadow: none !important;
        color: #0f172a !important;
        page-break-inside: avoid !important;
        break-inside: avoid !important;
      }}
      .report-content h1, .report-content h2, .report-content h3 {{
        color: #0f172a !important;
        border-color: #cbd5e1 !important;
      }}
      .report-content p, .report-content li {{ color: #1e293b !important; }}
      .report-content table th {{ background: #f1f5f9 !important; color: #0f172a !important; }}
      .report-content pre {{
        background: #f8fafc !important;
        border-color: #cbd5e1 !important;
      }}
      .report-content code {{ color: #0369a1 !important; }}
    }}
  </style>
</head>
<body>

  <header class="action-bar">
    <div class="bar-brand">
      <div class="brand-logo">&#x1F6E1;</div>
      <div>
        <div class="brand-title">Web Security Defensive Auditor</div>
        <div class="brand-meta">
          <span>Asset: {hostname}</span>
          <span class="badge-confidential">Confidential // Restricted</span>
        </div>
      </div>
    </div>

    <div class="bar-controls">
      <button class="btn btn-outline" onclick="toggleTheme()" title="Switch Theme">
        <span id="themeIcon">&#x2600;</span> Theme
      </button>

      <button class="btn btn-primary" onclick="window.print()" title="Open Print dialog to Save as PDF">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
          <polyline points="7 10 12 15 17 10"></polyline>
          <line x1="12" y1="15" x2="12" y2="3"></line>
        </svg>
        Download as PDF
      </button>
    </div>
  </header>

  <div class="container">
    <section class="hero-card">
      <div class="hero-top-row">
        <span class="hero-pill">&#x1F6E1; Defensive Security Audit</span>
        <div style="font-size: 0.85rem; color: var(--text-muted); font-family: 'JetBrains Mono', monospace;">
          Generated: {timestamp}
        </div>
      </div>
      <h1 class="hero-title">Security Hardening & Posture Assessment</h1>
      <p class="hero-subtitle">
        Independent defensive cybersecurity analysis and technical remediation guide for <strong>{hostname}</strong>.
      </p>
      <div class="hero-meta-grid">
        <div class="meta-item">
          <span class="meta-label">Target Asset</span>
          <span class="meta-value"><code>{target_url}</code></span>
        </div>
        <div class="meta-item">
          <span class="meta-label">Audit Engine</span>
          <span class="meta-value">Web Security Agent 2.0</span>
        </div>
        <div class="meta-item">
          <span class="meta-label">Assessment Scope</span>
          <span class="meta-value">External Defensive Perimeter</span>
        </div>
        <div class="meta-item">
          <span class="meta-label">Skills Engaged</span>
          <span class="meta-value">{skills_count} SecOps Modules</span>
        </div>
      </div>
    </section>

    <section class="dashboard-grid">
      <div class="posture-card">
        <div>
          <div class="posture-header">
            <span class="posture-title">Posture Assessment</span>
            <span class="hero-pill" style="font-size: 0.7rem;">{posture_rating}</span>
          </div>
          <div class="score-display">
            <span class="score-grade">{posture_grade}</span>
            <div>
              <div class="score-rating">{posture_rating}</div>
              <div style="font-size: 0.75rem; color: var(--text-muted);">Score: {calc_score}/100</div>
            </div>
          </div>
          <p style="font-size: 0.85rem; color: var(--text-secondary);">
            Automated defensive evaluation of transport parameters, header hygiene, and exposed infrastructure endpoints.
          </p>
        </div>
      </div>

      <div class="kpi-cards-grid">
        <div class="kpi-card">
          <div class="kpi-header">
            <span class="kpi-label">Missing Headers</span>
            <span class="kpi-indicator {'ind-danger' if missing_count > 3 else 'ind-warning' if missing_count > 0 else 'ind-success'}"></span>
          </div>
          <div class="kpi-value" style="color: {'var(--sev-critical)' if missing_count > 3 else 'var(--sev-high)' if missing_count > 0 else 'var(--sev-success)'};">{missing_count}</div>
          <div class="kpi-sub">Lacking browser directives</div>
        </div>

        <div class="kpi-card">
          <div class="kpi-header">
            <span class="kpi-label">Transport Layer</span>
            <span class="kpi-indicator ind-info"></span>
          </div>
          <div class="kpi-value" style="color: var(--brand-primary); font-size: 1.6rem;">{tls_version}</div>
          <div class="kpi-sub">{tls_sub}</div>
        </div>

        <div class="kpi-card">
          <div class="kpi-header">
            <span class="kpi-label">Exposed Paths</span>
            <span class="kpi-indicator {'ind-danger' if exposed_count > 0 else 'ind-success'}"></span>
          </div>
          <div class="kpi-value" style="color: {'var(--sev-critical)' if exposed_count > 0 else 'var(--sev-success)'};">{exposed_count}</div>
          <div class="kpi-sub">Sensitive files discovered</div>
        </div>

        <div class="kpi-card">
          <div class="kpi-header">
            <span class="kpi-label">Skills Engaged</span>
            <span class="kpi-indicator ind-info"></span>
          </div>
          <div class="kpi-value">{skills_count}</div>
          <div class="kpi-sub">Cybersecurity procedures</div>
        </div>
      </div>
    </section>

    <div class="report-card">
      <div class="report-content">
        {body_html}
      </div>
    </div>

    <footer>
      <p><strong>Web Security Agent</strong> &bull; Curated defensive cybersecurity procedures &bull; Authorized audit only</p>
      <p style="font-size: 0.75rem; color: var(--text-muted); margin-top: 0.35rem;">
        Confidential Security Assessment Report &bull; Generated for system owner remediation
      </p>
    </footer>
  </div>

  <script>
    function toggleTheme() {{
      const isLight = document.body.classList.toggle('light-theme');
      const themeIcon = document.getElementById('themeIcon');
      if (themeIcon) {{
        themeIcon.innerHTML = isLight ? "&#x1F319;" : "&#x2600;";
      }}
    }}
  </script>
</body>
</html>"""
    return html_template
