"""
Benign, read-only recon against a site YOU OWN or are authorized to test.

Everything here only sends normal GET/HEAD requests and reads the TLS
certificate your own server already serves to any visitor's browser.
It never attempts to exploit anything, brute force anything, or send
attack payloads - it just collects facts for the AI agent to reason
about using the cybersecurity skill library.
"""
import socket
import ssl
import datetime
from urllib.parse import urlparse

import requests

TIMEOUT = 8

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
]

LEAKY_HEADERS = ["server", "x-powered-by", "x-aspnet-version"]

# Paths that commonly leak secrets/config if a deploy step went wrong.
# We only ever GET them - never try to read contents past the status code
# and a short snippet, and never attempt auth bypass.
COMMON_EXPOSED_PATHS = [
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/wp-config.php.bak",
    "/config.php.bak",
    "/.DS_Store",
    "/backup.zip",
    "/.aws/credentials",
    "/phpinfo.php",
    "/debug",
    "/.well-known/security.txt",
]


def fetch_headers(url):
    try:
        resp = requests.get(url, timeout=TIMEOUT, allow_redirects=True)
        return {
            "status_code": resp.status_code,
            "final_url": resp.url,
            "headers": dict(resp.headers),
            "cookies": [
                {
                    "name": c.name,
                    "secure": c.secure,
                    "httponly": "httponly" in [k.lower() for k in c._rest.keys()],
                    "samesite": c._rest.get("SameSite") or c._rest.get("samesite"),
                }
                for c in resp.cookies
            ],
        }
    except requests.RequestException as e:
        return {"error": str(e)}


def check_missing_security_headers(headers_dict):
    present = {k.lower(): v for k, v in headers_dict.items()}
    missing = [h for h in SECURITY_HEADERS if h not in present]
    leaky = {h: present[h] for h in LEAKY_HEADERS if h in present}
    return {"missing": missing, "leaky_disclosure": leaky}


def check_tls(hostname, port=443):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()
                not_after = datetime.datetime.strptime(
                    cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
                )
                days_left = (not_after - datetime.datetime.utcnow()).days
                return {
                    "tls_version": version,
                    "cert_expires": cert["notAfter"],
                    "days_until_expiry": days_left,
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                }
    except Exception as e:
        return {"error": str(e)}


def check_exposed_paths(base_url):
    from concurrent.futures import ThreadPoolExecutor, as_completed
    findings = []
    
    def _check(path):
        try:
            resp = requests.get(base_url.rstrip("/") + path, timeout=TIMEOUT)
            if resp.status_code == 200:
                return {"path": path, "status_code": resp.status_code}
        except requests.RequestException:
            pass
        return None

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(_check, p): p for p in COMMON_EXPOSED_PATHS}
        for future in as_completed(futures):
            res = future.result()
            if res:
                findings.append(res)
    findings.sort(key=lambda x: x["path"])
    return findings


def run_targeted_skill_probes(target_url, selected_skills, http_data=None):
    """
    Performs safe, non-intrusive targeted diagnostic probes based directly
    on which cybersecurity skills the user selected.
    Returns a dict mapping skill_name -> targeted evidence & observation.
    """
    probes = {}
    if not selected_skills:
        return probes

    headers = (http_data or {}).get("headers", {})
    lower_headers = {k.lower(): v for k, v in headers.items()}
    cookies = (http_data or {}).get("cookies", [])

    selected_names = set()
    for s in selected_skills:
        if isinstance(s, dict):
            selected_names.add(s.get("name", ""))
        else:
            selected_names.add(str(s))

    # 1. CORS Probe
    if "testing-cors-misconfiguration" in selected_names:
        try:
            cors_resp = requests.options(
                target_url,
                headers={"Origin": "https://unauthorized-origin.test", "Access-Control-Request-Method": "GET"},
                timeout=TIMEOUT,
            )
            cors_headers = {k.lower(): v for k, v in cors_resp.headers.items()}
            acao = cors_headers.get("access-control-allow-origin") or lower_headers.get("access-control-allow-origin")
            acac = cors_headers.get("access-control-allow-credentials") or lower_headers.get("access-control-allow-credentials")
            probes["testing-cors-misconfiguration"] = {
                "probe_origin_sent": "https://unauthorized-origin.test",
                "access_control_allow_origin": acao or "None",
                "access_control_allow_credentials": acac or "None",
                "is_wildcard": bool(acao == "*"),
                "is_origin_reflected": bool(acao == "https://unauthorized-origin.test"),
                "verdict": "Permissive / Insecure CORS" if (acao == "*" or acao == "https://unauthorized-origin.test") else "Secure / No Permissive CORS Detected",
            }
        except Exception as e:
            probes["testing-cors-misconfiguration"] = {"error": str(e)}

    # 2. Host Header Probe
    if "testing-for-host-header-injection" in selected_names:
        try:
            evil_host = "security-audit-probe.internal"
            host_resp = requests.get(
                target_url,
                headers={"Host": evil_host, "X-Forwarded-Host": evil_host},
                timeout=TIMEOUT,
                allow_redirects=False,
            )
            reflected_in_loc = evil_host in host_resp.headers.get("Location", "")
            reflected_in_body = evil_host in host_resp.text[:2000]
            probes["testing-for-host-header-injection"] = {
                "injected_host_tested": evil_host,
                "response_status_code": host_resp.status_code,
                "reflected_in_redirect_location": reflected_in_loc,
                "reflected_in_response_body": reflected_in_body,
                "verdict": "Vulnerable to Host Header Poisoning" if (reflected_in_loc or reflected_in_body) else "Protected / Host Header Rejected or Ignored",
            }
        except Exception as e:
            probes["testing-for-host-header-injection"] = {"error": str(e)}

    # 3. Clickjacking & Frame Protection Probe
    if "performing-clickjacking-attack-test" in selected_names:
        xfo = lower_headers.get("x-frame-options")
        csp = lower_headers.get("content-security-policy", "")
        has_frame_ancestors = "frame-ancestors" in csp.lower()
        is_blocked = (xfo in ["DENY", "SAMEORIGIN"]) or has_frame_ancestors
        probes["performing-clickjacking-attack-test"] = {
            "x_frame_options": xfo or "MISSING",
            "csp_frame_ancestors": "PRESENT" if has_frame_ancestors else "MISSING",
            "frame_embedding_blocked": is_blocked,
            "verdict": "Protected Against Clickjacking" if is_blocked else "Vulnerable to UI Redressing / Clickjacking",
        }

    # 4. XSS & Client-Side Protections Probe
    if "testing-for-xss-vulnerabilities" in selected_names:
        csp = lower_headers.get("content-security-policy", "")
        has_csp = bool(csp)
        has_unsafe_inline = "'unsafe-inline'" in csp.lower()
        has_unsafe_eval = "'unsafe-eval'" in csp.lower()
        insecure_cookies = [c["name"] for c in cookies if not c.get("httponly")]
        probes["testing-for-xss-vulnerabilities"] = {
            "csp_present": has_csp,
            "csp_allows_unsafe_inline": has_unsafe_inline,
            "csp_allows_unsafe_eval": has_unsafe_eval,
            "non_httponly_cookies_exposed_to_js": insecure_cookies,
            "x_content_type_options": lower_headers.get("x-content-type-options", "MISSING"),
            "verdict": "Defenses Hardened" if (has_csp and not has_unsafe_inline and not insecure_cookies) else "Weak Client Protections / Elevates XSS Risk",
        }

    # 5. Rate Limiting Probe
    if any(k in selected_names for k in ["implementing-api-rate-limiting-and-throttling", "performing-api-rate-limiting-bypass"]):
        rate_headers = {
            k: v for k, v in lower_headers.items()
            if any(term in k for term in ["ratelimit", "rate-limit", "retry-after"])
        }
        probes["api-rate-limiting"] = {
            "rate_limit_headers_detected": rate_headers if rate_headers else "None Detected",
            "verdict": "Rate-Limiting Directives Present" if rate_headers else "No Standard Rate-Limiting Headers Exposed",
        }

    # 6. OAuth / Session / Auth Probe
    if any(k in selected_names for k in [
        "configuring-oauth2-authorization-flow",
        "detecting-oauth-token-theft",
        "exploiting-oauth-misconfiguration",
        "performing-oauth-scope-minimization-review",
        "exploiting-idor-vulnerabilities",
        "exploiting-broken-function-level-authorization",
        "detecting-broken-object-property-level-authorization"
    ]):
        auth_cookies = [c for c in cookies if any(term in c["name"].lower() for term in ["auth", "token", "session", "sess", "jwt", "id", "user"])]
        cookie_flaws = []
        for c in auth_cookies:
            if not c.get("secure"):
                cookie_flaws.append(f"{c['name']} (Missing Secure flag)")
            if not c.get("httponly"):
                cookie_flaws.append(f"{c['name']} (Missing HttpOnly flag)")
            if not c.get("samesite"):
                cookie_flaws.append(f"{c['name']} (Missing SameSite attribute)")

        probes["auth-session-security"] = {
            "identified_auth_session_cookies": [c["name"] for c in auth_cookies],
            "cookie_configuration_deficiencies": cookie_flaws if cookie_flaws else "None (Flags Securely Configured)",
            "www_authenticate_header": lower_headers.get("www-authenticate", "None"),
        }

    # 7. SSL / TLS Assessment Probe
    if any(k in selected_names for k in ["performing-ssl-tls-security-assessment", "configuring-tls-1-3-for-secure-communications", "performing-ssl-certificate-lifecycle-management"]):
        hsts = lower_headers.get("strict-transport-security", "")
        probes["ssl-tls-hardening"] = {
            "hsts_present": bool(hsts),
            "hsts_preload": "preload" in hsts.lower(),
            "hsts_subdomains": "includesubdomains" in hsts.lower(),
            "hsts_header_value": hsts or "MISSING",
        }

    return probes


def run_full_scan(target_url, selected_skills=None):
    parsed = urlparse(target_url)
    hostname = parsed.hostname

    result = {"target": target_url}
    result["http"] = fetch_headers(target_url)

    if "headers" in result["http"]:
        result["header_findings"] = check_missing_security_headers(result["http"]["headers"])

    if parsed.scheme == "https" and hostname:
        result["tls"] = check_tls(hostname)

    result["exposed_paths"] = check_exposed_paths(target_url)
    result["skill_probes"] = run_targeted_skill_probes(target_url, selected_skills, result["http"])

    return result
