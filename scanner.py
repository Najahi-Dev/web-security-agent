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
    findings = []
    for path in COMMON_EXPOSED_PATHS:
        try:
            resp = requests.get(base_url.rstrip("/") + path, timeout=TIMEOUT)
            if resp.status_code == 200:
                findings.append({"path": path, "status_code": resp.status_code})
        except requests.RequestException:
            continue
    return findings


def run_full_scan(target_url):
    parsed = urlparse(target_url)
    hostname = parsed.hostname

    result = {"target": target_url}
    result["http"] = fetch_headers(target_url)

    if "headers" in result["http"]:
        result["header_findings"] = check_missing_security_headers(result["http"]["headers"])

    if parsed.scheme == "https" and hostname:
        result["tls"] = check_tls(hostname)

    result["exposed_paths"] = check_exposed_paths(target_url)

    return result
