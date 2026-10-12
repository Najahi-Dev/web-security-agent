# Security Report for https://softlenz.hrlenz.lk/

## Defensive Hardening Report: Application Server

### Executive Summary
The application demonstrates a strong baseline by utilizing TLS 1.3 and enforcing `Secure` and `HttpOnly` flags on the session cookie. However, the absence of critical security headers leaves the application susceptible to Cross-Site Scripting (XSS), Clickjacking, and protocol downgrade attacks. The overall risk level is **Moderate**, requiring immediate implementation of browser-level protection headers.

---

### Prioritized Findings

#### 1. Critical: Missing HTTP Strict Transport Security (HSTS)
*   **What was found**: The `Strict-Transport-Security` header is not present.
*   **Why it matters**: Without HSTS, the application is vulnerable to SSL stripping attacks, where an attacker intercepts an initial HTTP request and forces the user onto an unencrypted connection to steal session data.
*   **Fix**: Configure your web server (or Cloudflare rules) to send the following header:
    `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`

#### 2. High: Missing Content Security Policy (CSP)
*   **What was found**: No `Content-Security-Policy` header is defined.
*   **Why it matters**: This is the primary defense against Cross-Site Scripting (XSS) and data injection. Without it, the browser will execute any malicious script injected into the page.
*   **Fix**: Implement a strict CSP. Start with a report-only policy to monitor violations, then enforce:
    `Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';`

#### 3. High: Missing Frame Protection (Clickjacking Defense)
*   **What was found**: `X-Frame-Options` and the CSP `frame-ancestors` directive are missing.
*   **Why it matters**: Attackers can overlay the application within an invisible iframe on a malicious site, tricking users into performing unauthorized actions (Clickjacking).
*   **Fix**: Add the following header:
    `X-Frame-Options: DENY` (Alternatively, ensure CSP `frame-ancestors 'none'` is implemented).

#### 4. Medium: Missing X-Content-Type-Options
*   **What was found**: `X-Content-Type-Options: nosniff` is missing.
*   **Why it matters**: Browsers may attempt to "sniff" the MIME type of a file, potentially executing a non-executable file (like a text file containing malicious script) as an HTML document.
*   **Fix**: Add the following header:
    `X-Content-Type-Options: nosniff`

#### 5. Low: Missing Security Policy Headers
*   **What was found**: `Referrer-Policy`, `Permissions-Policy`, and `Cross-Origin-*` headers are missing.
*   **Why it matters**: These headers reduce information leakage and restrict browser capabilities (like camera/mic) if the app is compromised.
*   **Fix**: Implement:
    *   `Referrer-Policy: strict-origin-when-cross-origin`
    *   `Permissions-Policy: camera=(), microphone=(), geolocation=()`

---

### Hardening Recommendations for Defense-in-Depth

1.  **XSRF-TOKEN Hardening**: Your `XSRF-TOKEN` cookie is missing the `HttpOnly` flag. While XSRF tokens are often read by JS, ensure this token is strictly validated server-side to prevent session-based CSRF.
2.  **Cloudflare Security Settings**: 
    *   Enable **"Always Use HTTPS"** within the Cloudflare dashboard to ensure HTTP to HTTPS redirection happens at the edge.
    *   Enable **"Authenticated Origin Pulls"** if possible, to ensure only Cloudflare can connect to your origin server.
3.  **Certificate Management**: Your certificate expires in 54 days. Ensure your automated renewal process (e.g., Let's Encrypt/AutoSSL) is functioning correctly to avoid service disruption.
4.  **CSP Nonce Implementation**: For advanced XSS protection, transition from a domain-based CSP to a **nonce-based CSP**, where only scripts containing a cryptographically secure, server-side generated `nonce` are allowed to execute. 
5.  **Audit Cache**: Ensure `Cache-Control` is set to `no-store, no-cache, must-revalidate` for any pages containing sensitive user data to prevent browser-based caching of PII.
