# Open Redirect (Unvalidated Redirect Parameter Enables Phishing Attack Chain)

**Vulnerability Type:** Open Redirect <br>
**Severity:** Medium (CVSS 3.1 Score: 6.1)<br>
**Platform:** Bug Bounty (Redacted)<br>
**Status:** Resolved / Disclosed<br>
**Date:** 2024<br>

---

## Summary

An Open Redirect vulnerability was identified in the post-login redirect functionality of a web application. After successful authentication, the application redirected users to a URL specified in the `next` query parameter without validating that the destination was within the application's own domain. By crafting a malicious login URL with an external attacker-controlled domain in the `next` parameter, users who clicked the link and logged in were silently redirected to a phishing site — making the attack highly convincing since it originated from a trusted domain.

---

## Vulnerability Details

| Field | Details |
|---|---|
| Type | Open Redirect — Unvalidated `next` Parameter |
| Endpoint | `GET /login?next=` |
| Authentication Required | No (pre-login) |
| User Interaction | Yes (victim must click crafted link and log in) |
| Impact | Phishing, credential harvesting, OAuth token theft |
| CVSS Vector | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N |

---

## Background: Why Open Redirect Matters

Open redirects are sometimes dismissed as low-severity because they require user interaction. However, they are particularly dangerous when chained with other attacks:

- **Phishing** — Attackers send links from a trusted domain that redirect to a fake login page
- **OAuth abuse** — Some OAuth flows use redirect URIs, and an open redirect can be used to steal authorization codes
- **XSS bypass** — Can bypass same-origin policy checks in certain JavaScript redirect patterns
- **Credibility** — Victims see `https://trusted-site.com/login?next=...` in the URL — the legitimate domain makes the link appear safe

---

## Steps to Reproduce

### 1. Identify the redirect parameter

Navigate to the login page. After a failed login attempt or when accessing a protected page while unauthenticated, observe the URL:

```
https://redacted.com/login?next=/dashboard
```

After successful login, the application redirects to `/dashboard`. The `next` parameter controls the destination.

### 2. Test with an external URL

Replace the `next` value with an external domain:

```
https://redacted.com/login?next=https://evil.com
```

Log in with valid credentials. After successful authentication, the browser is immediately redirected to `https://evil.com`.

**No warning, no confirmation — a seamless redirect to an attacker-controlled site.**

### 3. Test URL encoding bypass

Some applications attempt to block external URLs by checking for `http://` or `https://` prefixes. Test bypasses:

```
# Double-encoded slash
https://redacted.com/login?next=%2F%2Fevil.com

# Protocol-relative URL
https://redacted.com/login?next=//evil.com

# Using @ symbol (browser resolves to evil.com)
https://redacted.com/login?next=https://redacted.com@evil.com
```

All three bypasses redirected successfully to `evil.com`, confirming there was no robust validation in place.

### 4. Build a realistic phishing scenario

An attacker would clone the application's login page on `evil.com` and craft the following email:

> **Subject:** Your account requires verification
>
> *"Please log in to verify your account details: https://redacted.com/login?next=https://evil.com/fake-login"*

The victim sees the legitimate `redacted.com` URL, logs in, and is redirected to a fake login page that says "Session expired, please log in again" — capturing their credentials a second time.

### 5. OAuth token theft scenario (demonstrated in report)

If the application uses OAuth and a redirect_uri parameter:

```
https://redacted.com/oauth/authorize?client_id=app&redirect_uri=https://redacted.com/login?next=https://evil.com&response_type=code
```

In some configurations this can redirect the authorization code to the attacker's domain after the OAuth flow completes.

---

## Impact

- **Phishing attacks** — Highly convincing because the initial URL is a legitimate trusted domain
- **Credential harvesting** — Redirect to a cloned login page after authentication
- **OAuth token theft** — Steal authorization codes in OAuth flows using open redirect as the redirect_uri
- **Trust exploitation** — Bypass email filters and security awareness training since the link domain is legitimate
- **Session token theft** — If the post-login redirect includes tokens in the URL fragment

---

## Root Cause

The application read the `next` parameter and redirected without any domain validation:

```python
# Vulnerable pseudocode
@app.route('/login', methods=['POST'])
def login():
    if authenticate(request.form['username'], request.form['password']):
        next_url = request.args.get('next', '/dashboard')
        return redirect(next_url)  # No validation — redirects anywhere
```

No check was performed to ensure the `next` URL belonged to the same origin.

---

## Remediation

1. **Validate the redirect URL against an allowlist** — Only redirect to paths within your own domain:
   ```python
   from urllib.parse import urlparse, urljoin
   
   def is_safe_url(target, host):
       ref_url = urlparse(host)
       test_url = urlparse(urljoin(host, target))
       return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc
   
   next_url = request.args.get('next', '/dashboard')
   if not is_safe_url(next_url, request.host_url):
       next_url = '/dashboard'
   return redirect(next_url)
   ```
2. **Use relative paths only** — Accept only paths (e.g., `/dashboard`) not full URLs. Reject any value containing `://` or starting with `//`.
3. **Avoid redirect parameters entirely** — Store the intended destination in the server-side session rather than passing it in the URL.
4. **Apply Content Security Policy** — A strict CSP can limit the damage of redirect-based attacks in some scenarios.

---

## References

- [PortSwigger — Open Redirection](https://portswigger.net/kb/issues/00500100_open-redirection-reflected)
- [OWASP — Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- [HackTricks — Open Redirect](https://book.hacktricks.xyz/pentesting-web/open-redirect)

---

*This writeup is published for educational purposes. All testing was conducted within an authorized bug bounty program. The phishing scenario was described hypothetically in the report — no phishing infrastructure was deployed and no real users were targeted.*
