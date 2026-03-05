# Security Research & Vulnerability Writeups

<br>

| | |
|---|---|
| **Author** | Danish Abbas |
| **Focus** | Web Application Security · Bug Bounty · Penetration Testing |
| **LinkedIn** | [linkedin.com/in/danish-abbas-132411216](https://linkedin.com/in/danish-abbas-132411216) |
| **GitHub** | [github.com/DanishAbbas72](https://github.com/DanishAbbas72) |
| **Email** | [danish.abbas.infosec@gmail.com](mailto:daniibangash72@gmail.com) |
| **Location** | Islamabad, Pakistan 🇵🇰 |

---

## About

This repository contains vulnerability research writeups, proof-of-concept demonstrations, and security findings from bug bounty programs and personal security research. All writeups follow responsible disclosure principles. No sensitive data, credentials, or personally identifiable information is included.

All testing described was conducted within the scope of authorized bug bounty programs or controlled lab environments.

---

## Writeups

| # | Vulnerability | Severity | Category | CVSS |
|---|---|---|---|---|
| 01 | [IDOR — Unauthorized Access to User Profile Data](./01-idor-user-data-exposure.md) | 🟠 High | Access Control | 7.5 |
| 02 | [Stored XSS — Persistent Injection via Profile Bio Field](./02-stored-xss-profile-bio.md) | 🟠 High | Injection | 6.8 |
| 03 | [Broken Authentication — JWT None Algorithm Bypass](./03-broken-auth-jwt-none-algorithm.md) | 🔴 Critical | Authentication | 9.1 |
| 04 | [SQL Injection — Error-Based SQLi in Search Functionality](./04-sql-injection-error-based-search.md) | 🔴 Critical | Injection | 9.8 |
| 05 | [Reflected XSS — Script Injection via URL Parameter](./05-reflected-xss-search-parameter.md) | 🟡 Medium | Injection | 6.1 |
| 06 | [SSRF — AWS Metadata Service Exposure](./06-ssrf-aws-metadata-exposure.md) | 🟠 High | SSRF | 8.6 |
| 07 | [Broken Access Control — Privilege Escalation via Mass Assignment](./07-broken-access-control-privilege-escalation.md) | 🔴 Critical | Access Control | 9.1 |
| 08 | [Open Redirect — Unvalidated Redirect Enables Phishing](./08-open-redirect-phishing-chain.md) | 🟡 Medium | Redirect | 6.1 |
| 09 | [XXE Injection — Local File Disclosure via File Upload](./09-xxe-local-file-disclosure.md) | 🟠 High | Injection | 7.5 |
| 10 | [CSRF — Account Email Takeover](./10-csrf-account-email-takeover.md) | 🟠 High | CSRF | 7.1 |
| 11 | [Subdomain Takeover — Dangling CNAME on GitHub Pages](./11-subdomain-takeover-dangling-cname.md) | 🟠 High | Recon | 7.5 |
| 12 | [Insecure File Upload — Remote Code Execution via PHP Shell](./12-insecure-file-upload-rce.md) | 🔴 Critical | File Upload / RCE | 9.8 |

---

## Vulnerability Summary

```
Total Writeups    : 12
Critical (9.0+)   : 4  (JWT Bypass, SQLi, Privilege Escalation, File Upload RCE)
High    (7.0-8.9) : 6  (IDOR, Stored XSS, SSRF, XXE, CSRF, Subdomain Takeover)
Medium  (4.0-6.9) : 2  (Reflected XSS, Open Redirect)
```

---

## OWASP Top 10 Coverage

| OWASP Category | Writeup |
|---|---|
| A01 — Broken Access Control | IDOR, Privilege Escalation, CSRF |
| A02 — Cryptographic Failures | JWT None Algorithm |
| A03 — Injection | Stored XSS, Reflected XSS, SQLi, XXE |
| A05 — Security Misconfiguration | XXE, Insecure File Upload |
| A07 — Identification & Auth Failures | JWT Bypass |
| A10 — Server-Side Request Forgery | SSRF |
| Other — Subdomain Takeover | Dangling CNAME |
| Other — File Upload RCE | PHP Web Shell |

---

## Skills Demonstrated

- Manual web application penetration testing (Burp Suite)
- OWASP Top 10 vulnerability identification and exploitation
- SQL injection (error-based, boolean-based)
- XSS (stored, reflected, WAF bypass)
- JWT security analysis and algorithm confusion attacks
- IDOR / Broken Object Level Authorization (BOLA)
- SSRF — internal network access and cloud metadata exploitation
- XXE injection via XML file uploads
- CSRF — account takeover via forged requests
- Subdomain enumeration and takeover via dangling CNAME
- Insecure file upload — PHP web shell, extension bypass, RCE
- Mass assignment / privilege escalation
- Open redirect chaining for phishing attacks
- CVSS risk scoring and structured vulnerability reporting
- Responsible disclosure and professional bug bounty communication

---

## Methodology

All assessments follow a structured approach:

```
Reconnaissance → Enumeration → Vulnerability Identification
→ Exploitation (PoC) → Impact Assessment → Reporting → Disclosure
```

---

## Tools

| Tool | Use |
|---|---|
| Burp Suite | Traffic interception, repeater, intruder, active scanning |
| Nmap | Port and service enumeration |
| OWASP ZAP | Automated scanning and fuzzing |
| Python | Custom scripts and PoC development |
| subfinder / httpx | Subdomain enumeration and probing |
| jwt.io | JWT decoding and analysis |
| dig / nslookup | DNS record analysis |
| curl | HTTP response verification |

---

## Responsible Disclosure Policy

All vulnerabilities documented in this repository were:
- Discovered within authorized bug bounty program scope
- Reported to the affected vendor before public disclosure
- Tested using safe, non-destructive proof-of-concept payloads only
- Not exploited for personal gain or to access real user data

---

## Disclaimer

This repository is for **educational purposes only**. The techniques described are intended to help developers understand and fix security vulnerabilities. Unauthorized testing of systems you do not own or have explicit permission to test is illegal and unethical.

---

*Writeups added regularly as research progresses.*
