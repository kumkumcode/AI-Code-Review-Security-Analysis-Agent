Copy and paste this entire code block directly into your main A05_2021-Security_Misconfiguration.md file:

Markdown
---
id: OWASP-2021-A05
title: Security Misconfiguration
category: Security Misconfiguration
severity_hint: High
languages: [python, java]
cwes: [CWE-2, CWE-11, CWE-13, CWE-15, CWE-16, CWE-260, CWE-315, CWE-520, CWE-526, CWE-537, CWE-541, CWE-547, CWE-611, CWE-614, CWE-756, CWE-776, CWE-942, CWE-1004, CWE-1032, CWE-1174]
related_guidelines: [CONFIG-1, HARDENING-1]
---

# A05:2021 – Security Misconfiguration

## Factors

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Avg Weighted Exploit | Avg Weighted Impact | Max Coverage | Avg Coverage | Total Occurrences | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 20 | 19.84% | 4.51% | 8.12 | 6.56 | 89.58% | 44.84% | 208,387 | 789 |

## Overview
Security Misconfiguration can occur at any level of an application stack, including network services, platform infrastructure, web servers, database systems, containers, and custom application frameworks. It includes missing appropriate hardening, active default features, and overly informative error messages.

### 🛡️ Secure Deployment Process
┌─────────────────────────────────────────────────────────────┐
│              Automated Infrastructure (IaC / GitOps)        │
└──────────────┬──────────────────────────────────────────────┘
▼
┌─────────────────────────────────────────────────────────────┐
│ 1. HARDEN STACK (Disable defaults, debug logs, unused ports)│
└──────────────┬──────────────────────────────────────────────┘
▼
┌─────────────────────────────────────────────────────────────┐
│ 2. SECURE CLIENT HEADERS (HSTS, CSP, HttpOnly, Secure Flags)│
└──────────────┬──────────────────────────────────────────────┘
▼
┌─────────────────────────────────────────────────────────────┐
│ 3. ENFORCE XML SAFEPARSING (Disable DTDs & External Entities)│
└─────────────────────────────────────────────────────────────┘


---

## Modern Python Examples

### ❌ Insecure XML Parsing (CWE-611: XML External Entity - XXE)
By default, some legacy Python libraries or misconfigured parsers allow document type definitions (DTDs) and external entities, permitting system file leakage.
```python
from fastapi import FastAPI, Request
from lxml import etree

app = FastAPI()

@app.post("/upload-xml")
async def parse_xml(request: Request):
    body = await request.body()
    # VULNERABLE: Parser configured with resolve_entities=True allows XXE injection
    parser = etree.XMLParser(resolve_entities=True, no_network=False)
    root = etree.fromstring(body, parser=parser)
    return {"message": "Parsed successfully", "root_tag": root.tag}
✅ Secure XML Parsing (XXE Mitigation)
Explicitly disabling DTD parsing and external entity resolution ensures the XML processor ignores malicious remote references entirely.

Python
from fastapi import FastAPI, Request
from lxml import etree

app = FastAPI()

@app.post("/upload-xml")
async def parse_xml(request: Request):
    body = await request.body()
    # SECURE: Explicitly disable external entity resolution and DTD loading
    parser = etree.XMLParser(resolve_entities=False, dtd_validation=False)
    # Ensure no network access is permitted during parsing processes
    parser.resolvers.add(etree.Resolver()) 
    
    root = etree.fromstring(body, parser=parser)
    return {"message": "Parsed safely", "root_tag": root.tag}
❌ Insecure Middleware Configuration (Missing Security Headers)
Running a public API without sending modern browser instructions leaves users susceptible to Clickjacking, MIME-sniffing, and cross-site scripting.

Python
from fastapi import FastAPI

app = FastAPI()

@app.get("/data")
def read_data():
    # VULNERABLE: Standard response without protective security headers
    return {"secure": False}
✅ Secure Middleware Configuration (Enforcing HTTP Headers)
Registering structured middleware ensuring every response conveys explicit isolation guidelines to modern client runtimes.

Python
from fastapi import FastAPI, Request

app = FastAPI()

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    # SECURE: Enforce essential security directives
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    return response
Modern Java Examples
❌ Insecure DocumentBuilder (CWE-611: Java XXE)
Java
import javax.xml.parsers.DocumentBuilderFactory;
import org.xml.sax.InputSource;
import java.io.StringReader;

public class XmlParser {
    public void parse(String xmlInput) throws Exception {
        // VULNERABLE: Default parser properties resolve external entities
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        var builder = dbf.newDocumentBuilder();
        var doc = builder.parse(new InputSource(new StringReader(xmlInput)));
    }
}
✅ Secure DocumentBuilder (Disabling External DTDs)
Java
import javax.xml.parsers.DocumentBuilderFactory;
import org.xml.sax.InputSource;
import java.io.StringReader;

public class XmlParser {
    public void parse(String xmlInput) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        
        // SECURE: Explicitly disable DTDs (Document Type Definitions) completely
        String FEATURE = "[http://apache.org/xml/features/disallow-doctype-decl](http://apache.org/xml/features/disallow-doctype-decl)";
        dbf.setFeature(FEATURE, true);
        
        // Alternative protection if DTDs are strictly necessary but external entities are not:
        dbf.setFeature("[http://xml.org/sax/features/external-general-entities](http://xml.org/sax/features/external-general-entities)", false);
        dbf.setFeature("[http://xml.org/sax/features/external-parameter-entities](http://xml.org/sax/features/external-parameter-entities)", false);
        dbf.setFeature("[http://apache.org/xml/features/nonvalidating/load-external-dtd](http://apache.org/xml/features/nonvalidating/load-external-dtd)", false);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);

        var builder = dbf.newDocumentBuilder();
        var doc = builder.parse(new InputSource(new StringReader(xmlInput)));
    }
}
Real-World Edge Cases & Advanced Vulnerabilities
1. S3 / Cloud Storage Permissive Policies
Cloud misconfigurations frequently expose private resources due to overly permissive Access Control Lists (ACLs) or wildcards in identity policies.

The Flaw: Granting wildcard read or write permissions (*) to dynamic resource actions.

Remediation: Apply the Principle of Least Privilege. Restrict storage policies to specific IAM roles instead of using anonymous access parameters.

2. Cookie Management without Secure Flags
Transmitting sensitive cookies (such as session tokens or anti-CSRF state) over unencrypted connections or allowing client scripts to read them.

The Flaw: Omitting the HttpOnly and Secure attributes on session identifiers.

Remediation: Always compile cookies with HttpOnly=true, Secure=true, and explicit SameSite=Strict (or Lax) policies.

How to Prevent
Automated Hardening: Use Infrastructure-as-Code (IaC) templates to programmatically maintain identical sandbox, staging, and production server profiles.

Strip Default Assets: Actively remove developer sample scripts, administrative console templates, and generic helper utilities from deployment bundles.

Control Security Headers: Configure robust HTTP system boundaries (such as Content Security Policy, HSTS, and X-Content-Type-Options) by default.

Enforce Safe Defaults for Parsers: Configure all JSON, XML, and template engine processors to explicitly reject external structural parsing queries.

References
OWASP Cheat Sheet: XML External Entity Prevention

OWASP ASVS: V14 Configuration Verification

CIS Security Benchmarks

NIST SP 800-123: Guide to General Server Hardening

# Security Misconfiguration Addendum: Practical Hardening Controls

## Python — Debug Mode Enabled in Production

Running an application in debug mode can expose interactive debugger consoles, structural source files, and stack traces directly to external actors, leading to remote code execution (RCE) or information disclosure.

### ❌ Insecure Configuration (Unconditional Debug Mode)
```python
from flask import Flask
app = Flask(__name__)

# VULNERABLE: Direct enforcement of debug console and system-wide visibility
app.run(debug=True, host="0.0.0.0")
✅ Secure Configuration (Environment-Driven Evaluation)
Python
import os
from flask import Flask
app = Flask(__name__)

# SECURE: Read state from external system environments defaulting to strict safe modes
app.config["DEBUG"] = os.environ.get("FLASK_DEBUG", "False").strip().lower() == "true"

# Enforce host bindings depending on production segregation needs
app.run(debug=app.config["DEBUG"], host="127.0.0.1")
Java — Verbose Error Pages Exposing Stack Traces
Standard Spring Boot/Java deployment parameters can expose active database connections, table names, and logical code layers within browser-facing response bodies when internal application exceptions arise.

❌ Insecure Configuration (Verbose Error Diagnostics)
Properties
# application.properties
# VULNERABLE: Exposes critical exception details and execution paths to clients
server.error.include-stacktrace=always
server.error.include-message=always
✅ Secure Configuration (Sanitized Response Structures)
Properties
# application.properties
# SECURE: Restrict debug errors to localized system/container logging agents
server.error.include-stacktrace=never
server.error.include-message=never
Key Configuration Checklists
No Production Debug Runs: Never deploy service runtimes with debug indicators turned on. Ensure build configurations or CI/CD pipelines strip out debugging states.

Access Hardening: Disable server directory listings (e.g., Options -Indexes in Apache/Nginx routing configurations) and instantly scrub out default accounts or built-in developer templates.

Generic Failures: Standardize global server exception filters to yield consistent, sanitized error structures to consumers while preserving the raw traceback data solely within secure internal logger endpoints.