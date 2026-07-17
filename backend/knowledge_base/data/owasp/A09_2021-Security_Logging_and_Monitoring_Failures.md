---
id: OWASP-2021-A09
title: Security Logging and Monitoring Failures
category: Security Logging and Monitoring Failures
severity_hint: Medium
languages: [python, java]
cwes: [CWE-117, CWE-223, CWE-532, CWE-778]
related_guidelines: [LOGGING-1, MONITORING-1]
---

# A09:2021 – Security Logging and Monitoring Failures

## Factors

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Avg Weighted Exploit | Avg Weighted Impact | Max Coverage | Avg Coverage | Total Occurrences | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 4 | 19.23% | 6.51% | 6.87 | 4.99 | 53.67% | 39.97% | 53,615 | 242 |

## Overview
Security Logging and Monitoring Failures prevent organizations from detecting, escalating, and responding to active breaches. Without rapid and accurate alerts, compromises can remain completely unnoticed for months or years. This category encompasses insufficient transaction trails, raw sensitive data exposure in logs, and log injection vulnerabilities.

### 🛡️ Structured Logging & Detection Pipeline
┌─────────────────────────────────────────────────────────────┐
│                     Application Event                       │
└──────────────┬──────────────────────────────────────────────┘
▼
┌─────────────────────────────────────────────────────────────┐
│ 1. NEUTRALIZE INPUTS (Strip CRLF characters/line-breaks to  │
│    thwart Log Injection / Forge attacks)                    │
└──────────────┬──────────────────────────────────────────────┘
▼
┌─────────────────────────────────────────────────────────────┐
│ 2. REDACT SECRETS (Never write passwords, tokens, or PII)   │
└──────────────┬──────────────────────────────────────────────┘
▼
┌─────────────────────────────────────────────────────────────┐
│ 3. CENTRALIZED INGESTION (Stream securely to read-only,     │
│    append-only SIEM with active threshold alerts)           │
└─────────────────────────────────────────────────────────────┘


---

## Modern Python Examples

### ❌ Insecure Python Logging (CWE-117: Log Injection & Missing Audits)
Failing to record suspicious events, or writing raw unvalidated inputs directly to logs, allows an attacker to inject carriage returns and line feeds (CRLF) to forge log entries or execute log-injection exploits.
```python
import logging
from fastapi import FastAPI, Request, HTTPException

app = FastAPI()
logger = logging.getLogger("auth")

@app.post("/login")
async def login(request: Request):
    data = await request.json()
    username = data.get("username")
    password = data.get("password")
    
    # 1. VULNERABLE: Direct login validation failure is not recorded, ignoring audits
    if not verify_credentials(username, password):
        return {"error": "Invalid credentials"}
        
    # 2. VULNERABLE: Raw unsanitized username logged directly, allowing log-forgery injection
    # If the username contains "\n[INFO] User admin successfully logged in", the log is falsified.
    logger.warning(f"Failed attempt from username: {username}")
    raise HTTPException(status_code=401, detail="Unauthorized")
✅ Secure Python Logging (CRLF Neutralization & Context Retention)
Sanitizing log content and logging structured authentication context securely without recording credentials.

Python
import logging
from fastapi import FastAPI, Request, HTTPException, status

app = FastAPI()
logger = logging.getLogger("secure_auth")

def sanitize_for_log(input_string: str) -> str:
    # SECURE: Strip out dangerous control characters and newlines to prevent log injection
    return input_string.replace("\r", "").replace("\n", "")[:100]

@app.post("/login")
async def login(request: Request):
    data = await request.json()
    username = data.get("username", "")
    password = data.get("password", "")
    
    if not verify_credentials(username, password):
        # SECURE: Sanitize untrusted variables and log failures with explicit IP attributes
        safe_username = sanitize_for_log(username)
        logger.warning(
            "Authentication failed | identity=%s | source=%s | status=unauthorized",
            safe_username,
            request.client.host
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    return {"status": "authenticated"}
Modern Java Examples
❌ Insecure Java Logging (CWE-532: Logging Sensitive Data & Credentials)
Concatenating strings with credentials or personal keys inside logger methods writes unencrypted critical credentials directly to files or logging networks.

Java
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SecurityController {
    private static final Logger log = LoggerFactory.getLogger(SecurityController.class);

    public void processLogin(String username, String password) {
        // VULNERABLE: Logging plaintext passwords exposes credentials to anyone with log access
        log.info("User login request: user=" + username + " password=" + password);
    }
}
✅ Secure Java Logging (Parameterization & Sensitive Data Redaction)
Strictly omitting sensitive data and implementing robust logging parameters to prevent both leakage and log injection.

Java
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SecurityController {
    private static final Logger log = LoggerFactory.getLogger(SecurityController.class);

    public void processLogin(String username, String password) {
        // SECURE: Log only non-sensitive identity metadata, utilizing parameterized formatting
        // This mitigates string concatenation overhead and reduces log-injection risks
        String sanitizedUser = username.replaceAll("[\r\n]", "");
        log.info("User login attempt initiated | username={}", sanitizedUser);
    }
}
Real-World Edge Cases & Advanced Vulnerabilities
1. Log Forgery and Line-Injection Attacks
If an attacker sends custom newline sequences (\r\n or %0D%0A) in a request payload, and that payload is written to a standard file log, the output file splits into fake entries.

The Flaw: Trusting user inputs (e.g., query params, user agents, cookies) within plain-text logger statements.

Remediation: Always strip carriage returns and line feeds, or format your system to output structured JSON logs, which treat newlines safely as escaped characters (\n).

2. Failure to Log High-Value Transactions and API Key Usage
Recording basic system errors but failing to audit privilege escalations, financial adjustments, or access token creations.

The Flaw: High-privilege actions occur silently, making post-incident forensics impossible.

Remediation: Enforce a strict audit policy requiring cryptographic logging or tamper-evident trails (e.g., database constraints, ledger logging) for all key business actions.

How to Prevent
Audit Security Events: Log all authentication, authorization, validation, and authorization failures with rich, sanitized context.

Neutralize Log Inputs: Strip out newline characters and control symbols from all user-supplied variables before logging them.

Redact Sensitive Information: Never log raw credentials, session identifiers, security tokens, full payment details, or personal identifiable information (PII).

Stream Externally: Never store logs exclusively in local storage. Ship logs to a centralized, read-only SIEM with automated real-world thresholds and active monitoring configurations.

References
OWASP Cheat Sheet: Logging

OWASP ASVS: V7 Logging and Monitoring

NIST SP 800-61r2: Computer Security Incident Handling Guide

OWASP Cheat Sheet: Application Logging Vocabulary