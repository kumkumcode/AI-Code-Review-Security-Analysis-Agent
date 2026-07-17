Copy and paste this entire code block directly into your main A08_2021-Software_and_Data_Integrity_Failures.md file:

Markdown
---
id: OWASP-2021-A08
title: Software and Data Integrity Failures
category: Software and Data Integrity Failures
severity_hint: High
languages: [python, java]
cwes: [CWE-345, CWE-353, CWE-426, CWE-494, CWE-502, CWE-565, CWE-784, CWE-829, CWE-830, CWE-915]
related_guidelines: [INTEGRITY-1, PIPELINE-1]
---

# A08:2021 – Software and Data Integrity Failures

## Factors

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Avg Weighted Exploit | Avg Weighted Impact | Max Coverage | Avg Coverage | Total Occurrences | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 10 | 16.67% | 2.05% | 6.94 | 7.94 | 75.04% | 45.35% | 47,972 | 1,152 |

## Overview
Software and data integrity failures occur when code, application dependencies, update configurations, or serialized objects are processed without verifying their authenticity and integrity. One of the most severe manifestations is insecure deserialization, where arbitrary input structures can trick interpreters into executing system-level commands.

### 🛡️ Secure Deserialization & Pipeline Integrity
┌─────────────────────────────────────────────────────────────┐
│                      Untrusted Byte Stream                  │
└──────────────┬──────────────────────────────────────────────┘
▼
┌─────────────────────────────────────────────────────────────┐
│ 1. DATA REJECTION (Avoid binary formats like pickle or      │
│    native Java serialization completely)                    │
└──────────────┬──────────────────────────────────────────────┘
▼
┌─────────────────────────────────────────────────────────────┐
│ 2. SCHEMA-BASED PARSING (Deserialize only flat, structured  │
│    formats like JSON with strict, strongly typed classes)   │
└──────────────┬──────────────────────────────────────────────┘
▼
┌─────────────────────────────────────────────────────────────┐
│ 3. ENFORCE CRYPTOGRAPHIC SIGNATURES (HMAC-SHA256 verification│
│    for transient state objects before processing)           │
└─────────────────────────────────────────────────────────────┘


---

## Modern Python Examples

### ❌ Insecure Python Deserialization (CWE-502: Python `pickle`)
The Python `pickle` module builds arbitrary object graphs. If the payload is modified to return a class with a custom `__reduce__` method, system command execution occurs immediately upon parsing.
```python
import pickle
from fastapi import FastAPI, Request, HTTPException

app = FastAPI()

@app.post("/restore-session")
async def restore_session(request: Request):
    body = await request.body()
    # VULNERABLE: Direct deserialization of untrusted binary streams
    # An attacker can send a serialized payload that executes system commands
    session_data = pickle.loads(body)
    return {"status": "restored", "user": session_data.get("username")}
✅ Secure Python Deserialization (Structured JSON)
By migrating away from arbitrary binary object graphs and using plain-text, statically typed JSON models, parsing is restricted strictly to simple data primitives.

Python
import json
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel, ValidationError

app = FastAPI()

class SessionModel(BaseModel):
    username: str
    session_id: str

@app.post("/restore-session")
async def restore_session(request: Request):
    body = await request.body()
    try:
        # SECURE: Parse raw payload strictly as plain-text, static JSON structure
        decoded_string = body.decode("utf-8")
        data = json.loads(decoded_string)
        
        # Enforce validation schemas on incoming keys
        session_data = SessionModel(**data)
        return {"status": "restored", "user": session_data.username}
    except (json.JSONDecodeError, ValidationError, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="Invalid session payload")
Modern Java Examples
❌ Insecure Java Deserialization (CWE-502: Native ObjectInputStream)
Native Java serialization is notoriously dangerous when used on untrusted streams. Attackers can exploit gadgets in the application's classpath to achieve remote code execution (RCE).

Java
import java.io.ObjectInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;

public class SessionService {
    public Object deserializeSession(byte[] rawData) throws IOException, ClassNotFoundException {
        // VULNERABLE: Native Java deserialization is highly vulnerable to gadget-chain RCE
        try (ByteArrayInputStream bais = new ByteArrayInputStream(rawData);
             ObjectInputStream ois = new ObjectInputStream(bais)) {
            return ois.readObject();
        }
    }
}
✅ Secure Java Deserialization (Explicit JSON Model Mapping)
Instead of deserializing complex class hierachies from binary code streams, map incoming payloads into strict Data Transfer Objects (DTOs) using Jackson or Gson.

Java
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;

public class SessionService {
    private final ObjectMapper mapper = new ObjectMapper();

    public SessionDto deserializeSession(byte[] rawData) throws IOException {
        // SECURE: Strict schema validation mapping flat JSON structures to an immutable DTO
        return mapper.readValue(rawData, SessionDto.class);
    }
}

// Statically defined Session DTO
class SessionDto {
    private String username;
    private String sessionId;

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getSessionId() { return sessionId; }
    public void setSessionId(String sessionId) { this.sessionId = sessionId; }
}
Real-World Edge Cases & Advanced Vulnerabilities
1. Second-Order Object Mutation / Mass Assignment
When an application converts JSON structures directly to domain models or database objects without filtering fields, attackers can inject unexpected properties.

The Flaw: Specifying internal administrative properties (e.g., {"is_admin": true}) on public registration endpoints that map directly to model models.

Remediation: Always decouple structural input parameters using explicit, scoped DTOs or Pydantic models. Avoid direct model mapping on controllers.

2. Lack of Signature Validation on Updates and Libraries
Downloading files or dependency libraries over plain HTTP channels or using package registries without verifying signature paths or checksum hashes.

The Flaw: Active DNS spoofing or proxy compromise can inject modified dependencies directly into standard build pipelines.

Remediation: Configure artifact repositories and package pipelines to mandate cryptographic hash validations (sha256) and signed software releases.

How to Prevent
Banish Native Binary Deserialization: Strictly avoid native pickle (Python) or standard ObjectInputStream (Java) for untrusted network input.

Standardize on Safe Formats: Enforce flat, structured serialization formats such as JSON, XML (safely configured), or Protocol Buffers.

Assert Payload Cryptography: If serialized data must travel through untrusted client channels, protect the package using digital signatures (such as HMAC-SHA256).

Secure the CI/CD Pipeline: Restrict developer push policies, isolate build container environments, and enforce automated supply chain signature verification checks.

References
OWASP Cheat Sheet: Deserialization Prevention

Java Serial Killer tool (Mitigation Strategy)

OWASP CycloneDX (SBOM Generation)

SAFECode Software Integrity Controls