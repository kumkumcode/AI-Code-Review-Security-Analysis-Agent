Copy and paste this entire code block directly into your main A07_2021-Identification_and_Authentication_Failures.md file:

Markdown
---
id: OWASP-2021-A07
title: Identification and Authentication Failures
category: Identification and Authentication Failures
severity_hint: High
languages: [python, java]
cwes: [CWE-255, CWE-259, CWE-287, CWE-288, CWE-290, CWE-294, CWE-295, CWE-297, CWE-300, CWE-302, CWE-304, CWE-306, CWE-307, CWE-346, CWE-384, CWE-521, CWE-613, CWE-620, CWE-640, CWE-798, CWE-940, CWE-1216]
related_guidelines: [AUTH-1, SESSION-1]
---

# A07:2021 – Identification and Authentication Failures

## Factors

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Avg Weighted Exploit | Avg Weighted Impact | Max Coverage | Avg Coverage | Total Occurrences | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 22 | 14.84% | 2.55% | 7.40 | 6.50 | 79.51% | 45.72% | 132,195 | 3,897 |

## Overview
Confirming user identity, authentication status, and active session boundaries is paramount for application security. Failure to properly manage session persistence, enforce strict authentication flows, or defend against automation exposes the platform to credential stuffing, brute-forcing, and hijacking attacks.

### 🛡️ Authentication & Session Boundary Flow
┌─────────────────────────────────────────────────────────────┐
│                      Client Auth Request                    │
└──────────────┬──────────────────────────────────────────────┘
▼
┌─────────────────────────────────────────────────────────────┐
│ 1. RATE LIMITER / BOT PROTECTION (Mitigate brute-force /    │
│    credential stuffing attempts using sliding windows)     │
└──────────────┬──────────────────────────────────────────────┘
▼
┌─────────────────────────────────────────────────────────────┐
│ 2. SECURE COMPARED CREDENTIALS (Secure hashing / Argon2)    │
└──────────────┬──────────────────────────────────────────────┘
▼
┌─────────────────────────────────────────────────────────────┐
│ 3. REGENERATE SESSION IDENTIFIER (Invalidate anonymous and   │
│    hijacked session keys immediately upon authorization)    │
└─────────────────────────────────────────────────────────────┘


---

## Modern Python Examples

### ❌ Insecure Python Authentication (No Rate Limiting / Brute-Force Exposed)
Exposing credential verification routes directly to users without limits turns the system into an open oracle for credential-stuffing bots.
```python
from fastapi import FastAPI, Request, HTTPException
from database import authenticate_user

app = FastAPI()

@app.post("/login")
async def login(request: Request):
    data = await request.json()
    # VULNERABLE: Direct access to password checks without invocation limits
    user = authenticate_user(data.get("username"), data.get("password"))
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"status": "authenticated"}
✅ Secure Python Authentication (Rate-Limited Authorization)
Leveraging limits and generic error structures to defend routes against rapid iteration attacks.

Python
from fastapi import FastAPI, Request, HTTPException, status
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from database import authenticate_user

limiter = Limiter(key_func=get_remote_address)
app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.post("/login")
# SECURE: Strict sliding limit on structural login routes (e.g., 5 attempts per minute)
@limiter.limit("5/minute")
async def login(request: Request):
    data = await request.json()
    username = data.get("username", "")
    password = data.get("password", "")
    
    user = authenticate_user(username, password)
    # SECURE: Use generic response messages preventing username enumeration
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Incorrect username or password"
        )
    return {"status": "authenticated"}
Modern Java Examples
❌ Insecure Session Management (Session Fixation)
Failing to rotate context identifiers during security transitions allows an attacker to intercept or plant an active anonymous session token.

Java
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

public class LoginService {
    public void handleAuthentication(HttpServletRequest request, User user) {
        // VULNERABLE: Retaining the pre-login Session ID allows Session Fixation attacks
        HttpSession session = request.getSession();
        session.setAttribute("user", user);
    }
}
✅ Secure Session Management (Dynamic Session Regeneration)
Enforcing session changes immediately upon user transition from anonymous to authenticated state.

Java
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

public class LoginService {
    public void handleAuthentication(HttpServletRequest request, User user) {
        // SECURE: Regenerate the session ID immediately upon identity change
        request.changeSessionId();
        
        HttpSession session = request.getSession();
        session.setAttribute("user", user);
    }
}
Real-World Edge Cases & Advanced Vulnerabilities
1. Session Fixation
An attacker crafts a known anonymous session ID, tricks a victim into using it (e.g., via a phishing link), and waits for them to log in.

The Flaw: If the application does not issue a new session token upon authentication, the attacker can hijack the fully authorized session using the pre-shared token.

Remediation: Explicitly regenerate or change the session identifier using standard context actions (such as request.changeSessionId()) immediately after credentials are verified.

2. Password Reset Account Enumeration
Using distinct messages for password recovery requests based on whether the username exists (e.g., "Email not found" vs. "Password reset link sent").

The Flaw: Allows attackers to programmatically probe and map valid system user databases.

Remediation: Standardize the system's responses. Always display a generic, neutral result: "If this email exists in our records, a recovery link has been sent."

How to Prevent
Enforce Multi-Factor Authentication (MFA): Implement MFA as a baseline requirement to neutralize stolen credentials and automated brute-force attempts.

Implement Rate Limiting: Apply sliding rate limits to registration, password recovery, and login endpoints.

Regenerate Session Identifiers: Always invalidate and regenerate session keys during any privilege boundary transitions.

Harden Against Account Enumeration: Keep validation responses neutral across all entry-point endpoints.

References
OWASP Cheat Sheet: Session Management

OWASP Cheat Sheet: Credential Stuffing Prevention

NIST SP 800-63b: Memorized Secrets (Section 5.1.1)

OWASP ASVS: V2 Authentication and V3 Session Management Verification