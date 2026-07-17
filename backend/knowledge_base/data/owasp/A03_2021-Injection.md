---
id: OWASP-2021-A03
title: Injection
category: Injection
severity_hint: High
languages: [python, java]
cwes: [CWE-20, CWE-74, CWE-75, CWE-77, CWE-78, CWE-79, CWE-80, CWE-83, CWE-87, CWE-88, CWE-89, CWE-90, CWE-91, CWE-93, CWE-94, CWE-95, CWE-96, CWE-97, CWE-98, CWE-99, CWE-100, CWE-113, CWE-116, CWE-138, CWE-184, CWE-470, CWE-471, CWE-564, CWE-610, CWE-643, CWE-644, CWE-652, CWE-917]
related_guidelines: [ACCESS-1, CONFIDENTIAL-1]
---

# A03:2021 – Injection

## Factors

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Avg Weighted Exploit | Avg Weighted Impact | Max Coverage | Avg Coverage | Total Occurrences | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 33 | 19.09% | 3.37% | 7.25 | 7.15 | 94.04% | 47.90% | 274,228 | 32,078 |

## Overview
Injection occurs when untrusted user data is sent to an interpreter as part of a command or query. The attacker’s hostile data tricks the interpreter into executing unintended commands or accessing data without proper authorization.

### 🛡️ Separation of Code and Data
┌─────────────────────────────────────────────────────────────┐
│                       Hostile User Input                     │
└──────────────┬──────────────────────────────────────────────┘
│ (Malicious commands disguised as data)
▼
┌─────────────────────────────────────────────────────────────┐
│ Boundary Validation & Type Coercion (FastAPI / Spring Boot)  │
└──────────────┬──────────────────────────────────────────────┘
▼
┌─────────────────────────────────────────────────────────────┐
│ Safe APIs / Parameterized Boundary (SQL Placeholders / APIs) │
└──────────────┬──────────────────────────────────────────────┘
▼
┌─────────────────────────────────────────────────────────────┐
│ SQL / OS Interpreter (Data treated strictly as literal)     │
└─────────────────────────────────────────────────────────────┘


---

## Modern Python Examples

### ❌ Insecure SQL (Dynamic Query Formatting)
Failing to separate code and data leaves the system open to SQL Injection (SQLi), allowing arbitrary query execution.
```python
from fastapi import FastAPI, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session
from database import get_db

app = FastAPI()

@app.get("/users/{user_id}")
def get_user(user_id: str, db: Session = Depends(get_db)):
    # VULNERABLE: Direct string formatting into SQL statement
    query = text(f"SELECT * FROM users WHERE id = '{user_id}'")
    return db.execute(query).fetchall()
✅ Secure SQL (Parameterized Binding)
Using parameter binding ensures that the database driver escapes user inputs, enforcing strict typing at the database layer.

from fastapi import FastAPI, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session
from database import get_db

app = FastAPI()

@app.get("/users/{user_id}")
def get_user(user_id: int, db: Session = Depends(get_db)):
    # SECURE: Bind parameters safely and use strong type hinting (int)
    query = text("SELECT * FROM users WHERE id = :user_id")
    return db.execute(query, {"user_id": user_id}).fetchall()

❌ Insecure OS Command (Shell Injection)
Using execution environments with active shell parsing converts single parameters into system command execution chains.

import os

def run_network_diagnostic(user_host: str):
    # VULNERABLE: shell execution allows command concatenation (e.g., "127.0.0.1; rm -rf /")
    return os.system(f"ping -c 1 {user_host}")

✅ Secure OS Command (No Shell Execution)
By spawning processes directly without passing string queries to a terminal shell, arguments are processed safely as isolated elements.

import subprocess
import shlex

def run_network_diagnostic(user_host: str):
    # SECURE: Explicit list parsing, shell disabled, input validated
    # Use shlex to sanitize arguments or avoid OS executions entirely
    command = ["ping", "-c", "1", user_host]
    result = subprocess.run(command, shell=False, capture_output=True, text=True, check=True)
    return result.stdout

Modern Java Examples
❌ Insecure SQL (Concatenated Statements)

import java.sql.*;

public class UserService {
    public void queryUserData(String id, Connection connection) throws SQLException {
        // VULNERABLE: Raw string manipulation breaks SQL structure boundaries
        String query = "SELECT * FROM accounts WHERE id = '" + id + "'";
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(query);
    }
}

✅ Secure SQL (Precompiled PreparedStatements)

import java.sql.*;

public class UserService {
    public void queryUserData(String id, Connection connection) throws SQLException {
        // SECURE: Precompiled execution plan with placeholder parameters
        String query = "SELECT * FROM accounts WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setString(1, id);
            try (ResultSet rs = stmt.executeQuery()) {
                // Process results safely
            }
        }
    }
}
Real-World Edge Cases & Advanced Vulnerabilities
1. Second-Order SQL Injection
Second-order injection occurs when malicious data is safely stored in a database but later retrieved and executed unsafely inside another SQL query or interpreter.

The Trap: Relying on the assumption that "data inside our database is clean." This bypasses perimeter controls and breaks database integrity.

Remediation: Treat all data retrieved from a persistent store as untrusted. Parameterize all secondary queries.

2. Blind SQL Injection (Time-Based / Boolean-Based)
When an endpoint doesn't return direct SQL query errors or output values, attackers can still leak database contents by sending conditional sleep or execution statements.

How it works: Sending an payload like ' UNION SELECT SLEEP(5);-- causes the application response to freeze or lag, letting the attacker map schema characters bit by bit.

Remediation: Strict parameterization and standard query timeouts mitigate detection opportunities.

How to Prevent
Prefer Parameterized APIs: Leverage modern frameworks and ORMs that naturally map parameters rather than concatenating raw values.

Implement Input Whitelisting: For variables that cannot be easily parameterized (e.g., table or column names, sorting direction), match against a strict list of allowed values.

Escaping and Sanitization: If dynamic query assembly is unavoidable, utilize contextual, driver-supported escaping routines.

Defense-in-Depth Policies: Limit interpreter system permissions at the database and container environment levels.

References
OWASP Proactive Controls: Secure Database Access

OWASP ASVS: V5 Input Validation and Encoding

OWASP Cheat Sheet: SQL Injection Prevention

OWASP Cheat Sheet: Query Parameterization