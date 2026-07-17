---
id: OWASP-2021-A01
title: Broken Access Control
category: Access Control
severity_hint: High
languages: [python, java]
cwes: [CWE-22, CWE-200, CWE-284, CWE-285, CWE-352, CWE-566, CWE-639, CWE-862, CWE-863]
related_guidelines: [ACCESS-1, CONFIDENTIAL-1]
---

# A01:2021 – Broken Access Control

## Overview
Access control restricts user operations based on authorization policies. When access control fails, attackers can bypass authorization checks, access sensitive resources (IDOR/BOLA), elevate privileges, or tamper with metadata.

### 🛡️ Defense-in-Depth Architecture
┌─────────────────────────────────────────────────────────────┐
│                    Internet / API Client                     │
└──────────────┬──────────────────────────────────────────────┘
▼
┌─────────────────────────────────────────────────────────────┐
│ 1. ROUTE GUARD (Role / Authentication verification)         │
└──────────────┬──────────────────────────────────────────────┘
▼
┌─────────────────────────────────────────────────────────────┐
│ 2. CONTROLLER / SERVICE (Explicit Resource Ownership check) │
└──────────────┬──────────────────────────────────────────────┘
▼
┌─────────────────────────────────────────────────────────────┐
│ 3. DATABASE / STORAGE (Row-Level Security / Tenant Isolation)│
└─────────────────────────────────────────────────────────────┘
---

## Modern Python (FastAPI + SQLAlchemy) Examples

### ❌ Insecure (BOLA / IDOR)
The application relies solely on the path variable and performs no validation to check if the current user owns the requested invoice.
```python
from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session
from database import get_db, Invoice

app = FastAPI()

@app.get("/invoices/{invoice_id}")
def get_invoice(invoice_id: int, db: Session = Depends(get_db)):
    # VULNERABLE: Any authenticated user can view any invoice by guessing the ID
    invoice = db.query(Invoice).filter(Invoice.id == invoice_id).first()
    return invoice
✅ Secure (Granular Resource Ownership)
We enforce both user authentication and explicit resource ownership checks within the database query execution.

Python
from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from database import get_db, Invoice
from auth import get_current_user, User

app = FastAPI()

@app.get("/invoices/{invoice_id}", status_code=status.HTTP_200_OK)
def get_invoice(
    invoice_id: int, 
    db: Session = Depends(get_db), 
    current_user: User = Depends(get_current_user)
):
    # SECURE: Bind query parameters to both Resource ID and User ID
    invoice = db.query(Invoice).filter(
        Invoice.id == invoice_id, 
        Invoice.owner_id == current_user.id
    ).first()
    
    if not invoice:
        # Prevent resource enumeration by returning 404 instead of 403
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail="Invoice not found"
        )
    return invoice
Modern Java (Spring Boot + Spring Security) Examples
❌ Insecure (Missing Access Control)
Java
@RestController
@RequestMapping("/api/accounts")
public class AccountController {

    @Autowired
    private AccountRepository accountRepository;

    @GetMapping("/{accountId}")
    public AccountResponse getAccount(@PathVariable UUID accountId) {
        // VULNERABLE: Lacks role checking and ownership validation
        return accountRepository.findById(accountId)
            .map(AccountResponse::new)
            .orElseThrow(() -> new ResourceNotFoundException());
    }
}
✅ Secure (Declarative & Programmatic Authorization)
By combining Spring Security annotations with custom service-level evaluations, we guarantee robust security boundaries.

Java
@RestController
@RequestMapping("/api/accounts")
public class AccountController {

    @Autowired
    private AccountService accountService;

    @GetMapping("/{accountId}")
    @PreAuthorize("hasRole('ROLE_USER')")
    public AccountResponse getAccount(
        @PathVariable UUID accountId, 
        @AuthenticationPrincipal UserPrincipal principal
    ) {
        // SECURE: Business logic layer validates principal ownership over resource
        Account account = accountService.getAccountForUser(accountId, principal.getId());
        return new AccountResponse(account);
    }
}
Real-World Edge Cases & Advanced Vulnerabilities
1. The "UUID-as-Security" Fallacy
Many developers believe swapping sequential integers (e.g., /invoice/101) with UUIDs (e.g., /invoice/9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d) solves IDOR.

Reality: UUIDs only prevent guessing via sequential scanning; they do not enforce authorization. If a UUID is leaked in system logs, referrers, or HTTP payloads, an unauthorized actor can still access it if the endpoint lacks owner checks.

2. BOLA in GraphQL Nested Resolvers
In GraphQL, endpoint-level path authorization fails because queries can traverse object relationships dynamically.

# An attacker can bypass top-level query rules by nesting queries:
query {
  me {
    friends {
      invoices {  # Under-secured nested resolver leaks data
        amount
        billingAddress
      }
    }
  }
}

Remediation: Enforce permission and ownership assertions at the resolver layer for every nested object, rather than just inspecting top-level queries.

Key Engineering Rules
Never Trust Input IDs: Always cross-reference client-supplied IDs with session identity tokens inside server-side transactions.

Deny by Default: Restrict routing, API methods, and assets at the system gate; explicitly open routes only when needed.

Handle Enumeration Hazards: Return generic 404 Not Found messages instead of descriptive 403 Forbidden errors to prevent attackers from mapping active IDs.