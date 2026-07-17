Copy and paste this entire code block directly into your main A10_2021-Server-Side_Request_Forgery.md file:

Markdown
---
id: OWASP-2021-A10
title: Server-Side Request Forgery (SSRF)
category: Server-Side Request Forgery (SSRF)
severity_hint: High
languages: [python, java]
cwes: [CWE-918]
related_guidelines: [SSRF-1, NETWORK-1]
---

# A10:2021 – Server-Side Request Forgery (SSRF)

## Factors

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Avg Weighted Exploit | Avg Weighted Impact | Max Coverage | Avg Coverage | Total Occurrences | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 1 | 2.72% | 2.72% | 8.28 | 6.72 | 67.72% | 67.72% | 9,503 | 385 |

## Overview
Server-Side Request Forgery (SSRF) occurs when an application fetches a remote resource without validating the user-supplied URL. This behavior allows an attacker to force the server to issue requests to arbitrary internal or external locations, bypassing network security controls such as firewalls, VPNs, or network Access Control Lists (ACLs).

### 🛡️ Secure Resource Fetching Flow
┌─────────────────────────────────────────────────────────────┐
│                      Untrusted Client URL                   │
└──────────────┬──────────────────────────────────────────────┘
▼
┌─────────────────────────────────────────────────────────────┐
│ 1. PROTOCOL & SCHEMA CHECK (Enforce HTTP/HTTPS only;        │
│    explicitly reject file://, gopher://, or ftp://)         │
└──────────────┬──────────────────────────────────────────────┘
▼
┌─────────────────────────────────────────────────────────────┐
│ 2. POSITIVE ALLOW-LIST FILTERING (Check parsed hostname     │
│    against allowed list; reject loopback/metadata IPs)     │
└──────────────┬──────────────────────────────────────────────┘
▼
┌─────────────────────────────────────────────────────────────┐
│ 3. RESTRICT REQUEST CLIENT (Configure timeouts, disable      │
│    redirects, and never echo raw response headers)          │
└─────────────────────────────────────────────────────────────┘


---

## Modern Python Examples

### ❌ Insecure Request Execution (CWE-918: Unvalidated URL Fetch)
Trusting user-controlled destination strings directly inside a server HTTP client allows requests to loopback addresses or internal cloud metadata endpoints.
```python
import requests
from fastapi import FastAPI, Request, HTTPException

app = FastAPI()

@app.post("/fetch-avatar")
async def fetch_avatar(request: Request):
    data = await request.json()
    url = data.get("image_url")
    # VULNERABLE: Direct lookup allows request to target localhost or 169.254.169.254
    response = requests.get(url)
    return {"content_type": response.headers.get("Content-Type")}
✅ Secure Request Execution (Strict Schema, Host, and Redirect Checks)
Utilizing positive allow-listing, checking parsed hostnames, and disabling automatic redirects to prevent secondary request manipulation.

Python
import requests
from fastapi import FastAPI, HTTPException, status
from urllib.parse import urlparse

app = FastAPI()

# SECURE: Define a strictly managed allow-list of authorized resource domains
ALLOWED_HOSTS = {"images.trusted-cdn.com", "static.trusted-cdn.com"}

@app.post("/fetch-avatar")
async def fetch_avatar(image_url: str):
    try:
        parsed_url = urlparse(image_url)
        
        # SECURE: Enforce expected network schema explicitly
        if parsed_url.scheme not in {"http", "https"}:
            raise HTTPException(status_code=400, detail="Invalid URI scheme")
            
        # SECURE: Enforce positive allow-list validation on parsed hostnames
        if parsed_url.hostname not in ALLOWED_HOSTS:
            raise HTTPException(status_code=400, detail="Untrusted domain host")
            
        # SECURE: Set strict request timeouts and disable automatic redirect following
        response = requests.get(
            image_url, 
            timeout=3.0, 
            allow_redirects=False
        )
        
        # SECURE: Do not pass raw unchecked response body directly back to clients
        return {"status": "success", "content_type": response.headers.get("Content-Type")}
    except requests.RequestException:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, 
            detail="Failed to retrieve remote media asset"
        )
Modern Java Examples
❌ Insecure Connection Execution (CWE-918: Direct URL Ingestion)
Executing a network connection directly on arbitrary HTTP addresses parsed from incoming parameters.

Java
import java.io.InputStream;
import java.net.URL;

public class ResourceFetcher {
    public InputStream fetchImage(String imageUrl) throws Exception {
        // VULNERABLE: Direct access to arbitrary client url requests
        URL url = new URL(imageUrl);
        return url.openStream();
    }
}
✅ Secure Connection Execution (Validated Connection Boundaries)
Restricting connections to authorized target ranges, and defining request timeouts to protect against performance exhaustion.

Java
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.util.Set;

public class SecureResourceFetcher {
    private static final Set<String> ALLOWED_HOSTS = Set.of("images.trusted-cdn.com");

    public InputStream fetchImage(String imageUrl) throws Exception {
        URL url = new URL(imageUrl);
        String host = url.getHost();
        
        // SECURE: Validate input against schema and domain allow-lists before openConnection()
        if (!"https".equalsIgnoreCase(url.getProtocol())) {
            throw new IllegalArgumentException("Only secure HTTPS connections are permitted");
        }
        
        if (!ALLOWED_HOSTS.contains(host)) {
            throw new IllegalArgumentException("Target host destination not permitted");
        }
        
        // SECURE: Enforce strict connection and read timeouts
        URLConnection conn = url.openConnection();
        conn.setConnectTimeout(3000); // 3-second limit
        conn.setReadTimeout(3000);
        
        return conn.getInputStream();
    }
}
Real-World Edge Cases & Advanced Vulnerabilities
1. Cloud Metadata API Attacks (Scenario #3)
Cloud providers maintain local diagnostic metadata services accessible via the loopback-routed IP address range 169.254.169.254.

The Flaw: SSRF flaws allow external attackers to fetch this path to extract AWS IAM credentials, Google Cloud service account keys, or environment profiles.

Remediation: Implement local networking firewall restrictions that block out-of-band requests to local link addresses, or mandate AWS IMDSv2 (session-token based) metadata retrieval requirements.

2. DNS Rebinding Attacks
An attacker maps an allow-listed domain name (e.g., trust.allowed.com) to a transient DNS configuration. At the Time of Check, the DNS resolves to a valid public IP. At the Time of Use, the resolution switches to 127.0.0.1.

The Flaw: By combining a short TTL (Time to Live) on the malicious DNS entry with dynamic connection attempts, the attacker bypasses the host check.

Remediation: Resolve the target address to an IP address once, validate that the resolved IP does not reside within private, local, or loopback network segments, and execute the request directly against that validated IP address (injecting the target hostname into the HTTP Host header instead).

How to Prevent
Validate via Positive Allow-Lists: Always evaluate client-provided URLs against explicit schema, host, and destination allow-lists. Avoid regex deny-lists.

De-couple Context Responses: Never return raw payload responses or original header structures directly back to calling browsers.

Turn Off HTTP Redirects: Force HTTP request engines to drop connections if a remote endpoint issues an automatic HTTP redirect directive.

Isolate Resource Access Networks: Place components with remote fetch capabilities inside dedicated, isolated subnetworks to minimize the reach of internal SSRF scans.

References
OWASP Cheat Sheet: Server-Side Request Forgery Prevention

PortSwigger: Server-Side Request Forgery (SSRF)

A New Era of SSRF (BlackHat USA)