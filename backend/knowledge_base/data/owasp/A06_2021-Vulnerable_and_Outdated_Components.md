Copy and paste this entire code block directly into your main A06_2021-Vulnerable_and_Outdated_Components.md file:

Markdown
---
id: OWASP-2021-A06
title: Vulnerable and Outdated Components
category: Vulnerable and Outdated Components
severity_hint: Medium
languages: [python, java]
cwes: [CWE-937, CWE-1035, CWE-1104]
related_guidelines: [COMPONENTS-1, INVENTORY-1]
---

# A06:2021 – Vulnerable and Outdated Components

## Factors

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Max Coverage | Avg Coverage | Avg Weighted Exploit | Avg Weighted Impact | Total Occurrences | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 3 | 27.96% | 8.77% | 51.78% | 22.47% | 5.00 | 5.00 | 30,457 | 0 |

## Overview
Vulnerable Components are a known structural risk that teams struggle to systematically test and assess. Because components typically execute with the same system privileges as the parent application itself, a vulnerability in any third-party library can lead to a complete host compromise.

### 🛡️ Dependency Validation Pipeline
┌─────────────────────────────────────────────────────────────┐
│                 Third-Party Package Registry                │
└──────────────┬──────────────────────────────────────────────┘
▼
┌─────────────────────────────────────────────────────────────┐
│ 1. EXPLICIT PINNING (Enforce hash-checked lockfiles)        │
└──────────────┬──────────────────────────────────────────────┘
▼
┌─────────────────────────────────────────────────────────────┐
│ 2. SOFTWARE COMPOSITION ANALYSIS (SCA) (pip-audit / Maven)  │
└──────────────┬──────────────────────────────────────────────┘
▼
┌─────────────────────────────────────────────────────────────┐
│ 3. RUNTIME PRIVILEGE SANITIZATION (Least privilege limits)  │
└─────────────────────────────────────────────────────────────┘


---

## Modern Python Examples

### ❌ Insecure Python Dependency Management (Unpinned / Floating Versions)
Allowing dependencies to resolve dynamically or leaving them floating without constraints (`requirements.txt`) introduces serious risk. It permits the silent installation of untested major versions or compromised dependency chains.
```text
# requirements.txt - VULNERABLE
flask
requests
# These will resolve to the latest available versions during build time,
# potentially introducing breaking changes or supply-chain compromises.
✅ Secure Python Dependency Management (Pinned & Hash-Locked)
Enforcing strict version matching and utilizing integrity hashes in lockfiles guarantees that deployment artifacts match verified local security audits exactly.

Plaintext
# requirements.txt - SECURE
flask==3.0.3
requests==2.32.3

# For optimal pipeline security, leverage poetry.lock or requirements.txt with hash checks:
# requests==2.32.3 --hash=sha256:74d754ab24d274c...
To audit Python dependencies in your build pipeline, run:

Bash
# Run SCA scan locally and within CI/CD pipelines
pip-audit -r requirements.txt
Modern Java Examples
❌ Insecure Maven POM (Outdated, Vulnerable Library)
Using obsolete components with publicly cataloged Remote Code Execution (RCE) vectors leaves applications fully exposed.

XML
<!-- pom.xml - VULNERABLE -->
<dependency>
    <groupId>org.apache.struts</groupId>
    <artifactId>struts2-core</artifactId>
    <!-- VULNERABLE: Susceptible to CVE-2017-5638 RCE via malicious Content-Type headers -->
    <version>2.3.20</version> 
</dependency>
✅ Secure Maven POM (Remediated Stable Release)
Upgrading transitive and direct dependencies to actively maintained and patched versions.

XML
<!-- pom.xml - SECURE -->
<dependency>
    <groupId>org.apache.struts</groupId>
    <artifactId>struts2-core</artifactId>
    <!-- SECURE: Fully patched release mitigating historical execution vectors -->
    <version>6.3.0.2</version>
</dependency>
To continuously inspect Java vulnerabilities via your build lifecycle, integrate the OWASP dependency-check plugin:

XML
<plugin>
    <groupId>org.owasp</groupId>
    <artifactId>dependency-check-maven</artifactId>
    <version>9.0.9</version>
    <executions>
        <execution>
            <goals>
                <goal>check</goal>
            </goals>
        </execution>
    </executions>
</plugin>
Real-World Edge Cases & Advanced Vulnerabilities
1. Transitive (Nested) Dependencies
While your root components might appear modern, they may import nested dependencies that are unmaintained, outdated, or vulnerable.

The Flaw: Direct dependency audits overlook vulnerabilities deep within the package tree.

Remediation: Generate an exhaustive Software Bill of Materials (SBOM) and run continuous Software Composition Analysis (SCA) deep-tree analysis.

2. Supply-Chain Dependency Confusion & Typo-Squatting
Attackers register malicious packages on public registries (e.g., PyPI, Maven Central) using names similar to popular internal private packages.

The Flaw: Build environments configured without private registry scopes download malicious public packages instead.

Remediation: Enforce scoped registries, use internal artifact repositories (e.g., Nexus, Artifactory), and disable fallback searches to external unverified mirrors.

How to Prevent
Enforce Complete Inventories: Continuously audit client-side and server-side libraries using SCA tools.

Explicit Dependency Pinning: Never rely on dynamic floating versions. Enforce precise versions and SHA verification hashes.

Minimize Attack Surface: Proactively remove unused modules, framework samples, test harnesses, and redundant database adapters.

Automate Patch Pipelines: Establish recurring cycles to inspect, build, and deploy verified security updates for all stack layers.

References
OWASP Dependency-Check Project

GitHub Advisory Database

National Vulnerability Database (NVD)

OWASP Virtual Patching Best Practices