---
id: JAVA-FUNDAMENTALS-01
title: Secure API Design, Encapsulation, and Duplication Control
category: Defensive Design / Broken Encapsulation
severity_hint: Medium
cwe: [CWE-493, CWE-656, CWE-1044]
java_versions: "All Versions (Always Applicable)"
---

# Secure API Design, Encapsulation, and Duplication Control

## Overview
Secure Java applications should be built so that it is "obviously simple with no flaws" rather than merely "having no obvious flaws." Retrospective security fixes are fragile. Avoid duplication, make security constraints explicit in API contracts, and enforce strict class encapsulation (e.g., declaring classes `final` to prevent subclassing overrides).

---

## Code Triad

### ❌ Insecure (Exposed Internals & Extensible API)
An over-exposed, non-final class that leaks mutable internal fields, letting subclasses override and manipulate business logic state.
```java
package com.app.api;

// VULNERABLE: Class can be subclassed to bypass checks; public mutable state allows direct manipulation
public class AccountSession {
    public double balance; 
    public String role;

    public AccountSession(double balance, String role) {
        this.balance = balance;
        this.role = role;
    }

    public void processTransaction(double amount) {
        this.balance -= amount;
    }
}
⚠️ Flawed Attempt (Accessor Leaks)
Making the class final and fields private, but providing standard getters and setters that leak references to mutable internal structures (like dates or arrays).

Java
package com.app.api;

import java.util.Date;

public final class AccountSessionFlawed {
    private final Date creationDate; // Mutable object

    public AccountSessionFlawed(Date creationDate) {
        this.creationDate = creationDate;
    }

    // FLAWED: Exposes a direct reference to the mutable Date object.
    // Callers can modify the date externally, altering the session state.
    public Date getCreationDate() {
        return this.creationDate; 
    }
}
✅ Secure (Defensive Copying, Final API, & Encapsulated Fields)
Enforce absolute encapsulation: make classes final, expose no public mutable fields, and use defensive copying or immutable records for internal types.

Java
package com.app.api;

import java.util.Date;
import java.util.Objects;

/**
 * SECURE: API is designed to be immutable, final, and thoroughly encapsulated.
 * All state modifications are checked at construction time.
 */
public final class AccountSessionSecure {
    private final double balance;
    private final String role;
    private final Date creationDate;

    public AccountSessionSecure(double balance, String role, Date creationDate) {
        if (balance < 0) {
            throw new IllegalArgumentException("Balance cannot be negative.");
        }
        this.balance = balance;
        this.role = Objects.requireNonNull(role, "Role cannot be null");
        // SECURE: Store a defensive copy of the mutable Date object
        this.creationDate = new Date(creationDate.getTime());
    }

    public double getBalance() {
        return balance;
    }

    public String getRole() {
        return role;
    }

    // SECURE: Return a defensive copy to prevent external modification
    public Date getCreationDate() {
        return new Date(creationDate.getTime());
    }
}

---

### File 10: Process Isolation & Privilege Restricton (`FUNDAMENTALS-3`)

```markdown
---
id: JAVA-FUNDAMENTALS-03
title: Process Isolation and Privilege Restriction
category: Architectural Isolation / Least Privilege
severity_hint: High
cwe: [CWE-250, CWE-288]
java_versions: "All Versions (Strict Modern Standard for Java 24+)"
---

# Process Isolation and Privilege Restriction

## Overview
With the removal of the `SecurityManager` in modern Java (JEP 486), privilege restriction is no longer handled reliably inside a single JVM. Security must instead be enforced at the boundary of the JVM using operating system sandbox permissions, containers, or process isolation.

---

## Code Triad

### ❌ Insecure (Monolithic Untrusted Code Execution)
Executing third-party plugins or parsing untrusted data within the primary, highly privileged application JVM.
```java
package com.app.sandbox;

public class PluginRunner {
    // VULNERABLE: Executing arbitrary code in-process has full host system access in modern Java
    public void executePlugin(Runnable untrustedPlugin) {
        untrustedPlugin.run(); 
    }
}
⚠️ Flawed Attempt (Inert SecurityManager Configuration)
Attempting to dynamically register a local security context or check legacy system permissions to limit arbitrary plugin capabilities.

Java
package com.app.sandbox;

public class PluginRunner {
    public void executePluginFlawed(Runnable untrustedPlugin) {
        // FLAWED: Will always evaluate as true or null in Java 24+, 
        // leading to silent failure of privilege restriction.
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(new RuntimePermission("runPlugin"));
        }
        untrustedPlugin.run();
    }
}
✅ Secure (OS-Level Subprocess & Container Sandboxing)
Decompose the application. Spawn untrusted operations in a completely isolated JVM instance using a low-privilege OS user or container.

Java
package com.app.sandbox;

import java.io.IOException;
import java.util.List;

public class PluginRunner {
    
    // SECURE: Execute untrusted code inside an isolated process container or separate JVM
    public void executePluginSecure(String pluginJarPath) throws IOException, InterruptedException {
        // Use ProcessBuilder to spin up a child JVM with reduced host permissions
        ProcessBuilder pb = new ProcessBuilder(
            "docker", "run", "--rm", 
            "-v", pluginJarPath + ":/app/plugin.jar:ro", 
            "amazoncorretto:21", "java", "-jar", "/app/plugin.jar"
        );
        
        Process process = pb.start();
        int exitCode = process.waitFor();
        
        if (exitCode != 0) {
            throw new SecurityException("Plugin execution failed or exceeded system resource limits.");
        }
    }
}

---

### File 11: Trust Boundaries and Validation (`FUNDAMENTALS-4`)

```markdown
---
id: JAVA-FUNDAMENTALS-04
title: Trust Boundaries and Input Sanitization
category: Security Misconfiguration / Untrusted Inputs
severity_hint: Critical
cwe: [CWE-20, CWE-74]
java_versions: "All Versions (Always Applicable)"
---

# Trust Boundaries and Input Sanitization

## Overview
A system must establish explicit trust boundaries. Any data crossing outside the boundary of your program (such as client inputs, external database values, file systems, or properties) must be assumed malicious, thoroughly validated, and normalized before parsing or executing.

---

## Code Triad

### ❌ Insecure (No Input Boundary Validation)
Accepting raw data from an external API payload and utilizing it directly in system operations.
```java
package com.app.boundary;

public class PathHandler {
    // VULNERABLE: Direct path traversal using unvalidated user input
    public void processFileUnsafe(String userPath) {
        java.io.File file = new java.io.File("/data/uploads/" + userPath);
        // Perform action on file...
    }
}
⚠️ Flawed Attempt (Sanitizing via Replacing Disallowed Strings)
Employing clean-up code that attempts to replace malicious character targets (like ../), which can be bypassed via alternative encodings or double-stripping attacks.

Java
package com.app.boundary;

public class PathHandler {
    public void processFileFlawed(String userPath) {
        // FLAWED: Nested traversal attacks can bypass simple replacement routines (e.g. "..././")
        String sanitized = userPath.replace("../", "");
        java.io.File file = new java.io.File("/data/uploads/" + sanitized);
        // Action...
    }
}
✅ Secure (Strict Path Normalization and Whitelisting)
Perform strict type validation, resolve relative paths, and confirm that the canonical representation is strictly trapped inside the designated directory hierarchy.

Java
package com.app.boundary;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

public class PathHandler {
    private static final Path BASE_DIR = Paths.get("/data/uploads").toAbsolutePath().normalize();

    public void processFileSecure(String userPath) throws IOException {
        // SECURE: Enforce strict format matching
        if (!userPath.matches("^[a-zA-Z0-9_-]+\\.[a-z]{3}$")) {
            throw new IllegalArgumentException("Invalid file format.");
        }

        Path targetPath = BASE_DIR.resolve(userPath).toAbsolutePath().normalize();

        // SECURE: Explicitly assert trust boundaries using parent/child checks
        if (!targetPath.startsWith(BASE_DIR)) {
            throw new SecurityException("Directory traversal attack detected.");
        }

        File file = targetPath.toFile();
        // Securely proceed with file action...
    }
}

---

### File 12: Capability-Based Security & Third-Party Auditing (`FUNDAMENTALS-5`, `8`)

```markdown
---
id: JAVA-FUNDAMENTALS-05-08
title: Capability-Based Securities & Third-Party Dependencies
category: Vulnerable Dependencies / Capability Leaks
severity_hint: High
cwe: [CWE-1104, CWE-1395]
java_versions: "All Versions (Always Applicable)"
---

# Capability-Based Securities & Third-Party Dependencies

## Overview
Perform authorization checks once and hand off a "capability object" (e.g., an opened channel, token, or session file) to reduce security overhead. Additionally, track, check, and automatically block outdated third-party library dependencies containing CVEs using software composition analysis (SCA) tools.

---

## Code Triad

### ❌ Insecure (Spreading Authorization Checks & Neglecting Dependencies)
Repeatedly running heavyweight permission validations across the entire application and ignoring external dependency CVE tracking.
```java
package com.app.auth;

public class DataStore {
    // VULNERABLE: Requires querying the active state/role repeatedly. 
    // If the database context changes mid-transaction, access states can desynchronize.
    public void readSensitiveRecord(String sessionToken, String recordId) {
        if (!SessionManager.isAdmin(sessionToken)) {
            throw new SecurityException("Unauthorized access.");
        }
        // Proceed with reading
    }
}
⚠️ Flawed Attempt (Passing Raw System Capabilities Unprotected)
Issuing highly powerful capability tokens or raw open files directly to client code without checking who can steal or misuse them.

Java
package com.app.auth;

import java.io.FileInputStream;

public class SecurityTokenIssuer {
    // FLAWED: Handing a raw, live system stream handle to untrusted components.
    // The consumer could leak this stream or consume resources indefinitely.
    public FileInputStream getStreamCap(String token) throws Exception {
        if (!"VALID".equals(token)) throw new SecurityException();
        return new FileInputStream("/opt/data/app.log");
    }
}
✅ Secure (Encapsulated Capabilities & Verified Dependency Chains)
Pass carefully designed capability interfaces that limit client actions and enforce strict dependency checking during build pipelines.

Java
package com.app.auth;

import java.io.InputStream;
import java.io.IOException;

public class DataStoreSecure {
    
    // SECURE: Encapsulate capability access. The client gets a limited wrapper 
    // object and cannot access the internal storage, system paths, or raw resources.
    public interface RecordCapability {
        byte[] readData() throws IOException;
    }

    public RecordCapability getRecordReader(String sessionToken, String recordId) {
        // 1. Perform authorization check strictly once at instantiation
        if (!SessionManager.isAdmin(sessionToken)) {
            throw new SecurityException("Access Denied.");
        }

        // 2. Return a restricted capability context
        return new RecordCapability() {
            @Override
            public byte[] readData() throws IOException {
                // Return encapsulated reading logic of recordId
                return ("RecordContent_" + recordId).getBytes();
            }
        };
    }
}