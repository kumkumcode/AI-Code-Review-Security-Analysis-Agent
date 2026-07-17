---
id: JAVA-OBJECT-01-05
title: Safe Object Construction, Lifecycle Integrity, and Clone Defenses
category: Object Lifecycle Security
severity_hint: High
cwe: [CWE-372, CWE-585, CWE-502]
java_versions: "All Versions (Always Applicable)"
---

# Safe Object Construction, Lifecycle Integrity, and Clone Defenses

## Overview
An object must remain completely unusable until its initialization successfully completes. Exposing raw public constructors on sensitive classes can permit unauthorized instantiation or subclassing. Additionally, calling overridable methods inside a constructor or during deserialization (`readObject`) is a severe security flaw—it leaks an uninitialized `this` reference to a subclass, bypassing initialization checks and security policies.

---

## Code Triad

### ❌ Insecure (Exposed Constructors, Overridable Calls, and Clone Vulnerabilities)
A non-final class that exposes a public constructor, calls an overridable method inside it, and is vulnerable to unauthorized cloning.
```java
package com.app.object;

public class SensitiveService implements Cloneable {
    private boolean initialized = false;

    // VULNERABLE: Public constructor allows unrestricted instantiation and subclassing
    public SensitiveService() {
        // VULNERABLE: Calling an overridable method inside a constructor.
        // A subclass can override this to capture the uninitialized "this" reference.
        initializeService();
        this.initialized = true;
    }

    public void initializeService() {
        System.out.println("Base initialization");
    }

    // VULNERABLE: Inherits default Cloneable behavior, enabling shallow-copy exploits
    @Override
    public Object clone() throws CloneNotSupportedException {
        return super.clone();
    }
}
⚠️ Flawed Attempt (Constructors with Lazy Flags)
Checking initialization flags in methods, but failing to stop subclass overriding attacks or malicious clone replication.

Java
package com.app.object;

public class SensitiveServiceFlawed {
    private boolean initialized = false;

    public SensitiveServiceFlawed() {
        // FLAWED: Class is not final. A subclass can still override the helper method 
        // to steal a partial instance or intercept the initialization state.
        doSetup();
        this.initialized = true;
    }

    protected void doSetup() {
        // Setup logic...
    }

    public void performAction() {
        if (!initialized) {
            throw new SecurityException("Not initialized!");
        }
        // Action logic...
    }
}
✅ Secure (Final Classes, Private Constructors, Static Factories, and Final Methods)
Hide constructors behind private access control, expose instances via static factory methods, make classes final (or declare configuration methods final/private), and actively disable cloning.

Java
package com.app.object;

public final class SensitiveServiceSecure {
    private final String config;

    // SECURE: Constructor is private to prevent unauthorized inheritance or direct instantiation
    private SensitiveServiceSecure(String config) {
        this.config = config;
    }

    // SECURE: Controlled instantiation via static factory method
    public static SensitiveServiceSecure createInstance(String config) {
        if (config == null || config.isBlank()) {
            throw new IllegalArgumentException("Invalid configuration string");
        }
        return new SensitiveServiceSecure(config);
    }

    // SECURE: No clone capability is inherited or permitted. 
    // If subclassing a non-final class is required, explicitly implement clone() to throw an exception.
    @Override
    protected final Object clone() throws CloneNotSupportedException {
        throw new CloneNotSupportedException("Cloning of this sensitive object is strictly prohibited");
    }
}

---

### File 22: Defending Non-Final Classes Against Partial Initialization (`OBJECT-3`)

```markdown
---
id: JAVA-OBJECT-03
title: Defending Against Partially Initialized Non-Final Class Exploits
category: Object Lifecycle Security
severity_hint: High
cwe: [CWE-372, CWE-909]
java_versions: "All Versions (Always Applicable)"
---

# Defending Against Partially Initialized Non-Final Class Exploits

## Overview
When a constructor of a non-final class throws an exception, an attacker can capture a reference to the partially initialized object (for example, if the instance has registered itself with a listener before the failure, or by utilizing finalizer exploits on older JVMs). Security-sensitive classes must check their complete initialization state prior to performing any operational task.

---

## Code Triad

### ❌ Insecure (Relying on Constructor Exceptions for Security Blocks)
Throwing an exception in the constructor, but leaving the class methods open to execution on a partially constructed instance.
```java
package com.app.object;

public class DatabaseCredential {
    private String secret;

    public DatabaseCredential(String token) {
        if (token == null || !token.startsWith("SECURE_")) {
            // VULNERABLE: If this throws, the object exists in memory in a partially
            // initialized state. If leaked, methods can still be invoked on it.
            throw new SecurityException("Unauthorized credentials profile.");
        }
        this.secret = token;
    }

    public String getSecret() {
        return this.secret;
    }
}
⚠️ Flawed Attempt (Weak Initialization State Checks)
Using a non-final boolean flag that can be bypassed if subclassing or serialization constructs the object outside normal lifecycles.

Java
package com.app.object;

public class DatabaseCredentialFlawed {
    private boolean initialized = false;
    private String secret;

    public DatabaseCredentialFlawed(String token) {
        if (token == null) {
            throw new IllegalArgumentException("Null token");
        }
        this.secret = token;
        this.initialized = true;
    }

    public String getSecret() {
        // FLAWED: While checking initialized is good, subclassing tricks or 
        // deserialization paths can bypass constructor initialization entirely.
        if (!initialized) {
            throw new SecurityException("Object not initialized.");
        }
        return this.secret;
    }
}
✅ Secure (Active State Validation via Sentinel Objects)
Use a private, non-serializable inner token object or a robust validation check to verify that constructor execution completed successfully before performing any operational steps.

Java
package com.app.object;

public class DatabaseCredentialSecure {
    // SECURE: Use a secure token initialized ONLY at the very end of successful construction
    private final Object initializationSentinel;
    private final String secret;

    public DatabaseCredentialSecure(String token) {
        if (token == null || !token.startsWith("SECURE_")) {
            throw new SecurityException("Unauthorized credentials profile.");
        }
        this.secret = token;
        
        // SECURE: Instantiated only as the absolute last step of a valid construction run
        this.initializationSentinel = new Object();
    }

    private void checkInitialization() {
        // SECURE: Throws a SecurityException if the sentinel is missing (bypassed lifecycle)
        if (this.initializationSentinel == null) {
            throw new SecurityException("Instance is not fully initialized.");
        }
    }

    public String getSecret() {
        checkInitialization();
        return this.secret;
    }
}

---

<ElicitationsGroup message="We have established robust controls for object lifecycles and initialization integrity. What would you like to explore next?">
{/* Reason: Offers clear, highly valuable follow-up paths to explore remaining guidelines. */}
  <Elicitation label="Secure Deserialization and Serialization Patterns" query="How do I safely implement Serializable and prevent deserialization injection vulnerabilities in Java?"/>
  <Elicitation label="Mutator and Accessor Defensive Copying" query="How should I design secure getters and setters to prevent internal state exposure in mutable objects?"/>
</ElicitationsGroup>