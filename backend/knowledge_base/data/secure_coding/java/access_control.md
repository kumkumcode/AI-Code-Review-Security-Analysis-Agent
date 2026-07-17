---
id: JAVA-ACCESS-01-02
title: Permissions checking, stack-walk intersection, and callback bridging
category: Access Control / Privilege Escalation
severity_hint: High
cwe: [CWE-250, CWE-285]
java_versions: "Java 8 to 23 (Functional), Java 24+ (Obsolete/Inert)"
---

# Permissions Checking & Callback Bridging

## Overview
Java's legacy `SecurityManager` relies on a stack-walk where permissions are evaluated as the intersection of all execution frames. If unprivileged code initiates a chain that calls privileged code, the action is blocked. However, callbacks (like listeners, thread targets, or event handlers) can easily bridge malicious code to elevated system execution paths if context boundaries are not strictly preserved.

*Note: In Java 24+, the SecurityManager and AccessController are permanently disabled (JEP 486). This file provides legacy alignment and safe migration pathways.*

---

## Code Triad

### ❌ Insecure (Naive Callback / Trust Bridge)
Registering and triggering a user-provided callback directly on an elevated system execution frame without taking context snapshots.
```java
package xx.lib;

public class SystemEventManager {
    // VULNERABLE: Invokes the callback inside a system thread without restricting scope.
    // Untrusted handlers will execute with system-level privileges.
    public void executeCallback(Runnable userCallback) {
        new Thread(userCallback).start();
    }
}
⚠️ Flawed Attempt (Unusable Local Security Check)
Attempting to manually inspect the stack using stack trace analysis or relying on local SecurityManager instances which are disabled or bypassable.

Java
package xx.lib;

public class SystemEventManager {
    public void executeCallbackFlawed(Runnable userCallback) {
        // FLAWED: SecurityManager is inactive/deprecated in Java 24. 
        // This check will either be bypassed entirely or always return true/null.
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(new RuntimePermission("executeEventCallback"));
        }
        userCallback.run();
    }
}
✅ Secure (Preserved Caller Context or Process Isolation)
For legacy environments, capture and assert the caller's explicit AccessControlContext. For modern Java 24+ environments, perform untrusted execution in a sandbox sub-process or restricted OS container.

Java
package xx.lib;

import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.PrivilegedAction;

public class SystemEventManager {
    public void executeCallbackSecure(Runnable userCallback) {
        // SECURE (Pre-Java 24): Snapshot the caller's restricted execution context
        @SuppressWarnings("removal")
        final AccessControlContext callerContext = AccessController.getContext();

        new Thread(() -> {
            @SuppressWarnings("removal")
            AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
                userCallback.run();
                return null;
            }, callerContext);
        }).start();
    }

    // SECURE (Java 24+ Modern Standard): Native Process Separation
    // Spin up untrusted callbacks inside a restricted subprocess using ProcessBuilder
    // with OS-level restrictions (seccomp, low-privilege user execution).
}

---

### File 2: Safe `doPrivileged` Scope & Privilege Restriction
```markdown
---
id: JAVA-ACCESS-03-04
title: Safe Execution of doPrivileged and Privilege Reduction
category: Privilege Elevation / Unauthorized Execution
severity_hint: Critical
cwe: [CWE-250, CWE-20, CWE-918]
java_versions: "Java 8 to 23 (Functional), Java 24+ (Obsolete/Inert)"
---

# Safe doPrivileged Execution and Privilege Reduction

## Overview
`AccessController.doPrivileged` truncates the stack walk, meaning permissions of callers below the invoking frame are ignored. If unvalidated client input is allowed to reach a `doPrivileged` block, attackers can coerce the system to perform privileged file system or network activities.

---

## Code Triad

### ❌ Insecure (Tainted Parameter in Privileged Scope)
Directly passing an unvalidated parameter (such as a system property key or file path) into a privileged block.
```java
package xx.lib;

import java.security.AccessController;
import java.security.PrivilegedAction;

public class FileService {
    // VULNERABLE: External caller can pass arbitrary property names to read sensitive system configuration
    public static String getSystemPropertyUnsafe(String userSuppliedKey) {
        return AccessController.doPrivileged((PrivilegedAction<String>) () -> 
            System.getProperty(userSuppliedKey)
        );
    }
}
⚠️ Flawed Attempt (Weak Block-Listing Validation)
Sanitizing inputs with a blocklist regular expression. Attackers can bypass blocklists via alternative property paths, environment maps, or classpaths.

Java
package xx.lib;

import java.security.AccessController;
import java.security.PrivilegedAction;

public class FileService {
    public static String getSystemPropertyFlawed(String userSuppliedKey) {
        // FLAWED: Weak block-list regex can be bypassed
        if (userSuppliedKey.toLowerCase().contains("password") || userSuppliedKey.toLowerCase().contains("path")) {
            throw new SecurityException("Unauthorized property request.");
        }
        return AccessController.doPrivileged((PrivilegedAction<String>) () -> 
            System.getProperty(userSuppliedKey)
        );
    }
}
✅ Secure (Strict Allow-Listing & Dynamic Privilege Restriction)
Using an explicit allow-list for parameters and constructing a restricted AccessControlContext targeting only the single required permission.

Java
package xx.lib;

import java.security.*;
import java.util.Set;
import java.util.PropertyPermission;

public class FileService {
    private static final Set<String> ALLOWED_KEYS = Set.of("app.version", "app.environment");

    public static String getSystemPropertySecure(String userSuppliedKey) {
        // SECURE: Enforce strict allow-list check before executing privileged block
        if (!ALLOWED_KEYS.contains(userSuppliedKey)) {
            throw new SecurityException("Access to property denied: " + userSuppliedKey);
        }

        // SECURE: Dynamically scale down privileges to only what is necessary
        Permission perm = new PropertyPermission(userSuppliedKey, "read");
        PermissionCollection perms = perm.newPermissionCollection();
        perms.add(perm);

        @SuppressWarnings("removal")
        AccessControlContext restrictedContext = new AccessControlContext(
            new ProtectionDomain[] { new ProtectionDomain(null, perms) }
        );

        return AccessController.doPrivileged(
            (PrivilegedAction<String>) () -> System.getProperty(userSuppliedKey),
            restrictedContext
        );
    }
}

---

### File 3: Privilege Caching Risks
```markdown
---
id: JAVA-ACCESS-05
title: Safeguarding Privileged Operation Results in Caches
category: Broken Access Control / Information Disclosure
severity_hint: High
cwe: [CWE-524, CWE-200]
java_versions: "Java 8 to 23 (Functional), Java 24+ (Obsolete/Inert)"
---

# Safeguarding Privileged Operation Results in Caches

## Overview
Caching the output of a privileged call exposes data to downstream callers. If a resource (such as a configuration object, class metadata, or file stream handle) is calculated under elevated privileges and then cached globally without verifying that subsequent callers possess the same permissions, access controls are bypassed.

---

## Code Triad

### ❌ Insecure (Direct Privilege Leak via Shared Cache)
Computing a privileged system resource, caching it globally, and returning it to any requester without confirming their permissions.
```java
package xx.lib;

import java.util.concurrent.ConcurrentHashMap;
import java.security.AccessController;
import java.security.PrivilegedAction;

public class SystemMetricsCache {
    private static final ConcurrentHashMap<String, String> cache = new ConcurrentHashMap<>();

    // VULNERABLE: Subsequent unprivileged callers bypass checks by retrieving directly from the static cache
    public static String getMetric(String key) {
        return cache.computeIfAbsent(key, k -> 
            AccessController.doPrivileged((PrivilegedAction<String>) () -> System.getProperty(k))
        );
    }
}
⚠️ Flawed Attempt (Cache Isolation via Stack Trace Examination)
Relying on reflective stack trace examination to determine caller legitimacy before serving cached artifacts.

Java
package xx.lib;

import java.util.concurrent.ConcurrentHashMap;

public class SystemMetricsCache {
    private static final ConcurrentHashMap<String, String> cache = new ConcurrentHashMap<>();

    public static String getMetricFlawed(String key) {
        // FLAWED: Simple package string check on the stack trace is highly fragile and bypassable
        StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();
        if (stackTrace[2].getClassName().startsWith("untrusted.user.")) {
            throw new SecurityException("Unauthorized caller");
        }
        return cache.computeIfAbsent(key, k -> System.getProperty(k));
    }
}
✅ Secure (Context Preservation and Pre-Cache Permission Assertions)
Store the corresponding required permission inside the cache mapping along with the resource. Prior to serving the cached asset, explicitly assert the caller's permission set against the cache entry's permission constraint.

Java
package xx.lib;

import java.security.*;
import java.util.PropertyPermission;
import java.util.concurrent.ConcurrentHashMap;

public class SystemMetricsCache {
    private static final ConcurrentHashMap<String, CacheEntry> cache = new ConcurrentHashMap<>();

    public static class CacheEntry {
        private final String value;
        private final Permission permission;

        public CacheEntry(String value, Permission permission) {
            this.value = value;
            this.permission = permission;
        }

        public String getValue() { return value; }
        public Permission getPermission() { return permission; }
    }

    public static String getMetricSecure(String key) {
        Permission requiredPerm = new PropertyPermission(key, "read");
        
        // SECURE: Always verify that the current thread's context holds the permission 
        // before pulling the cached value
        @SuppressWarnings("removal")
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(requiredPerm);
        }

        CacheEntry entry = cache.get(key);
        if (entry != null) {
            return entry.getValue();
        }

        // Fetch and populate if authorized
        String resolvedValue = AccessController.doPrivileged((PrivilegedAction<String>) () -> System.getProperty(key));
        cache.put(key, new CacheEntry(resolvedValue, requiredPerm));
        return resolvedValue;
    }
}

---

### File 4: Context Transfer and Thread Construction boundaries
```markdown
---
id: JAVA-ACCESS-06-07
title: Safe Context Transfer across Thread and Async Boundaries
category: Thread Safety / Privilege Escalation
severity_hint: Medium
cwe: [CWE-250, CWE-362]
java_versions: "Java 8 to 23 (Functional), Java 24+ (Obsolete/Inert)"
---

# Safe Context Transfer across Thread and Async Boundaries

## Overview
Newly constructed threads inherit the execution context and access control capabilities of their parent spawning threads. When orchestrating asynchronous task queues, executing tasks under the parent thread's elevated context can allow malicious workers to execute privileged tasks.

---

## Code Triad

### ❌ Insecure (Implicit Context Inheritance on Child Threads)
Spawning a thread while running under elevated privileges, exposing the child thread's execution path to unauthorized actions.
```java
package xx.lib;

import java.security.AccessController;
import java.security.PrivilegedAction;

public class ThreadPoolManager {
    // VULNERABLE: Running user-provided task inside a thread initialized within a privileged scope
    public void executeUserTask(Runnable userTask) {
        AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
            Thread t = new Thread(userTask);
            t.start(); // Thread t inherits the parent's elevated system context
            return null;
        });
    }
}
⚠️ Flawed Attempt (Manual Context Cleansing)
Passing null during Thread initiation to clear properties or attempting manually to unset thread configurations.

Java
package xx.lib;

public class ThreadPoolManager {
    public void executeUserTaskFlawed(Runnable userTask) {
        Thread t = new Thread(userTask);
        // FLAWED: Setting the context classloader alone does not flush the 
        // inherited ProtectionDomain and AccessControlContext of the spawning thread.
        t.setContextClassLoader(null);
        t.start();
    }
}
✅ Secure (Explicit Thread Context Reduction)
Ensure asynchronous threads are constructed under the explicit permission profile of the target execution frame rather than the framework manager.

Java
package xx.lib;

import java.security.*;

public class ThreadPoolManager {
    public void executeUserTaskSecure(Runnable userTask) {
        // SECURE: Snapshot the user's unprivileged execution environment
        @SuppressWarnings("removal")
        final AccessControlContext userContext = AccessController.getContext();

        Thread t = new Thread(() -> {
            // Force the thread to evaluate tasks under the captured context
            @SuppressWarnings("removal")
            AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
                userTask.run();
                return null;
            }, userContext);
        });
        t.start();
    }
}

---

### File 5: Caller-Sensitive Methods & Reflection Protections
```markdown
---
id: JAVA-ACCESS-08-13
title: Protecting Caller-Sensitive Methods and Reflection Handles
category: Access Control Bypass / Privilege Escalation
severity_hint: Critical
cwe: [CWE-470, CWE-288, CWE-829]
java_versions: "Java 8 to 24+ (Always Applicable)"
---

# Protecting Caller-Sensitive Methods and Reflection Handles

## Overview
Methods marked `@CallerSensitive` (e.g., `Class.forName()`, `Method.invoke()`, `MethodHandles.lookup()`) alter behavior based on the immediate caller's class loader instance. If a library exposes wrapper interfaces around these caller-sensitive reflection endpoints, untrusted code can manipulate package boundaries, load internal JDK elements, and bypass object visibility limitations.

---

## Code Triad

### ❌ Insecure (Exposing Unvalidated Class Loading wrappers)
Directly invoking caller-sensitive reflection utilities using unchecked parameters from external interfaces.
```java
package xx.lib;

public class ReflectionBridge {
    // VULNERABLE: Lets arbitrary callers invoke private classes and bypass package visibility checks
    public static Object instantiateClass(String className) throws Exception {
        Class<?> clazz = Class.forName(className);
        return clazz.getDeclaredConstructor().newInstance();
    }
}
⚠️ Flawed Attempt (Reflective Method.invoke Isolation Attempt)
Assuming wrapping a reflective call inside another Method.invoke call isolates or resets the immediate caller class check.

Java
package xx.lib;

import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.PrivilegedAction;

public class ReflectionBridge {
    public static Object instantiateFlawed(String className) throws Exception {
        // FLAWED: The JVM explicitly ignores Method.invoke frames when analyzing 
        // caller-sensitive actions. The actual caller class remains the untrusted caller.
        Method method = Class.class.getMethod("forName", String.class);
        return method.invoke(null, className);
    }
}
✅ Secure (StackWalker Verification & Caller Classloader Scoping)
Use StackWalker (available from Java 9+) to audit and confirm the package context of the caller class, or force all lookups to resolve through the explicit, unprivileged caller's ClassLoader.

Java
package xx.lib;

import java.util.Set;

public class ReflectionBridge {
    private static final Set<String> WHITE_LISTED_PACKAGES = Set.of("com.company.safe");

    public static Object instantiateSecure(String className) throws Exception {
        // SECURE: Audit caller identity using the StackWalker API
        StackWalker walker = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE);
        Class<?> callerClass = walker.getCallerClass();

        if (!WHITE_LISTED_PACKAGES.contains(callerClass.getPackageName())) {
            throw new SecurityException("Unauthorized access: reflection path is locked for " + callerClass.getName());
        }

        // SECURE: Constrain lookup to the immediate caller's ClassLoader instead of the System context
        Class<?> clazz = Class.forName(className, true, callerClass.getClassLoader());
        return clazz.getDeclaredConstructor().newInstance();
    }
}