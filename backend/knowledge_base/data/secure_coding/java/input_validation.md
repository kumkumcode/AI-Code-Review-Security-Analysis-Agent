---
id: JAVA-INPUT-01-02-04
title: Input Validation, Defensive Copying, and State Checking
category: Input Validation & Defensive Copying
severity_hint: Critical
cwe: [CWE-20, CWE-367, CWE-374, CWE-437]
java_versions: "All Versions (Always Applicable)"
---

# Input Validation, Defensive Copying, and State Checking

## Overview
All input from untrusted sources must be validated before use. Critically, to prevent Time-of-Check to Time-of-Use (TOCTOU) exploits and state changes after verification, **defensive copying of mutable objects must occur before input validation**. Furthermore, when dealing with callbacks or upcalls to untrusted objects, their output must be treated as untrusted input and thoroughly re-validated. Never rely on external constructor side-effects to sanitize inputs; always use the instantiated object state directly.

---

## Code Triad

### ❌ Insecure (Validation Before Copying & Reference Leakage)
Validating a mutable reference first, allowing a concurrent thread to swap its state immediately after the check but prior to execution.
```java
package com.app.input;

import java.util.Date;

public class EventScheduler {
    private Date scheduledTime;

    // VULNERABLE: Validates first, then saves reference. 
    // Another thread can modify 'userDate' after check (TOCTOU).
    public void scheduleEventUnsafe(Date userDate) {
        if (userDate.before(new Date())) {
            throw new IllegalArgumentException("Cannot schedule events in the past.");
        }
        this.scheduledTime = userDate; 
    }
}
⚠️ Flawed Attempt (Relying on External Constructor Sanitization)
Using a standard validator or parser object but assuming the original input string was safely modified in place, or trusting that an upcall output is automatically safe.

Java
package com.app.input;

import java.net.URI;

public class Downloader {
    // FLAWED: Constructs URI but does not use the parsed URI object. 
    // If the URI constructor silently tolerates or escapes certain characters, 
    // the raw 'urlString' remains unsanitized and dangerous when used directly.
    public void downloadFlawed(String urlString) throws Exception {
        new URI(urlString); // Checks syntax but discards the result object
        
        // VULNERABLE: Using raw, un-escaped input instead of URI object representation
        executeHttpCall(urlString); 
    }

    private void executeHttpCall(String url) {}
}
✅ Secure (Defensive Copying first, then Strict Validation)
Always clone or copy mutable inputs first, perform validation on the isolated clone, and always reference the newly created object rather than raw input strings.

Java
package com.app.input;

import java.net.URI;
import java.util.Date;
import java.util.Objects;

public final class EventSchedulerSecure {
    private final Date scheduledTime;

    public EventSchedulerSecure(Date userDate) {
        // SECURE: Perform defensive copy FIRST
        Date dateCopy = new Date(userDate.getTime());

        // SECURE: Perform validation on the copy
        if (dateCopy.before(new Date())) {
            throw new IllegalArgumentException("Cannot schedule events in the past.");
        }
        this.scheduledTime = dateCopy;
    }

    // SECURE: Always use returned, fully parsed API object representations
    public void downloadSecure(String urlString) throws Exception {
        Objects.requireNonNull(urlString, "URL cannot be null");
        
        // SECURE: Rely on the verified output of the parser rather than the raw string
        URI verifiedUri = new URI(urlString).normalize();
        
        executeHttpCall(verifiedUri);
    }

    private void executeHttpCall(URI uri) {
        // Use verified URI properties safely
    }
}

---

### File 20: Safe Native Method Wrappers (`INPUT-3`)

```markdown
---
id: JAVA-INPUT-03
title: Safe Native Method Wrappers and Integer Overflow Guarding
category: Native Code Boundaries / Buffer Overflow
severity_hint: High
cwe: [CWE-119, CWE-190]
java_versions: "All Versions (Always Applicable)"
---

# Safe Native Method Wrappers and Integer Overflow Guarding

## Overview
Java is memory-safe, but native methods (JNI/Panama API) are not. Buffer overflow, memory corruption, and boundary errors can crash the entire JVM or allow arbitrary code execution. Native methods must **never** be declared `public`. They must be kept `private` and wrapped within a final Java class that performs defensive copying, strict bounds checks, and guards against integer overflow.

---

## Code Triad

### ❌ Insecure (Public Native Methods)
Exposing native methods directly to callers, allowing bypass of array boundary checks, buffer sizes, and type rules.
```java
package com.app.jni;

public class NativeBridge {
    // VULNERABLE: Direct access to native boundary. 
    // Callers can pass a negative length or an offset causing immediate buffer overflow.
    public native void writeSharedBuffer(byte[] src, int offset, int length);
}
⚠️ Flawed Attempt (Wrapper without Integer Overflow Protection)
Providing a Java wrapper but using simple addition (offset + length > src.length) to validate bounds, which can be bypassed via integer overflow.

Java
package com.app.jni;

public final class NativeBridgeFlawed {
    private native void writeSharedBuffer(byte[] src, int offset, int length);

    public void writeBuffer(byte[] src, int offset, int length) {
        byte[] copy = src.clone();
        
        // FLAWED: If offset = 1 and length = Integer.MAX_VALUE, 
        // offset + length overflows to Integer.MIN_VALUE (which is less than copy.length),
        // bypassing this validation completely.
        if (offset + length > copy.length) {
            throw new IndexOutOfBoundsException("Invalid bounds");
        }
        writeSharedBuffer(copy, offset, length);
    }
}
✅ Secure (Private Native Methods with Safe Safe Math Bounds Checking)
Keep the native interface private. Implement a final public wrapper that executes clone operations first and checks boundaries using robust arithmetic equations that are immune to integer overflow.

Java
package com.app.jni;

import java.util.Objects;

public final class NativeBridgeSecure {

    // SECURE: Native method is completely inaccessible outside this class boundary
    private native void writeSharedBuffer(byte[] src, int offset, int length);

    public void writeBuffer(byte[] src, int offset, int length) {
        Objects.requireNonNull(src, "Source buffer cannot be null");
        
        // SECURE: Deep copy mutable array state before applying constraints
        byte[] bufferCopy = src.clone();

        // SECURE: Bounds checking using subtraction logic to prevent integer overflow.
        // E.g., checks if offset/length are negative, and ensures they do not exceed bounds.
        if (offset < 0 || length < 0 || offset > bufferCopy.length - length) {
            throw new IndexOutOfBoundsException("Buffer write bounds violation.");
        }

        writeSharedBuffer(bufferCopy, offset, length);
    }
}