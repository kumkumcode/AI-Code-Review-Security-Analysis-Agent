---
id: JAVA-SERIAL-01-04
title: Guarding Sensitive Serialization Data and Replicating Safety Checks
category: Serialization Security
severity_hint: Critical
cwe: [CWE-502, CWE-200, CWE-358]
java_versions: "All Versions (Always Applicable)"
---

# Guarding Sensitive Serialization Data and Replicating Safety Checks

## Overview
Making a class serializable bypasses normal access modifiers and hidden constructor rules, effectively exposing private fields to anyone who can intercept the serialized byte stream. When writing serializable classes, any security-related validation, range-checking, or access-permission routines executed during standard construction must be mirrored precisely inside customized `readObject` and `writeObject` methods.

---

## Code Triad

### ❌ Insecure (Exposing Raw Fields and Bypassing Access Checks)
A serializable class that stores cleartext API tokens in a default serializable field and executes security evaluations inside its constructor but fails to replicate them on deserialization.
```java
package com.app.serial;

import java.io.Serializable;

public final class UserSession implements Serializable {
    private static final long serialVersionUID = 1L;
    
    // VULNERABLE: Sensitive token is written in cleartext to the serialization stream
    private String apiToken;
    private int sessionLevel;

    public UserSession(String apiToken, int sessionLevel) {
        // VULNERABLE: This check is bypassed when deserializing a compromised object stream
        if (sessionLevel < 1 || sessionLevel > 5) {
            throw new IllegalArgumentException("Invalid privilege level");
        }
        this.apiToken = apiToken;
        this.sessionLevel = sessionLevel;
    }

    public String getApiToken() {
        return apiToken;
    }
}
⚠️ Flawed Attempt (Replicating Logic without Defensive Copying)
Enforcing validation inside readObject but directly assigning deserialized fields without performing defensive cloning of mutable fields first.

Java
package com.app.serial;

import java.io.*;

public final class UserSessionFlawed implements Serializable {
    private static final long serialVersionUID = 1L;
    
    private transient String apiToken; // Marked transient, but state-saving logic is flawed
    private int sessionLevel;

    public UserSessionFlawed(String apiToken, int sessionLevel) {
        if (sessionLevel < 1 || sessionLevel > 5) {
            throw new IllegalArgumentException("Invalid privilege level");
        }
        this.apiToken = apiToken;
        this.sessionLevel = sessionLevel;
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        // FLAWED: Using defaultReadObject can bind corrupted references directly to fields
        in.defaultReadObject();
        
        // FLAWED: Validates bounds after the unchecked initialization occurred
        if (sessionLevel < 1 || sessionLevel > 5) {
            throw new InvalidObjectException("Privilege range error");
        }
    }
}
✅ Secure (Transient Fields, readFields extraction, and Re-validation)
Keep highly sensitive state fields transient (or use a Serialization Proxy). When using standard fields, use readFields() to load inputs safely, perform defensive cloning, and re-run all constructor security and boundary checks before binding them.

Java
package com.app.serial;

import java.io.*;

public final class UserSessionSecure implements Serializable {
    private static final long serialVersionUID = 2L;

    // SECURE: Keep sensitive fields out of persistent formats
    private transient String apiToken; 
    private int sessionLevel;

    public UserSessionSecure(String apiToken, int sessionLevel) {
        validatePrivileges(sessionLevel);
        this.apiToken = apiToken;
        this.sessionLevel = sessionLevel;
    }

    private static void validatePrivileges(int level) {
        if (level < 1 || level > 5) {
            throw new IllegalArgumentException("Invalid privilege level: " + level);
        }
    }

    // SECURE: Enforce authorization controls prior to writing instance to stream
    private void writeObject(ObjectOutputStream out) throws IOException {
        out.defaultWriteObject();
        // Alternatively, write an encrypted variant of apiToken here if storage is required
    }

    // SECURE: treat deserialization identically to object construction
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        ObjectInputStream.GetField fields = in.readFields();
        int level = fields.get("sessionLevel", 1);

        // SECURE: Re-evaluate state validation rules prior to field assignment
        validatePrivileges(level);
        this.sessionLevel = level;
        
        // SECURE: Re-initialize transient values to safe, default values
        this.apiToken = "REVOKED_ON_DESERIALIZE";
    }
}

---

### File 24: Serialization Filters and Object Input Controls (`SERIAL-6`)

```markdown
---
id: JAVA-SERIAL-06
title: Serialization Filtering of Untrusted Data
category: Insecure Deserialization / Object Filtering
severity_hint: Critical
cwe: [CWE-502]
java_versions: "Java 9 and higher (Enhanced in Java 17)"
---

# Serialization Filtering of Untrusted Data

## Overview
Unchecked deserialization of untrusted streams is one of the most destructive attack vectors in Java application architectures, potentially leading to immediate Remote Code Execution (RCE). To mitigate this vulnerability, you must deploy strict `ObjectInputFilter` configurations to block unauthorized gadget classes and enforce explicit class allow-lists during stream processing.

---

## Code Triad

### ❌ Insecure (Unchecked Object Deserialization)
Instantiating a standard `ObjectInputStream` and deserializing raw user-supplied binary files with no filter parameters configured.
```java
package com.app.serial;

import java.io.*;

public class SerializationHandler {
    // VULNERABLE: Any class on the application classpath can be instantiated before type-casting,
    // leading to remote code execution (RCE) via common library exploits (e.g., commons-collections).
    public Object deserializeStreamUnsafe(InputStream rawStream) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(rawStream)) {
            return ois.readObject(); 
        }
    }
}
⚠️ Flawed Attempt (Deny-list / Block-list Deserialization Filters)
Configuring deserialization filters to block common known vulnerable classes, which fails when newly discovered gadgets or unblocked classpath dependencies are targeted.

Java
package com.app.serial;

import java.io.*;

public class SerializationHandler {
    public Object deserializeStreamFlawed(InputStream rawStream) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(rawStream)) {
            // FLAWED: Using a reject/deny list is highly fragile. 
            // Attackers will easily locate unlisted class gadget chains on the classpath.
            ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
                "!org.apache.commons.collections4.functors.*;"
            );
            ois.setObjectInputFilter(filter);
            return ois.readObject();
        }
    }
}
✅ Secure (Strict Allow-list Configuration via ObjectInputFilter)
Implement a strict, targeted allow-list filter that accepts only a tightly defined set of safe, local DTO classes, and rejects everything else.

Java
package com.app.serial;

import java.io.*;
import java.util.Set;

public class SerializationHandler {
    
    // SECURE: Enforce a strict allow-list that is limited strictly to expected, benign data types
    private static final Set<String> ALLOWED_CLASSES = Set.of(
        "com.app.serial.SafePayloadDTO",
        "java.lang.String",
        "java.lang.Integer"
    );

    public Object deserializeStreamSecure(InputStream rawStream) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(rawStream)) {
            
            // SECURE: Allow only explicitly matched classes, specify limits on tree depth/size, and reject everything else
            ObjectInputFilter filter = filterInfo -> {
                Class<?> serialClass = filterInfo.serialClass();
                if (serialClass == null) {
                    return ObjectInputFilter.Status.UNDECIDED;
                }
                
                // Enforce strict stream parameter metrics (Max depth, references, array sizes)
                if (filterInfo.depth() > 10 || filterInfo.references() > 1000) {
                    return ObjectInputFilter.Status.REJECTED;
                }

                if (ALLOWED_CLASSES.contains(serialClass.getName())) {
                    return ObjectInputFilter.Status.ALLOWED;
                }
                
                return ObjectInputFilter.Status.REJECTED;
            };

            ois.setObjectInputFilter(filter);
            return ois.readObject();
        }
    }
}

---

### File 25: Safe Serialization Proxies (`SERIAL-2`, `3`)

```markdown
---
id: JAVA-SERIAL-02-03
title: Safe Serialization Proxies
category: Serialization Security
severity_hint: High
cwe: [CWE-502, CWE-372]
java_versions: "All Versions (Always Applicable)"
---

# Safe Serialization Proxies

## Overview
A Serialization Proxy pattern replaces the actual instance of a class with a helper container during the serialization process. This completely bypasses default deserialization, guaranteeing that instances can only ever be constructed through their public APIs and validated constructor paths, avoiding partial-initialization exploits or corrupted internal references.

---

## Code Triad

### ❌ Insecure (Exposing Complex Internal Graphs)
Implementing direct, raw `Serializable` on complex, mutable classes, allowing attackers to reconstruct invalid object relationships.
```java
package com.app.serial;

import java.io.Serializable;

public final class Coordinates implements Serializable {
    private static final long serialVersionUID = 1L;
    
    private final int x;
    private final int y;

    // VULNERABLE: Attacker stream can inject coordinates outside of normal constraints
    public Coordinates(int x, int y) {
        if (x < 0 || y < 0) {
            throw new IllegalArgumentException("Negative coordinates not permitted.");
        }
        this.x = x;
        this.y = y;
    }

    public int getX() { return x; }
    public int getY() { return y; }
}
⚠️ Flawed Attempt (Constructing Invalid Internal States via Custom Deserializers)
Implementing complex logic checks inside readObject to enforce constraints. This remains highly complex, error-prone, and susceptible to reflection and memory reference capturing during deserialization.

Java
package com.app.serial;

import java.io.*;

public final class CoordinatesFlawed implements Serializable {
    private static final long serialVersionUID = 1L;
    private int x;
    private int y;

    public CoordinatesFlawed(int x, int y) {
        validate(x, y);
        this.x = x;
        this.y = y;
    }

    private void validate(int x, int y) {
        if (x < 0 || y < 0) {
            throw new IllegalArgumentException("Negative coordinates not permitted.");
        }
    }

    // FLAWED: Direct assignment inside readObject bypasses constructor structure and safety wrappers.
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        validate(this.x, this.y);
    }
}
✅ Secure (The Serialization Proxy Pattern)
Use a private, static inner class (SerializationProxy) to handle serialization operations. Implement writeReplace() to output the proxy, and configure readObject() on the base class to throw an exception if deserialized directly.

Java
package com.app.serial;

import java.io.*;

public final class CoordinatesSecure implements Serializable {
    private static final long serialVersionUID = 3L;

    private final int x;
    private final int y;

    public CoordinatesSecure(int x, int y) {
        if (x < 0 || y < 0) {
            throw new IllegalArgumentException("Negative coordinates not permitted.");
        }
        this.x = x;
        this.y = y;
    }

    // SECURE: This inner class is the ONLY entity saved in serialized storage
    private static class SerializationProxy implements Serializable {
        private static final long serialVersionUID = 3L;
        private final int x;
        private final int y;

        SerializationProxy(CoordinatesSecure original) {
            this.x = original.x;
            this.y = original.y;
        }

        // SECURE: Instantiates the target outer class via its official public constructor on deserialization
        private Object readResolve() {
            return new CoordinatesSecure(x, y);
        }
    }

    // SECURE: Automatically serialize the proxy container instead of this outer class instance
    private Object writeReplace() {
        return new SerializationProxy(this);
    }

    // SECURE: Block any attempt to bypass the serialization proxy via compromised data streams
    private void readObject(ObjectInputStream stream) throws InvalidObjectException {
        throw new InvalidObjectException("Proxy transaction required for serialization execution.");
    }

    public int getX() { return x; }
    public int getY() { return y; }
}

---

<ElicitationsGroup message="These serialization rules seal critical holes in object construction pipelines. What would you like to explore next?">
{/* Reason: Offers highly relevant follow-up prompts tailored specifically to JVM safety patterns. */}
  <Elicitation label="Access Control and Defensive Class Designing" query="How should I structure access permissions and package levels in Java to enforce class boundaries safely?"/>
  <Elicitation label="Preventing Thread Race Conditions in Mutable Objects" query="How do I design thread-safe classes that are protected against concurrent state corruption?"/>
</ElicitationsGroup>