---
id: CS-JV-01
title: Primitive Obsession
category: Code Smells / Design Quality
severity_hint: Warning
cwe: [CWE-391]
java_versions: "All Versions"
---

# Primitive Obsession in Java

## Overview
**Primitive Obsession** is the overuse of basic primitive types (like `String`, `int`, `double`) to represent complex domain concepts that have their own validation rules or logic (such as Email Addresses, Phone Numbers, or Zip Codes). When you pass raw primitives everywhere, validation logic gets duplicated across the codebase, making it highly prone to developer errors and inconsistencies.

---

## Code Triad

### ❌ Smelly (Using Raw Strings with Duplicated Validation)
Passing a raw String as an Email address and validating it manually inside every single service class.
```java
public class UserService {
    // SMELLY: Email is treated as a raw String. 
    // Any method accepting a String can accidentally pass a username or address instead.
    public void registerUser(String username, String email) {
        if (!email.contains("@")) {
            throw new IllegalArgumentException("Invalid email format");
        }
        // Save user...
    }
}
⚠️ Flawed Attempt (Helper Validation Class)
Using a utility validation class. While this centralizes the check, the variable is still a raw String, meaning developers can still easily bypass the validator by mistake.

Java
public class EmailValidator {
    public static boolean isValid(String email) {
        return email != null && email.contains("@");
    }
}

// FLAWED: The method signature still accepts any String. 
// A developer can easily forget to call the validator.
public class OrderService {
    public void sendInvoice(String email) {
        // Validation check is missing or optional here
        System.out.println("Invoice sent to " + email);
    }
}
✅ Clean (Using Value Objects)
Create a small, immutable domain wrapper class (Value Object) that encapsulates both the data and its validation.

Java
// CLEAN: Email is now a distinct type. 
// It is physically impossible to instantiate an invalid Email object.
public final class Email {
    private final String value;

    public Email(String value) {
        if (value == null || !value.contains("@")) {
            throw new IllegalArgumentException("Invalid email format");
        }
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}

// CLEAN: Method signatures are self-documenting and strictly type-safe.
public class UserServiceSecure {
    public void registerUser(String username, Email email) {
        // No validation needed here! The type guarantees the email is valid.
    }
}

---

### File 39: For your `best_practices/` Folder

Create a file named `java_resource_management.md` under `knowledge_base/data/best_practices/`.

```markdown
---
id: BP-JV-01
title: Try-With-Resources for Safe Resource Cleanup
category: Best Practices / Resource Management
severity_hint: Info
cwe: [CWE-775]
java_versions: "Java 7 and higher"
---

# Try-With-Resources for Safe Resource Cleanup

## Overview
When dealing with resources that implement `java.lang.AutoCloseable` (such as `InputStream`, `OutputStream`, `Connection`, or `BufferedReader`), you must close them when the operations are done. If you close them manually, any runtime exception thrown before the `.close()` line will leak the file descriptor or database connection. Java's **Try-With-Resources** statement automatically handles this cleanup, even if exceptions are thrown.

---

## Code Triad

### ❌ Unoptimized (Manual stream closing in normal execution flow)
Closing the stream manually at the end of the method.
```java
import java.io.*;

public class ConfigLoader {
    // UNOPTIMIZED: If reader.readLine() throws an IOException,
    // reader.close() is bypassed, leaking the system file handle.
    public String loadConfig(String path) throws IOException {
        BufferedReader reader = new BufferedReader(new FileReader(path));
        String line = reader.readLine();
        reader.close(); 
        return line;
    }
}
⚠️ Flawed Attempt (Verbose Try-Catch-Finally Blocks)
Using traditional try-finally blocks. While technically safe, they are incredibly verbose, hard to read, and can throw exceptions from within the finally block that mask original program errors.

Java
import java.io.*;

public class ConfigLoaderFlawed {
    // FLAWED: Extremely verbose and prone to "loss of exception" 
    // if reader.close() itself throws an exception.
    public String loadConfig(String path) throws IOException {
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new FileReader(path));
            return reader.readLine();
        } finally {
            if (reader != null) {
                reader.close();
            }
        }
    }
}
✅ Best Practice (Try-With-Resources)
Declaring the resource directly inside the try statement context.

Java
import java.io.*;

public class ConfigLoaderClean {
    // BEST PRACTICE: The compiler automatically generates the closing logic.
    // The reader is guaranteed to close safely regardless of execution success or failure.
    public String loadConfig(String path) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(path))) {
            return reader.readLine();
        }
    }
}