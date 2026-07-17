---
id: BP-PY-01
title: Secure Resource Management and File I/O
category: Best Practices / Resource Management
severity_hint: Info
cwe: [CWE-775]
python_versions: "Python 3.x"
---

# Secure Resource Management and File I/O

## Overview
When opening external resources (such as files, sockets, or database connections), failing to properly close them can lead to **Resource Exhaustion**. If an exception occurs between opening a file and closing it, the system handle is left open. The most idiomatic and secure way to handle resource allocations in Python is through Context Managers (the `with` statement), which guarantees that resources are torn down cleanly regardless of runtime failures.

---

## Code Triad

### ❌ Unoptimized (Manual Resource Tracking)
Explicitly calling `.close()` on a file object, leaving the handle hanging open if an exception occurs during reading.
```python
# UNOPTIMIZED: If json.loads() throws an exception, the file descriptor 
# is never closed, eventually exhausting OS resource handles over time.
def load_config_unsafe(filepath: str):
    f = open(filepath, 'r')
    data = f.read()
    f.close()
    return data
⚠️ Flawed Attempt (Try-Finally Blocks)
Using complex, deeply-nested try-finally blocks. While technically functional, it introduces unnecessary syntax clutter and decreases readability.

Python
# FLAWED: While functional, nesting try/finally blocks repeatedly 
# across multiple resources creates highly unreadable, fragile structures.
def load_config_flawed(filepath: str):
    f = open(filepath, 'r')
    try:
        data = f.read()
    finally:
        f.close()
    return data
✅ Best Practice (Explicit Context Managers)
Use the native with context manager, which handles cleanup implicitly.

Python
# BEST PRACTICE: The with statement guarantees close() is executed 
# immediately upon exiting the block, even if an exception is raised.
def load_config_secure(filepath: str):
    with open(filepath, 'r', encoding='utf-8') as f:
        return f.read()

---

And just in case you need **File 39** (the Java equivalent) right next to it to put in the same folder:

### File 39: For `knowledge_base/data/best_practices/java_resource_management.md`

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