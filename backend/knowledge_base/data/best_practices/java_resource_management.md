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