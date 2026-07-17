To transform these raw injection and processing guidelines into a premium, RAG-ready dataset, we will parse and modularize Guideline 3-1 through 3-9 (Injection & Input Parsing - INJECT-1 to INJECT-9).

As with the previous sets, we will completely eliminate dense academic paragraphs, strip away non-essential text, map each file to its respective CWE targets, and build clear Insecure / Flawed / Secure code triads that account for the modern JVM landscape of 2026.

File 13: Input Parsing, SQL, and HTML/XML Injection (INJECT-1, 2, 3)
Markdown
---
id: JAVA-INJECT-01-03
title: Valid Formatting, SQL Parameterization, and Output Encoding
category: Injection Vulnerabilities
severity_hint: Critical
cwe: [CWE-89, CWE-79, CWE-116, CWE-20]
java_versions: "All Versions (Always Applicable)"
---

# Valid Formatting, SQL Parameterization, and Output Encoding

## Overview
Combining string correction and validation is highly error-prone. Perform parsing and canonicalization *before* validating inputs. Always use well-tested libraries rather than ad hoc escaping logic when constructing XML, HTML, or executing database queries. 

---

## Code Triad

### ❌ Insecure (Dynamic SQL, Ad-hoc Escaping, and Direct String Concat)
Directly concatenating untrusted inputs into SQL strings and using manual string replacement to "sanitize" HTML outputs.
```java
package com.app.inject;

import java.sql.*;

public class QueryHandler {
    // VULNERABLE: Direct SQL Injection via dynamic query assembly
    public void searchUserUnsafe(Connection conn, String userId, String userBio) throws SQLException {
        String sql = "SELECT * FROM users WHERE id = '" + userId + "'";
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
        
        // VULNERABLE: Weak, easily bypassed HTML escaping using manual string manipulation
        String escapedBio = userBio.replace("<", "&lt;").replace(">", "&gt;");
        System.out.println("<div>" + escapedBio + "</div>");
    }
}
⚠️ Flawed Attempt (Incorrect PreparedStatement Usage)
Using a PreparedStatement but still appending unvalidated, dynamic string components to the SQL query template prior to execution.

Java
package com.app.inject;

import java.sql.*;

public class QueryHandler {
    public void searchUserFlawed(Connection conn, String column, String value) throws SQLException {
        // FLAWED: PreparedStatement parameter placeholders (?) cannot be used for structural SQL 
        // elements like table/column names. Dynamically concatenating the 'column' parameter reintroduces SQL injection.
        String sql = "SELECT * FROM users WHERE " + column + " = ?";
        PreparedStatement pstmt = conn.prepareStatement(sql);
        pstmt.setString(1, value);
        ResultSet rs = pstmt.executeQuery();
    }
}
✅ Secure (Parameterized SQL & Context-Aware Output Encoding)
Enforce strict parameterization for query data values, validate dynamic column identifiers against an explicit structural allow-list, and utilize verified libraries (such as OWASP Encoder) for output escaping.

Java
package com.app.inject;

import java.sql.*;
import java.util.Set;
import org.owasp.encoder.Encode;

public class QueryHandler {
    private static final Set<String> ALLOWED_COLUMNS = Set.of("username", "email", "created_at");

    public void searchUserSecure(Connection conn, String column, String value, String userBio) throws SQLException {
        // SECURE: Strict structural validation using an allow-list
        if (!ALLOWED_COLUMNS.contains(column)) {
            throw new IllegalArgumentException("Unauthorized column target: " + column);
        }

        // SECURE: Enforce fully parameterized SQL execution
        String sql = "SELECT * FROM users WHERE " + column + " = ?";
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, value);
            try (ResultSet rs = pstmt.executeQuery()) {
                // Process results...
            }
        }

        // SECURE: Use a trusted, context-aware library for HTML output escaping
        String safeHtml = Encode.forHtml(userBio);
        System.out.println("<div>" + safeHtml + "</div>");
    }
}

---

### File 14: Command Line & Process Injection Protection (`INJECT-4`)

```markdown
---
id: JAVA-INJECT-04
title: Preventing Command-Line Argument and Process Injection
category: Command Injection / Argument Injection
severity_hint: Critical
cwe: [CWE-78, CWE-88]
java_versions: "All Versions (Always Applicable)"
---

# Preventing Command-Line Argument and Process Injection

## Overview
Passing raw, untrusted user inputs directly as system command arguments is highly dangerous. Command parsers are platform-specific and behave unpredictably. An attacker can supply arguments starting with flags (e.g., `-` or `/`) to alter process execution properties, or force spaces to split single parameters into multiple parameters.

---

## Code Triad

### ❌ Insecure (Concatenated Shell Execution)
Executing operating system processes by concatenating raw, untrusted strings inside a system shell runtime.
```java
package com.app.inject;

import java.io.IOException;

public class ProcessExecutor {
    // VULNERABLE: String concatenation allows argument injection and subshell execution (e.g. "file.txt; rm -rf /")
    public void inspectFileUnsafe(String userFilename) throws IOException {
        Runtime.getRuntime().exec("sh -c 'ls -la " + userFilename + "'");
    }
}
⚠️ Flawed Attempt (Array-Based Parsing without Flag Sanitization)
Using ProcessBuilder with an array of arguments, but allowing user inputs to serve directly as individual command parameters without validating if they contain leading options/flags.

Java
package com.app.inject;

import java.io.IOException;

public class ProcessExecutor {
    public void inspectFileFlawed(String userFilename) throws IOException {
        // FLAWED: While ProcessBuilder prevents basic subshell injection (; or &&), 
        // an attacker can supply a value starting with a hyphen (e.g., "--help" or "-R") 
        // to inject arguments/options into the target execution binary.
        ProcessBuilder pb = new ProcessBuilder("ls", "-la", userFilename);
        pb.start();
    }
}
✅ Secure (Decoupled Process Execution and Safe Argument Encoding)
Avoid using operating system commands where native Java APIs exist. If a subprocess is unavoidable, validate that arguments do not start with hyphen-prefixed option characters, or pass input via standard input (stdin)/temporary files.

Java
package com.app.inject;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class ProcessExecutor {
    private static final Path SAFE_DIR = Paths.get("/var/app/sandbox").toAbsolutePath().normalize();

    public void inspectFileSecure(String userFilename) throws IOException {
        // SECURE: Enforce strict format matching (no hyphens or path-traversal patterns allowed)
        if (!userFilename.matches("^[a-zA-Z0-9_]+\\.[a-z]{3}$")) {
            throw new IllegalArgumentException("Invalid filename characters");
        }

        Path target = SAFE_DIR.resolve(userFilename).toAbsolutePath().normalize();
        if (!target.startsWith(SAFE_DIR) || !Files.exists(target)) {
            throw new SecurityException("Unauthorized file target access.");
        }

        // SECURE: Native process separation using array-based arguments with validated flags
        ProcessBuilder pb = new ProcessBuilder("ls", "-la", target.toString());
        pb.start();
    }
}

---

### File 15: Secure XML Processing & XXE Restriction (`INJECT-5`)

```markdown
---
id: JAVA-INJECT-05
title: Disabling XML External Entities (XXE) and DTD Processing
category: XML Injection / XXE
severity_hint: Critical
cwe: [CWE-611, CWE-827]
java_versions: "All Versions (Always Applicable)"
---

# Disabling XML External Entities (XXE) and DTD Processing

## Overview
By default, standard Java XML parsers are configured to resolve external Document Type Definitions (DTDs) and System Entities. This permits attackers to craft malicious XML files that extract local server files (via XXE) or perform Server-Side Request Forgery (SSRF) when the document is parsed.

---

## Code Triad

### ❌ Insecure (Default XML Parser Configurations)
Initializing and parsing an untrusted XML payload using a default parser instance with no features disabled.
```java
package com.app.inject;

import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import java.io.InputStream;

public class XmlParser {
    // VULNERABLE: Default DocumentBuilder permits external system entities and DTD resolution (XXE)
    public Document parseXmlUnsafe(InputStream xmlStream) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        return dbf.newDocumentBuilder().parse(xmlStream);
    }
}
⚠️ Flawed Attempt (Incomplete Secure Processing Feature Activation)
Enabling the XMLConstants.FEATURE_SECURE_PROCESSING setting alone. While this limits entity expansion size, it does not reliably block external system entity lookup in all JVM implementation profiles.

Java
package com.app.inject;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import java.io.InputStream;

public class XmlParser {
    public Document parseXmlFlawed(InputStream xmlStream) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // FLAWED: This feature alone does not guarantee safety against local file retrieval (XXE) 
        // across all XML parsers/JDK installations.
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        return dbf.newDocumentBuilder().parse(xmlStream);
    }
}
✅ Secure (Explicitly Disabling DTDs and External Entities)
Configure the parser to explicitly disable DTD execution, external entity declaration, and external parameter entity processing.

Java
package com.app.inject;

import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import java.io.InputStream;

public class XmlParser {
    public Document parseXmlSecure(InputStream xmlStream) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

        // SECURE: Disallow DTDs entirely to mitigate XXE injection completely
        dbf.setFeature("[http://apache.org/xml/features/disallow-doctype-decl](http://apache.org/xml/features/disallow-doctype-decl)", true);

        // SECURE: If DTDs are absolutely required, block external references specifically
        dbf.setFeature("[http://xml.org/sax/features/external-general-entities](http://xml.org/sax/features/external-general-entities)", false);
        dbf.setFeature("[http://xml.org/sax/features/external-parameter-entities](http://xml.org/sax/features/external-parameter-entities)", false);
        dbf.setFeature("[http://apache.org/xml/features/nonvalidating/load-external-dtd](http://apache.org/xml/features/nonvalidating/load-external-dtd)", false);

        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);

        return dbf.newDocumentBuilder().parse(xmlStream);
    }
}

---

### File 16: Swing Component HTML Rendering & BMP Security (`INJECT-6`, `7`)

```markdown
---
id: JAVA-INJECT-06-07
title: Safe Swing UI Rendering and BMP File Processing
category: Injection Vulnerabilities / Denial of Service
severity_hint: Low
cwe: [CWE-79, CWE-400]
java_versions: "All Versions (Always Applicable)"
---

# Safe Swing UI Rendering and BMP File Processing

## Overview
Many Swing components (such as `JLabel`, `JButton`, and `JToolTip`) render text starting with the tag `<html>` as functional HTML. Displaying untrusted input in these fields lets adversaries execute client-side injection or manipulate rendering structures. Additionally, parsing BMP image files with embedded ICC color profile lookups can lead to unexpected local I/O resource consumption.

---

## Code Triad

### ❌ Insecure (Exposing Raw Inputs to Swing Renderers & BMP Loaders)
Passing raw user-derived input directly into Swing text setters, and loading arbitrary BMP files without restrictive isolation boundaries.
```java
package com.app.gui;

import javax.swing.JLabel;

public class PanelView {
    // VULNERABLE: If input starts with "<html>", Swing renders it, permitting layout manipulation
    public void updateUserLabelUnsafe(JLabel label, String untrustedInput) {
        label.setText(untrustedInput); 
    }
}
⚠️ Flawed Attempt (Weak HTML Tag Stripping)
Attempting to sanitize the input using simple regex string-matching to strip out <html> elements before rendering.

Java
package com.app.gui;

import javax.swing.JLabel;

public class PanelView {
    public void updateUserLabelFlawed(JLabel label, String untrustedInput) {
        // FLAWED: Case-insensitive variations or leading whitespace can bypass this check
        String sanitized = untrustedInput;
        if (untrustedInput.startsWith("<html>")) {
            sanitized = untrustedInput.substring(6);
        }
        label.setText(sanitized);
    }
}
✅ Secure (Disabling Swing HTML Features & File Isolation)
Explicitly disable Swing HTML rendering capabilities on the component instance using the html.disable system client property, and scale down privileges prior to parsing graphic resource files.

Java
package com.app.gui;

import java.lang.Boolean;
import javax.swing.JLabel;

public class PanelView {
    public void updateUserLabelSecure(JLabel label, String untrustedInput) {
        // SECURE: Set the exact boolean property to permanently turn off component HTML parsing
        label.putClientProperty("html.disable", Boolean.TRUE);
        label.setText(untrustedInput);
    }
}

---

### File 17: Interpreting Untrusted Code, Reflection, and JNDI Filters (`INJECT-8`)

```markdown
---
id: JAVA-INJECT-08
title: Restricting JNDI Lookups and Untrusted Script Interpretation
category: Remote Code Execution / Insecure Deserialization
severity_hint: Critical
cwe: [CWE-502, CWE-74, CWE-917]
java_versions: "All Versions (Strict Modern Standard for JNDI)"
---

# Restricting JNDI Lookups and Untrusted Script Interpretation

## Overview
Loading external scripts (`javax.script`), executing unvalidated JavaBean serializations, or performing JNDI lookups with user-controlled strings enables Remote Code Execution (RCE) via remote directory registries (LDAP, RMI). Modern Java restricts remote class loading by default, but internal classpath gadgets can still be abused.

---

## Code Triad

### ❌ Insecure (Unchecked JNDI Lookups & Dynamic Scripting)
Performing unvalidated JNDI queries with untrusted target paths or directly executing raw user strings via scripting engines.
```java
package com.app.jndi;

import javax.naming.InitialContext;
import javax.naming.Context;

public class DirectoryConnector {
    // VULNERABLE: An attacker passing an "ldap://..." target can cause malicious class instantiation (RCE)
    public Object lookupUnsafe(String userQuery) throws Exception {
        Context ctx = new InitialContext();
        return ctx.lookup(userQuery);
    }
}
⚠️ Flawed Attempt (String Check for JNDI Schemes)
Blocking the obvious ldap: and rmi: schemas before performing lookups, which fails to block other lookups such as local filesystem resolving schemes or nested references.

Java
package com.app.jndi;

import javax.naming.InitialContext;
import javax.naming.Context;

public class DirectoryConnector {
    public Object lookupFlawed(String userQuery) throws Exception {
        // FLAWED: String checks can be bypassed with case-folding variations (e.g., "lDaP:")
        // or complex nested naming provider configurations.
        if (userQuery.toLowerCase().startsWith("ldap:") || userQuery.toLowerCase().startsWith("rmi:")) {
            throw new SecurityException("Unauthorized scheme detected");
        }
        Context ctx = new InitialContext();
        return ctx.lookup(userQuery);
    }
}
✅ Secure (Strict Schema Restrictions & JNDI Filter Settings)
Completely disable runtime code loading from remote repositories, restrict allowable lookup endpoints using static directories, and enforce robust filter constraints via JVM properties.

Java
package com.app.jndi;

import javax.naming.InitialContext;
import javax.naming.Context;
import java.util.Set;

public class DirectoryConnector {
    // SECURE: Enforce an explicit whitelist of permitted local directory naming records
    private static final Set<String> PERMITTED_RECORDS = Set.of("java:comp/env/jdbc/MyDb", "java:comp/env/mail/Session");

    public Object lookupSecure(String userQuery) throws Exception {
        if (!PERMITTED_RECORDS.contains(userQuery)) {
            throw new SecurityException("Access to directory lookup denied: " + userQuery);
        }

        Context ctx = new InitialContext();
        return ctx.lookup(userQuery);
    }
}

---

### File 18: Sanitizing Exceptional Floating-Point Boundaries (`INJECT-9`)

```markdown
---
id: JAVA-INJECT-09
title: Sanitizing Exceptional Floating-Point Values
category: Numeric Processing / Validation Bypass
severity_hint: Medium
cwe: [CWE-20, CWE-682]
java_versions: "All Versions (Always Applicable)"
---

# Sanitizing Exceptional Floating-Point Values

## Overview
Unchecked external strings parsed as floats or doubles can introduce special values like `Double.NaN` (Not a Number) or `Double.POSITIVE_INFINITY`. Standard comparisons against `NaN` using equality operators (such as `==`) always return `false`. When cast to integers, these values degrade into unexpected numbers (`NaN` becomes `0`; `Infinity` becomes `Integer.MAX_VALUE`), which can bypass authorization and financial thresholds.

---

## Code Triad

### ❌ Insecure (Direct Parsing without Boundary Validation)
Parsing a user-supplied floating point input and integrating it directly into processing routines.
```java
package com.app.numeric;

public class TransactionProcessor {
    // VULNERABLE: If user value is "NaN", comparing (amount > 0) evaluates to false, 
    // but arithmetic operations and casting will yield unexpected, bypassed outcomes.
    public void processPaymentUnsafe(String userAmount, Account acc) {
        double amount = Double.parseDouble(userAmount);
        if (amount <= 0.0) {
            throw new IllegalArgumentException("Invalid amount");
        }
        // Proceeding with transaction
        acc.adjustBalance(-amount);
    }
}
⚠️ Flawed Attempt (Direct Equality Comparison for NaN)
Attempting to check for NaN values using the standard Java equality operator (==).

Java
package com.app.numeric;

public class TransactionProcessor {
    public void processPaymentFlawed(String userAmount, Account acc) {
        double amount = Double.parseDouble(userAmount);
        // FLAWED: According to IEEE 754 standards, (amount == Double.NaN) is ALWAYS false!
        // This check will never trigger even if 'amount' is indeed NaN.
        if (amount == Double.NaN || amount == Double.POSITIVE_INFINITY) {
            throw new IllegalArgumentException("Invalid numeric value.");
        }
        acc.adjustBalance(-amount);
    }
}
✅ Secure (Sanitizing via isNaN and isInfinite Checking)
Utilize the built-in helper methods Double.isNaN() and Double.isInfinite() to thoroughly validate floating-point bounds before allowing any business logic execution.

Java
package com.app.numeric;

public class TransactionProcessor {
    public void processPaymentSecure(String userAmount, Account acc) {
        double amount = Double.parseDouble(userAmount);

        // SECURE: Thoroughly validate exceptional IEEE 754 floating-point cases
        if (Double.isNaN(amount) || Double.isInfinite(amount)) {
            throw new IllegalArgumentException("Exceptional floating-point value rejected.");
        }

        // SECURE: Enforce expected business domain limits
        if (amount <= 0.0 || amount > 10000.0) {
            throw new IllegalArgumentException("Transaction amount out of valid bounds.");
        }

        acc.adjustBalance(-amount);
    }
}