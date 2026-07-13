Guideline 3-1 / INJECT-1: Generate valid formatting
Attacks using maliciously crafted inputs to cause incorrect formatting of outputs are well-documented [7]. Such attacks generally involve exploiting special characters in an input string, incorrect escaping, or partial removal of special characters.

If the input string has a particular format, combining correction and validation is highly error prone. Parsing and canonicalization should be done before validation. If possible, reject invalid data and any subsequent data, without attempting correction. For instance, many network protocols are vulnerable to cross-site POST attacks, by interpreting the HTTP body even though the HTTP header causes errors.

Use well-tested libraries instead of ad hoc code. There are many libraries for creating XML. Creating XML documents using raw text is error-prone. For unusual formats where appropriate libraries do not exist, such as configuration files, create classes that cleanly handle all formatting and only formatting code.


Guideline 3-2 / INJECT-2: Avoid dynamic SQL
It is well known that dynamically created SQL statements including untrusted input are subject to command injection. This often takes the form of supplying an input containing a quote character (') followed by SQL. Avoid dynamic SQL.

For parameterized SQL statements using Java Database Connectivity (JDBC), use java.sql.PreparedStatement or java.sql.CallableStatement instead of java.sql.Statement. In general, it is better to use a well-written, higher-level library to insulate application code from SQL. When using such a library, it is not necessary to limit characters such as quote ('). If text destined for XML/HTML is handled correctly during output (Guideline 3-3), then it is unnecessary to disallow characters such as less than (<) in inputs to SQL.

An example of using PreparedStatement correctly:

Copy
Copied to ClipboardError: Could not Copy
String sql = "SELECT * FROM User WHERE userId = ?"; 
PreparedStatement stmt = con.prepareStatement(sql); 
stmt.setString(1, userId); 
ResultSet rs = prepStmt.executeQuery();

Guideline 3-3 / INJECT-3: XML and HTML generation requires care
Untrusted data should be properly sanitized before being included in HTML or XML output. Failure to properly sanitize the data can lead to many different security problems, such as Cross-Site Scripting (XSS) and XML Injection vulnerabilities. It is important to be particularly careful when using Java Server Pages (JSP).

There are many ways to sanitize data before including it in output. Characters that are problematic for the specific type of output can be filtered, escaped, or encoded. Alternatively, characters that are known to be safe can be allowed, and everything else can be filtered, escaped, or encoded. This latter approach is preferable, as it does not require identifying and enumerating all characters that could potentially cause problems.

Implementing correct data sanitization and encoding can be tricky and error prone. Therefore, it is better to use a library to perform these tasks during HTML or XML construction.


Guideline 3-4 / INJECT-4: Avoid any untrusted data on the command line
When creating new processes, do not place any untrusted data on the command line. Behavior is platform-specific, poorly documented, and frequently surprising. Malicious data may, for instance, cause a single argument to be interpreted as an option (typically a leading - on Unix or / on Windows) or as two separate arguments. Any data that needs to be passed to the new process should be passed either as encoded arguments (e.g., Base64), in a temporary file, or through a inherited channel.


Guideline 3-5 / INJECT-5: Restrict XML inclusion
XML Document Type Definitions (DTDs) allow URLs to be defined as system entities, such as local files and HTTP URLs within the local intranet or localhost. XML External Entity (XXE) attacks insert local files into XML data which may then be accessible to the client. Similar attacks may be made using XInclude, the XSLT document function, and the XSLT import and include elements. The safest way to avoid these problems while maintaining the power of XML is to reduce privileges (as described in Guideline 9-2) and to use the most restrictive configuration possible for the XML parser. Reducing privileges still allows you to grant some access, such as inclusion to pages from the same-origin web site if necessary. XML parsers can also be configured to limit functionality based on what is required, such as disallowing external entities or disabling DTDs altogether.

Note that this issue generally applies to the use of APIs that use XML but are not specifically XML APIs.


Guideline 3-6 / INJECT-6: Care with BMP files
BMP images files may contain references to local ICC (International Color Consortium) files. Whilst the contents of ICC files is unlikely to be interesting, the act of attempting to read files may be an issue. Either avoid BMP files, or reduce privileges as Guideline 9-2.


Guideline 3-7 / INJECT-7: Disable HTML display in Swing components
Many Swing pluggable look-and-feels interpret text in certain components starting with <html> as HTML. If the text is from an untrusted source, an adversary may craft the HTML such that other components appear to be present or to perform inclusion attacks.

To disable the HTML render feature, set the "html.disable" client property of each component to Boolean.TRUE (no other Boolean true instance will do).

label.putClientProperty("html.disable", true);


Guideline 3-8 / INJECT-8: Take care interpreting untrusted code
Code can be hidden in a number of places. If the source is not trusted to supply code, then a secure sandbox must be constructed to run it in. Some examples of components or APIs that can potentially execute untrusted code include:

Scripts run through the javax.script scripting API or similar.
LiveConnect interfaces with JavaScript running in the browser1. The JavaScript running on a web page will not usually have been verified with an object code signing certificate.
By default the Oracle implementation of the XSLT interpreter enables extensions to call Java code. Set the javax.xml.XMLConstants.FEATURE_SECURE_PROCESSING feature to disable it.
Long Term Persistence of JavaBeans Components supports execution of Java statements. Long Term Bean Persistency [26] is a feature to transfer the state of an object via an XML representation, typically stored in files. Applications (especially those from the XML-era) may choose to handle their inter-process communication via this mechanism. However, while the use for bean compatible classes such as UI-controls is widely known, it is also possible to instantiate and potentially make calls to arbitrary classes, via method calls that are scripted in the XML file. Fortunately, the programmer can still introspect the content and intercept a potential malicious input. Application developers may therefore choose to re-inspect whether their code is using XML Bean Persistence, and as defense measure add appropriate checks and interception points. This includes third-party dependencies that may also make use of Bean Persistency.
Java Sound will load code through the javax.sound.midi.MidiSystem.getSoundbank methods.
RMI may allow loading of remote code specified by remote connection. On the Oracle JDK, this is disabled by default but may be enabled or disabled through the java.rmi.server.useCodebaseOnly system property.
LDAP (RFC 2713) allows loading of remote code in a server response. On the Oracle JDK, this is disabled by default but may be enabled or disabled through the com.sun.jndi.ldap.object.trustURLCodebase system property.
Many SQL implementations allow execution of code with effects outside of the database itself.
Performing JNDI lookups using untrusted data should be avoided, as it can lead to interactions with potentially malicious CORBA, LDAP, or RMI servers, or other malicious systems. If it cannot be avoided, then appropriate safety measures should be taken, including all of the following:
Ensuring that system properties related to remote class loading (discussed earlier in this guideline) are set to secure values.
Ensuring that system properties related to JNDI object factories are set to secure values. This includes jdk.jndi.object.factoriesFilter, jdk.jndi.ldap.object.factoriesFilter, and jdk.jndi.rmi.object.factoriesFilter. See [27] and [28] for additional information. It is also necessary to ensure that none of the allowed object factories (e.g., javax.naming.spi.ObjectFactory implementations) on the class path can be abused by attackers during the lookup process.
Leveraging restrictive deserialization filters (see Guideline 8-6 for more information), disabling LDAP serialization via com.sun.jndi.ldap.object.trustSerialData [27], and more generally following the deserialization guidance covered in Section 8.
Annotation processors: When compiling Java code, there is an option to run annotation processors found in the code base. This feature is disabled by default. Running untrusted annotation processors may cause unexpected or hostile side effects.

Guideline 3-9 / INJECT-9: Prevent injection of exceptional floating point values
Working with floating point numbers requires care when importing those from outside of a trust boundary, as the NaN (not a number) or infinite values can be injected into applications via untrusted input data, for example by conversion of (untrusted) Strings converted by the Double.valueOf method. Unfortunately the processing of exceptional values is typically not immediately noticed without introducing sanitization code. Moreover, passing an exceptional value to an operation propagates the exceptional numeric state to the operation result.

Both positive and negative infinity values are possible outcomes of a floating point operation [2], when results become too high or too low to be representable by the memory area that backs a primitive floating point value. Also, the exceptional value NaN can result from dividing 0.0 by 0.0 or subtracting infinity from infinity.

The results of casting propagated exceptional floating point numbers to short, integer and long primitive values need special care, too. This is because an integer conversion of a NaN value will result in a 0, and a positive infinite value is transformed to Integer.MAX_VALUE (or Integer.MIN_VALUE for negative infinity), which may not be correct in certain use cases.

There are distinct application scenarios where these exceptional values are expected, such as scientific data analysis which relies on numeric processing. However, it is advised that the result values be contained for that purpose in the local component. This can be achieved by sanitizing any floating point results before passing them back to the generic parts of an application.

Operations that involve AffineTransform objects can cause exceptional states to occur in 2D calculations, and potentially when unchecked, later negative/oversized allocations. At a minimum, the end result of a transformation should be checked for exceptional values (+/-Infinity, NaN).

As mentioned before, the programmer may wish to include sanitization code for these exceptional values when working with floating point numbers, especially if related to authorization or authentication decisions, or forwarding floating point values to JNI. The Double and Float classes help with sanitization by providing the isNan and isInfinite methods. Also keep in mind that comparing instances of Double.NaN via the equality operator always results to be false, which may cause lookup problems in maps or collections when using the equality operator on a wrapped double field within the equals method in a class definition.

A typical code pattern that can block further processing of unexpected floating point numbers is shown in the following example snippet.

Copy
Copied to ClipboardError: Could not Copy
if (Double.isNaN(untrusted_double_value)) {
    // specific action for non-number case
}

if (Double.isInfinite(untrusted_double_value)){
    // specific action for infinite case
}

// normal processing starts here