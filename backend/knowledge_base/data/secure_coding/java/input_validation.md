Guideline 5-1 / INPUT-1: Validate inputs
Input from untrusted sources must be validated before use. Maliciously crafted inputs may cause problems, whether coming through method arguments or external streams. Examples include overflow of integer values and directory traversal attacks by including "../" sequences in filenames. Ease-of-use features should be separated from programmatic interfaces.

It may also be necessary to perform validation on input more than once. Performing validation early can be beneficial, as it will reject invalid input sooner and reduce exposure to malformed data. However, validating the input immediately prior to using it for a security-sensitive task will cover any modifications made since it was previously validated, and also allows for validation to be more specific to the context of its use. Earlier validation may not be effective for the current task, as it could have been performed by another part of the application or system, using different assumptions about the context or intended use of the input.

Whenever possible, processing untrusted input should be avoided. For example, consuming a JAR file from an untrusted source might allow an attacker to inject malicious code or data into the system, causing misbehavior, excessive resource consumption, or other problems.

Note that input validation must occur after any defensive copying of that input (see Guideline 6-2).


Guideline 5-2 / INPUT-2: Validate output from untrusted objects as input
In general method arguments should be validated but not return values. However, in the case of an upcall (invoking a method of higher level code) the returned value should be validated. Likewise, an object only reachable as an implementation of an upcall need not validate its inputs.

A subtle example would be Class objects returned by ClassLoaders. Untrusted code might control ClassLoader instances that get passed as arguments, or that are set in Thread context. Thus, when calling methods on ClassLoaders not many assumptions can be made. Multiple invocations of ClassLoader.loadClass() are not guaranteed to return the same Class instance or definition, which could cause TOCTOU issues.


Guideline 5-3 / INPUT-3: Define wrappers around native methods
Java code is subject to runtime checks for type, array bounds, and library usage. Native code, on the other hand, is generally not. While pure Java code is effectively immune to traditional buffer overflow attacks, native methods are not. To offer some of these protections during the invocation of native code, do not declare a native method public. Instead, declare it private and expose the functionality through a public Java-based wrapper method. A wrapper can safely perform any necessary input validation prior to the invocation of the native method:

Copy
Copied to ClipboardError: Could not Copy
public final class NativeMethodWrapper {

    // private native method
    private native void nativeOperation(byte[] data, int offset,
                                        int len);

    // wrapper method performs checks
    public void doOperation(byte[] data, int offset, int len) {
        // copy mutable input
        data = data.clone();

        // validate input
        // Note offset+len would be subject to integer overflow.
        // For instance if offset = 1 and len = Integer.MAX_VALUE,
        //   then offset+len == Integer.MIN_VALUE which is lower
        //   than data.length.
        // Further,
        //   loops of the form
        //       for (int i=offset; i<offset+len; ++i) { ... }
        //   would not throw an exception or cause native code to
        //   crash.

        if (offset < 0 || len < 0 || offset > data.length - len) {
              throw new IllegalArgumentException();
        }

        nativeOperation(data, offset, len);
    }
}

Guideline 5-4 / INPUT-4: Verify API behavior related to input validation
Do not rely on an API for input validation without first verifying through documentation and testing that it performs necessary validation for the given context. For example, if documentation states that a class or method expects input to be in a specific syntax (e.g., according to a documented standard), do not assume that the called method/constructor will throw an exception if the input does not strictly adhere to that syntax, unless the documentation explicitly specifies that behavior. Verifying the API behavior is especially important when validating untrusted data.

If a constructor (or method that returns an object) is relied upon to perform input validation, be sure to use the created/returned object and not the original input passed to it. Some constructors or methods may not outright reject invalid input, and may instead filter, escape, or encode the input used to construct the object. Therefore, even if the object has been safely constructed, the input may not be safe in its original form. Additionally, some classes may not validate the input until it is used, which may occur later (e.g., when a method is called on the created object).

Additional steps may be required when using an API for input validation. It might be necessary to perform context-specific checks (such as range checks, allow/block list checks, etc.) in addition to the syntactic validation performed by the API. The caller may also need to sanitize certain data, such as meta-characters that identify macros or have other special meaning in the given context, prior to passing the data to the API. It may not be sufficient to use lower-level APIs for input validation, as they often provide additional flexibility that could be problematic in a higher-level application context.

It is also necessary to account for any discrepancies in behavior between different APIs when using the same data across them. Different implementations may not parse certain types of data (URLs, file paths, etc.) the same way, especially when ambiguities exist in related specifications. When using the implementations together, these discrepancies often lead to security issues. Therefore, it is important to either verify that the implementations handle the given data type consistently, or make sure that additional validation or other steps are taken to account for the discrepancies. In some cases, it may be better not to use multiple APIs when processing data in order to avoid these discrepancies or inconsistent behavior.

One situation where issues often arise is parsing ZIP and JAR files. These file types can contain a number of discrepancies, such as conflicting information about the same entry, missing entries, or duplicate entries. It is also possible for signed JARs to contain unsigned entries, or to have subsets of entries signed by different signers. Depending on the situation, it may be necessary to detect these cases and reject the input, notify the user, or perform other actions.

When accessing ZIP/JAR files programmatically, it is important to understand how the APIs being used process the input. If multiple APIs are being used, and they process the input using different approaches, then inconsistent behavior between the APIs can lead to issues. Therefore, it is often safer to always use the same API in order to avoid those inconsistencies.