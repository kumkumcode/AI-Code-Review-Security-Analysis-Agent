Guideline 8-1 / SERIAL-1: Avoid serialization for security-sensitive classes
Security-sensitive classes that are not serializable will not have the problems detailed in this section. Making a class serializable effectively creates a public interface to all fields of that class. Serialization also effectively adds a hidden public constructor to a class, which needs to be considered when trying to restrict object construction.

Similarly, lambdas should be scrutinized before being made serializable. Functional interfaces should not be made serializable without due consideration for what could be exposed.

It is also important to avoid unintentionally making a security-sensitive class serializable, either by subclassing a serializable class or implementing a serializable interface.


Guideline 8-2 / SERIAL-2: Guard sensitive data during serialization
Once an object has been serialized the Java language's access controls can no longer be enforced and attackers can access private fields in an object by analyzing its serialized byte stream. Therefore, do not serialize sensitive data in a serializable class.

Approaches for handling sensitive fields in serializable classes are:

Declare sensitive fields transient
Define the serialPersistentFields array field appropriately
Implement writeObject and use ObjectOutputStream.putField selectively
Implement writeReplace to replace the instance with a serial proxy
Implement the Externalizable interface

Guideline 8-3 / SERIAL-3: View deserialization the same as object construction
Deserialization creates a new instance of a class without invoking any constructor on that class. Therefore, deserialization should be designed to behave like normal construction.

Default deserialization and ObjectInputStream.defaultReadObject can assign arbitrary objects to non-transient fields and does not necessarily return. Use ObjectInputStream.readFields instead to insert copying before assignment to fields. Or, if possible, don't make sensitive classes serializable.

Copy
Copied to ClipboardError: Could not Copy
public final class ByteString implements java.io.Serializable {
    private static final long serialVersionUID = 1L;
    private byte[] data;
    public ByteString(byte[] data) {
        this.data = data.clone(); // Make copy before assignment.
    }
    private void readObject(
        java.io.ObjectInputStream in
    ) throws java.io.IOException, ClassNotFoundException {
        java.io.ObjectInputStream.GetField fields =
            in.readFields();
        this.data = ((byte[])fields.get("data")).clone();
    }
    // ...
}
Perform the same input validation checks in a readObject method implementation as those performed in a constructor. Likewise, assign default values that are consistent with those assigned in a constructor to all fields, including transient fields, which are not explicitly set during deserialization.

In addition create copies of deserialized mutable objects before assigning them to internal fields in a readObject implementation. This defends against hostile code deserializing byte streams that are specially crafted to give the attacker references to mutable objects inside the deserialized container object.

Copy
Copied to ClipboardError: Could not Copy
public final class Nonnegative implements java.io.Serializable {
    private static final long serialVersionUID = 1L;
    private int value;
    public Nonnegative(int value) {
        // Make check before assignment.
        this.data = nonnegative(value);
    }
    private static int nonnegative(int value) {
        if (value < 0) {
            throw new IllegalArgumentException(value +
                                               " is negative");
        }
        return value;
    }
    private void readObject(
        java.io.ObjectInputStream in
    ) throws java.io.IOException, ClassNotFoundException {
        java.io.ObjectInputStream.GetField fields =
            in.readFields();
        this.value = nonnegative(field.get(value, 0));
    }
    // ...
}
Attackers can also craft hostile streams in an attempt to exploit partially initialized (deserialized) objects. Ensure a serializable class remains totally unusable until deserialization completes successfully. For example, use an initialized flag. Declare the flag as a private transient field and only set it in a readObject or readObjectNoData method (and in constructors) just prior to returning successfully. All public and protected methods in the class must consult the initialized flag before proceeding with their normal logic. As discussed earlier, use of an initialized flag can be cumbersome. Simply ensuring that all fields contain a safe value (such as null) until deserialization successfully completes can represent a reasonable alternative.

Security-sensitive serializable classes should ensure that object field types are final classes, or do special validation to ensure exact types when deserializing. Otherwise, an attacker may populate the fields with unsafe subclasses which behave in unexpected ways.


Guideline 8-4 / SERIAL-4: Duplicate the security-related checks performed in a class during serialization and deserialization
Prevent security-related checks enforced in a class from being bypassed via serialization or deserialization. Specifically, if a serializable class performs a security-related check in its constructors, then perform that same check in a readObject or readObjectNoData method implementation. Otherwise, an instance of the class can be created via deserialization without any check.

Copy
Copied to ClipboardError: Could not Copy
public final class SensitiveClass implements java.io.Serializable {
    public SensitiveClass() {
        // security check needed to instantiate SensitiveClass
        securityCheck();

        // regular logic follows
    }

    // implement readObject to enforce checks
    //   during deserialization
    private void readObject(java.io.ObjectInputStream in) {
        // duplicate check from constructor
        securityCheck();

        // regular logic follows
    }
}
If a serializable class enables internal state to be modified by a caller (via a public method, for example) and the modification is guarded with a security-related check, then perform that same check in a readObject method implementation. Otherwise, deserialization may result in the creation of another instance of an object with modified state without passing the check.

Copy
Copied to ClipboardError: Could not Copy
public final class SecureName implements java.io.Serializable {

    // private internal state
    private String name;

    private static final String DEFAULT = "DEFAULT";

    public SecureName() {
        // initialize name to default value
        name = DEFAULT;
    }

    // allow callers to modify private internal state
    public void setName(String name) {
        if (name!=null ? name.equals(this.name)
                       : (this.name == null)) {
            // no change - do nothing
            return;
        } else {
            // security check needed to modify name
            securityCheck();

            inputValidation(name);

            this.name = name;
        }
    }

    // implement readObject to enforce checks
    //   during deserialization
    private void readObject(java.io.ObjectInputStream in) {
        java.io.ObjectInputStream.GetField fields =
            in.readFields();
        String name = (String) fields.get("name", DEFAULT);

        // if the deserialized name does not match the default
        //   value normally created at construction time,
        //   duplicate checks


        if (!DEFAULT.equals(name)) {
            securityCheck();
            inputValidation(name);
        }
        this.name = name;
    }

}
If a serializable class enables internal state to be retrieved by a caller and the retrieval is guarded with a security-related check to prevent disclosure of sensitive data, then perform that same check in a writeObject method implementation. Otherwise, the check may be bypassed and internal state accessed simply by reading the serialized byte stream.

Copy
Copied to ClipboardError: Could not Copy
public final class SecureValue implements java.io.Serializable {
    // sensitive internal state
    private String value;

    // public method to allow callers to retrieve internal state

    public String getValue() {
        // security check needed to get value
        securityCheck();

        return value;
    }


    // implement writeObject to enforce checks 
    //  during serialization
    private void writeObject(java.io.ObjectOutputStream out) {
        // duplicate check from getValue()
        securityCheck();
        out.writeObject(value);
    }
}

Guideline 8-5 / SERIAL-5: Understand the security permissions given to serialization and deserialization
This guideline has been moved to 9-20.


Guideline 8-6 / SERIAL-6: Filter untrusted serial data
Serialization Filtering is a feature introduced in JDK 9 to improve both security and robustness when using Object Serialization. JDK 17 enhanced this feature by implementing context-specific filters [25].


Security guidelines require that application developers validate inputs from external sources. To protect the JVM against deserialization vulnerabilities, developers should create an inventory of the objects that can be serialized or deserialized by each component or library. Serialization filtering can be leveraged as a security mechanism to validate classes before they are deserialized. For each context and use case, developers should construct and apply an appropriate filter.

Serialization filters can be installed programmatically for specific input streams. Filters can also be configured that apply to most uses of object deserialization without modifying the application. These system-wide filters are configured via system properties or configured using the override mechanism of the security properties. As part of JEP 415, JDK 17 also introduced the ability to "configure context-specific and dynamically-selected deserialization filters via a JVM-wide filter factory that is invoked to select a filter for each individual deserialization operation."[25]

Creating an allow-list of safe classes and rejecting everything else is the most secure approach, and gives protection against unexpected objects in a stream. If an allow-list is not feasible, then a reject-list should include classes, packages, and modules that can be abused during deserialization. When taking this approach, it is important to consider that subclasses of the rejected class can still be deserialized. Allow-lists are preferred over reject-lists, as it is challenging to enumerate every possible class that could be leveraged in a deserialization attack in order to block them.

RMI supports the setting of serialization filters to protect remote invocations of exported objects. The RMI Registry and RMI distributed garbage collector use the filtering mechanisms defensively.

Support for the configurable filters has been included in the CPU releases for JDK 8u121, JDK 7u131, and JDK 6u141. For more information and details please refer to [17], [20], and [25].
