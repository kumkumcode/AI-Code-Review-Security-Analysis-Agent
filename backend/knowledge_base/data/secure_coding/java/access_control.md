Guideline 9-1 / ACCESS-1: Understand how permissions are checked
NOTE: The security manager has been permanently disabled since Java 24, so this guideline is only applicable to earlier releases3.

The standard security check ensures that each frame in the call stack has the required permission. That is, the current permissions in force is the intersection of the permissions of each frame in the current access control context. If any frame does not have a permission, no matter where it lies in the stack, then the current context does not have that permission.

Consider an application that indirectly uses secure operations through a library.

Copy
Copied to ClipboardError: Could not Copy
package xx.lib;

public class LibClass {
    private static final String OPTIONS = "xx.lib.options";

    public static String getOptions() {
        // checked by SecurityManager
        return System.getProperty(OPTIONS);
    }
}

package yy.app;

class AppClass {
    public static void main(String[] args) {
        System.out.println(
            xx.lib.LibClass.getOptions()
        );
    }
}
When the permission check is performed, the call stack will be as illustrated below.

Copy



        +--------------------------------+
        | java.security.AccessController |
        |   .checkPermission(Permission) |
        +--------------------------------+
        | java.lang.SecurityManager      |
        |   .checkPermission(Permission) |
        +--------------------------------+
        | java.lang.SecurityManager      |
        |   .checkPropertyAccess(String) |
        +--------------------------------+
        | java.lang.System               |
        |   .getProperty(String)         |
        +--------------------------------+
        | xx.lib.LibClass                |
        |   .getOptions()                |
        +--------------------------------+
        | yy.app.AppClass                |
        |   .main(String[])              |
        +--------------------------------+

In the above example, if the AppClass frame does not have permission to read a file but the LibClass frame does, then a security exception is still thrown. It does not matter that the immediate caller of the privileged operation is fully privileged, but that there is unprivileged code on the stack somewhere.

For library code to appear transparent to applications with respect to privileges, libraries should be granted permissions at least as generous as the application code that it is used with. For this reason, almost all the code shipped in the JDK and extensions is fully privileged. It is therefore important that there be at least one frame with the application's permissions on the stack whenever a library executes security checked operations on behalf of application code.


Guideline 9-2 / ACCESS-2: Beware of callback methods
NOTE: The security manager has been permanently disabled since Java 24, so this guideline is only applicable to earlier releases3.

Callback methods are generally invoked from the system with full permissions. It seems reasonable to expect that malicious code needs to be on the stack in order to perform an operation, but that is not the case. Malicious code may set up objects that bridge the callback to a security checked operation. For instance, a file chooser dialog box that can manipulate the filesystem from user actions, may have events posted from malicious code. Alternatively, malicious code can disguise a file chooser as something benign while redirecting user events.

Callbacks are widespread in object-oriented systems. Examples include the following:

Static initialization is often done with full privileges
Application main method
Applet/Midlet/Servlet lifecycle events1
Runnable.run
This bridging between callback and security-sensitive operations is particularly tricky because it is not easy to spot the bug or to work out where it is.

When implementing callback types, use the technique described in Guideline 9-6 to transfer context.


Guideline 9-3 / ACCESS-3: Safely invoke java.security.AccessController.doPrivileged
NOTE: The security manager has been permanently disabled since Java 24, so this guideline is only applicable to earlier releases3.

AccessController.doPrivileged enables code to exercise its own permissions when performing SecurityManager-checked operations. For the purposes of security checks, the call stack is effectively truncated below the caller of doPrivileged. The immediate caller is included in security checks.

Copy



        +--------------------------------+
        | action                         |
        |   .run                         |
        +--------------------------------+
        | java.security.AccessController |
        |   .doPrivileged                |
        +--------------------------------+
        | SomeClass                      |
        |   .someMethod                  |
        +--------------------------------+
        | OtherClass                     |
        |  .otherMethod                  |
        +--------------------------------+
        |                                |

In the above example, the privileges of the OtherClass frame are ignored for security checks.

To avoid inadvertently performing such operations on behalf of unauthorized callers, be very careful when invoking doPrivileged using caller-provided inputs (tainted inputs):

Copy
Copied to ClipboardError: Could not Copy
package xx.lib;

import java.security.*;

public class LibClass {
    // System property used by library, 
    //  does not contain sensitive information
    private static final String OPTIONS = "xx.lib.options";

    public static String getOptions() {
        return AccessController.doPrivileged(
            new PrivilegedAction<String>() {
                public String run() {
                    // this is checked by SecurityManager
                    return System.getProperty(OPTIONS);
                }
            }
        );
    }
}
The implementation of getOptions properly retrieves the system property using a hardcoded value. More specifically, it does not allow the caller to influence the name of the property by passing a caller-provided (tainted) input to doPrivileged.

It is also important to ensure that privileged operations do not leak sensitive information. Whenever the return value of doPrivileged is made accessible to untrusted code, verify that the returned object does not expose sensitive information. In the above example, getOptions returns the value of a system property, but the property does not contain any sensitive data.

Caller inputs that have been validated can sometimes be safely used with doPrivileged. Typically the inputs must be restricted to a limited set of acceptable (usually hardcoded) values.

Privileged code sections should be made as small as practical in order to make comprehension of the security implications tractable.

By convention, instances of PrivilegedAction and PrivilegedExceptionAction may be made available to untrusted code, but doPrivileged must not be invoked with caller-provided actions.

The two-argument overloads of doPrivileged allow changing of privileges to that of a previous acquired context. A null context is interpreted as adding no further restrictions. Therefore, before using stored contexts, make sure that they are not null (AccessController.getContext never returns null).

Copy
Copied to ClipboardError: Could not Copy
if (acc == null) {
    throw new SecurityException("Missing AccessControlContext");
}
AccessController.doPrivileged(new PrivilegedAction<Void>() {
        public Void run() {
            // ...
        }
    }, acc);

Guideline 9-4 / ACCESS-4: Know how to restrict privileges through doPrivileged
NOTE: The security manager has been permanently disabled since Java 24, so this guideline is only applicable to earlier releases3.

As permissions are restricted to the intersection of frames, an artificial AccessControlContext representing no (zero) frames implies all permissions. The following three calls to doPrivileged are equivalent:

Copy
Copied to ClipboardError: Could not Copy
private static final AccessControlContext allPermissionsAcc =
    new AccessControlContext(
        new java.security.ProtectionDomain[0]
    );
void someMethod(PrivilegedAction<Void> action) {
    AccessController.doPrivileged(action, allPermissionsAcc);
    AccessController.doPrivileged(action, null);
    AccessController.doPrivileged(action);
}
All permissions can be removed using an artificial AccessControlContext context containing a frame of a ProtectionDomain with no permissions:

Copy
Copied to ClipboardError: Could not Copy
private static final java.security.PermissionCollection
    noPermissions = new java.security.Permissions();
private static final AccessControlContext noPermissionsAcc =
    new AccessControlContext(
        new ProtectionDomain[] {
            new ProtectionDomain(null, noPermissions)
        }
    );

void someMethod(PrivilegedAction<Void> action) {
    AccessController.doPrivileged(new PrivilegedAction<Void>() {
        public Void run() {
            // ... context has no permissions ...
            return null;
        }
    }, noPermissionsAcc);
}
Copy



        +--------------------------------+
        | ActionImpl                     |
        |   .run                         |
        +--------------------------------+
        |                                |
        | noPermissionsAcc               |
        + - - - - - - - - - - - - - - - -+
        | java.security.AccessController |
        |   .doPrivileged                |
        +--------------------------------+
        | SomeClass                      |
        |   .someMethod                  |
        +--------------------------------+
        |  OtherClass                    |
        |    .otherMethod                |
        +--------------------------------+
        |                                |



An intermediate situation is possible where only a limited set of permissions is granted. If the permissions are checked in the current context before being supplied to doPrivileged, permissions may be reduced without the risk of privilege elevation. This enables the use of the principle of least privilege:

Copy
Copied to ClipboardError: Could not Copy
private static void doWithFile(final Runnable task,
                               String knownPath) {
    Permission perm = new java.io.FilePermission(knownPath,
                                                 "read,write");

    // Ensure context already has permission,
    //   so privileges are not elevate.
    AccessController.checkPermission(perm);

    // Execute task with the single permission only.
    PermissionCollection perms = perm.newPermissionCollection();
    perms.add(perm);
    AccessController.doPrivileged(new PrivilegedAction<Void>() {
        public Void run() {
            task.run();
            return null;
        }},
        new AccessControlContext(
            new ProtectionDomain[] {
                new ProtectionDomain(null, perms)
            }
        )
    );
}
When granting permission to a directory, extreme care must be taken to ensure that the access does not have unintended consequences. Files or subdirectories could have insecure permissions, or filesystem objects could provide additional access outside of the directory (e.g. symbolic links, loop devices, network mounts/shares, etc.). It is important to consider this when granting file permissions via a security policy or AccessController.doPrivileged block, as well as for less obvious cases (e.g. classes can be granted read permission to the directory from which they were loaded).

Applications should utilize dedicated directories for code as well as for other filesystem use, and should ensure that secure permissions are applied. Running code from or granting access to shared/common directories (including access via symbolic links) should be avoided whenever possible. As a second line of defense, using Files.setPosixFilePermissions can help to control low-level modifications of the involved files and directories. It is also recommended to configure file permission checking to be as strict and secure as possible [21].

A limited doPrivileged approach was also added in Java 8. This approach allows code to assert a subset of its privileges while still allowing a full access-control stack walk to check for other permissions. If a check is made for one of the asserted permissions, then the stack check will stop at the doPrivileged invocation. For other permission checks, the stack check continues past the doPrivileged invocation. This differs from the previously discussed approach, which will always stop at the doPrivileged invocation.

Consider the following example:

Copy
Copied to ClipboardError: Could not Copy
private static void doWithURL(final Runnable task,
                                          String knownURL) {
    URLPermission urlPerm = new URLPermission(knownURL);
    AccessController.doPrivileged(
                            new PrivilegedAction<Void>() {                 
        public Void run() {                     
            task.run();                     
            return null;                 
        }},
        someContext,              
        urlPerm             
    );  
}
If a permission check matching the URLPermission is performed during the execution of task, then the stack check will stop at doWithURL. However, if a permission check is performed that does not match the URLPermission then the stack check will continue to walk the stack.

As with other versions of doPrivileged, the context argument can be null with the limited doPrivileged methods, which results in no additional restrictions being applied.


Guideline 9-5 / ACCESS-5: Be careful caching results of potentially privileged operations
NOTE: The security manager has been permanently disabled since Java 24, so this guideline is only applicable to earlier releases3.

A cached result must never be passed to a context that does not have the relevant permissions to generate it. Therefore, ensure that the result is generated in a context that has no more permissions than any context it is returned to. Because calculation of privileges may contain errors, use the AccessController API to enforce the constraint.

Copy
Copied to ClipboardError: Could not Copy
private static final Map cache;

public static Thing getThing(String key) {
    // Try cache.
    CacheEntry entry = cache.get(key);
    if (entry != null) {
        // Ensure we have required permissions before returning
        //   cached result.
        AccessController.checkPermission(entry.getPermission());
        return entry.getValue();
    }

    // Ensure we do not elevate privileges (per <a href="#9-2">Guideline 9-2</a>).
    Permission perm = getPermission(key);
    AccessController.checkPermission(perm);

    // Create new value with exact privileges.
    PermissionCollection perms = perm.newPermissionCollection();
    perms.add(perm);
    Thing value = AccessController.doPrivileged(
        new PrivilegedAction<Thing>() { public Thing run() {
            return createThing(key);
        }},
        new AccessControlContext(
            new ProtectionDomain[] {
                new ProtectionDomain(null, perms)
            }
        )
    );
    cache.put(key, new CacheEntry(value, perm));

    return value;
}

Guideline 9-6 / ACCESS-6: Understand how to transfer context
NOTE: The security manager has been permanently disabled since Java 24, so this guideline is only applicable to earlier releases3.

It is often useful to store an access control context for later use. For example, one may decide it is appropriate to provide access to callback instances that perform privileged operations, but invoke callback methods in the context that the callback object was registered. The context may be restored later on in the same thread or in a different thread. A particular context may be restored multiple times and even after the original thread has exited.

AccessController.getContext returns the current context. The two-argument forms of AccessController.doPrivileged can then replace the current context with the stored context for the duration of an action.

Copy
Copied to ClipboardError: Could not Copy
package xx.lib;

public class Reactor {
    public void addHandler(Handler handler) {
        handlers.add(new HandlerEntry(
                handler, AccessController.getContext()
        ));
    }
    private void fire(final Handler handler,
                      AccessControlContext acc) {
        if (acc == null) {
            throw new SecurityException(
                          "Missing AccessControlContext");
        }
        AccessController.doPrivileged(
            new PrivilegedAction<Void>() {
                public Void run() {
                    handler.handle();
                    return null;
                }
            }, acc);
     }
     // ...
}
Copy



                                         +--------------------------------+
                                         | xx.lib.FileHandler             |
                                         |   handle()                     |
                                         +--------------------------------+
                                         | xx.lib.Reactor.(anonymous)     |
                                         |   run()                        |
+--------------------------------+ \     +--------------------------------+
| java.security.AccessController |  `    |                                |
|   .getContext()                |  +--> | acc                            |
+--------------------------------+  |    + - - - - - - - - - - - - - - - -+
| xx.lib.Reactor                 |  |    | java.security.AccessController |
|   .addHandler(Handler)         |  |    |   .doPrivileged(handler, acc)  |
+--------------------------------+  |    +--------------------------------+
| yy.app.App                     |  |    | xx.lib.Reactor                 |
|   .main(String[] args)         |  ,    |   .fire                        |
+--------------------------------+ /     +--------------------------------+
                                         | xx.lib.Reactor                 |
                                         | .run                           |
                                         +--------------------------------+
                                         |                                |


Guideline 9-7 / ACCESS-7: Understand how thread construction transfers context
NOTE: The security manager has been permanently disabled since Java 24, so this guideline is only applicable to earlier releases3.

Newly constructed threads are executed with the access control context that was present when the Thread object was constructed. In order to prevent bypassing this context, void run() of untrusted objects should not be executed with inappropriate privileges.


Guideline 9-8 / ACCESS-8: Safely invoke standard APIs that bypass SecurityManager checks depending on the immediate caller's class loader
NOTE: The security manager has been permanently disabled since Java 24, so this guideline is only applicable to earlier releases3.

Certain standard APIs in the core libraries of the Java runtime enforce SecurityManager checks but allow those checks to be bypassed depending on the immediate caller's class loader. When the java.lang.Class.newInstance method is invoked on a Class object, for example, the immediate caller's class loader is compared to the Class object's class loader. If the caller's class loader is an ancestor of (or the same as) the Class object's class loader, the newInstance method bypasses a SecurityManager check. (See Section 4.3.2 in [1] for information on class loader relationships). Otherwise, the relevant SecurityManager check is enforced.

The difference between this class loader comparison and a SecurityManager check is noteworthy. A SecurityManager check investigates all callers in the current execution chain to ensure each has been granted the requisite security permission. (If AccessController.doPrivileged was invoked in the chain, all callers leading back to the caller of doPrivileged are checked.) In contrast, the class loader comparison only investigates the immediate caller's context (its class loader). This means any caller who invokes Class.newInstance and who has the capability to pass the class loader check--thereby bypassing the SecurityManager--effectively performs the invocation inside an implicit AccessController.doPrivileged action. Because of this subtlety, callers should ensure that they do not inadvertently invoke Class.newInstance on behalf of untrusted code.

Copy
Copied to ClipboardError: Could not Copy
package yy.app;

class AppClass {
   OtherClass appMethod() throws Exception {
       return OtherClass.class.newInstance();
   }
}
Copy



        +--------------------------------+
        | xx.lib.LibClass                |
        |   .LibClass                    |
        +--------------------------------+
        | java.lang.Class                |
        |   .newInstance                 |
        +--------------------------------+
        | yy.app.AppClass                |<-- AppClass.class.getClassLoader
        |   .appMethod                   |       determines check
        +--------------------------------+
        |                                |

Code has full access to its own class loader and any class loader that is a descendant. In the case of Class.newInstance access to a class loader implies access to classes in restricted packages (e.g., system classes prefixed with sun.).

In the diagram below, classes loaded by B have access to B and its descendants C, E, and D. Other class loaders, shown in grey strikeout font, are subject to security checks.

Copy



        +-------------------------+
        |    bootstrap loader     | <--- null
        +-------------------------+
                 ^              ^
        +------------------+  +---+
        | extension loader |  | A |
        +------------------+  +---+
                 ^
        +------------------+
        |  system loader   | <--- Class.getSystemClassLoader()
        +------------------+
             ^           ^
        +----------+   +---+
        |    B     |   | F |
        +----------+   +---+
           ^      ^       ^
        +---+  +---+   +---+
        | C |  | E |   | G |                
        +---+  +---+   +---+
          ^
        +---+
        | D |
        +---+

The following methods behave similar to Class.newInstance, and potentially bypass SecurityManager checks depending on the immediate caller's class loader:

Copy
Copied to ClipboardError: Could not Copy
java.io.ObjectStreamField.getType
java.io.ObjectStreamClass.forClass
java.lang.Class.newInstance (deprecated)
java.lang.Class.getClassLoader
java.lang.Class.getClasses
java.lang.Class.getField(s)
java.lang.Class.getMethod(s)
java.lang.Class.getConstructor(s)
java.lang.Class.getDeclaredClasses
java.lang.Class.getDeclaredField(s)
java.lang.Class.getDeclaredMethod(s)
java.lang.Class.getDeclaredConstructor(s)
java.lang.Class.getDeclaringClass
java.lang.Class.getEnclosingMethod
java.lang.Class.getEnclosingClass
java.lang.Class.getEnclosingConstructor
java.lang.Class.getNestHost
java.lang.Class.getNestMembers
java.lang.ClassLoader.getParent
java.lang.ClassLoader.getPlatformClassLoader
java.lang.ClassLoader.getSystemClassLoader
java.lang.StackWalker.forEach
java.lang.StackWalker.getCallerClass
java.lang.StackWalker.walk
java.lang.foreign.SymbolLookup.loaderLookup
java.lang.invoke.MethodHandleProxies.asInterfaceInstance
java.lang.reflect.Proxy.getInvocationHandler
java.lang.reflect.Proxy.getProxyClass (deprecated)
java.lang.reflect.Proxy.newProxyInstance
java.lang.Thread.getContextClassLoader
javax.sql.rowset.serial.SerialJavaObject.getFields
Methods such as these that vary their behavior according to the immediate caller's class are considered to be caller-sensitive, and should be annotated in code with the @CallerSensitive annotation [16]. Due to the security implications described here and in subsequent guidelines, making a method caller-sensitive should be avoided whenever possible.

Refrain from invoking the above methods on Class, ClassLoader, or Thread instances that are received from untrusted code. If the respective instances were acquired safely (or in the case of the static ClassLoader.getSystemClassLoader method), do not invoke the above methods using inputs provided by untrusted code. Also, do not propagate objects that are returned by the above methods back to untrusted code.


Guideline 9-9 / ACCESS-9: Safely invoke standard APIs that perform tasks using the immediate caller's class loader instance
NOTE: The security manager has been permanently disabled since Java 24, so this guideline is only applicable to earlier releases3.

The following static methods perform tasks using the immediate caller's class loader:

Copy
Copied to ClipboardError: Could not Copy
java.lang.Class.forName
java.lang.ClassLoader.getPlatformClassLoader
java.lang.Package.getPackage(s) (deprecated)
java.lang.Runtime.load
java.lang.Runtime.loadLibrary
java.lang.System.load
java.lang.System.loadLibrary
java.sql.DriverManager.deregisterDriver     
java.sql.DriverManager.getConnection
java.sql.DriverManager.getDriver(s)
java.security.AccessController.doPrivileged* (deprecated)
java.util.logging.Logger.getAnonymousLogger
java.util.logging.Logger.getLogger
java.util.ResourceBundle.getBundle
Methods such as these that vary their behavior according to the immediate caller's class are considered to be caller-sensitive, and should be annotated in code with the @CallerSensitive annotation [16].

For example, System.loadLibrary("/com/foo/MyLib.so") uses the immediate caller's class loader to find and load the specified library. (Loading libraries enables a caller to make native method invocations.) Do not invoke this method on behalf of untrusted code, since untrusted code may not have the ability to load the same library using its own class loader instance. Do not invoke any of these methods using inputs provided by untrusted code, and do not propagate objects that are returned by these methods back to untrusted code.

Guideline 9-10 / ACCESS-10: Be aware of standard APIs that perform Java language access checks against the immediate caller
NOTE: The security manager has been permanently disabled since Java 24, so this guideline is only applicable to earlier releases3.

When an object accesses fields or methods of another object, the JVM performs access control checks to assert the valid visibility of the target method or field. For example, it prevents objects from invoking private methods in other objects.

Code may also call standard APIs (primarily in the java.lang.reflect package) to reflectively access fields or methods in another object. The following reflection-based APIs mirror the language checks that are enforced by the virtual machine:

Copy
Copied to ClipboardError: Could not Copy
java.lang.Class.newInstance (deprecated)
java.lang.invoke.MethodHandles.lookup 
java.lang.reflect.AccessibleObject.canAccess
java.lang.reflect.AccessibleObject.setAccessible
java.lang.reflect.AccessibleObject.tryAccessible
java.lang.reflect.Constructor.newInstance
java.lang.reflect.Constructor.setAccessible
java.lang.reflect.Field.get*
java.lang.reflect.Field.set*
java.lang.reflect.Method.invoke
java.lang.reflect.Method.setAccessible
java.util.concurrent.atomic.AtomicIntegerFieldUpdater.newUpdater
java.util.concurrent.atomic.AtomicLongFieldUpdater.newUpdater
java.util.concurrent.atomic.AtomicReferenceFieldUpdater.newUpdater
Methods such as these that vary their behavior according to the immediate caller's class are considered to be caller-sensitive, and should be annotated in code with the @CallerSensitive annotation [16].

Language checks are performed solely against the immediate caller, not against each caller in the execution sequence. Because the immediate caller may have capabilities that other code lacks (it may belong to a particular package and therefore have access to its package-private members), do not invoke the above APIs on behalf of untrusted code. Specifically, do not invoke the above methods on Class, Constructor, Field, or Method instances that are received from untrusted code. If the respective instances were acquired safely, do not invoke the above methods using inputs that are provided by untrusted code. Also, do not propagate objects that are returned by the above methods back to untrusted code.

Guideline 9-11 / ACCESS-11: Be aware java.lang.reflect.Method.invoke is ignored for checking the immediate caller
NOTE: The security manager has been permanently disabled since Java 24, so this guideline is only applicable to earlier releases3.

Consider:

Copy
Copied to ClipboardError: Could not Copy
package xx.lib;

class LibClass {
    void libMethod(
        PrivilegedAction action
    ) throws Exception {
        Method doPrivilegedMethod =
            AccessController.class.getMethod(
                "doPrivileged", PrivilegedAction.class
            );
        doPrivilegedMethod.invoke(null, action);
    }
}
If Method.invoke was taken as the immediate caller, then the action would be performed with all permissions. So, for the methods discussed in Guidelines 9-8 through 9-10, the Method.invoke implementation is ignored when determining the immediate caller.

Copy



        +--------------------------------+
        | action                         |
        |   .run                         |
        +--------------------------------+
        | java.security.AccessController |
        |   .doPrivileged                |
        +--------------------------------+
        | java.lang.reflect.Method       |
        |    .invoke                     |
        +--------------------------------+
        | xx.lib.LibClass                | <--- Effective caller
        |   .libMethod                   |
        +--------------------------------+
        |                                |

Therefore, avoid Method.invoke.

Guideline 9-12 / ACCESS-12: Avoid using caller-sensitive method names in interface classes
NOTE: The security manager has been permanently disabled since Java 24, so this guideline is only applicable to earlier releases3.

When designing an interface class, one should avoid using methods with the same name and signature of caller-sensitive methods, such as those listed in Guidelines 9-8, 9-9, and 9-10. In particular, avoid calling these from default methods on an interface class.

Guideline 9-13 / ACCESS-13: Avoid returning the results of privileged operations
NOTE: The security manager has been permanently disabled since Java 24, so this guideline is only applicable to earlier releases3.

Care should be taken when designing lambdas which are to be returned to untrusted code; especially ones that include security-related operations. Without proper precautions, e.g., input and output validation, untrusted code may be able to leverage the privileges of a lambda inappropriately.

Similarly, care should be taken before returning Method objects, MethodHandle objects, MethodHandles.Lookup objects, VarHandle objects, and StackWalker objects (depends on options used at creation time) to untrusted code. These objects have checks for language access and/or privileges inherent in their creation and incautious distribution may allow untrusted code to bypass private / protected access restrictions as well as restricted package access. If one returns a Method or MethodHandle object that an untrusted user would not normally have access to, then a careful analysis is required to ensure that the object does not convey undesirable capabilities. Similarly, MethodHandles.Lookup objects have different capabilities depending on who created them.  For example, in Java SE 15 the Lookup objects can now inject hidden classes into the class / nest the Lookup came from. If untrusted code has access to Reference objects and their referents, then the relationship between the two types might be inferred. It is important to understand the access granted by any such object before it is returned to untrusted code.

Guideline 9-14 / ACCESS-14: Safely invoke standard APIs that perform tasks using the immediate caller's module
NOTE: The security manager has been permanently disabled since Java 24, so this guideline is only applicable to earlier releases3.

The following static methods perform tasks using the immediate caller's Module:

Copy
Copied to ClipboardError: Could not Copy
java.lang.System.getLogger
java.lang.Class.forName(Module,String)
java.lang.Class.getResourceAsStream
java.lang.Class.getResource
java.lang.Module.addExports
java.lang.Module.addOpens
java.lang.Module.addReads
java.lang.Module.addUses
java.lang.Module.getResourceAsStream
java.lang.Module.getResource
java.lang.invoke.MethodHandles.privateLookupIn
java.util.ResourceBundle.getBundle
java.util.ServiceLoader.load
java.util.ServiceLoader.loadInstalled
java.util.logging.Logger.getAnonymousLogger
Methods such as these that vary their behavior according to the immediate caller's class are considered to be caller-sensitive, and should be annotated in code with the @CallerSensitive annotation [16].

For example, Module::addExports uses the immediate caller's Module to decide if a package should be exported. Do not invoke these methods on behalf of untrusted code, since untrusted code may not have the ability to make the same change.

Do not invoke any of these methods using inputs provided by untrusted code, and do not propagate objects that are returned by these methods back to untrusted code.

Guideline 9-15 / ACCESS-15: Design and use InvocationHandlers conservatively
NOTE: The security manager has been permanently disabled since Java 24, so this guideline is only applicable to earlier releases3.

When creating a java.lang.reflect.Proxy instance, a class that implements java.lang.reflect.InvocationHandler is required to handle the delegation of the methods on the Proxy instance. The InvocationHandler is assumed to have the permissions of the code that created the Proxy. Thus, access to InvocationHandlers should not be generally available.

InvocationHandlers should also validate the method names they are asked to invoke to prevent the InvocationHandler from being used for a purpose for which it was not intended. For example:

Copy
Copied to ClipboardError: Could not Copy
public Object invoke(Object proxy, Method method, Object[] args)
                                                  throws Throwable {
    if (! Proxy.isProxyClass(proxy.getClass())) {
        throw new IllegalArgumentException("not a proxy");
    }

    if (Proxy.getInvocationHandler(proxy) != this) {
        throw new IllegalArgumentException("handler mismatch");
    }

    String methodName = method.getName();
    Class<!--?-->[] paramTypes = method.getParameterTypes();
    int paramsLen = paramTypes.length;

    if ( methodName.equals("hashCode") && paramsLen == 0 ) {
        // handle hashCode here
        return true;
    } else ...
        // equals, toString
        // ignore clone, finalize
    } else ...
        // check for methods expected on interfaces implemented
        // method name, number of parameters and types
    }
}
Guideline 9-16 / ACCESS-16: Limit package accessibility with package.access
NOTE: The security manager has been permanently disabled since Java 24, so this guideline is only applicable to earlier releases3.

The original content of this guideline that covers limiting package accessibility with modules can be found in 4-2.

Containers (meaning code that manages code with a lower level of trust, as described in Guideline 9-17) may hide implementation code by adding to the package.access security property. This property prevents untrusted classes from other class loaders linking and using reflection on the specified package hierarchy. Care must be taken to ensure that packages cannot be accessed by untrusted contexts before this property has been set.

This example code demonstrates how to append to the package.access security property. Note that it is not thread-safe. This code should generally only appear once in a system.

Copy
Copied to ClipboardError: Could not Copy
private static final String PACKAGE_ACCESS_KEY = "package.access";
static {
    String packageAccess = java.security.Security.getProperty(
        PACKAGE_ACCESS_KEY
    );
    java.security.Security.setProperty(
        PACKAGE_ACCESS_KEY,
        (
            (packageAccess == null ||
             packageAccess.trim().isEmpty()) ?
            "" :
            (packageAccess + ",")
        ) +
        "xx.example.product.implementation."
    );
}

Guideline 9-17 / ACCESS-17: Isolate unrelated code
NOTE: The security manager has been permanently disabled since Java 24, so this guideline is only applicable to earlier releases3.

Containers, that is to say code that manages code with a lower level of trust, should isolate unrelated application code. Even otherwise untrusted code is typically given permissions to access its origin, and therefore untrusted code from different origins should be isolated. The Java Plugin, for example, loads unrelated applets into separate class loader instances and runs them in separate thread groups.1

Although there may be security checks on direct accesses, there are indirect ways of using the system class loader and thread context class loader. Programs should be written with the expectation that the system class loader is accessible everywhere and the thread context class loader is accessible to all code that can execute on the relevant threads.

Some apparently global objects are actually local to applet1 or application contexts. Applets loaded from different web sites will have different values returned from, for example, java.awt.Frame.getFrames. Such static methods (and methods on true globals) use information from the current thread and the class loaders of code on the stack to determine which is the current context. This prevents malicious applets from interfering with applets from other sites.

Library code can be carefully written such that it is safely usable by less trusted code. Libraries require a level of trust at least equal to the code it is used by in order not to violate the integrity of the client code. Containers should ensure that less trusted code is not able to replace more trusted library code and does not have package-private access. Both restrictions are typically enforced by using a separate class loader instance, the library class loader a parent of the application class loader.

Mutable statics (see Guideline 6-11) and exceptions are common ways that isolation is inadvertently breached. Mutable statics allow any code to interfere with code that directly or, more likely, indirectly uses them.

When a security manager is in place, some mutable statics require a security permission to update state. The updated value will be visible globally. Therefore mutation should be done with extreme care. Methods that update global state or provide a capability to do so, with a security check, include:

Copy
Copied to ClipboardError: Could not Copy
java.lang.ClassLoader.getSystemClassLoader
java.lang.System.clearProperty
java.lang.System.getProperties
java.lang.System.setErr
java.lang.System.setIn
java.lang.System.setOut
java.lang.System.setProperties
java.lang.System.setProperty
java.lang.System.setSecurityManager
java.lang.Thread.setDefaultUncaughtExceptionHandler
java.net.Authenticator.setDefault
java.net.CookieHandler.getDefault
java.net.CookieHandler.setDefault
java.net.Datagram.setDatagramSocketImplFactory
java.net.HttpURLConnection.setFollowRedirects
java.net.ProxySelector.setDefault
java.net.ResponseCache.getDefault
java.net.ResponseCache.setDefault
java.net.ServerSocket.setSocketFactory (deprecated)
java.net.Socket.setSocketImplFactory (deprecated)
java.net.URL.setURLStreamHandlerFactory
java.net.URLConnection.setContentHandlerFactory
java.net.URLConnection.setFileNameMap
java.rmi.server.RMISocketFactory.setFailureHandler
java.rmi.server.RMISocketFactory.setSocketFactory
java.rmi.activation.ActivationGroup.createGroup  (deprecated)
java.rmi.activation.ActivationGroup.setSystem (deprecated)
java.rmi.server.RMIClassLoader.getDefaultProviderInstance
java.security.Policy.setPolicy (deprecated)
java.sql.DriverManager.deregisterDriver
java.sql.DriverManager.setLogStream (deprecated)
java.sql.DriverManager.setLogWriter
java.util.Locale.setDefault
java.util.TimeZone.setDefault
javax.naming.spi.NamingManager.setInitialContextFactoryBuilder
javax.naming.spi.NamingManager.setObjectFactoryBuilder
javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier
javax.net.ssl.HttpsURLConnection.setDefaultSSLSocketFactory
javax.net.ssl.SSLContext.setDefault
javax.security.auth.login.Configuration.setConfiguration
javax.security.auth.login.Policy.setPolicy
javax.sql.rowset.spi.SyncFactory.setJNDIContext
javax.sql.rowset.spi.SyncFactory.setLogger
Java PlugIn and Java WebStart isolate certain global state within an AppContext1. Often no security permissions are necessary to access this state, so it cannot be trusted (other than for Same Origin Policy within PlugIn and WebStart). While there are security checks, the state is still intended to remain within the context. Objects retrieved directly or indirectly from the AppContext should therefore not be stored in other variations of globals, such as plain statics of classes in a shared class loader. Any library code directly or indirectly using AppContext on behalf of an application should be clearly documented. Users of AppContext include:

Copy
Copied to ClipboardError: Could not Copy
Extensively within AWT
Extensively within Swing
Extensively within JavaBeans Long Term Persistence
java.beans.Beans.setDesignTime
java.beans.Beans.setGuiAvailable
java.beans.Introspector.getBeanInfo
java.beans.PropertyEditorFinder.registerEditor
java.beans.PropertyEditorFinder.setEdiorSearchPath
javax.imageio.ImageIO.createImageInputStream
javax.imageio.ImageIO.createImageOutputStream
javax.imageio.ImageIO.getUseCache
javax.imageio.ImageIO.setCacheDirectory
javax.imageio.ImageIO.setUseCache
javax.print.StreamPrintServiceFactory.lookupStreamPrintServices
javax.print.PrintServiceLookup.lookupDefaultPrintService
javax.print.PrintServiceLookup.lookupMultiDocPrintServices
javax.print.PrintServiceLookup.lookupPrintServices
javax.print.PrintServiceLookup.registerService
javax.print.PrintServiceLookup.registerServiceProvider

Guideline 9-18 / ACCESS-18: Prevent the unauthorized construction of sensitive classes
NOTE: The security manager has been permanently disabled since Java 24, so this guideline is only applicable to earlier releases3.

Where an existing API exposes a security-sensitive constructor, limit the ability to create instances. A security-sensitive class enables callers to modify or circumvent SecurityManager access controls. Any instance of ClassLoader, for example, has the power to define classes with arbitrary security permissions.

To restrict untrusted code from instantiating a class, enforce a SecurityManager check at all points where that class can be instantiated. In particular, enforce a check at the beginning of each public and protected constructor. In classes that declare public static factory methods in place of constructors, enforce checks at the beginning of each factory method. Also enforce checks at points where an instance of a class can be created without the use of a constructor. Specifically, enforce a check inside the readObject or readObjectNoData method of a serializable class, and inside the clone method of a cloneable class.

If the security-sensitive class is non-final, this guideline not only blocks the direct instantiation of that class, it blocks unsafe or malicious subclassing as well.


Guideline 9-19 / ACCESS-19: Defend against partially initialized instances of non-final classes
NOTE: The security manager has been permanently disabled since Java 24, so this guideline is only applicable to earlier releases3.

When a constructor in a non-final class throws an exception, attackers can attempt to gain access to partially initialized instances of that class. Ensure that a non-final class remains totally unusable until its constructor completes successfully.

From JDK 6 on, construction of a subclassable class can be prevented by throwing an exception before the Object constructor completes. To do this, perform the checks in an expression that is evaluated in a call to this() or super().

Copy
Copied to ClipboardError: Could not Copy
// non-final java.lang.ClassLoader
public abstract class ClassLoader {
    protected ClassLoader() {
        this(securityManagerCheck());
    }
    private ClassLoader(Void ignored) {
        // ... continue initialization ...
    }
    private static Void securityManagerCheck() {
        SecurityManager security = System.getSecurityManager();
        if (security != null) {
            security.checkCreateClassLoader();
        }
        return null;
    }
}
For compatibility with older releases, a potential solution involves the use of an initialized flag. Set the flag as the last operation in a constructor before returning successfully. All methods providing a gateway to sensitive operations must first consult the flag before proceeding:

Copy
Copied to ClipboardError: Could not Copy
public abstract class ClassLoader {

    private volatile boolean initialized;

    protected ClassLoader() {
        // permission needed to create ClassLoader
        securityManagerCheck();
        init();

        // Last action of constructor.
        this.initialized = true;
    }
    protected final Class defineClass(...) {
        checkInitialized();

        // regular logic follows
        //  ...
    }

    private void checkInitialized() {
        if (!initialized) {
            throw new SecurityException(
                "NonFinal not initialized"
            );
        }
    }
}
Furthermore, any security-sensitive uses of such classes should check the state of the initialization flag. In the case of ClassLoader construction, it should check that its parent class loader is initialized.

Partially initialized instances of a non-final class can be accessed via a finalizer attack. The attacker overrides the protected finalize method in a subclass and attempts to create a new instance of that subclass. This attempt fails (in the above example, the SecurityManager check in ClassLoader's constructor throws a security exception), but the attacker simply ignores any exception and waits for the virtual machine to perform finalization on the partially initialized object. When that occurs the malicious finalize method implementation is invoked, giving the attacker access to this, a reference to the object being finalized. Although the object is only partially initialized, the attacker can still invoke methods on it, thereby circumventing the SecurityManager check. While the initialized flag does not prevent access to the partially initialized object, it does prevent methods on that object from doing anything useful for the attacker.

Use of an initialized flag, while secure, can be cumbersome. Simply ensuring that all fields in a public non-final class contain a safe value (such as null) until object initialization completes successfully can represent a reasonable alternative in classes that are not security-sensitive.

A more robust, but also more verbose, approach is to use a "pointer to implementation" (or "pimpl"). The core of the class is moved into a non-public class with the interface class forwarding method calls. Any attempts to use the class before it is fully initialized will result in a NullPointerException. This approach is also good for dealing with clone and deserialization attacks.

Copy
Copied to ClipboardError: Could not Copy
public abstract class ClassLoader {

    private final ClassLoaderImpl impl;

    protected ClassLoader() {
        this.impl = new ClassLoaderImpl();
    }
    protected final Class defineClass(...) {
        return impl.defineClass(...);
    }
}

/* pp */ class ClassLoaderImpl {
    /* pp */ ClassLoaderImpl() {
        // permission needed to create ClassLoader
        securityManagerCheck();
        init();
    }

    /* pp */ Class defineClass(...) {
        // regular logic follows
        // ...
    }
}

Guideline 9-20 / ACCESS-20: Understand the security permissions given to serialization and deserialization
NOTE: The security manager has been permanently disabled since Java 24, so this guideline is only applicable to earlier releases3.

When a security manager is in place, permissions appropriate for deserialization should be carefully checked. Additionally, deserialization of untrusted data should generally be avoided whenever possible (regardless of whether a security manager is in place).

Serialization with full permissions allows permission checks in writeObject methods to be circumvented. For instance, java.security.GuardedObject checks the guard before serializing the target object. With full permissions, this guard can be circumvented and the data from the object (although not the object itself) made available to the attacker.

Deserialization is more significant. A number of readObject implementations attempt to make security checks, which will pass if full permissions are granted. Further, some non-serializable security-sensitive, subclassable classes have no-argument constructors, for instance ClassLoader. Consider a malicious serializable class that subclasses ClassLoader. During deserialization the serialization method calls the constructor itself and then runs any readObject in the subclass. When the ClassLoader constructor is called no unprivileged code is on the stack, hence security checks will pass. Thus, don't deserialize with permissions unsuitable for the data. Instead, data should be deserialized with the least necessary privileges.