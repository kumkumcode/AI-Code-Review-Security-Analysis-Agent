Guideline 7-1 / OBJECT-1: Avoid exposing constructors of sensitive classes
Construction of classes can be more carefully controlled if constructors are not exposed. Define static factory methods instead of public constructors. Support extensibility through delegation rather than inheritance. Implicit constructors through serialization and clone should also be avoided.


Guideline 7-2 / OBJECT-2: Prevent the unauthorized construction of sensitive classes
This guideline has been moved to 9-18.


Guideline 7-3 / OBJECT-3: Defend against partially initialized instances of non-final classes
The original content of this guideline has been moved to 9-19.

Ensure that a non-final class remains totally unusable until it is successfully initialized and its constructor completes successfully. Use of an object before it was successfully initialized (e.g., via a leaked reference to this) can lead to unexpected results.

Furthermore, any security-sensitive uses of such classes should check the state of initialization before use.


Guideline 7-4 / OBJECT-4: Prevent constructors from calling methods that can be overridden
Constructors that call overridable methods may leak a reference to this (the object being constructed) before the object has been fully initialized. Likewise, clone, readObject, or readObjectNoData methods that call overridable methods may do the same. The readObject methods will usually call java.io.ObjectInputStream.defaultReadObject, which is an overridable method.


Guideline 7-5 / OBJECT-5: Defend against cloning of non-final classes
A non-final class may be subclassed by a class that also implements java.lang.Cloneable. The result is that the base class can be unexpectedly cloned, although only for instances created by an adversary. The clone will be a shallow copy. The twins will share referenced objects but have different fields and separate intrinsic locks. The "pointer to implementation" approach detailed in Guideline 7-3 provides a good defense.

