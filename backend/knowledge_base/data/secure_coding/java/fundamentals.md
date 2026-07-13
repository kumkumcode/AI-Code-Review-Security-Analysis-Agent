Guideline 0-0 / FUNDAMENTALS-0: Prefer to have obviously no flaws rather than no obvious flaws [8]
Creating secure code is not necessarily easy. Despite the unusually robust nature of Java, flaws can slip past with surprising ease. Design and write code that does not require clever logic to see that it is safe. Specifically, follow the guidelines in this document unless there is a very strong reason not to.


Guideline 0-1 / FUNDAMENTALS-1: Design APIs to avoid security concerns
It is better to design APIs with security in mind. Trying to retrofit security into an existing API is more difficult and error prone. For example, making a class final prevents a subclass from overriding methods in a way that could compromise security (Guideline 4-5).


Guideline 0-2 / FUNDAMENTALS-2: Avoid duplication
Duplication of code and data causes many problems. Both code and data tend not to be treated consistently when duplicated, e.g., changes may not be applied to all copies.


Guideline 0-3 / FUNDAMENTALS-3: Restrict privileges
Despite best efforts, not all coding flaws will be eliminated even in well reviewed code. However, if the code is operating with reduced privileges, then exploitation of any flaws is likely to be thwarted. The most extreme form of this is known as the principle of least privilege, where code is run with the least privileges required to function. Low-level mechanisms available from operating systems or containers can be used to restrict privileges. Separate processes (JVMs) should be used to isolate untrusted code from trusted code with sensitive information. Previous use of the security manager should be replaced with these stronger approaches.

Applications can also be decomposed into separate services or processes to help restrict privileges. These services or processes can be granted different capabilities and OS-level permissions or even run on separate machines. Components of the application that require special permissions can be run separately with elevated privileges. Components that interact with untrusted code, users, or data can also be restricted or isolated, running with lower privileges. Separating parts of the application that require elevated privileges or that are more exposed to security threats can help to reduce the impact of security issues.


Guideline 0-4 / FUNDAMENTALS-4: Establish trust boundaries
In order to ensure that a system is protected, it is necessary to establish trust boundaries. Data that crosses these boundaries should be sanitized and validated before use. Trust boundaries are also necessary to allow security audits to be performed efficiently. Code that ensures integrity of trust boundaries must itself be loaded in such a way that its own integrity is assured.

For instance, a web browser is outside of the system for a web server. Equally, a web server is outside of the system for a web browser. Therefore, web browser and server software should not rely upon the behavior of the other for security.

When auditing trust boundaries, there are some questions that should be kept in mind. Are the code and data used sufficiently trusted? Could a library be replaced with a malicious implementation? Is untrusted configuration data being used? Is code calling with lower privileges adequately protected against?


Guideline 0-5 / FUNDAMENTALS-5: Minimise the number of security checks
Java is primarily an object-capability language. Perform security checks at a few defined points and return an object (a capability) that client code retains so that no further checks are required. Note, however, that care must be taken by both the code performing the check and the caller to prevent the capability from being leaked to other code.


Guideline 0-6 / FUNDAMENTALS-6: Encapsulate
Allocate behaviors and provide succinct interfaces. Fields of objects should be private and accessors avoided. The interface of a method, class, package, and module should form a coherent set of behaviors, and no more.


Guideline 0-7 / FUNDAMENTALS-7: Document security-related information
API documentation should cover security-related information such as required permissions, security-related exceptions, caller sensitivity (see Guidelines 9-8 through 9-11 for additional on this topic), and any preconditions or postconditions that are relevant to security. Furthermore, APIs should clearly document which checked exceptions are thrown, and, in the event an API chooses to throw unchecked exceptions to indicate domain-specific error conditions, should also document these unchecked exceptions, so that callers may handle them if desired. Documenting this information in comments for a tool such as Javadoc can also help to ensure that it is kept up to date.


Guideline 0-8 / FUNDAMENTALS-8: Secure third-party code
Libraries, frameworks, and other third-party software can introduce security vulnerabilities and weaknesses, especially if they are not kept up to date. Security updates released by the author may take time to reach bundled applications, dependent libraries, or OS package management updates. Therefore, it is important to keep track of security updates for any third-party code being used, and make sure that the updates get applied in a timely manner. This includes both frameworks and libraries used by an application, as well as any dependencies of those libraries/frameworks. Dependency checking tools can help to reduce the effort required to perform these tasks, and can usually be integrated into the development and release process.

It is also important to understand the security model and best practices for third-party software. Identify secure configuration options, any security-related tasks performed by the code (e.g., cryptographic functions or serialization), and any security considerations for APIs being used. Understanding past security issues and attack patterns against the code can also help to use it in a more secure manner. For example, if past security issues have applied to certain functionality or configurations, avoiding those may help to minimize exposure.

Security considerations of third-party code should also be periodically revisited. In addition to applying security updates whenever they are released, more secure APIs or configuration options could be made available over time.