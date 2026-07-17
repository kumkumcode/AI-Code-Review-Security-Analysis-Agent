# Milestone 1: System Architecture, Agent Responsibilities, and Technical Study Guide

This document serves as a comprehensive study and architectural guide for the AI Code Review & Security Analysis Agent. It outlines the foundational concepts of OWASP, secure coding, code smells, RAG pipelines, and details the multi-agent design of this system.

---

## Part 1: Educational Study Guide (Milestone 1, Item 1)

### 1. OWASP Vulnerability Standards
The Open Worldwide Application Security Project (OWASP) maintains the "OWASP Top 10," a globally recognized standard for the most critical web application security risks. In our code review system, we focus heavily on scanning for these key standards:

*   **A01:2021-Broken Access Control**: Occurs when restrictions on what authenticated users are allowed to do are not properly enforced. For example, allowing a guest user to view administrative records by simply changing a number in a web link.
*   **A03:2021-Injection (including SQLi & XSS)**: 
    *   *SQL Injection (SQLi)*: Happens when untrusted user input is directly mixed with database commands. A malicious actor can input special characters to trick the database into bypass login screens or deleting data.
    *   *Cross-Site Scripting (XSS)*: Occurs when an application includes untrusted data in a web page without proper validation or escaping, allowing hackers to execute malicious scripts in a victim's browser.
*   **A07:2021-Identification and Authentication Failures**: Weaknesses in how user identities are verified, such as permitting brute-force password attempts or hardcoding cryptographic keys and API secrets directly in the source code.

### 2. Secure Coding Guidelines
Secure coding is the practice of writing software in a way that guards against security vulnerabilities. Our knowledge base is built around several foundational secure coding pillars:
*   **Defense in Depth**: Relying on multiple layers of security (e.g., validating data on the screen, verifying it again on the server, and restricting database permissions) rather than a single security wall.
*   **Least Privilege**: Giving a program, user, or process only the absolute minimum permissions needed to complete its task.
*   **Input Validation & Output Encoding**: 
    *   *Input Validation*: Checking every piece of incoming data to make sure it matches expected formats (e.g., ensuring an age field only contains numbers).
    *   *Output Encoding*: Treating outputted user data as safe text rather than executable script before rendering it back to a screen.

### 3. Code Smell Patterns
Unlike security vulnerabilities, which are security exploits waiting to happen, "code smells" represent structural weaknesses in the code's design. They indicate that code might be difficult to maintain, prone to bugs when changed, or highly inefficient:
*   **Primitive Obsession**: Using basic, raw data types (like strings or integers) to represent complex concepts (like phone numbers or zip codes) instead of creating dedicated, protective objects.
*   **Mutable Defaults**: (Specific to languages like Python) Passing a changeable list or dictionary as a default value to a function. Because default arguments are built only once when the program starts, subsequent runs of the function will accidentally share and corrupt the same collection data.
*   **Unclosed Resources**: Leaving file connections, databases, or network streams open after using them, slowly exhausting the system's memory and crashing the server.

### 4. Retrieval-Augmented Generation (RAG) Architecture
A standard AI model only knows the general information it was trained on. Retrieval-Augmented Generation (RAG) solves this by giving the AI an "open-book exam":
1.  **Semantic Indexing**: We take thousands of pages of secure coding books, OWASP guides, and clean-code examples and convert them into math vectors (lists of numbers reflecting their conceptual meaning).
2.  **Vector Databases**: These math vectors are saved in a highly specialized, lightweight database (Chroma DB).
3.  **Context Injection**: When a developer submits code, the system searches Chroma DB for the exact secure-coding rules that match the developer's language and problems. It then pastes those rules directly into the AI's prompt as the "open book," guaranteeing highly accurate, untampered remediation instructions.

---

## Part 2: System Design & Orchestration (Milestone 1, Item 2)

### 1. Architectural Topology

Below is the structured data flow, showing how raw code moves from the developer's web browser, through our validation layer, out to specialized parallel agents, and back into a clean dashboard:

[ Developer Portal / Web UI ]
│
▼ (Submits Code File)
[ Syntax Validation Module ]
│
├── (If invalid) ──> [ Return Immediate Syntax Error Alert ]
│
▼ (If valid)
[ Multi-Agent Orchestration Hub ]
├───► [ Agent 1: Code Analysis Agent ] (Evaluates Code Smells)
├───► [ Agent 2: Security Agent ]      (Evaluates Security Risks)
│
▼ (Consolidation of Findings)
[ Agent 3: Remediation Agent ] <───(Retrieves Rules)───> [ Local Vector DB (Chroma) ]
│
▼ (Generates Explanations)
[ Agent 4: PR Summary Agent ]
│
▼ (Compiles Final Markdown Report)
[ Interactive Developer Dashboard ]
│
▼ (Asynchronous Websocket Channel)
[ Agent 5: Conversational Assistant ] (Answers user follow-up questions in real-time)

---

## 2. Comprehensive Agent Responsibility Matrix

Our system divides complex tasks among five highly focused AI agents. This separation of duties prevents information overload and ensures surgical accuracy:

| Agent Name | Dedicated Role | Primary Objectives | Analytical Scope |
| :--- | :--- | :--- | :--- |
| **Code Analysis Agent** | The Quality Specialist | Identify maintainability issues, excessive complexity, and structural bad habits. | Scans for high cyclomatic complexity, deeply nested loops, mutable default arguments, primitive obsession, and resource leaks. |
| **Security Agent** | The Penetration Tester | Scan for active, exploitable security holes violating safety standards. | Scans for raw SQL execution, unescaped browser outputs, insecure cryptographic libraries, hardcoded credentials, and missing authentication. |
| **Remediation Agent** | The Interactive Educator | Build a bridge between a discovered problem and its perfect solution using the local knowledge base. | Queries the semantic vector store using the finding context, extracts the proper clean-code template, and generates a structured side-by-side correction guide. |
| **PR Summary Agent** | The Executive Compiler | Synthesize high-density agent findings into an understandable, prioritized pull-request overview. | Aggregates all alerts, calculates an overall project safety grade, counts vulnerabilities by severity, and compiles a comprehensive Markdown report. |
| **Conversational Assistant** | The RAG Chat Coach | Provide interactive, direct support to the developer regarding the flagged problems. | Processes incoming user follow-up chat prompts, searches the vectorized database for supporting theory, and hosts a real-time discussion. |

---

## 3. Detailed Step-by-Step Orchestration Flow

To ensure high performance, our pipeline processes code in five highly organized, distinct phases:

1.  **Phase 1: Reception & Parsing**:
    *   The user pastes code or uploads a `.py` or `.java` file.
    *   The backend validates that the file compiles or is syntactically correct. If a user tries to submit an empty file or plain text instead of code, the system instantly rejects it with a friendly error message.
2.  **Phase 2: Parallel Inspection**:
    *   The code is simultaneously analyzed by both the **Code Analysis Agent** and the **Security Agent**.
    *   Running these two agents in parallel cuts review times in half.
3.  **Phase 3: Semantic Enrichment**:
    *   Each discovered issue is handed to the **Remediation Agent**.
    *   The agent uses the issue's keyword and programming language to query the Chroma Vector Database. It retrieves the appropriate educational "Code Triad" (Unoptimized -> Flawed -> Clean) to accompany the finding.
4.  **Phase 4: Synthesis**:
    *   The **PR Summary Agent** gathers all findings.
    *   It calculates a safety score (e.g., "A" to "F") and prints out a detailed review that resembles a standard developer's Pull Request page on GitHub.
5.  **Phase 5: Contextual Q&A Loop**:
    *   A conversation session is opened between the user and the **Conversational Assistant**.
    *   The assistant holds the active review context in memory, allowing the developer to ask general or highly specific questions about how to improve their security skills.   
 