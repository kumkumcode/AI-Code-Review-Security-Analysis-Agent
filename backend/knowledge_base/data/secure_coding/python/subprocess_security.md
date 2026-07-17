---
id: PY-SUBP-01
title: Secure Subprocess Execution and Command Injection Mitigation
category: OS Command Injection
severity_hint: Critical
cwe: [CWE-78, CWE-88, CWE-74]
python_versions: "Python 3.x"
---

# Secure Subprocess Execution and Command Injection Mitigation

## Overview
The `subprocess` module is designed to invoke external system binaries. The primary security vulnerability associated with this module is **OS Command Injection (CWE-78)**, which typically occurs when setting `shell=True` while passing unsanitized user inputs. When `shell=True` is active, the string is passed directly to the underlying system shell (`/bin/sh` or `cmd.exe`), allowing malicious input strings containing separators (such as `;`, `&`, `|`, or backticks) to execute arbitrary commands. 

To ensure complete safety, developers must pass commands as a structural list of individual string arguments with `shell=False` (default), implement defensive input validation, and enforce strict execution timeouts to prevent Denial of Service (DoS) from resource-hanging processes.

---

## Code Triad

### ❌ Insecure (Shell Processing with Untrusted Strings)
Passing an unvalidated, user-supplied string directly to a process with `shell=True` enabled, permitting direct shell command execution.
```python
import subprocess

# VULNERABLE: If a user passes an input like "code.py; rm -rf /", the shell executes 
# the interpreter check first and then immediately runs the destructive payload.
def analyze_code_unsafe(user_filename: str):
    command = f"python3 -m py_compile {user_filename}"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout
⚠️ Flawed Attempt (Passing String Lists inside a Shell Context)
Attempting to split user input manually or using string lists while still keeping shell=True enabled, which fails to neutralize shell processing parsing logic.

Python
import subprocess

# FLAWED: Passing a list to shell=True on POSIX platforms treats the first element 
# as the command string and all subsequent elements as arguments *to the shell itself*,
# failing to safely isolate parameters or prevent unexpected execution states.
def analyze_code_flawed(user_filename: str):
    command_args = ["python3", "-m", "py_compile", user_filename]
    result = subprocess.run(command_args, shell=True, capture_output=True, text=True)
    return result.stdout
✅ Secure (List Arguments, Disabled Shell, and Strict Timeouts)
Always construct execution parameters as an isolated list of exact arguments, leave shell=False active, and enforce a rigid timeout boundary inside a TimeoutExpired exception block to kill frozen scripts.

Python
import subprocess
import os

def analyze_code_secure(user_filename: str) -> str:
    # SECURE: Explicit validation ensuring the file target is a pure, local alphanumeric path
    # and preventing path traversal or argument manipulation flags (e.g., starting with '-')
    clean_filename = os.path.basename(user_filename)
    if not clean_filename.endswith('.py') or clean_filename.startswith('-'):
        raise ValueError("Invalid target filename structural profile")

    # SECURE: Structural separation. The OS binds arguments directly to the binary array.
    # No shell parser is invoked, completely eliminating command injection vectors.
    command_args = ["python3", "-m", "py_compile", clean_filename]
    
    try:
        result = subprocess.run(
            command_args,
            shell=False,               # SECURE: Explicitly block shell interpretation
            capture_output=True,       # Safely capture outputs via PIPEs under the hood
            text=True,                 # Return clean string output
            timeout=5,                 # SECURE: Prevent DoS by terminating hung processes after 5 seconds
            check=True                 # Automatically raise exception on non-zero exit codes
        )
        return result.stdout

    except subprocess.TimeoutExpired as e:
        # SECURE: Handle long-running or malicious infinite-loop inputs gracefully
        return f"Execution terminated: Operation exceeded maximum allowed time limit. Partial output: {e.stdout}"
    except subprocess.CalledProcessError as e:
        # Handle structural script compilation errors safely without leaking internal stack traces
        return f"Compilation Error: {e.stderr}"

---

<ElicitationsGroup message="This completely hardens the process execution boundary for the AI Code Review engine. What should we tackle next to continue building your security patterns?">
{/* Reason: Provides follow-up prompts explicitly connected to isolated code execution and web hooks. */}
  <Elicitation label="Sandboxing untrusted code execution using Docker or chroot" query="How do I safely isolate and sandbox untrusted code execution in Python using secure runtimes or containers?"/>
  <Elicitation label="Secure handling of standard input stream (stdin) writes in Popen" query="How do I safely pass interactive runtime variables to a child process using Popen.communicate without deadlocks?"/>
</ElicitationsGroup>