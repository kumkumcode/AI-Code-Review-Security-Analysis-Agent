---
id: PY-TEMP-01
title: Secure Temporary File and Directory Management
category: File System Security
severity_hint: High
cwe: [CWE-377, CWE-59, CWE-732]
python_versions: "Python 3.x"
---

# Secure Temporary File and Directory Management

## Overview
The `tempfile` module creates temporary files and directories that are automatically removed after use. When working on shared environments (like common Linux `/tmp` directories), creating temporary files using predictable names or insecure default permissions opens the application up to **Insecure Temporary File (CWE-377)** vulnerabilities, symlink attacks, and local data disclosure. 

Always utilize high-level APIs like `TemporaryFile`, `NamedTemporaryFile`, and `TemporaryDirectory` wrapped inside context managers (`with` statements) to guarantee unpredictable names, tight file permissions (`0o700`), and reliable cleanup.

---

## Code Triad

### ❌ Insecure (Predictable Names or Manual String Concatenation)
Using standard file creation methods with hardcoded or predictable strings inside public temporary directories, allowing other local processes to guess or pre-create the file.
```python
import os

# VULNERABLE: The filename is predictable and created using standard open(). 
# A malicious local user could pre-create this as a symlink pointing to a critical 
# system file, causing the application to overwrite it (Symlink Attack / CWE-59).
def write_temp_data_unsafe(payload: str):
    temp_path = "/tmp/my_app_temp_data.txt"
    with open(temp_path, "w") as f:
        f.write(payload)
    
    # VULNERABLE: If the application crashes before this line, the file is left behind permanently
    os.remove(temp_path)
⚠️ Flawed Attempt (Using mktemp or Missing Context Managers)
Using deprecated functions like tempfile.mktemp() or failing to wrap temporary files in context managers, which can leak file handles and leave data behind if an exception occurs.

Python
import tempfile

# FLAWED: tempfile.mktemp() is deprecated because it only returns a file path string.
# A race condition exists between the time the path is returned and the time the file is opened.
def process_data_flawed(payload: str):
    temp_path = tempfile.mktemp() 
    
    f = open(temp_path, "w")
    try:
        f.write(payload)
    finally:
        f.close()
        # FLAWED: If system execution is violently killed, manual cleanup fails
✅ Secure (Context Managers with Automatic Cleanup and Secure Permissions)
Leverage tempfile.NamedTemporaryFile or tempfile.TemporaryDirectory within a with context manager. This ensures the file is created with restrictive permissions (0o700 / read-write by owner only) and is completely erased the moment the code block exits.

Python
import tempfile
import os

def process_data_secure(payload: str):
    # SECURE: NamedTemporaryFile creates a cryptographically unpredictable filename
    # and restricts access to the file owner only.
    # 'delete=True' (default) guarantees automatic file deletion upon closing or crash exit.
    with tempfile.NamedTemporaryFile(mode='w+', suffix='.tmp', delete=True) as temp_file:
        
        # Write sensitive runtime data securely
        temp_file.write(payload)
        temp_file.flush()
        
        # Seek back to read the data if necessary
        temp_file.seek(0)
        data = temp_file.read()
        
        # SECURE: The file path can be accessed safely via temp_file.name if needed,
        # but the file handle remains fully isolated under OS owner protections.
        print(f"Temporary file securely processed at: {temp_file.name}")

def manage_bulk_operations_secure():
    # SECURE: For multiple associated files, create an isolated temporary directory
    with tempfile.TemporaryDirectory() as temp_dir:
        secure_file_path = os.path.join(temp_dir, "isolated_payload.dat")
        
        with open(secure_file_path, "wb") as f:
            f.write(b"System Execution Data")
            
        # Do processing...
    # SECURE: The entire directory and all contents are instantly wiped when exiting this block

---

<ElicitationsGroup message="This completes the core file safety profile for Python's temp storage. Where should we point the AI's attention next?">
{/* Reason: Offers highly relevant follow-up prompts to expand file-system and data safety coverage. */}
  <Elicitation label="Python json module and preventing DoS vulnerabilities" query="How do I safely parse untrusted JSON input in Python and prevent Denial of Service (DoS) attacks?"/>
  <Elicitation label="Secure File Upload handling and validation in Python" query="How do I securely handle and validate uploaded user files in a Python web framework to prevent RCE?"/>
</ElicitationsGroup>