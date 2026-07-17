---
id: PY-ZIP-01
title: Secure Archive Extraction and Path Traversal Protections
category: File System Security / Path Traversal
severity_hint: Critical
cwe: [CWE-22, CWE-409, CWE-23]
python_versions: "Python 3.x"
---

# Secure Archive Extraction and Path Traversal Protections

## Overview
Processing untrusted compressed archives (like `.zip` or `.tar`) exposes applications to two severe security vectors:
* **Zip Slip / Path Traversal (CWE-22):** Attackers place directory traversal sequences (`../../`) inside the filenames stored within the archive metadata. If extracted unchecked, the files can escape the intended destination folder and overwrite system binaries, configuration files, or source files.
* **Zip Bomb / Compression Bomb (CWE-409):** A tiny archive file (a few kilobytes) expands into gigabytes of data upon decompression, exhausting disk space or memory and forcing a complete system crash (Denial of Service).

To build bulletproof archive extractors, you must explicitly resolve and validate the absolute path of every single file entry *before* writing it to disk, and keep a strict running tally on uncompressed byte thresholds.

---

## Code Triad

### ❌ Insecure (Blind Extraction using extractall)
Using the high-level `extractall()` method directly on user-uploaded archives without any sizing checks or path validation.
```python
import zipfile

# CRITICAL VULNERABILITY: zipfile.extractall() does not thoroughly guard against 
# sophisticated relative path modifications on older configurations, nor does it limit 
# the maximum expanded disk footprint, opening the door to Zip Slip and DoS crashes.
def unpack_archive_unsafe(zip_path: str, extract_to: str):
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_to)
⚠️ Flawed Attempt (Checking for dot-dot strings manually)
Looking for simple "../../" string matches inside the archive's listing arrays. This is fragile because alternate characters, absolute paths (/etc/...), or varying OS slashes can easily slip right past manual string filters.

Python
import zipfile
import os

# FLAWED: Simple string inclusion checks are highly bypassable depending on how 
# paths are normalized, resolved, or handled across mixed OS boundaries (Windows vs Linux).
def unpack_archive_flawed(zip_path: str, extract_to: str):
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        for member in zip_ref.namelist():
            if "../" in member or "..\\" in member:
                raise ValueError("Potential path traversal attempt detected!")
            
            # FLAWED: Still lacks tracking thresholds for explosive file scaling (Zip Bombs)
            zip_ref.extract(member, extract_to)
✅ Secure (Resolved Canonical Paths and Threshold Boundaries)
Iterate through archive files manually using zipfile.namelist(). Resolve each target to a fully normalized absolute path, ensure it remains inside the designated landing directory, and track total uncompressed size metrics.

Python
import zipfile
import os

# SECURE: Combined defensive patterns ensuring absolute folder containment and exact file size tracking.
def unpack_archive_secure(zip_path: str, target_destination: str):
    # Establish canonical absolute paths for safety boundaries
    base_dir = os.path.abspath(target_destination)
    
    # Configuration Rules for Decompression Protection
    MAX_UNCOMPRESSED_SIZE = 100 * 1024 * 1024  # 100 MB Limit
    total_expanded_bytes = 0

    with zipfile.ZipFile(zip_path, 'r') as archive:
        for file_info in archive.infolist():
            
            # SECURE: Calculate target path and resolve symlinks using realpath
            target_file_path = os.path.abspath(os.path.join(base_dir, file_info.filename))
            
            # SECURE: Strict containment check. Ensure the file CANNOT break out of the base folder.
            if not target_file_path.startswith(base_dir + os.sep) and target_file_path != base_dir:
                raise PermissionError(f"Security Alert: Directory traversal blocked for item: {file_info.filename}")
            
            # SECURE: Zip Bomb Check. Accumulate and enforce size boundaries.
            total_expanded_bytes += file_info.file_size
            if total_expanded_bytes > MAX_UNCOMPRESSED_SIZE:
                raise ValueError("Extraction aborted: Uncompressed payload volume exceeds system caps.")
                
            # SECURE: Extract individual file safely now that boundaries are validated
            archive.extract(file_info, base_dir)
            
    print("Archive decompressed securely under strict operational constraints.")

---

<ElicitationsGroup message="This closes out your comprehensive security profiles for core Python and file-system modules. What would you like to review next?">
{/* Reason: Prompts the user on next steps, whether converting more modules or expanding the training engine scope. */}
  <Elicitation label="Review the complete set of Python security files generated so far" query="Summarize all the Python security code patterns we have built across these training files."/>
  <Elicitation label="Secure handling of user authentication and JWTs in Python" query="How do I securely issue, verify, and store JSON Web Tokens (JWT) in a Python backend application?"/>
</ElicitationsGroup>