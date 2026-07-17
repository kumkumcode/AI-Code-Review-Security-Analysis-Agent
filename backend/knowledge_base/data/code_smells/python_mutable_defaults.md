---
id: CS-PY-01
title: Mutable Default Arguments
category: Code Smells / Bug Proneness
severity_hint: Warning
cwe: [CWE-391]
python_versions: "Python 3.x"
---

# Mutable Default Arguments in Python

## Overview
In Python, default arguments are evaluated **only once** when the function is defined, not every time the function is called. If you use a mutable object (like a list, dictionary, or set) as a default argument, that single object instance is shared across *all* future invocations of the function. This leads to silent state accumulation, unexpected side effects, and subtle runtime bugs.

---

## Code Triad

### ❌ Smelly (Using Mutable Defaults)
Using an empty list directly as a default argument, causing subsequent calls to append data to the same persistent list object.
```python
# SMELLY: The target list is created once at import time.
# If called multiple times without passing an explicit list, 
# it continuously appends elements to the same old instance.
def append_to_cache(item: str, target_list=[]):
    target_list.append(item)
    return target_list
⚠️ Flawed Attempt (Reinitializing inside signature with factory types)
Using standard container initializations or attempting to re-evaluate the parameter dynamically inside the signature.

Python
# FLAWED: Using list() still evaluates exactly once at function definition time, 
# resulting in the same state-sharing issue.
def append_to_cache_flawed(item: str, target_list=list()):
    target_list.append(item)
    return target_list
✅ Clean (Default to None with Lazy Initialization)
Set the default value to None, and instantiate a new mutable collection inside the function body only if the argument remains None.

Python
# CLEAN: Each time this function is called without a list parameter,
# a fresh, isolated list instance is safely created inside the local scope.
def append_to_cache_clean(item: str, target_list=None):
    if target_list is None:
        target_list = []
        
    target_list.append(item)
    return target_list

---

### File 37: For your `best_practices/` Folder

Create a file named `python_resource_management.md` under `knowledge_base/data/best_practices/`.

```markdown
---
id: BP-PY-01
title: Secure Resource Management and File I/O
category: Best Practices / Resource Management
severity_hint: Info
cwe: [CWE-775]
python_versions: "Python 3.x"
---

# Secure Resource Management and File I/O

## Overview
When opening external resources (such as files, sockets, or database connections), failing to properly close them can lead to **Resource Exhaustion**. If an exception occurs between opening a file and closing it, the system handle is left open. The most idiomatic and secure way to handle resource allocations in Python is through Context Managers (the `with` statement), which guarantees that resources are torn down cleanly regardless of runtime failures.

---

## Code Triad

### ❌ Unoptimized (Manual Resource Tracking)
Explicitly calling `.close()` on a file object, leaving the handle hanging open if an exception occurs during reading.
```python
# UNOPTIMIZED: If json.loads() throws an exception, the file descriptor 
# is never closed, eventually exhausting OS resource handles over time.
def load_config_unsafe(filepath: str):
    f = open(filepath, 'r')
    data = f.read()
    f.close()
    return data
⚠️ Flawed Attempt (Try-Finally Blocks)
Using complex, deeply-nested try-finally blocks. While technically functional, it introduces unnecessary syntax clutter and decreases readability.

Python
# FLAWED: While functional, nesting try/finally blocks repeatedly 
# across multiple resources creates highly unreadable, fragile structures.
def load_config_flawed(filepath: str):
    f = open(filepath, 'r')
    try:
        data = f.read()
    finally:
        f.close()
    return data
✅ Best Practice (Explicit Context Managers)
Use the native with context manager, which handles cleanup implicitly.

Python
# BEST PRACTICE: The with statement guarantees close() is executed 
# immediately upon exiting the block, even if an exception is raised.
def load_config_secure(filepath: str):
    with open(filepath, 'r', encoding='utf-8') as f:
        return f.read()

---

## How to Scale This Process 🚀

To turn this into a fully operational engine:

1. **Keep the Metadata Block consistent:** Keep using the same metadata format (`id`, `title`, `category`, `severity_hint`, etc.) across all files. This makes it incredibly easy for your AI's backend script to parse and categorize these documents during its validation pipeline.
2. **Train your RAG system to map files:**
   * If a user writes code that triggers a rule from `/secure_coding/` or `/owasp/`, let your database tell the AI to flag it as a **Critical/High Security Defect** (Stop deployment!).
   * If a rule from `/code_smells/` is triggered, flag it as a **Maintainability Warning** (Should fix before merge).
   * If a rule from `/best_practices/` matches, flag it as an **Idiomatic Suggestion** (Nice-to-have cleanup).

Would you like to write a custom parsing script to ingest these markdown files into your vector search index next?