# tempfile — Generate temporary files and directories

## Overview

The `tempfile` module is used to create **temporary files and directories** securely.

It helps applications store temporary data that is automatically removed after use.

Common uses:
- Creating temporary files
- Creating temporary folders
- Storing temporary data during program execution
- Handling files that do not need permanent storage

The module provides automatic cleanup using:
- `TemporaryFile`
- `NamedTemporaryFile`
- `TemporaryDirectory`
- `SpooledTemporaryFile`

---

# Import tempfile module

```python
import tempfile