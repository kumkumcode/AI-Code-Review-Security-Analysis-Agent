# subprocess — Subprocess Management

## Introduction

The `subprocess` module allows Python programs to create and manage new processes. It is used to execute external commands, communicate with them, and get their output, errors, and return codes.

It replaces older modules/functions:
- `os.system()`
- `os.spawn*`

---

## Import

```python
import subprocess
```

---

## subprocess.run()

`subprocess.run()` is the recommended method to execute a command. It runs the command, waits for completion, and returns a `CompletedProcess` object.

### Syntax

```python
subprocess.run(args, *, capture_output=False, shell=False, timeout=None, check=False, text=False)
```

### Example

```python
import subprocess

result = subprocess.run(["python", "--version"])

print(result)
```

---

## Important Parameters

### args
Command or program to execute.

Example:

```python
subprocess.run(["ls", "-l"])
```

### capture_output
Captures standard output and error.

```python
subprocess.run(
    ["python", "--version"],
    capture_output=True
)
```

### stdout
Stores program output.

```python
stdout=subprocess.PIPE
```

### stderr
Stores error messages.

```python
stderr=subprocess.PIPE
```

### text=True
Returns output as a string instead of bytes.

```python
result = subprocess.run(
    ["python", "--version"],
    capture_output=True,
    text=True
)

print(result.stdout)
```

### timeout
Stops execution after a specified time.

```python
subprocess.run(
    ["python", "file.py"],
    timeout=5
)
```

### check=True
Raises `CalledProcessError` if the command fails.

```python
subprocess.run(
    ["python", "file.py"],
    check=True
)
```

---

# CompletedProcess Object

`subprocess.run()` returns a `CompletedProcess` object.

Important attributes:

| Attribute | Description |
|---|---|
| args | Command that was executed |
| returncode | Exit status of the process |
| stdout | Captured output |
| stderr | Captured error messages |

Return codes:
- `0` → Successful execution
- Non-zero → Error occurred

---

# subprocess.Popen()

`Popen()` provides advanced control over processes. It allows communication with a running process.

Example:

```python
import subprocess

process = subprocess.Popen(
    ["python", "--version"],
    stdout=subprocess.PIPE
)

output = process.stdout.read()

print(output)
```

---

# Popen Methods

## poll()

Checks whether the process has finished.

```python
process.poll()
```

## wait()

Waits for the process to complete.

```python
process.wait()
```

## communicate()

Sends input and reads output/error safely.

```python
process.communicate()
```

## terminate()

Stops the process.

```python
process.terminate()
```

## kill()

Forcefully stops the process.

```python
process.kill()
```

---

# subprocess.PIPE

`PIPE` creates a connection between the parent process and child process.

Example:

```python
subprocess.run(
    ["python", "--version"],
    stdout=subprocess.PIPE
)
```

---

# Security Considerations

Avoid using `shell=True` with untrusted input because it can cause command injection vulnerabilities.

Unsafe:

```python
subprocess.run(command, shell=True)
```

Safer:

```python
subprocess.run(["ls", "-l"])
```

---

# Common Uses

- Running system commands
- Executing external programs
- Running scripts
- Capturing command output
- Managing child processes
- Automating tasks

---

# Usage in AI Code Review System

The `subprocess` module can be used to:

- Execute submitted Python/Java code
- Run syntax validation
- Capture compiler/interpreter errors
- Return execution results for AI analysis