---
id: PY-SERIAL-02
title: Insecure Deserialization in Shelve Databases
category: Insecure Deserialization
severity_hint: Critical
cwe: [CWE-502]
python_versions: "Python 3.x"
---

# Insecure Deserialization in Shelve Databases

## Overview
The `shelve` module provides a simple key-value persistent storage system for Python objects. However, because `shelve` relies entirely on the `pickle` serialization format under the hood, loading or opening a shelf file from an untrusted, modified, or external source results directly in **Insecure Deserialization (CWE-502)**. Attackers can forge a malicious payload inside the database file that executes arbitrary shell commands automatically the moment a key is retrieved or opened.

---

## Code Triad

### ❌ Insecure (Opening Untrusted Shelve Databases)
Opening an externally supplied or uploaded `.db` shelf file directly, assuming it is just a safe data store.
```python
import shelve

# VULNERABLE: If user_uploaded_cache.db is tampered with by an attacker, 
# reading a key or even just opening the file will trigger the __reduce__ 
# method of a malicious pickle object, leading to immediate RCE.
def load_user_cache_unsafe(filepath: str):
    with shelve.open(filepath) as db:
        user_data = db.get("user_profile") 
        return user_data
⚠️ Flawed Attempt (Relying on Signature/Integrity Checks Post-Open)
Attempting to check the structure or values of a shelf database after opening it, which fails because the malicious code executes during the retrieval process.

Python
import shelve

# FLAWED: Validating keys or checking values happens far too late.
# The payload executes the instant db["data"] is evaluated.
def verify_and_load_flawed(filepath: str):
    with shelve.open(filepath) as db:
        if "data" not in db:
            raise ValueError("Invalid database format")
        
        # FLAWED: Deserialization happens here before type verification can run
        data = db["data"]
        if not isinstance(data, dict):
            raise TypeError("Data must be a dictionary")
        return data
✅ Secure (Safe Serialization using JSON or SQLite with Explicit Schema)
For local data persistence of non-trusted input, completely replace shelve with a text-based format like json or use an explicit schema database like sqlite3.

Python
import json
import sqlite3

# SECURE: Using a structured SQLite database completely eliminates pickle dependencies.
# Data is stored strictly as text or blobs, preventing arbitrary code execution.
def save_user_cache_secure(db_path: str, user_id: str, profile_data: dict):
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cache (
                id TEXT PRIMARY KEY, 
                data TEXT
            )
        """)
        # Serialize to plain string JSON format
        json_str = json.dumps(profile_data)
        cursor.execute("INSERT OR REPLACE INTO cache (id, data) VALUES (?, ?)", (user_id, json_str))
        conn.commit()

def load_user_cache_secure(db_path: str, user_id: str) -> dict:
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT data FROM cache WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        if row:
            # SECURE: Parsing pure string JSON text safely instantiates safe Python types (dict, list, str)
            return json.loads(row[0])
        return {}

---

### File 31: Inter-Process Communication and Pickle Traps (`MULTIPROCESSING`)

```markdown
---
id: PY-DESERIAL-03
title: Inter-Process Communication Security in Multiprocessing
category: Insecure Deserialization / Network Security
severity_hint: Critical
cwe: [CWE-502, CWE-749]
python_versions: "Python 3.x"
---

# Inter-Process Communication Security in Multiprocessing

## Overview
The `multiprocessing` module allows Python applications to execute tasks across distinct OS processes. However, its high-level communication tools—specifically `Connection.recv()` and `Pipe()`—implicitly use the `pickle` serialization protocol to pass complex Python objects across boundaries. If a `multiprocessing.connection` listener binds to an exposed network port or accepts connections from unprivileged local processes, an attacker can feed malicious byte streams into the socket, achieving full Remote Code Execution within the parent application context.

---

## Code Triad

### ❌ Insecure (Exposing Raw Multiprocessing Listeners Globally)
Binding a multiprocessing `Listener` to an external network interface without authentication or validation, allowing arbitrary remote connections to pass pickle objects.
```python
from multiprocessing.connection import Listener

# VULNERABLE: Binds to all interfaces without an authentication key. 
# Anyone who connects can send a serialized pickle payload via connection.recv(), 
# hijacking the process control immediately.
def start_global_listener_unsafe():
    address = ('0.0.0.0', 6000)
    listener = Listener(address)
    
    while True:
        conn = listener.accept()
        # VULNERABLE: Implicitly uses pickle.loads() on incoming data
        msg = conn.recv() 
        print(f"Received message: {msg}")
⚠️ Flawed Attempt (Relying Solely on basic authkey Parameters)
Using the built-in authkey parameter. While it provides a basic challenge-response mechanism, the underlying transport protocol still processes raw byte blocks natively, and simple key leaks lead to instant compromise.

Python
from multiprocessing.connection import Listener

# FLAWED: While authkey provides a layer of authentication, it relies on a shared secret.
# If the secret key is intercepted, weak, or brute-forced, the system remains 
# exposed to high-risk pickle execution over the network.
def start_listener_flawed():
    address = ('127.0.0.1', 6000)
    listener = Listener(address, authkey=b'secret_key_2026')
    
    conn = listener.accept()
    msg = conn.recv()
    return msg
✅ Secure (Text-Based IPC Sockets or JSON Transport Layer)
Avoid multiprocessing.connection channels over networks. Instead, use standard network sockets, validate inputs strictly, and use safe serialization standards like JSON, protocol buffers, or structured text messages.

Python
import socket
import json

# SECURE: Using a standard network socket transferring strict JSON text payloads.
# No pickle engine is present in the pipeline, completely mitigating RCE vulnerabilities.
def start_network_receiver_secure(host: str = '127.0.0.1', port: int = 6500):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)
    
    while True:
        client_socket, client_address = server_socket.accept()
        try:
            # Limit buffer stream size to prevent DoS memory exhaustion
            raw_data = client_socket.recv(4096)
            if not raw_data:
                continue
                
            # SECURE: Safe parsing of clear string structures 
            payload = json.loads(raw_data.decode('utf-8'))
            
            # Enforce validation on expected fields
            if "command" in payload and isinstance(payload["command"], str):
                process_system_command_safely(payload["command"])
                
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            # Handle bad data structural transmissions safely
            pass
        finally:
            client_socket.close()

def process_system_command_safely(cmd: str):
    print(f"Safely executing defined internal directive: {cmd}")

---

<ElicitationsGroup message="These entries secure Python's native object pipelines. What areas of the security training architecture would you like to build out next?">
{/* Reason: Offers follow-up ideas centered on advanced python security features. */}
  <Elicitation label="Safely executing dynamic expressions using literal_eval" query="How do I safely parse string evaluations in Python without using the dangerous eval() function?"/>
  <Elicitation label="XML parsing vulnerabilities and DefusedXML usage" query="How do I protect Python applications against XML External Entity (XXE) and Billion Laughs attacks?"/>
</ElicitationsGroup>