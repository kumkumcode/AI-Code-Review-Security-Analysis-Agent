---
id: OWASP-2021-A02
title: Cryptographic Failures
category: Cryptographic Failures
severity_hint: High
languages: [python, java]
cwes: [CWE-259, CWE-261, CWE-296, CWE-310, CWE-319, CWE-321, CWE-322, CWE-323, CWE-324, CWE-325, CWE-326, CWE-327, CWE-328, CWE-329, CWE-330, CWE-331, CWE-335, CWE-336, CWE-337, CWE-338, CWE-340, CWE-347, CWE-523, CWE-720, CWE-757, CWE-759, CWE-760, CWE-780, CWE-818, CWE-916]
related_guidelines: [ACCESS-1, CONFIDENTIAL-1]
---

# A02:2021 – Cryptographic Failures

## Factors

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Avg Weighted Exploit | Avg Weighted Impact | Max Coverage | Avg Coverage | Total Occurrences | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 29 | 46.44% | 4.49% | 7.29 | 6.81 | 79.33% | 34.85% | 233,788 | 3,075 |

## Overview
Previously known as *Sensitive Data Exposure*, this category focuses on root-cause failures related to cryptography (or the lack thereof) which lead to data compromise. Key failures include the use of hard-coded credentials, broken or risky cryptographic algorithms, and weak entropy generation.

### 🛡️ Secure Cryptographic Pipeline
┌─────────────────────────────────────────────────────────────┐
│             Data-In-Transit: TLS 1.3 Only & HSTS            │
└──────────────┬──────────────────────────────────────────────┘
▼
┌─────────────────────────────────────────────────────────────┐
│ Data-At-Rest: Authenticated Symmetric Encryption (AES-GCM)  │
└──────────────┬──────────────────────────────────────────────┘
▼
┌─────────────────────────────────────────────────────────────┐
│ Secrets Management: KMS / Environment-Injected Keys (No Repo)│
└──────────────┬──────────────────────────────────────────────┘
▼
┌─────────────────────────────────────────────────────────────┐
│ Password Security: Adaptive, Salted Hashing (Argon2 / bcrypt)│
└─────────────────────────────────────────────────────────────┘


---

## Modern Python (FastAPI / bcrypt) Hashing Examples

### ❌ Insecure (Weak & Fast Hash Function)
Using MD5 or SHA1 is highly vulnerable to rapid collision creation and GPU-accelerated brute-force attacks (rainbow tables).
```python
import hashlib

def hash_user_password(password: str) -> str:
    # VULNERABLE: MD5 has zero computational delay and lacks automatic unique salting
    return hashlib.md5(password.encode()).hexdigest()
✅ Secure (Adaptive, Cryptographically Salted Hashing)
We enforce adaptive work-factor hashing using bcrypt which automatically handles unique salts and slow iteration execution to thwart GPU cracking.
import bcrypt

def hash_user_password(password: str) -> str:
    # SECURE: Automatically generates a secure salt and uses key stretching
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password_bytes, salt).decode('utf-8')

def verify_password(password: str, hashed_password: str) -> bool:
    # SECURE: Safe comparison against timing attacks
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

Modern Java (AES-256-GCM) Symmetric Encryption Examples
❌ Insecure (Hard-coded Keys & Weak Cipher Mode)
Hard-coding encryption secrets in source control makes leakage inevitable. Furthermore, using insecure cipher modes like ECB or weak key lengths exposes the ciphertext to pattern analysis.

import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;

public class LegacyEncryption {
    public byte[] encryptData(String data) throws Exception {
        // VULNERABLE: Hardcoded key inside source code
        String key = "1234567890123456"; 
        SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes(), "AES");
        
        // VULNERABLE: ECB mode leaks structural patterns and does not use an IV
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        return cipher.doFinal(data.getBytes());
    }
}
✅ Secure (KMS Keys & Authenticated AES-GCM)
We resolve key-disclosure risks by pulling cryptographic keys from secure environments or a Key Management Service (KMS). We use AES-GCM to enforce authenticated encryption with a secure initialization vector (IV).

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;

public class ModernEncryptionService {
    private static final int GCM_IV_LENGTH_BYTES = 12;
    private static final int GCM_TAG_LENGTH_BITS = 128;

    public SecretKey generateKey() throws Exception {
        // SECURE: Generate a strong 256-bit AES key programmatically
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        return keyGen.generateKey(); 
        // Note: Store this key in a secure Secrets Manager or HSM, never in code.
    }

    public byte[] encryptData(byte[] plaintext, SecretKey secretKey) throws Exception {
        // SECURE: Utilize a strong cryptographically secure pseudo-random number generator (CSPRNG)
        byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
        SecureRandom random = SecureRandom.getInstanceStrong();
        random.nextBytes(iv);

        // SECURE: Use Authenticated Encryption (AES/GCM) to prevent padding oracle attacks
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        
        byte[] ciphertext = cipher.doFinal(plaintext);
        
        // Prepend the IV to the ciphertext so it can be retrieved during decryption
        byte[] combined = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);
        
        return combined;
    }
}
Real-World Edge Cases & Advanced Vulnerabilities
1. The Danger of ECB (Electronic Codebook) Mode
In ECB mode, identical blocks of plaintext are encrypted into identical blocks of ciphertext. This fails to hide visual or structural data patterns.

Example: Encrypting a BMP image file using AES-ECB preserves the visual outline of the image in the encrypted output, rendering the encryption highly ineffective. Always use modes requiring unique IVs, preferably authenticated ones like GCM.

2. IV/Nonce Reuse in AES-GCM (The "Forbidden" Frontier)
Encrypting two different messages with the same key and the same initialization vector (nonce) under GCM mode destroys the cryptographic protection of GCM.

Impact: An observer capturing both ciphertexts can easily compute the XOR difference of the two plaintexts, opening the door to complete decryption and forgeability. Secure IVs must be uniquely generated via CSPRNGs for every operation.

How to Prevent
Classify and Minimize Storage: Classify data elements according to sensitivity rules (GDPR, PCI DSS) and discard data that is no longer strictly required.

Apply Authenticated Encryption (AEAD): Always prefer authenticated encryption modes (e.g., AES-GCM or ChaCha20-Poly1305) over simple encryption to defend against tampering and oracle attacks.

Use Strong Adaptive KDFs: Passwords must be run through work-factored algorithms (Argon2id, scrypt, bcrypt, or PBKDF2) to defend against high-velocity offline cracking.

Isolate Keys from Code: Use external KMS platforms, cloud secrets vaults, or localized OS keychains.

References
OWASP Proactive Controls: Protect Data Everywhere

OWASP Application Security Verification Standard (V7, V9, V10)

OWASP Cheat Sheet: Password Storage

OWASP Cheat Sheet: Cryptographic Storage