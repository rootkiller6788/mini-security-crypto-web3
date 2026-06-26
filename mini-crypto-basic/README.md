# mini-crypto-basic — 密码学基础 (C 语言实现)

A comprehensive cryptographic library implemented in pure C99. Provides implementations of common hash functions, symmetric ciphers, asymmetric ciphers, digital signatures, and a Public Key Infrastructure (PKI) simulation model — all from scratch with no external dependencies.

## Overview

```
mini-crypto-basic/
├── include/                  # Public headers
│   ├── hash_func.h           # SHA-256, MD5, HMAC, Merkle-Damgard
│   ├── symmetric_cipher.h    # AES-128, DES, CBC/CTR, PKCS7
│   ├── asymmetric_cipher.h   # RSA, ECDH (secp256k1), BigInt, PEM
│   ├── digital_sig.h         # RSA-PSS, ECDSA, X.509, CRL
│   └── pki_model.h           # CA, CSR, Trust Store, ACME, OCSP
├── src/                      # Implementation
│   ├── hash_func.c           # (187 lines)
│   ├── symmetric_cipher.c    # (233 lines)
│   ├── asymmetric_cipher.c   # (245 lines)
│   ├── digital_sig.c         # (200 lines)
│   └── pki_model.c           # (170 lines)
├── examples/                 # Demo programs
│   ├── demo_hash.c           # SHA-256 + MD5 + HMAC demo
│   ├── demo_aes_rsa.c        # AES + RSA + ECDH + PEM demo
│   ├── demo_pki.c            # CA/CSR/ACME/OCSP demo
│   └── README.md
├── docs/
│   ├── API_REFERENCE.md      # Full API reference
│   ├── DESIGN_NOTES.md       # Design rationale & notes
│   └── README.md
├── README.md                 # This file
└── Makefile                  # GCC build configuration
```

## Features

### Hash Functions (`hash_func.h`)
| Algorithm   | Digest Size | Block Size | Implementation      |
|-------------|-------------|------------|---------------------|
| SHA-256     | 256 bits    | 512 bits   | Init/Update/Final   |
| MD5         | 128 bits    | 512 bits   | Full round functions |
| HMAC-SHA256 | 256 bits    | 512 bits   | Keyed-hash MAC      |
| Merkle-Damgard | Generic | Configurable | Structural framework |

### Symmetric Ciphers (`symmetric_cipher.h`)
| Algorithm | Key Size  | Block Size | Rounds | Modes        |
|-----------|-----------|------------|--------|--------------|
| AES-128   | 128 bits  | 128 bits   | 10     | CBC, CTR     |
| DES       | 56 bits   | 64 bits    | 16     | CBC, CTR     |
| PKCS7 Pad | N/A       | N/A        | N/A    | Pad/Unpad    |

### Asymmetric Ciphers (`asymmetric_cipher.h`)
| Algorithm       | Key Size      | Features                          |
|-----------------|---------------|-----------------------------------|
| RSA             | 1024+ bits    | Keygen, Encrypt, Sign, Verify     |
| ECDH (secp256k1)| 256 bits      | Key exchange, scalar multiplication|
| BigInt          | Arbitrary     | Add, Sub, Mul, Div, Mod, ModExp   |
| PEM             | N/A           | Encode/Decode RSA & EC keys       |

### Digital Signatures (`digital_sig.h`)
| Feature           | Description                              |
|-------------------|------------------------------------------|
| RSA-PSS           | Probabilistic Signature Scheme           |
| ECDSA             | Elliptic Curve Digital Signature Algorithm|
| X.509 Certificate | Basic fields, parse, print, verify       |
| Certificate Chain | Verify chain to trust root               |
| CRL               | Certificate Revocation List check        |

### PKI Model (`pki_model.h`)
| Feature              | Description                            |
|----------------------|----------------------------------------|
| Certificate Authority| Issue certificates, self-sign root CA  |
| CSR                  | Certificate Signing Request            |
| Trust Store          | Root CA certificate storage            |
| ACME                 | Let's Encrypt-style automation (sim)   |
| OCSP Stapling        | Online Certificate Status Protocol     |

## Quick Start

### Build

```bash
make all
```

### Run Demos

```bash
make run-demos

# Or individually:
./bin/demo_hash
./bin/demo_aes_rsa
./bin/demo_pki
```

### Clean

```bash
make clean
```

## Code Conventions

- **Standard**: C99 (`-std=c99`)
- **Guards**: `#ifndef HEADER_H` / `#define HEADER_H`
- **Naming**:
  - snake_case — functions, variables
  - PascalCase — structs, typedefs, enums
  - UPPER_SNAKE_CASE — macros, constants
- **Booleans**: `#include <stdbool.h>`
- **Warnings**: `-Wall -Wextra`
- **Optimization**: `-O2`

## API Summary

### SHA-256
```c
Sha256Context ctx;
uint8_t digest[32];
sha256_init(&ctx);
sha256_update(&ctx, data, len);
sha256_final(&ctx, digest);
// or: sha256_hash(data, len, digest);
```

### AES-128 CBC
```c
AesContext aes;
aes128_key_schedule(&aes, key);
CbcContext cbc;
cbc_encrypt_init(&cbc, &aes, CIPHER_ALGO_AES128, iv);
cbc_encrypt_update(&cbc, plain, len, cipher, &out_len);
cbc_encrypt_final(&cbc, cipher + out_len, &final_len);
```

### RSA
```c
RsaPrivateKey priv; RsaPublicKey pub;
rsa_keygen(&priv, &pub, 1024);
rsa_sign(&priv, hash, 32, sig, &sig_len);
rsa_verify(&pub, hash, 32, sig, sig_len);
```

### PKI / ACME
```c
AcmeAccount acc;
acme_account_create(&acc, "admin@ex.com");
AcmeOrder order;
acme_new_order(&order, "mysite.com");
acme_submit_challenge_response(&order, 0, "key-auth");
acme_finalize_order(&order, &csr);
```

## Security Notes

**IMPORTANT**: This is an educational/simulation library. Do NOT use in production.

- RSA uses simplified big integer arithmetic (32-bit word size)
- ECDH uses a simulated field — NOT real secp256k1 arithmetic
- X.509 parsing is skeletal — no full DER decoding
- ACME and OCSP are simulated protocol flows
- DES is included for historical/comparative study only

## Dependencies

- C99 compliant compiler (GCC, Clang, MSVC)
- Standard C library (`<string.h>`, `<stdlib.h>`, `<stdio.h>`, `<stdint.h>`, `<stdbool.h>`, `<stddef.h>`, `<time.h>`)
- No external libraries required

## License

Educational use. See source files for details.

## References

- FIPS 180-4: Secure Hash Standard (SHA-256)
- FIPS 197: Advanced Encryption Standard (AES)
- FIPS 46-3: Data Encryption Standard (DES)
- RFC 3447: PKCS #1 v2.1 — RSA Cryptography
- RFC 8017: PKCS #1 v2.2 — RSA-PSS
- RFC 5280: X.509 PKI and CRL
- RFC 6960: OCSP
- RFC 8555: ACME Protocol
