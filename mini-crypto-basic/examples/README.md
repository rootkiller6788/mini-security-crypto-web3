# mini-crypto-basic Examples

This directory contains three demonstration programs that exercise every module of the `mini-crypto-basic` library.

## Building

From the project root:

```bash
make all
```

Or compile individually:

```bash
gcc -std=c99 -Wall -Wextra -O2 -I ../include \
    ../src/hash_func.c \
    ../src/symmetric_cipher.c \
    ../src/asymmetric_cipher.c \
    ../src/digital_sig.c \
    ../src/pki_model.c \
    demo_hash.c -o ../bin/demo_hash
```

## Demos Overview

### 1. demo_hash — Hash Functions

```
=== mini-crypto-basic Hash Demo ===

SHA256("Hello, crypto world!") = <32-byte hex>
MD5("Hello, crypto world!")   = <16-byte hex>
SHA256(streaming) = <same as above>
HMAC-SHA256(key="secret-key", data="authenticate this message") = <32-byte hex>
HMAC-SHA256(streaming) = <same as above>

--- Merkle-Damgard Structure ---
  |---[pad + len]---|
  IV --> f --> f --> ... --> H(M)
  Block size: 64 bytes
  Digest size: 32 bytes
```

This demo exercises:
- **sha256_hash** — one-shot hashing
- **sha256_init/update/final** — streaming API
- **md5_hash** — MD5 one-shot
- **hmac_sha256** — keyed-hash message authentication code (one-shot)
- **hmac_sha256_init/update/final** — HMAC streaming
- Visual illustration of the **Merkle-Damgard** construction

Key takeaways:
- The streaming API produces the same result as the one-shot API because both follow the same Merkle-Damgard structure.
- HMAC uses two passes of the hash function with key-derived padding (ipad/opad).
- SHA-256's Merkle-Damgard structure: IV → compression function → chained output.

Expected output:
```
SHA256("Hello, crypto world!") = 04cdbfeb82c9c8f4d30b9edc6757175cd2e2107573aa4c1b3636016ea3cd5d05
MD5("Hello, crypto world!")   = e9cfa92c9d37fc0d94e142a53e54f47b
```

### 2. demo_aes_rsa — Symmetric + Asymmetric Ciphers

```
=== mini-crypto-basic AES / RSA / ECDH Demo ===

AES-128 Encryption:
  Plain:  3243f6a8885a308d313198a2e0370734
  Key:    2b7e151628aed2a6abf7158809cf4f3c
  Cipher: 3925841d02dc09fbdc118597196a0b32
  Decrypt:3243f6a8885a308d313198a2e0370734
  Match: YES

PKCS7 Padding:
  Original: 26 bytes, Padded: 32 bytes

CBC Encrypt: <hex>
CBC Decrypt: Encrypt me with CBC mode!

CTR Encrypt: <hex>
CTR Decrypt: Encrypt me with CBC mode!

RSA Key Generation + Sign/Verify:
  Keygen: OK (size=1024 bits)
  Sign: OK (xxx bytes)
  Verify: OK

ECDH Key Exchange (secp256k1 sim):
  Alice shared: <hex>
  Bob shared:   <hex>
  Match: YES

PEM Encoding (RSA Private Key):
-----BEGIN RSA PRIVATE KEY-----
n=...
d=...
e=...
-----END RSA PRIVATE KEY-----
PEM size: xxx bytes
```

This demo exercises:
- **AES-128 encrypt/decrypt** — standard test vector (FIPS 197)
- **PKCS7 padding** — pad plaintext to block boundary, unpad after decrypt
- **CBC mode** — cipher block chaining with IV
- **CTR mode** — counter mode (stream cipher) encryption
- **RSA keygen** — 1024-bit key generation with fixed primes (for repeatable demos)
- **RSA sign/verify** — hash-then-sign with raw RSA
- **ECDH key exchange** — generate keypair, compute shared secret, verify both sides match
- **PEM encoding** — RSA private key to PEM text format

Key takeaways:
- AES SubBytes, ShiftRows, MixColumns, AddRoundKey are all exercised internally.
- CBC encryption requires a unique IV for each message.
- CTR mode turns a block cipher into a stream cipher.
- ECDH shared secrets match because scalar multiplication is commutative: alice_priv × bob_pub == bob_priv × alice_pub.

### 3. demo_pki — PKI & Certificate Workflow

```
=== mini-crypto-basic PKI Demo ===

--- Certificate Authority Setup ---
Root CA self-signed certificate created.
Certificate:
  Version: 2
  Subject: CN=Root CA, O=Root CA Org, C=US
  Issuer: CN=Root CA, O=Root CA Org, C=US
  Valid from: ...
  Valid to: ...
  Is CA: Yes

--- Certificate Signing Request ---
CSR: CN=example.com, O=Example Inc, C=US
CSR signed: OK

--- Certificate Issuance ---
Leaf certificate issued (365 days).
Certificate:
  Version: 2
  Subject: CN=example.com, O=Example Inc, C=US
  ...

--- Trust Store ---
Trust store: 2 certificates
Find 'Root CA': FOUND

--- Certificate Chain Verification ---
Chain verify: OK

--- Certificate Revocation List ---
Revoked serial aa:bb: YES
Good serial 01:02: Not revoked

--- ACME (Let's Encrypt Simulation) ---
Account: acct-xxxxxxxx (contact=admin@example.com)
Order: order-xxxxxxxx (domain=myblog.example.com, status=pending)
  Challenge HTTP-01:
    Token: tok-xxxx-xxxx
    URL: http://myblog.example.com/.well-known/acme-challenge/tok-xxxx-xxxx
  Challenge DNS-01:
    Token: dns-xxxx-xxxx
    URL: _acme-challenge.myblog.example.com
  Status: ready
  Certificate downloaded: 46 bytes

--- OCSP Stapling ---
OCSP request: 8 bytes
OCSP status: GOOD

--- Hash-then-Sign ---
Signed: "PKI demo message" (xxx bytes)
Verify: OK

=== PKI Demo Complete ===
```

This demo exercises:
- **CA self-sign** — create a root CA certificate
- **CSR creation and signing** — Certificate Signing Request workflow
- **Certificate issuance** — CA issues a leaf certificate for a domain
- **Trust store** — add/find certificates in the trust store
- **Certificate chain verification** — verify leaf → root chain
- **CRL** — check if a serial number is revoked
- **ACME protocol** — Let's Encrypt-style domain validation (simulated)
  - HTTP-01 and DNS-01 challenges
  - Order lifecycle: pending → ready → valid
  - Certificate download after validation
- **OCSP stapling** — build OCSP request, parse response, check status
- **Hash-then-sign** — ECDSA sign + verify flow

Key takeaways:
- PKI trust model: root CA → intermediate CA → leaf certificate
- CRL provides a negative list of revoked serial numbers
- ACME automates domain validation and certificate issuance
- OCSP provides real-time certificate status checking (as an alternative to CRLs)

## Building All Demos

```bash
make all
```

## Running All Demos

```bash
make run-demos
```

## Compiler Requirements

- GCC 5.0+ (or Clang 3.5+, MSVC 2015+)
- C99 standard support
- Standard C library

## Troubleshooting

**Compilation errors about `sha256_hash` undefined:**
Ensure `hash_func.h` is included and `hash_func.c` is compiled/linked.

**Segfault on RSA operations:**
The RSA implementation uses fixed test primes. If `rsa_keygen` fails, check the `BI_MAX_WORDS` constant in `asymmetric_cipher.h`.

**ECDH shared secret mismatch:**
The ECDH implementation is simulated. If random seeds collide, secrets will still match due to the commutative property.

## Further Reading

- See `../docs/API_REFERENCE.md` for the complete API
- See `../docs/DESIGN_NOTES.md` for implementation details
- See `../README.md` for project overview
