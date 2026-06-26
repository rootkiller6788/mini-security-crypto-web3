# mini-crypto-basic Documentation

Welcome to the `mini-crypto-basic` documentation. This directory contains the complete API reference and design notes for the library.

## Documentation Structure

```
docs/
├── README.md           # This file — documentation index and navigation
├── API_REFERENCE.md    # Complete API reference for all modules
└── DESIGN_NOTES.md     # Implementation details, trade-offs, and rationale
```

## Quick Navigation

| Document | Contents |
|----------|----------|
| [API_REFERENCE.md](API_REFERENCE.md) | Function signatures, structs, enums, constants, usage patterns |
| [DESIGN_NOTES.md](DESIGN_NOTES.md) | Architecture decisions, algorithm details, security considerations |

## Module Overview

### Module 1: Hash Functions (`hash_func.h`)

Provides cryptographic hash functions following the Merkle-Damgard construction paradigm.

**Algorithms:**
- **SHA-256** — FIPS 180-4 compliant, 256-bit digest, 512-bit blocks, 64 rounds of compression
- **MD5** — RFC 1321, 128-bit digest, 512-bit blocks, 64 rounds (4 round types: F/G/H/I)
- **HMAC-SHA256** — RFC 2104, keyed-hash message authentication using SHA-256
- **Merkle-Damgard** — Generic structural framework for iterative hash functions

**Key Types:**
- `Sha256Context` — Holds the eight 32-bit state words, working buffer, bit counter
- `Md5Context` — Holds the four 32-bit state words, working buffer, bit counter
- `HmacContext` — Holds inner/outer padded keys, inner SHA-256 context
- `MerkleDamgardConfig` — Configures block size, state size, compress/init function pointers

**APIs:**
- One-shot hashing: `sha256_hash()`, `md5_hash()`
- Streaming hashing: `sha256_init()`, `sha256_update()`, `sha256_final()`
- HMAC: `hmac_sha256_init()`, `hmac_sha256_update()`, `hmac_sha256_final()`
- Generic: `merkle_damgard_hash()`

### Module 2: Symmetric Ciphers (`symmetric_cipher.h`)

Implements block ciphers and their modes of operation.

**Algorithms:**
- **AES-128** — FIPS 197, 10 rounds, SubBytes/ShiftRows/MixColumns/AddRoundKey
- **DES** — FIPS 46-3, 16-round Feistel network with 56-bit key
- **CBC Mode** — Cipher Block Chaining, requires IV, not parallelizable
- **CTR Mode** — Counter mode, turns block cipher into stream cipher
- **PKCS7 Padding** — Block padding per RFC 2315

**Key Types:**
- `AesContext` — 44-word expanded key schedule (11 round keys × 16 bytes)
- `DesContext` — 16 × 48-bit round subkeys
- `CbcContext` — Holds cipher reference, IV, partial block buffer
- `CtrContext` — Holds cipher reference, counter value, keystream buffer

**Key Cryptographic Primitives:**
- `aes_sub_bytes()` — Non-linear byte substitution via 256-entry S-box
- `aes_shift_rows()` — Row-wise cyclic shift for diffusion
- `aes_mix_columns()` — Column mixing in GF(2^8) using MDS matrix
- `aes_add_round_key()` — XOR with round key (key whitening)
- `pkcs7_pad()` / `pkcs7_unpad()` — PKCS#7 padding/unpadding

**Design Notes:**
- AES S-box is generated from the multiplicative inverse in GF(2^8) followed by affine transformation
- DES uses 8 S-boxes (6-to-4 bit mapping) with carefully designed nonlinearity
- CBC requires the IV to be unpredictable for security
- CTR mode uses a nonce + counter — never reuse the same counter with the same key

### Module 3: Asymmetric Ciphers (`asymmetric_cipher.h`)

Implements public-key cryptography primitives with a custom big integer library.

**BigInt Library:**
- 32-bit word size, up to 2048-bit numbers
- Operations: add, sub, mul, divmod, mod, mod_exp, mod_mul, gcd, mod_inv
- Square-and-multiply exponentiation
- Extended Euclidean algorithm for modular inverse
- Miller-Rabin primality testing (probabilistic)

**RSA:**
- Key generation: select primes p, q → compute n = p*q, φ = (p-1)(q-1) → find e,d
- Fixed demonstration primes for deterministic output
- CRT parameters (dp, dq, qinv) for faster decryption
- Raw RSA encryption/decryption (no OAEP/PKCS1 in this simplified version)
- Sign = decrypt(private, hash), Verify = encrypt(public, sig) == hash

**ECDH (secp256k1):**
- Simulated curve arithmetic (NOT real secp256k1 for educational clarity)
- Scalar multiplication via double-and-add
- Keypair generation with random 256-bit scalar
- Shared secret derivation
- Point addition, doubling, generator access

**PEM:**
- ASCII-armored key format (simulated text-based format)
- RSA private/public key encode/decode
- EC private/public key encode

### Module 4: Digital Signatures (`digital_sig.h`)

Signature schemes and certificate infrastructure.

**RSA-PSS:**
- Probabilistic signature scheme with salt
- MGF1 mask generation function
- EMSA-PSS encoding per PKCS#1 v2.2

**ECDSA:**
- Elliptic Curve Digital Signature Algorithm
- DER encoding of signatures (SEQUENCE of two INTEGERs)
- Hash-then-sign wrapper

**X.509 Certificate:**
- Basic fields: version, serial, issuer, subject, validity, public key
- Extensions: key usage, extended key usage, basic constraints
- Parse (simulated), print human-readable, signature verification

**Certificate Chain:**
- Array of certificates from leaf to intermediate to root
- Verify each certificate's signature against its issuer
- Check validity periods

**CRL:**
- Array of revoked certificate serial numbers
- Revocation date and reason code
- Lookup by serial number

### Module 5: PKI Model (`pki_model.h`)

Complete Public Key Infrastructure simulation.

**CA:**
- Root CA self-signing
- Intermediate CA configuration
- Certificate issuance from CSR

**CSR:**
- PKCS#10-like certificate signing request
- Common name, organization, country
- RSA or EC public key attachment
- Sign and verify

**Trust Store:**
- Collection of trusted root CA certificates
- Add, remove, find by subject common name
- Chain verification against trust store

**ACME (Let's Encrypt Simulation):**
- Account creation with keypair
- Order creation for domain validation
- HTTP-01 and DNS-01 challenge types
- Challenge response submission and validation
- Order finalization and certificate download
- Certificate renewal

**OCSP Stapling:**
- Request building with serial number
- Response parsing with status (GOOD/REVOKED/UNKNOWN)
- Response verification against responder certificate
- Staple verification with time window checking

## API Usage Patterns

### Pattern 1: Streaming Hash
```c
Sha256Context ctx;
uint8_t digest[32];
sha256_init(&ctx);
while (has_data()) {
    sha256_update(&ctx, chunk, chunk_len);
}
sha256_final(&ctx, digest);
```

### Pattern 2: Encrypt-then-MAC
```c
// 1. Encrypt
uint8_t padded[48];
size_t pad_len = pkcs7_pad(plain, plain_len, 16, padded);
AesContext aes; aes128_key_schedule(&aes, key);
CbcContext cbc; cbc_encrypt_init(&cbc, &aes, CIPHER_ALGO_AES128, iv);
cbc_encrypt_update(&cbc, padded, pad_len, cipher, &out_len);
// 2. MAC the ciphertext
hmac_sha256(mac_key, mac_key_len, cipher, out_len, tag);
```

### Pattern 3: PKI Full Workflow
```c
// 1. Create CA
CaConfig root_ca; root_ca.name = "Root CA";
X509Certificate root_cert;
ca_self_sign_root(&root_ca, &root_cert);

// 2. Create CSR
CsrRequest csr;
csr_init(&csr, "example.com", "Example Inc", "US");
csr_sign(&csr, &priv_key, 1024);

// 3. Issue Certificate
X509Certificate leaf_cert;
ca_issue_certificate(&inter_ca, &csr, &leaf_cert, 365);

// 4. Verify Chain
CertChain chain = { .depth = 1, .certs[0] = leaf_cert };
bool valid = cert_chain_verify(&chain, &root_cert, time(NULL));
```

## Environment Variables

None required. All configuration is compile-time through header macros.

## Building Documentation

These markdown files serve as the primary documentation. No separate documentation build step is needed. To view:

```bash
# Any markdown viewer
cat docs/API_REFERENCE.md
```

## Contributing

This is an educational implementation. Contributions that improve correctness, add test vectors, or extend the simplified algorithms are welcome.

## Version History

- v1.0 — Initial release with all 5 modules

## License

Educational use only. Not for production cryptographic operations.
