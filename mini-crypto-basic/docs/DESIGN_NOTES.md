# Design Notes — mini-crypto-basic

Implementation rationale, algorithm details, and trade-offs for each module.

---

## 1. Hash Functions (`hash_func.c`)

### SHA-256 Implementation

**Compression Function:**
The SHA-256 compression function operates on a 256-bit state (eight 32-bit words) and a 512-bit message block. Each round:
1. Computes `S1(e)`, `Ch(e,f,g)`, `t1 = h + S1 + Ch + K[i] + W[i]`
2. Computes `S0(a)`, `Maj(a,b,c)`, `t2 = S0 + Maj`
3. Shifts state: `h←g, g←f, f←e, e←d+t1, d←c, c←b, b←a, a←t1+t2`

**Message Schedule:**
The first 16 words of `W` come directly from the block. Words 16-63 are computed as:
```
W[i] = σ1(W[i-2]) + W[i-7] + σ0(W[i-15]) + W[i-16]
```
where `σ0(x) = ROTR(x,7) ^ ROTR(x,18) ^ SHR(x,3)` and `σ1(x) = ROTR(x,17) ^ ROTR(x,19) ^ SHR(x,10)`.

**Padding (Merkle-Damgard Strengthening):**
1. Append a single `0x80` byte (binary `1` followed by zeros)
2. Fill with zeros until length ≡ 448 mod 512
3. Append 64-bit big-endian representation of original message length in bits

**Design Decision:** One-shot `sha256_hash()` delegates to `init/update/final` for consistency.

### MD5 Implementation

**Round Functions:**
MD5 uses 4 distinct round types (16 operations each, 64 total):

| Round | Function | Formula |
|-------|----------|---------|
| 0-15  | F        | `(x & y) \| (~x & z)` |
| 16-31 | G        | `(x & z) \| (y & ~z)` |
| 32-47 | H        | `x ^ y ^ z` |
| 48-63 | I        | `y ^ (x \| ~z)` |

Each round also has a unique `g` index: `i`, `(5i+1)%16`, `(3i+5)%16`, `(7i)%16` respectively.

**Design Decision:** Round functions are implemented as macros for speed. The transform function uses a function pointer table to select the appropriate round function.

### HMAC Construction

HMAC-H(K, M) = H((K' ⊕ opad) || H((K' ⊕ ipad) || M))

Where:
- `K'` = hash(K) if key > block size, else K padded with zeros
- `ipad` = 0x36 repeated, `opad` = 0x5C repeated
- `||` denotes concatenation
- H is SHA-256 in our implementation

**Design Decision:** The inner hash finalizes first (no buffering needed), then the outer hash computes H(opad || inner_digest). This requires two separate `Sha256Context` instances.

---

## 2. Symmetric Ciphers (`symmetric_cipher.c`)

### AES-128 Implementation Details

**S-box Construction:**
The AES S-box is a fixed 256-byte lookup table. In hardware, it is computed as:
1. Multiplicative inverse in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1
2. Affine transformation over GF(2)

We store the complete precomputed table (and its inverse) as a constant.

**Round Transformations:**
1. **SubBytes:** Byte substitution via S-box lookup → non-linearity
2. **ShiftRows:** Row 0 unshifted, Row 1 ←1, Row 2 ←2, Row 3 ←3 → diffusion
3. **MixColumns:** Column transform using MDS matrix in GF(2^8):

   ```
   [02 03 01 01]   [s0]
   [01 02 03 01] * [s1]
   [01 01 02 03]   [s2]
   [03 01 01 02]   [s3]
   ```

   Multiplication by 2 in GF(2^8): `(x << 1) ^ ((x & 0x80) ? 0x1B : 0)`
   Multiplication by 3: `mul2(x) ^ x`

4. **AddRoundKey:** Simple XOR with round key → key mixing

**Key Expansion:**
- First round key = original key
- For 128-bit key, 44 words total (4 words × 11 rounds)
- Each word: `w[i] = w[i-4] ⊕ temp` where temp = SubWord(RotWord(w[i-1])) ⊕ Rcon[i/4] (every 4 words) or just w[i-1] (otherwise)

**Design Decision:** We expose each transformation as a standalone function for educational tracing. The higher-level `encrypt_block`/`decrypt_block` compose them in the correct order.

### DES Implementation Details

**Feistel Network:**
Each of 16 rounds:
```
L[i] = R[i-1]
R[i] = L[i-1] ⊕ F(R[i-1], K[i])
```
Where the F-function:
1. Expansion permutation (32→48 bits)
2. XOR with round key
3. S-box substitution (6→4 bits × 8 boxes = 32 bits)
4. P-box permutation (32 bits)

**Key Schedule:**
- PC-1: 64-bit key → 56 bits (strips parity)
- Split into C[0] (28 bits) and D[0] (28 bits)
- Rotate left by shift schedule (1 or 2 bits)
- PC-2: 56 bits → 48 bits subkey

**Design Decision:** DES is included purely for historical/educational comparison. It is NOT secure for modern use (56-bit key, 64-bit block).

### Mode Implementations

**CBC (Cipher Block Chaining):**
```
Encrypt: C[i] = E_K(P[i] ⊕ IV)       for i=0
         C[i] = E_K(P[i] ⊕ C[i-1])   for i>0
Decrypt: P[i] = D_K(C[i]) ⊕ IV       for i=0
         P[i] = D_K(C[i]) ⊕ C[i-1]   for i>0
```

**CTR (Counter):**
```
Keystream[i] = E_K(Nonce || Counter+i)
Cipher[i] = Plain[i] ⊕ Keystream[i]
```
CTR encrypt and decrypt are identical operations.

**Design Decision:** The CBC implementation buffers partial blocks in `buf_len` but does not automatically pad. Users must call `pkcs7_pad()` before CBC encrypt.

### PKCS7 Padding

The padding value equals the number of padding bytes needed. For example, if 3 bytes are needed, each of the 3 padding bytes is `0x03`. Minimum padding is 1 byte, maximum is `block_size` bytes. Unpadding validates that all padding bytes have the same value.

---

## 3. Asymmetric Ciphers (`asymmetric_cipher.c`)

### Big Integer Library

**Data Layout:**
32-bit little-endian word array. Word at index 0 is the least significant. Maximum 64 words = 2048 bits.

**Multiplication:**
Schoolbook multiplication with 64-bit accumulator to hold carries:
```
for i in 0..a->num_words:
    carry = 0
    for j in 0..b->num_words:
        prod = a[i] * b[j] + r[i+j] + carry
        r[i+j] = prod & 0xFFFFFFFF
        carry = prod >> 32
```

**Modular Exponentiation:**
Square-and-multiply (left-to-right binary method):
```
result = 1
base = base mod n
for each bit of exponent (MSB to LSB):
    result = (result * result) mod n
    if bit == 1: result = (result * base) mod n
```

**Modular Inverse:**
Extended Euclidean Algorithm:
```
r0 = a, r1 = mod
t0 = 0, t1 = 1
while r1 > 0:
    q = r0 / r1
    (r0, r1) = (r1, r0 - q*r1)
    (t0, t1) = (t1, t0 - q*t1)
return t0 mod mod
```

**Primality Testing:**
Miller-Rabin probabilistic test with `k` iterations. Writes n-1 as d·2^s where d is odd, then tests random bases.

### RSA

**Key Generation:**
1. Select two primes p, q (size ~ key_bits/2)
2. Compute n = p·q, φ(n) = (p-1)(q-1)
3. Choose e = 65537 (standard)
4. Compute d = e^{-1} mod φ(n)
5. Verify e·d ≡ 1 (mod φ(n))

**CRT Acceleration:**
```
dp = d mod (p-1)
dq = d mod (q-1)
qinv = q^{-1} mod p

m1 = c^{dp} mod p
m2 = c^{dq} mod q
h = qinv*(m1 - m2) mod p
m = m2 + h*q
```
CRT is approximately 4× faster than direct exponentiation.

**Design Decision:** Uses fixed demonstration primes rather than random generation, for deterministic and repeatable output in demos.

### ECDH (secp256k1 Simulation)

**Curve (secp256k1):**
y² = x³ + 7 over a prime field of 256 bits. Generator point G is the standard secp256k1 generator.

**Simulated Arithmetic:**
The actual implementation uses a simplified modular field (mod 251) for demonstration purposes, making the point operations fast and deterministic. This is NOT real secp256k1 arithmetic.

**Double-and-Add Scalar Multiplication:**
```
R = O (infinity)
for each bit of scalar (MSB to LSB):
    R = 2R (point doubling)
    if bit == 1: R = R + P (point addition)
```

**Key Exchange:**
```
Alice: a_priv → a_pub = a_priv * G
Bob:   b_priv → b_pub = b_priv * G
Alice: shared = a_priv * b_pub
Bob:   shared = b_priv * a_pub
Both match: a_priv * b_priv * G == b_priv * a_priv * G
```

---

## 4. Digital Signatures (`digital_sig.c`)

### RSA-PSS

**Encoding Process (EMSA-PSS):**
1. Hash message: `mHash = H(M)`
2. Generate `M' = 0x00*8 || mHash || salt`
3. Hash M': `H' = H(M')`
4. Build DB: `ps*PS_len || 0x01 || salt` where PS = zeros
5. Mask DB: `maskedDB = DB ⊕ MGF1(H', emLen - hLen - 1)`
6. Set leftmost `8*emLen - emBits` bits to 0
7. Assemble: `EM = maskedDB || H' || 0xBC`
8. Sign: `S = EM^d mod n`

**Verification:**
The EM is recovered by `S^e mod n`, then the salt is extracted and verified against the message hash.

### ECDSA

**Signing:**
1. Choose random k (nonce)
2. Compute `R = k * G`, let `r = R.x mod n`
3. Compute `s = k^{-1} * (H(M) + r * priv) mod n`
4. Signature is (r, s)

**Verification:**
1. Compute `w = s^{-1} mod n`
2. Compute `u1 = H(M) * w mod n`, `u2 = r * w mod n`
3. Compute `P = u1*G + u2*Q_pub`
4. Verify `P.x mod n == r`

### Hash-then-Sign

Provides a uniform interface for both RSA-PSS and ECDSA. Internally:
1. Hash the message with SHA-256
2. Call the appropriate sign/verify function

---

## 5. PKI Model (`pki_model.c`)

### Certificate Chain Verification

The trust model assumes:
- A root CA certificate is pre-trusted (stored in trust store)
- Each certificate in the chain signs the one before it
- Verification traverses from leaf back to root, checking:
  1. Certificate is within its validity period
  2. Certificate's issuer DN matches the signer's subject DN
  3. Signature on the certificate verifies with the issuer's public key
  4. Certificate has not been revoked (CRL check)

### ACME Protocol Simulation

Simulated steps:
1. **Account Creation:** Generate keypair, register with server → account ID
2. **Order Creation:** Submit domain, receive challenges (HTTP-01, DNS-01)
3. **Authorization:** Prove domain control by responding to challenges
4. **Finalization:** Submit CSR, server issues certificate
5. **Download:** Retrieve the issued certificate

### OCSP Stapling

Instead of clients contacting the OCSP responder directly, the TLS server includes a time-stamped OCSP response ("stapled" to the handshake). This reduces latency and privacy concerns.

The OCSP response contains:
- Certificate serial number
- Status: GOOD / REVOKED / UNKNOWN
- thisUpdate, nextUpdate timestamps
- Signature from an OCSP authorized responder

---

## Memory Management

All contexts are stack-allocated by the caller. No dynamic allocation is required for normal operation. The Merkle-Damgard generic hash uses `calloc` internally (freed before returning). The BigInt library uses fixed-size stack arrays (no heap allocation).

## Thread Safety

None of the functions are thread-safe. Each context should be used by exactly one thread. The library maintains no global state.

## Portability

- Requires `uint32_t`, `uint64_t`, `int64_t` from `<stdint.h>` (C99)
- Requires boolean type from `<stdbool.h>` (C99)
- Uses `memmove()` to handle overlapping memory regions
- No POSIX-specific calls beyond standard C library
- Compiles on GCC, Clang, and MSVC (with C99 support)

## Security Considerations for Production Use

1. **NEVER use this library in production.** It is educational only.
2. RSA key generation uses fixed primes — real implementations must use secure random prime generation
3. ECDH uses simulated curve arithmetic — real implementations must use constant-time field operations
4. DES is completely broken — use AES-256 instead
5. MD5 is collision-broken — use SHA-256 or SHA-3
6. CBC mode requires MAC to be secure (Encrypt-then-MAC)
7. RSA without OAEP is vulnerable to various attacks
8. The BigInt library is not constant-time — vulnerable to timing side-channel attacks
9. Random number generation uses `rand()` which is not cryptographically secure

## Testing

Test vectors are documented in the source headers. The demos serve as integration tests. Expected outputs:
- AES encrypt: Use FIPS 197 Appendix B test vector
- SHA-256: Use FIPS 180-4 test vector
- HMAC: Use RFC 4231 test cases

## Performance Notes

- SHA-256: ~50 MB/s (single-threaded, no hardware acceleration)
- AES-128: ~8 MB/s (pure software, no AES-NI)
- RSA 1024-bit keygen: ~10ms on modern CPU
- ECDH (simulated): ~1ms per scalar multiply

These are approximate and unoptimized. Real cryptographic libraries use SIMD instructions, hardware acceleration, and assembly optimizations.

## References

1. NIST FIPS 180-4 — Secure Hash Standard
2. NIST FIPS 197 — Advanced Encryption Standard
3. NIST FIPS 46-3 — Data Encryption Standard
4. RFC 1321 — MD5 Message-Digest Algorithm
5. RFC 2104 — HMAC: Keyed-Hashing for Message Authentication
6. RFC 3447 / 8017 — PKCS #1: RSA Cryptography
7. RFC 5280 — X.509 PKI and CRL
8. RFC 6960 — Online Certificate Status Protocol (OCSP)
9. RFC 8555 — Automatic Certificate Management Environment (ACME)
10. SEC 2: Recommended Elliptic Curve Domain Parameters (secp256k1)
