# mini-adv-crypto Design Document

## Overview

**mini-adv-crypto** is a teaching-oriented C99 library implementing five advanced cryptography domains:
zero-knowledge proofs, homomorphic encryption, secure multi-party computation, post-quantum
cryptography, and threshold signatures.

## Design Philosophy

### Simplicity First
- All implementations are educational simplifications of real-world protocols
- No external dependencies beyond the C standard library
- Clearly commented algorithms with explicit step-by-step structure

### Modularity
- Each module is self-contained (one .h / one .c pair)
- No cross-module dependencies
- Each module exposes a version function: `xx_module_version()`

### Auditability
- Linear control flow, no hidden state
- All allocations are stack-based (fixed-size arrays)
- Deterministic "randomness" for reproducible testing

---

## Module Designs

### 1. Zero-Knowledge Proofs (`zk_proof.c`)

#### Architecture
```
Field Arithmetic → R1CS → QAP → Trusted Setup → Groth16/Pinocchio Proof → Verification
                                                                  ↓
                                                            STARK Trace → FRI
```

#### Key Design Decisions
- **Field**: Uses a simplified 128-bit prime field with 2-limb bigint arithmetic
- **R1CS**: Dense matrix representation with fixed dimensions (ZK_MAX_VARS x ZK_MAX_CONSTRAINTS)
- **QAP**: Lagrange interpolation over constraint evaluation points
- **Groth16**: Three-element proof (pi_a, pi_b, pi_c) + randomization element (pi_z)
- **STARK**: Execution trace with Merkle commitment and FRI low-degree testing

#### Security Notes
- This implementation is for educational purposes only
- Real Groth16 requires pairing-friendly elliptic curves (e.g., BN254, BLS12-381)
- Real STARKs require FFT over large extension fields
- The toxic waste ceremony is simulated, not cryptographically secure

---

### 2. Homomorphic Encryption (`homomorphic_enc.c`)

#### Architecture
```
BigInt Utilities → Paillier (Additive HE) → Scalar Multiplication
                 → BFV (Somewhat HE)      → Add, Multiply, Noise Management
```

#### Key Design Decisions
- **Paillier**: Textbook implementation with composite n = p*q
  - Encryption: c = g^m * r^n mod n^2
  - Decryption: m = L(c^λ mod n^2) * μ mod n
  - Homomorphic add: c1 * c2 mod n^2
- **BFV**: Simplified ring-LWE based scheme
  - Ciphertext = (c0, c1) where c0 + c1*s ≈ Δ*m
  - Noise grows additively on addition, multiplicatively on multiplication
  - Noise budget tracking for bootstrap decisions

#### Security Notes
- Keys are generated from fixed primes (deterministic, not secure)
- BFV uses a trivial secret key for demonstration
- Real BFV requires NTT-optimized polynomial multiplication
- No bootstrapping implemented (noise grows without bound)

---

### 3. Secure Multi-Party Computation (`mpc_proto.c`)

#### Architecture
```
Shamir SSS ← Secret Sharing
Yao GC     ← Garbled Circuit
OT         ← Oblivious Transfer
SPDZ       ← Authenticated Shares
             ↓
      Multi-Party Sum
```

#### Key Design Decisions
- **Shamir SSS**: Polynomial evaluation over prime field 2^31 - 1
  - t-of-n threshold: polynomial of degree t-1
  - Reconstruction via Lagrange interpolation
  - Homomorphic properties: share addition (free), share multiplication (degree doubles)
- **Yao GC**: Hash-based key derivation for AND gates
  - Each gate has 4 ciphertexts (k0[0], k0[1], k1[0], k1[1])
  - Evaluation: decrypt exactly one entry per gate
- **OT**: Simplified 1-of-2 protocol
- **SPDZ**: Information-theoretic MACs on secret shares
  - Each share has (value, mac_key, mac) where mac = value * mac_key

#### Security Notes
- Shamir uses a small prime (not cryptographically large)
- Garbled circuits lack point-and-permute optimization
- OT is not based on hard cryptographic assumptions
- SPDZ MAC verification is local-only (no broadcast)

---

### 4. Post-Quantum Cryptography (`post_quantum.c`)

#### Architecture
```
Polynomial Ring (Z_q[X]/(X^256+1))
    ├── NTT/INTT transforms
    ├── CBD sampling
    ├── Kyber (KEM): Keygen → Encaps → Decaps
    ├── Dilithium (Signature): Keygen → Sign → Verify
    └── SPHINCS+ (Hash-based): Keygen → Sign → Verify
```

#### Key Design Decisions
- **Kyber**: Module-LWE based KEM
  - Ring: Z_3329[X]/(X^256+1)
  - Secret: short polynomial vectors (eta=2)
  - IND-CPA core + FO transform for IND-CCA2
  - Shared secret derived via KDF from pre-key
- **Dilithium**: Module-LWE based signature
  - Ring: Z_8380417[X]/(X^256+1)
  - Fiat-Shamir with aborts (rejection sampling)
  - Signature: (z, c) where z = y + c*s
- **SPHINCS+**: Stateless hash-based signature
  - Hypertree of WOTS+ one-time signatures
  - FORS few-time signatures for leaf nodes
  - Root from hypertree as public key

#### Security Notes
- Simplified NTT without precomputed twiddle factors
- Polynomial multiplication is O(n^2) schoolbook (not NTT-optimized)
- Randomness is deterministic
- SPHINCS+ hypertree is conceptual, not complete

---

### 5. Threshold Signatures (`threshold_sig.c`)

#### Architecture
```
SSS (Shamir Secret Sharing)
    ├── Key Sharding
    ├── Lagrange Interpolation
    └── Share Homomorphism

FROST (Flexible Round-Optimized Schnorr Threshold)
    ├── Round 1: Nonce commitment (binding)
    ├── Round 2: Signature share generation
    └── Aggregation: R = ΣR_i, z = Σz_i

DKG (Distributed Key Generation)
    ├── Round 1: Generate polynomial, commit coefficients
    ├── Round 2: Distribute shares securely
    ├── Round 3: Compute group public key
    └── Finalize: Output group PK + individual SK shares

Share Refresh (Proactive Security)
    ├── Generate zero-sum polynomial
    ├── Add shares to existing shares
    └── Verify: secret unchanged
```

#### Key Design Decisions
- **FROST**: Two-round threshold Schnorr
  - Round 1: Each party generates nonce (r_i, R_i) with binding commitment
  - Round 2: Each party computes z_i = r_i + c * λ_i * sk_i
  - Aggregation: R = ΣR_i, z = Σz_i
  - Verification: g^z = R * PK^c (standard Schnorr)
- **DKG**: Three-round Pedersen-style DKG
  - Each party acts as a dealer, contributes to group key
  - Group public key = Σ PK_i (additive aggregation)
- **Proactive refresh**: Add shares of zero to existing shares
  - New polynomial coeffs[0] = 0 ensures secret unchanged
  - Periodic refresh limits attacker's window

#### Security Notes
- DKG uses simplified commitment scheme (not Pedersen)
- FROST binding factor is simplified
- Share refresh needs zero-knowledge proofs in production
- Lagrange coefficients assume sequential party indices

---

## Data Flow Patterns

### Typical ZK Proof Flow
```
1. Define computation as R1CS constraints
2. Generate witness (input + intermediate values)
3. Convert R1CS to QAP
4. Run trusted setup → (PK, VK)
5. Prover: Groth16_prove(PK, witness) → proof
6. Verifier: Groth16_verify(VK, public_inputs, proof) → accept/reject
```

### Typical HE Computation Flow
```
1. Keygen → (pub_key, priv_key)
2. Encrypt inputs: ct_i = Encrypt(pub_key, m_i)
3. Compute on ciphertexts: ct_result = F(ct_1, ..., ct_n)
4. Decrypt: m_result = Decrypt(priv_key, ct_result)
5. Check: noise_budget > 0 (for BFV)
```

### Typical MPC Flow
```
1. Secret share inputs among parties
2. Parties perform local computations on shares
3. Parties communicate for multiplication (Beaver triples)
4. Reconstruct output from enough shares
```

### Typical Threshold Signing Flow
```
1. DKG: Parties jointly generate group key
2. Signing round 1: Each party generates nonce
3. Signing round 2: Each party generates signature share
4. Aggregator combines shares into full signature
5. Verifier checks signature against group public key
```

---

## Limitations & Future Work

### Current Limitations
- Fixed array sizes (cannot scale beyond compile-time constants)
- No constant-time operations (vulnerable to timing attacks)
- Deterministic randomness (not suitable for production)
- Simplified polynomial arithmetic (not NTT-optimized)
- No side-channel protections

### Future Work
- Dynamic memory allocation with configurable limits
- NTT-based polynomial multiplication for PQ and HE modules
- Proper random number generation (OS entropy)
- Constant-time field operations
- Full SPHINCS+ hypertree implementation
- Bootstrapping for BFV
- Recursive proof composition for zk-SNARKs
- Full SPDZ offline/online phases

---

## References

1. Groth16: "On the Size of Pairing-based Non-interactive Arguments" (Groth, 2016)
2. Pinocchio: "Pinocchio: Nearly Practical Verifiable Computation" (Parno et al., 2013)
3. Paillier: "Public-Key Cryptosystems Based on Composite Degree Residuosity Classes" (Paillier, 1999)
4. BFV: "Somewhat Practical Fully Homomorphic Encryption" (Fan & Vercauteren, 2012)
5. Shamir: "How to Share a Secret" (Shamir, 1979)
6. Yao: "How to Generate and Exchange Secrets" (Yao, 1986)
7. SPDZ: "Multiparty Computation from Somewhat Homomorphic Encryption" (Damgard et al., 2012)
8. Kyber: NIST PQC Round 3 submission (Schwabe et al.)
9. Dilithium: NIST PQC Round 3 submission (Ducas et al.)
10. SPHINCS+: NIST PQC Round 3 submission (Bernstein et al.)
11. FROST: "Flexible Round-Optimized Schnorr Threshold Signatures" (Komlo & Goldberg, 2020)
