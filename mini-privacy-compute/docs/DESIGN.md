# mini-privacy-compute Design Document

## Architecture

```
mini-privacy-compute/
├── include/          # 5 header files (public API)
│   ├── differential_privacy.h
│   ├── federated_learn.h
│   ├── secure_mpc_comp.h
│   ├── anonymization.h
│   └── pet_tools.h
├── src/              # 5 implementation files
│   ├── differential_privacy.c      (300+ lines)
│   ├── federated_learn.c           (280+ lines)
│   ├── secure_mpc_comp.c           (400+ lines)
│   ├── anonymization.c             (330+ lines)
│   └── pet_tools.c                 (430+ lines)
├── examples/         # 3 usage examples
│   ├── example_dp.c
│   ├── example_fl.c
│   └── example_smpc.c
├── demos/            # 2 comprehensive demonstrations
│   ├── demo_anonymization.c        (250+ lines)
│   └── demo_pet.c                  (350+ lines)
├── docs/             # Documentation
│   ├── API.md
│   └── DESIGN.md
├── README.md
└── Makefile
```

## Design Principles

### 1. C99 Compliance
All code uses C99 features only. No VLAs beyond portable use, no `//` comments in C files. Portable across GCC and MSVC (with minimal adjustments).

### 2. Zero External Dependencies
The library depends only on the C standard library (`stdlib.h`, `string.h`, `math.h`, `stdio.h`, `stdint.h`). All cryptographic primitives are simplified educational implementations.

### 3. Modular API
Each module is independent. You can use just `differential_privacy.h` without linking the others. The only cross-module dependency is `pet_tools.c` which optionally references other modules in demos.

### 4. Naming Conventions
- Functions use `snake_case` with module prefix: `dp_`, `fl_`, `ss_`, `kanon_`, `pet_`
- Types use `PascalCase`: `DPBudget`, `FedAvgState`, `AnonCredential`
- Constants use `UPPER_CASE`

## Module Details

### Module 1: Differential Privacy

**Core concept**: ε-differential privacy guarantees that the output distribution is nearly identical whether or not any single individual's data is included.

**Laplace mechanism**: Adds Laplace(scale) noise where `scale = Δf_L1 / ε`. For L1 sensitivity Δf_L1 = max |f(D) - f(D')| over neighboring datasets.

**Gaussian mechanism**: Adds N(0, σ²) noise where `σ = Δf_L2 · √(2·ln(1.25/δ)) / ε`. Requires δ > 0 (approximate DP).

**Composition**: Sequential composition sums ε (k queries = k·ε). Parallel composition takes max ε (disjoint data partitions).

**RAPPOR**: Google's randomized response in the frequency domain. Uses bloom filters + randomized flipping. Decoding uses maximum likelihood estimation.

**DP-SGD**: Per-example gradient clipping + Gaussian noise addition. Controlled by clip_norm (C) and noise multiplier (σ/C).

### Module 2: Federated Learning

**FedAvg algorithm**:
1. Server selects C out of K clients
2. Each client downloads global model, trains locally
3. Clients upload gradients (or model deltas)
4. Server averages: `w_{t+1} = Σ (n_k / n) · w^k_{t+1}`

**Secure aggregation**: Each pair of clients shares a random mask. Each client adds all masks for which it is the "source" and subtracts masks for which it is the "target". Masks cancel out pairwise when summing.

**DP-FL**: Apply `fl_dp_protect_update()` which does clip + noise on each client's update before aggregation. Provides user-level DP.

**Vertical vs Horizontal FL**:
- Horizontal: same features, different samples (e.g., different hospitals)
- Vertical: same samples, different features (e.g., bank + insurance company)

### Module 3: SMPC

**Secret sharing**: Additive secret sharing over a prime field: x = Σ shares[i] mod p. Addition is local (no communication). Multiplication requires Beaver triples.

**Beaver triples**: Pre-computed triples (a,b,c) where c = a·b mod p. For x·y: open d=x-a and e=y-b, compute xy = c + d·b + e·a + d·e.

**SPDZ**: Information-theoretic MAC scheme. Each value [x] has a MAC share α·x where α is a global key. MAC check at the end detects cheating.

**Garbled circuits**: Boolean circuits where each wire has two random labels. Gates encrypt output labels under input labels. Evaluator decrypts one label per wire obliviously.

**ORAM**: Oblivious RAM hides access patterns. Simplified tree-based path ORAM implementation.

**PSI**: ECDH-based Private Set Intersection. Both parties hash their items, exchange hashed sets, compute intersection.

**PIR**: Private Information Retrieval. Client queries a specific record without revealing which one. IT-PIR uses linear combinations.

### Module 4: Anonymization

**k-anonymity**: Each record in the released dataset is indistinguishable from at least k-1 other records with respect to quasi-identifiers.

**l-diversity**: k-anonymous groups must have at least l "well-represented" distinct sensitive values. Variants: distinct l-diversity, entropy l-diversity, recursive (c,l)-diversity.

**t-closeness**: The distribution of sensitive values in any equivalence class must be within distance t (measured by EMD) from the overall distribution.

**De-anonymization attacks**: Simulates Netflix Prize-style (rating pattern correlation) and AOL-style (search query uniqueness) attacks.

**Re-identification scoring**: Four risk measures:
- Prosecutor risk: P(record belongs to specific target)
- Journalist risk: P(at least one match in population)
- Marketer risk: P(at least one record linkable)
- Uniqueness: fraction of unique quasi-identifier combinations

### Module 5: PET Tools

**On-device processing**: Minimizes data leaving the device. Computes locally, sends only essential results.

**Secure enclaves (TEE)**: Trusted Execution Environment abstraction with attestation, sealed storage, and isolated computation.

**Anonymous credentials**: Issue credentials with hidden attributes. Present selectively (reveal only specific attributes). Based on blind signatures + commitment schemes.

**ZK identity proofs**: Zero-knowledge proofs for identity claims without revealing the underlying identity. Range proofs for age verification.

**Verifiable credentials (W3C)**: JSON-based credentials with DID-based issuers, JWS signatures, and revocation registry checks.

**Data minimization**: Purpose-based feature reduction. Only collect/retain features with measured importance above a threshold.

**Privacy by Design**: 8-principle framework with data flow mapping, risk assessment per node, and GDPR compliance validation.

## Security Considerations

1. **Educational implementations**: The cryptographic primitives use simplified hash functions and random number generators. For production, replace with cryptographic libraries (OpenSSL, libsodium).

2. **Timing attacks**: `mpc_constant_time_cmp()` provides a constant-time comparison utility. Other operations are not hardened.

3. **Seed management**: All PRNG functions accept `uint64_t *seed`. Use cryptographic random seeds in production.

4. **DP guarantees**: The Laplace and Gaussian mechanisms mathematically guarantee (ε,δ)-DP assuming correctly computed sensitivity.

## Cross-Module Integration Example

A typical privacy-preserving ML pipeline:

```
Data (on device)
  → datamin_collect_purpose()     [Data minimization]
  → dp_local_laplace()            [Local DP]
  → odproc_minimize_upload()      [On-device processing]
  → fl_dp_protect_update()        [DP in FL]
  → secagg_add_update()           [Secure aggregation]
  → kanon_check()                 [K-anonymity on output]
```

The PET orchestrator (`petorch_*`) coordinates these across the pipeline with audit logging.

## Build and Test

```sh
make          # Build static library + examples + demos
make lib      # Build only libprivacycompute.a
make examples # Build examples only
make demos    # Build demos only
make clean    # Clean build artifacts

# Run
./examples/example_dp
./examples/example_fl
./examples/example_smpc
./demos/demo_anonymization
./demos/demo_pet
```

## License

Educational use. No warranty. Implementations are simplified for learning purposes.
