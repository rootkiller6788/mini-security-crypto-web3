# Design Documentation — mini-trusted-compute

## 1. Architecture Overview

mini-trusted-compute models five key trusted computing technologies in C99:

```
┌─────────────────────────────────────────────────────────────────┐
│                      User Applications                           │
│    (example_sgx / example_tdx_sev / example_tpm)                │
├─────────────────────────────────────────────────────────────────┤
│                        Demo Layer                                │
│    demo_attestation  —  Remote attestation end-to-end flow       │
│    demo_confidential —  Full trust chain + data lifecycle        │
├─────────────────────────────────────────────────────────────────┤
│                      Core API Layer                              │
│                                                                │
│  ┌──────────┐ ┌──────────┐ ┌──────────────┐ ┌────────────────┐  │
│  │ SGX      │ │ TDX/AMD  │ │ Remote       │ │ Confidential   │  │
│  │ Enclave  │ │ SEV      │ │ Attestation  │ │ Computing      │  │
│  └──────────┘ └──────────┘ └──────────────┘ └────────────────┘  │
│  ┌──────────┐                                                   │
│  │ TPM 2.0  │                                                   │
│  │ Trust    │                                                   │
│  └──────────┘                                                   │
├─────────────────────────────────────────────────────────────────┤
│                    Hardware Trust Root                           │
│  ┌───────┐  ┌───────┐  ┌───────┐  ┌───────┐  ┌───────┐        │
│  │  SGX  │  │  TDX  │  │  SEV  │  │  TME  │  │ TPM   │        │
│  │ EPC   │  │ SEAM  │  │  PSP  │  │ MKTME │  │ 2.0   │        │
│  └───────┘  └───────┘  └───────┘  └───────┘  └───────┘        │
└─────────────────────────────────────────────────────────────────┘
```

## 2. Intel SGX Enclave Model

### 2.1 Enclave Lifecycle

```
                     ┌──────────────┐
                     │ UNINITIALIZED │
                     └──────┬───────┘
                            │ ECREATE
                     ┌──────┴───────┐
                     │  INITIALIZED  │ ←── EADD (add pages)
                     └──────┬───────┘     EEXTEND (hash pages)
                            │ EINIT
                     ┌──────┴───────┐
                     │   RUNNING     │ ←── EENTER/EEXIT
                     └──────┬───────┘
                            │ EREMOVE
                     ┌──────┴───────┐
                     │  DESTROYED    │
                     └──────────────┘
```

### 2.2 EPC (Enclave Page Cache) Management

- EPC is carved from system DRAM at boot
- Each EPC page is 4 KiB (x86 page size)
- EPC maps to SECS (meta), TCS (thread), REGULAR (code/data), VA (version array)
- The CPU's Memory Encryption Engine (MEE) protects EPC confidentiality and integrity

### 2.3 Measurement (MRENCLAVE)

MRENCLAVE is a SHA-256 cryptographic hash of the enclave build:
- ECREATE: hash of SECS structure (size, base, attributes)
- EADD: hash of page content + SECINFO (RWX flags)
- EEXTEND: hash of 256-byte chunk (for incremental measurement)
- EINIT: final measurement locked

### 2.4 Sealing

```
Sealing Key = KDF(CPU Fused Key, MRENCLAVE | MRSIGNER, Policy)
```

- Key derived from:
  - CPU Root Key (fused at manufacturing)
  - Enclave Identity (MRENCLAVE or MRSIGNER)
  - Key Policy (product-bound vs enclave-bound)
  - CPUSVN, ISVSVN for version control

### 2.5 Attestation Flow

```
Prover (Enclave)                    Verifier (Relying Party)
─────────────────                   ─────────────────────────
                                    1. Generate Challenge (nonce)
2. Generate Quote (REPORT + sig)  ←───────────────────
   ├── EREPORT (local)
   ├── Quoting Enclave signs
   └── EPID or ECDSA attests
3. Send Quote + Cert Chain ─────────────────────────→
                                    4. Verify Quote signature
                                    5. Verify Cert Chain → Intel CA
                                    6. Check revocation (GroupID, TCB)
                                    7. Compare MRENCLAVE/MRSIGNER
                                    8. Return Attestation Result
```

## 3. Intel TDX Trust Domain

### 3.1 TDX Architecture

```
┌─────────────────────────────────────────────┐
│                  VMM (Untrusted)             │
│   ┌──────────────────────────────────────┐  │
│   │          Trust Domain (TD)            │  │
│   │   ┌──────────┐  ┌──────────┐        │  │
│   │   │ TD VCPU  │  │ TD VCPU  │  ...   │  │
│   │   └──────────┘  └──────────┘        │  │
│   │   ┌─────────────────────────────┐    │  │
│   │   │   Secure EPT (Private)      │    │  │
│   │   │   ┌───┐ ┌───┐ ┌───┐       │    │  │
│   │   │   │GPA│ │GPA│ │GPA│  ...  │    │  │
│   │   │   └───┘ └───┘ └───┘       │    │  │
│   │   └─────────────────────────────┘    │  │
│   └──────────────────────────────────────┘  │
│                                              │
│   SEAM (Secure Arbitration Mode)             │
│   ┌──────────────────────────────────────┐  │
│   │  TDX Module (Intel-signed)            │  │
│   │  - MKTME Key Management              │  │
│   │  - Secure EPT Operations             │  │
│   │  - Measurement Extension             │  │
│   └──────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
```

### 3.2 TD Measurement (MRTD)

- MRTD = SHA-384 hash of TD firmware (TDVF) and initial memory
- Extendable via TDH.MR.EXTEND for runtime measurement
- MR ConfigID, MR Owner, MR OwnerConfig for policy binding

### 3.3 SEAM Calls

SEAM calls are the interface between VMM and TDX module:
- TDH.MNG.* — management operations (create, destroy, key config)
- TDH.MEM.* — memory operations (page add/remove, SEPT)
- TDH.VP.* — vCPU operations (create, enter, flush)
- TDH.MR.* — measurement operations (extend, finalize)
- TDH.SYS.* — system operations (config read)

## 4. AMD SEV / SEV-ES / SEV-SNP

### 4.1 SEV Generations

| Generation | Feature |
|-----------|---------|
| SEV | Memory encryption per VM (one key per ASID) |
| SEV-ES | Encrypted VM state (register encryption on VMExit) |
| SEV-SNP | Secure Nested Paging + Attestation |

### 4.2 SEV-SNP Attestation

```
AMD PSP Firmware
      │
      ├── VCEK (Versioned Chip Endorsement Key)
      │       └── Certified by AMD Root Key (ARK → ASK → VCEK)
      │
      └── Attestation Report
              ├── Guest Measurement (SHA-384)
              ├── Platform TCB version
              ├── VM Policy
              ├── ID Block Digest
              ├── Author Key Digest
              ├── Family ID / Image ID
              └── Signature (VCEK)
```

### 4.3 Launch Measurement

```
Launch measurement = SHA-384(...)
  ├── Initial VM memory pages
  ├── VMSA (VM Save Area)
  ├── Policy
  ├── ID Block (optional)
  └── Host Data
```

## 5. Remote Attestation Protocol

### 5.1 Challenge-Response Model

```
Challenge (from Verifier):
    nonce[32] | session_id[32] | timeout | expected_measurements

Response (from Prover):
    quote | signature | cert_chain | session_id
```

### 5.2 IAS (Intel Attestation Service)

- EPID-based: uses Enhanced Privacy ID (group signature)
- Verifier sends Quote to IAS API
- IAS returns signed verification report
- IAS verifies: signature, group revocation, TCB level

### 5.3 DCAP (Data Center Attestation Primitives)

- ECDSA-based: X.509 certificate chain to Intel CA
- PCK (Provisioning Certification Key) certifies platform
- TCB info retrieved from Intel's Provisioning Service
- No runtime dependency on Intel service for verification

### 5.4 TLS + Attestation Integration

```
ClientHello │─── attestation_extension: { challenge }
ServerHello │─── attestation_extension: { quote + cert_chain }
Certificate│─── includes attestation evidence
```

## 6. Confidential Computing Security

### 6.1 Trust Boundary

The trust boundary is the **CPU package**:
- Inside: CPU cores, caches, memory controller, TEE
- Outside: DRAM (encrypted), I/O (untrusted), firmware, VMM

### 6.2 Memory Encryption

- **TME** (Total Memory Encryption): One key for all memory
- **MKTME** (Multi-Key TME): Per-domain keys, up to 16 keys
- KeyID bits encoded in physical address

### 6.3 Side-Channel Attack Mitigations

| Attack | Mitigation |
|--------|-----------|
| Cache timing | CAT (Cache Allocation Technology), cache coloring |
| Page fault | Page table hardening, prefault pages |
| Branch shadow | Retpoline, IBPB, IBRS |
| L1D eviction | L1D flush on enclave exit |
| LVI | LFENCE after every memory load |
| Microarch data | VERW, L1D_FLUSH |
| Power analysis | DVFS randomization |
| EM radiation | Package shielding |

### 6.4 Known Intel SGX Vulnerabilities

| Vulnerability | Year | Class | Impact |
|--------------|------|-------|--------|
| LVI | 2020 | Speculative | Enclave data read via load value injection |
| SGAxe | 2020 | Cache | EPC attestation key leakage |
| Plundervolt | 2019 | Physical | Undervolting faults key derivation |
| CrossTalk | 2020 | Microcode | Cross-core staging buffer leak |
| MicroScope | 2020 | Microcode | SGX key replay |
| ÆPIC Leak | 2022 | Hardware | APIC MMIO read from enclave |

### 6.5 Known AMD SEV Vulnerabilities

| Vulnerability | Year | Class | Impact |
|--------------|------|-------|--------|
| SEVered | 2020 | Side-Channel | Page-level memory access pattern leak |
| Cache Attacks | 2021 | Cache | Cross-VM cache-based key extraction |

### 6.6 Constant-Time Crypto in Enclaves

Critical for preventing timing side-channels within enclaves:
- `cc_constant_time_compare()` — secret-independent byte comparison
- `cc_constant_time_select()` — branchless conditional select
- `cc_constant_time_equal()` — timing-safe equality test

All operations use `volatile` to prevent compiler optimization that might
reintroduce timing leaks. No early exits, no branch-on-secret-data.

## 7. TPM 2.0 Platform Trust

### 7.1 TPM Architecture

```
┌──────────────────────────────────────────────┐
│                   TPM 2.0                      │
│  ┌────────────┐  ┌────────────┐              │
│  │  PCR Banks  │  │ Key Store   │              │
│  │ (SHA-256)   │  │ (SRK, EK,   │              │
│  │             │  │  AK, RSA)   │              │
│  └────────────┘  └────────────┘              │
│  ┌────────────┐  ┌────────────┐              │
│  │ NV Storage  │  │ RNG (DRBG)  │              │
│  │ (Lockboxes) │  │             │              │
│  └────────────┘  └────────────┘              │
│  ┌──────────────────────────────────────┐    │
│  │  Measured Boot Event Log             │    │
│  └──────────────────────────────────────┘    │
└──────────────────────────────────────────────┘
```

### 7.2 PCR Allocation

| PCR Index | Usage | Type |
|----------|-------|------|
| 0 | CRTM / BIOS | Static |
| 1 | Platform Config | Static |
| 2 | Option ROMs | Static |
| 3 | Option ROM Config | Static |
| 4 | IPL (MBR) | Static |
| 5 | IPL Config | Static |
| 6 | State Transition | Static |
| 7 | Platform Manufacturer | Static |
| 8-15 | OS-defined | Variable |
| 16 | Debug | Variable |
| 23 | Application | Variable |

### 7.3 Measured Boot

```
CRTM → BIOS → Option ROMs → MBR → Bootloader → OS Kernel
  │      │         │         │        │            │
  ▼      ▼         ▼         ▼        ▼            ▼
PCR0   PCR1      PCR2      PCR4     PCR8         PCR9
```

Each stage measures the next stage before executing it:
```
PCR[n] = Hash(PCR[n] || Digest(next_stage_code))
```

### 7.4 Key Hierarchy

```
Primary Seed (NV, generated at manufacturing)
    │
    ├── Storage Root Key (SRK) — persistent in TPM NV
    │       ├── Storage Keys
    │       └── Sealed Objects
    │
    ├── Endorsement Key (EK) — unique per TPM
    │       ├── EK Certificate (signed by TPM manufacturer)
    │       └── Attestation Keys (AK) — certified by EK
    │
    └── Platform Key
            └── Platform-specific keys
```

### 7.5 DICE (Device Identifier Composition Engine)

DICE creates a layered identity chain without requiring TPM:

```
ROM (Layer 0): CDI₀ = Hash(ROM_Code)
    │
    ├── DeviceID Key = KDF(CDI₀, "device-id")
    │   DeviceID Cert signed by DeviceID Key
    │
Bootloader (Layer 1): CDI₁ = Hash(CDI₀ || Bootloader_Code)
    │
    ├── Alias Key = KDF(CDI₁, "alias")
    │   Alias Cert signed by DeviceID Key
    │
OS (Layer 2): CDI₂ = Hash(CDI₁ || OS_Code)
    │
Application (Layer 3): CDI₃ = Hash(CDI₂ || App_Code)
```

Key property: if firmware changes, CDI changes, all derived keys change.
This cryptographically ensures only authorized firmware can access data.

### 7.6 TPM vs TEE vs HSM Comparison

| Property | TPM | TEE (SGX/TDX) | HSM |
|----------|-----|---------------|-----|
| Trust Root | Hardware chip | CPU package | Dedicated hardware |
| Isolation | Physical | Cryptographic | Physical |
| Performance | Low | High | Medium |
| Key Storage | Limited NV | Encrypted in EPC | Dedicated secure storage |
| Attestation | Platform state | Code identity | Transport keys |
| Use Case | Boot integrity | Confidential workloads | Root CA, signing |

### 7.7 Sealing Model

```
sealed_blob = {
    data: AES_encrypt(srk, plaintext),
    pcr_mask: [0, 1, 2]  // PCRs that must match
}

Unseal only succeeds if current PCR[0..2] match values at seal time:
∀ i ∈ pcr_mask: PCR[i]_current == PCR[i]_sealed
```

## 8. Cross-TEE Threat Model

```
                    Trust Boundary
    ┌──────────────────────┼────────────────────────┐
    │                      │                        │
    ▼                      ▼                        ▼
 Inside TEE           CPU Package              Outside
 ┌─────────┐       ┌──────────────┐        ┌──────────┐
 │ Enclave │◄─────►│Cache/Memory  │◄──────►│ DRAM     │
 │ (SGX)   │       │ Controller   │        │ (encr)   │
 └─────────┘       │ (encrypted)  │        └──────────┘
                   └──────────────┘        ┌──────────┐
 Threat:           Threat:                 │ I/O Bus  │
 - Side channels   - Microcode bugs        │ (plain)  │
 - Speculative     - Physical probing      └──────────┘
 - Page faults     - Power glitching
                   - EM leakage
```

## 9. References

1. Intel SGX Specification (Intel, 2014–2025)
2. Intel TDX Specification v1.5 (Intel, 2022)
3. AMD SEV-SNP ABI Specification (AMD, 2024)
4. TCG TPM 2.0 Library Specification (TCG, 2016)
5. IETF RATS Architecture RFC 9334 (IETF, 2023)
6. DICE Architecture Specification (TCG, 2018)
7. "LVI: Hijacking Transient Execution" (Van Bulck et al., 2020)
8. "SGAxe: How SGX Fails in Practice" (Van Schaik et al., 2020)
9. "Plundervolt: Software-based Fault Injection" (Buhan et al., 2019)
10. "SEVered: Subverting AMD's SEV" (Werner et al., 2020)
