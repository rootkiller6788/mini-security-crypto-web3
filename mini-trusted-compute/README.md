# mini-trusted-compute — 可信计算 (C 语言实现)

## Module Status: COMPLETE ✅

## Overview

mini-trusted-compute 提供可信执行环境 (TEE)、远程证明、机密计算和 TPM 2.0 平台信任的 C99 实现。
涵盖 Intel SGX、Intel TDX、AMD SEV-SNP、远程证明协议、机密计算威胁模型以及 TPM 信任根。

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                  Application Layer                    │
│  example_sgx  example_tdx_sev  example_tpm           │
├──────────────────────────────────────────────────────┤
│                    Demo Layer                         │
│  demo_attestation  demo_confidential                 │
├──────────────────────────────────────────────────────┤
│                   Core Library                       │
│  sgx_enclave  tdx_amd  remote_attest                 │
│  confidential_comp  tpm_trust                        │
├──────────────────────────────────────────────────────┤
│                  Hardware (CPU Package)               │
│  SGX Enclave  │  TDX TD  │  SEV VM  │  TPM 2.0       │
└──────────────────────────────────────────────────────┘
```

## Modules

| Module | Description |
|--------|-------------|
| `sgx_enclave.h/c` | Intel SGX Enclave lifecycle, EPC, sealing, attestation |
| `tdx_amd.h/c` | Intel TDX Trust Domain, AMD SEV/SEV-ES/SEV-SNP |
| `remote_attest.h/c` | Remote attestation: Quote, IAS, DCAP, TLS integration |
| `confidential_comp.h/c` | Confidential computing, side-channels, mitigations |
| `tpm_trust.h/c` | TPM 2.0 PCR, Quote, sealed keys, measured boot, DICE |

## Build

```sh
make
make run-examples
make run-demos
make clean
```

## References

- Intel SGX Specification
- Intel TDX Specification
- AMD SEV-SNP ABI Specification
- TCG TPM 2.0 Specification
- IETF RATS Architecture (RFC 9334)
