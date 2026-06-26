# mini-supply-chain-sec — 供应链安全 (C 语言实现)

## Module Status: COMPLETE ✅

## Overview

A C99 library implementing core supply chain security primitives: SBOM generation (SPDX/CycloneDX), SLSA framework, Sigstore/cosign keyless signing, dependency vulnerability analysis, and in-toto provenance attestation.

## Modules

| Module | Header | Description |
|--------|--------|-------------|
| SBOM | `sbom_gen.h` | SPDX & CycloneDX BOM generation, VEX, in-toto attestation |
| SLSA | `slsa_framework.h` | Supply-chain Levels L0-L4, provenance, build as code |
| Sigstore | `sigstore_cosign.h` | Keyless signing, Fulcio CA, Rekor log, cosign verify |
| DepVuln | `dep_vuln.h` | CVE/CVSS, NVD scanning, reachability, confusion prevention |
| Provenance | `provenance_model.h` | in-toto layouts, Grafeas, Kritis, binary authorization |

## Build

```
make          # build library and all targets
make test     # run examples
make demo     # run demos
make clean
```

Requires: C99 compiler, OpenSSL (libcrypto).

## License

MIT
