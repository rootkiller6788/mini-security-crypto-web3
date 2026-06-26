# Supply Chain Security Guide

## Overview

Modern software supply chains face threats from dependency confusion, compromised build pipelines, unsigned artifacts, and untracked vulnerabilities. This library provides C99 primitives to implement a defense-in-depth supply chain security posture.

## Threat Model

| Threat | Mitigation |
|--------|-----------|
| Dependency confusion | Namespace verification (`dep_vuln_prevent_confusion`) |
| Compromised dependencies | SBOM + vulnerability scanning (`dep_vuln_scan_cyclonedx`) |
| Tampered artifacts | in-toto link verification (`provenance_bundle_verify`) |
| Fake build provenance | SLSA provenance verification (`slsa_verify_provenance`) |
| Unsigned container images | Cosign keyless signing (`cosign_sign_image_keyless`) |
| Replay attacks | Rekor transparency log (`sigstore_rekor_create_entry`) |
| Identity spoofing | Fulcio short-lived certificates (`sigstore_fulcio_request_certificate`) |

## Key Concepts

### SBOM (Software Bill of Materials)

An SBOM enumerates all components in a software artifact. Two dominant formats:

- **SPDX 2.3**: ISO/IEC 5962 standard. Describes packages, relationships, licenses.
- **CycloneDX 1.5**: OWASP standard. Focus on components and dependencies.

Generate SBOM from build metadata using `sbom_spdx_generate_from_build()`. Parse existing SBOM files with `sbom_spdx_parse_json()`.

### VEX (Vulnerability Exploitability eXchange)

VEX documents communicate whether a product is affected by a known vulnerability:

- `VEX_STATUS_AFFECTED` — component is vulnerable
- `VEX_STATUS_NOT_AFFECTED` — component not affected (with justification)
- `VEX_STATUS_FIXED` — vulnerability has been fixed
- `VEX_STATUS_UNDER_INVESTIGATION` — still investigating

### SLSA Framework

Supply-chain Levels for Software Artifacts defines 5 levels:

| Level | Source | Build |
|-------|--------|-------|
| L0 | Any source, any build | No guarantees |
| L1 | Version-controlled source | Scripted/automated build |
| L2 | Signed commits | Build service with provenance |
| L3 | Two-person review, protected branch | Isolated, hermetic builds |
| L4 | All L3 requirements | Reproducible, parameterless builds |

Use `slsa_assess_source_level()` and `slsa_assess_build_level()` to evaluate your pipeline.

### Sigstore Stack

1. **OIDC** (`oidc_identity_t`) — authenticate with OpenID Connect provider
2. **Fulcio** (`fulcio_certificate_t`) — short-lived (10-minute) code signing certificate
3. **Rekor** (`rekor_entry_t`) — immutable transparency log entry
4. **Cosign** (`cosign_signature_t`) — sign and verify container images

Flow: `OIDC Auth -> Fulcio Cert -> Sign -> Rekor Log -> Verify`

### in-toto Framework

Components:

- **Layout** (`in_toto_layout_t`) — defines supply chain steps and inspections
- **Steps** (`in_toto_step_t`) — actions performed by functionaries
- **Inspections** (`in_toto_inspection_t`) — verification commands
- **Link** (`in_toto_link_t`) — signed metadata from each step (materials, products, byproducts)
- **Bundle** (`attestation_bundle_t`) — collection of links with layout

### Binary Authorization

Policies define which builders and signers are authorized for a given binary path:

```c
bin_auth_policy_t* policy = bin_auth_policy_create("/usr/bin/myapp");
bin_auth_policy_add_builder(policy, "github-actions-v2");
bin_auth_result_t* result = bin_auth_check_binary(path, digest, bundle, policy);
```

### Kritis (Deploy-Time Policy)

```
Policy                    Decision
+----------------+        +------------------+
| Attestors      | -----> | ALLOW / DENY     |
| Predicate types|        | Reason           |
| Builder IDs    |        | Vuln violations  |
| SLSA level     |        | SBOM requirement |
+----------------+        +------------------+
```

## Usage Patterns

### Generate and Scan SBOM

```c
cyclonedx_bom_t* bom = sbom_cyclonedx_generate_from_build("./build", "cmake");
nvd_feed_t* feed = dep_vuln_load_nvd_feed("nvdcve-1.1-2024.json");
cve_entry_t** vulns = NULL;
size_t vuln_count = 0;
dep_vuln_scan_cyclonedx(bom, feed, &vulns, &vuln_count);
```

### Keyless Container Signing

```c
oidc_identity_t* id = sigstore_oidc_authenticate("https://oauth2.sigstore.dev/auth", "myapp");
cosign_signature_t* sig = cosign_sign_image_keyless(
    "registry.example.com/myapp:v1.0.0", id,
    "https://fulcio.sigstore.dev", "https://rekor.sigstore.dev");
```

### SLSA Pipeline Assessment

```c
slsa_source_t* src = slsa_source_create("https://github.com/org/repo", "abc123");
slsa_source_set_signed(src, "dev@org.com", "SHA256:...");
slsa_level_t src_level = slsa_assess_source_level(src);
```

### in-toto Attestation Chain

```c
in_toto_layout_t* layout = provenance_layout_create("release-pipeline");
provenance_layout_add_step(layout, "build", "builder-key", cmds, count);

in_toto_link_t* link = provenance_link_create("build", "builder-1", "make build");
provenance_link_add_product(link, "bin/myapp", "sha256:digest");
provenance_link_sign(link, private_key, "key-id");

attestation_bundle_t* bundle = provenance_bundle_create(layout);
provenance_bundle_add_link(bundle, link);
```

## References

- [SLSA v1.0](https://slsa.dev/spec/v1.0/)
- [in-toto Specification](https://github.com/in-toto/docs/blob/master/in-toto-spec.md)
- [Sigstore Documentation](https://docs.sigstore.dev/)
- [SPDX Specification 2.3](https://spdx.dev/specifications/)
- [CycloneDX 1.5](https://cyclonedx.org/specification/overview/)
- [NVD CVSS v3.1 Calculator](https://www.first.org/cvss/calculator/3.1)
- [Grafeas API](https://grafeas.io/)
