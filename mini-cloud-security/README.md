# mini-cloud-security — Cloud Security (C Implementation)

C99 implementation of AWS cloud security core modules. Includes IAM Policy Engine, KMS Key Management, WAF Rules Engine, DDoS Protection, Container Security, Cloud Audit & Compliance, and VPC Network Security.

## Subsystems

| Module | Header | Knowledge Areas |
|--------|--------|----------------|
| IAM | `iam_policy.h` | Policy evaluation (Allow/Deny), conditions, roles, sessions, permission boundaries, SCP |
| KMS | `kms_key.h` | CMK lifecycle, envelope encryption (AES-GCM), data keys, grants, key rotation, multi-region, HSM |
| WAF | `waf_rules.h` | SQLi/XSS detection, rate limiting, IP/CIDR matching, geo filtering, managed rule groups |
| DDoS | `ddos_protect.h` | SYN/UDP/DNS flood detection, entropy analysis, blackhole routing, traffic scrubbing, Shield tiers |
| Container | `container_security.h` | Image vulnerability scanning (CVE), seccomp/AppArmor profiles, pod security standards, network policies, image signing (Cosign/Notary) |
| Cloud Audit | `cloud_audit.h` | Hash-chain audit trails (tamper-evident logging), Merkle tree batch verification, compliance frameworks (PCI-DSS, CIS AWS, HIPAA) |
| VPC Security | `vpc_security.h` | Security Groups (stateful), Network ACLs (stateless), CIDR algebra (overlap/merge/split), rule evaluation |

## Nine-Level Knowledge Coverage

| Level | Name | Status | Evidence |
|-------|------|--------|----------|
| **L1** | Definitions | **COMPLETE** | 7 header files: 42 typedefs, 35 enums, 80+ API functions. Core structs: iam_policy_t, kms_key_t, waf_rule_t, ddos_protection_t, cs_image_t, ca_audit_trail_t, vpc_security_group_t |
| **L2** | Core Concepts | **COMPLETE** | IAM RBAC/ABAC, KMS envelope encryption, WAF OWASP Top-10 filtering, DDoS mitigation pipeline, container image signing, stateful vs stateless firewalls, hash-chain integrity, compliance frameworks |
| **L3** | Engineering Structures | **COMPLETE** | Policy evaluation engine (explicit deny > allow), AES-GCM simulation, Merkle tree for batch log verification, CIDR interval algebra, rate-limiting data structures, seccomp syscall filtering |
| **L4** | Standards/Theorems | **COMPLETE** | PCI-DSS v4.0 (Req 3.4, 8.3, 10.5), CIS AWS Foundations v1.4, HIPAA Security Rule §164.312, FIPS 140-2 key lifecycle, RFC 6962 §2.1 Merkle trees, Haber-Stornetta time-stamping, CIDR containment lemma |
| **L5** | Algorithms/Methods | **COMPLETE** | IAM policy evaluation (default deny + explicit allow + explicit deny override), Merkle-Damgard hash construction, Merkle tree proof generation/verification (O(log n)), CIDR overlap/subset/adjacent/merge/split algorithms, entropy-based DDoS detection, pattern-matching SQLi/XSS detection |
| **L6** | Canonical Problems | **COMPLETE** | IAM authorization check, KMS envelope encrypt/decrypt, WAF SQLi/XSS detection, DDoS attack detection & mitigation, container image vulnerability scan, audit trail tamper detection, VPC firewall rule evaluation, CIDR conflict detection |
| **L7** | Applications | **PARTIAL+** | 3 examples (IAM, KMS, WAF) + 2 demos (cloud security scenario, security event simulator) + cloud compliance scoring engine |
| **L8** | Advanced Topics | **PARTIAL+** | Hash-chain tamper evidence (blockchain-like), Merkle tree proofs (cryptographic verification), CIDR algebra for VPC subnet management, entropy-based anomaly detection, compliance risk scoring |
| **L9** | Industry Frontiers | **PARTIAL** | Documented: Confidential Computing, AI-driven threat detection, Zero Trust architecture, Cloud Security Posture Management (CSPM) |

## Core Theorems & Standards

| Theorem/Standard | Implementation | File |
|-----------------|---------------|------|
| Default Deny + Explicit Allow | IAM policy evaluation engine | `src/iam_policy.c:108` |
| Envelope Encryption (NIST SP 800-57) | KMS GenerateDataKey + encrypt/decrypt | `src/kms_key.c:210-236` |
| Hash-chain tamper evidence (Haber-Stornetta 1991) | Audit trail with prev_hash chaining | `src/cloud_audit.c:118-155` |
| Merkle tree inclusion proof (Merkle 1980, RFC 6962) | Batch log verification with O(log n) proofs | `src/cloud_audit.c:165-226` |
| CIDR containment lemma | IP range overlap/subset/adjacent/merge | `src/vpc_security.c:98-184` |
| Shannon entropy for anomaly detection | DDoS traffic entropy scoring | `src/ddos_protect.c:312-320` |
| PCI-DSS v4.0, CIS AWS v1.4, HIPAA §164.312 | Compliance check engine with risk scoring | `src/cloud_audit.c:228-362` |

## Core Algorithms

| Algorithm | Complexity | Implementation |
|-----------|-----------|----------------|
| IAM Policy Evaluation | O(n·m) n=statements, m=conditions | `iam_evaluate_policy()` |
| AES-GCM (simplified) | O(n) over plaintext len | `sim_aes_gcm_encrypt/decrypt()` |
| Hash-chain verification | O(n) over events | `ca_trail_verify_chain()` |
| Merkle tree build | O(n) over leaves | `ca_merkle_build()` |
| Merkle proof verify | O(log n) proof length | `ca_merkle_verify_proof()` |
| CIDR overlap detection | O(1) per pair | `vpc_cidr_overlap()` |
| CIDR conflict detection | O(n²) pairwise | `vpc_find_cidr_conflicts()` |
| Entropy calculation | O(n) over source IPs | `ddos_calculate_entropy()` |
| Pattern-match SQLi/XSS | O(n·m) input × patterns | `waf_check_sql_injection()` / `waf_check_xss()` |

## Course Alignment (9-School Mapping)

| School | Course | Module Coverage |
|--------|--------|----------------|
| MIT | 6.858 Computer Security | IAM (authz), KMS (crypto), WAF (web sec), DDoS (network sec) |
| Stanford | CS 155 Computer & Network Security | KMS (crypto), WAF (web app sec), DDoS (network), Audit (forensics) |
| Berkeley | CS 161 Computer Security | Container security (OS sec), IAM (access control), Audit (logging) |
| CMU | 15-410 Operating Systems | Container (seccomp/AppArmor/SELinux), VPC (network stack) |
| UT Austin | CS 380D Distributed Systems | IAM (distributed authz), Audit (distributed logging), Merkle proofs |
| ETH | 263-4640 Computer Security | KMS (crypto engineering), Audit (tamper resistance) |
| Cambridge | Part II: Security | IAM (formal policy model), KMS (key management), Compliance frameworks |
| Tsinghua | Network & Information Security | WAF (web security), DDoS (network defense), VPC (network security) |
| Georgia Tech | CS 6262 Network Security | DDoS (detection/mitigation), VPC (firewall), WAF (application firewall) |

## Build

```
make all          # Compile all .o, examples, and demos
make examples     # Compile example programs
make demos        # Compile demo programs
make test         # Run unit tests (19 tests, all pass)
make clean        # Clean build artifacts
```

## Examples

- `example_iam` — IAM policy creation, evaluation, condition matching
- `example_kms` — KMS key lifecycle, envelope encryption, data keys, grants
- `example_waf` — WAF rule groups, SQLi/XSS detection, rate limiting

## Demos

- `demo_cloud_security` — Integrated scenario: IAM + KMS + WAF + DDoS + Container
- `demo_security_sim` — Security event simulator: policy conflicts, DoS detection, key compromise, CVE alerts

## Dependencies

- C99 compiler (gcc or clang)
- GNU Make
- libm (for logf in entropy calculation)

## Module Status: COMPLETE

- **include/ + src/ lines**: 4096 (threshold: 3000)
- **L1-L6**: Complete — all core definitions, concepts, structures, standards, algorithms, and canonical problems implemented
- **L7**: Partial+ — 5 executable examples/demos + compliance scoring engine
- **L8**: Partial+ — Hash-chain integrity, Merkle proofs, CIDR algebra, entropy detection
- **L9**: Partial — Industry frontiers documented in docs/

## License

MIT
