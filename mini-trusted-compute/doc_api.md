# API Reference — mini-trusted-compute

## Module 1: sgx_enclave (Intel SGX)

### Core Lifecycle

| Function | Description |
|----------|-------------|
| `sgx_enclave_init()` | Initialize enclave metadata, allocate EPC pages |
| `sgx_enclave_create()` | ECREATE: allocate SECS, initialize measurement |
| `sgx_enclave_add_page()` | EADD: add page to enclave, update measurement |
| `sgx_enclave_extend_measurement()` | EEXTEND: hash 256-byte chunk into MRENCLAVE |
| `sgx_enclave_initialize()` | EINIT: finalize enclave, mark RUNNING |
| `sgx_enclave_enter()` | EENTER: enter enclave from untrusted code |
| `sgx_enclave_exit()` | EEXIT: exit enclave to untrusted code |
| `sgx_enclave_destroy()` | EREMOVE: tear down enclave pages |
| `sgx_enclave_free()` | Free all enclave resources |

### Attestation & Sealing

| Function | Description |
|----------|-------------|
| `sgx_enclave_generate_report()` | EREPORT: generate locally verifiable report |
| `sgx_enclave_verify_report()` | Verify EREPORT MAC |
| `sgx_enclave_local_attestation()` | Local attestation between two enclaves |
| `sgx_enclave_derive_seal_key()` | EGETKEY: derive sealing key from CPU+fused key |
| `sgx_enclave_seal_data()` | Encrypt data with sealing key |
| `sgx_enclave_unseal_data()` | Decrypt sealed data |
| `sgx_enclave_create_quote()` | Generate Quote for remote attestation |
| `sgx_enclave_get_identity()` | Retrieve enclave identity (MRENCLAVE, etc.) |
| `sgx_enclave_get_platform_info()` | Query platform info (CPUSVN, FMSPC) |

### Key Policies

- `SGX_KEY_POLICY_MRENCLAVE` — key derived from enclave measurement
- `SGX_KEY_POLICY_MRSIGNER` — key derived from signer (product-level)
- `SGX_KEY_POLICY_NOISV` — no ISV version binding

## Module 2: tdx_amd (Intel TDX + AMD SEV)

### Intel TDX

| Function | Description |
|----------|-------------|
| `tdx_td_init()` | Allocate TD (Trust Domain) memory and SEPT |
| `tdx_td_create()` | TDH.MNG.CREATE |
| `tdx_td_build()` | Load firmware and compute initial measurement |
| `tdx_td_add_page()` | TDH.MEM.PAGE.ADD to Secure EPT |
| `tdx_td_extend_mr()` | TDH.MR.EXTEND: extend runtime measurement |
| `tdx_td_finalize()` | TDH.MR.FINALIZE: lock TD and start execution |
| `tdx_td_add_vcpu()` | TDH.VP.CREATE: add virtual CPU |
| `tdx_td_enter()` | TDH.VP.ENTER: run vCPU |
| `tdx_td_destroy()` | TDH.MNG.DESTROY: tear down TD |
| `tdx_td_get_info()` | Retrieve TD measurement and info |

### AMD SEV / SEV-ES / SEV-SNP

| Function | Description |
|----------|-------------|
| `sev_vm_init()` | Initialize SEV VM with encrypted memory |
| `sev_vm_launch_start()` | LAUNCH_START: begin launch, set policy |
| `sev_vm_launch_update()` | LAUNCH_UPDATE: encrypt guest pages |
| `sev_vm_launch_measure()` | LAUNCH_MEASURE: retrieve launch digest |
| `sev_vm_launch_finish()` | LAUNCH_FINISH: complete launch |
| `sev_vm_launch_secret()` | LAUNCH_SECRET: inject secrets |
| `sev_vm_attest()` | Generate SEV attestation report |
| `sev_vm_snp_attest()` | Generate SEV-SNP attestation report |
| `sev_vm_activate()` | ACTIVATE: enable encryption |
| `sev_vm_deactivate()` | DEACTIVATE: disable encryption |
| `sev_vm_destroy()` | Destroy SEV VM |

### SEV Policy Flags

- `SEV_POLICY_NODBG` — disable debugging
- `SEV_POLICY_NOKS` — disable key sharing
- `SEV_POLICY_ES` — SEV-ES enabled
- `SEV_POLICY_SNP` — SEV-SNP enabled

## Module 3: remote_attest (Remote Attestation)

### Verifier API

| Function | Description |
|----------|-------------|
| `ra_verifier_init()` | Initialize verifier with expected measurements |
| `ra_verifier_set_measurement()` | Set expected MRENCLAVE/MRSIGNER |
| `ra_verifier_set_tcb_policy()` | Configure TCB verification policy |
| `ra_verifier_set_fmspc()` | Restrict to specific FMSPC |
| `ra_verifier_set_root_ca()` | Set trusted root CA fingerprint |
| `ra_generate_challenge()` | Create attestation challenge (nonce + session) |
| `ra_verify_ias_attestation()` | Verify via Intel Attestation Service |
| `ra_verify_dcap_attestation()` | Verify via ECDSA/DCAP |
| `ra_verify_quote_signature()` | Verify Quote ECDSA signature |
| `ra_parse_quote_body()` | Parse Quote body fields |
| `ra_extract_mrenclave()` | Extract MRENCLAVE from Quote |
| `ra_extract_mrsigner()` | Extract MRSIGNER from Quote |
| `ra_cert_chain_verify()` | Verify X.509 certificate chain |
| `ra_cert_extract_public_key()` | Extract ECDSA public key from certificate |

### Prover API

| Function | Description |
|----------|-------------|
| `ra_prover_init()` | Initialize prover, bind to enclave |
| `ra_prover_set_platform_info()` | Set platform ID and FMSPC |
| `ra_generate_nonce()` | Generate cryptographic nonce |
| `ra_create_report_data()` | Create REPORTDATA hash for Quote |

### TLS Integration

| Function | Description |
|----------|-------------|
| `ra_tls_handshake_with_attestation()` | Perform TLS handshake embedding attestation |
| `ra_tls_verify_peer_attestation()` | Verify peer attestation within TLS context |

## Module 4: confidential_comp (Confidential Computing)

### Memory Encryption

| Function | Description |
|----------|-------------|
| `cc_init()` | Initialize confidential computing context |
| `cc_enable_tme()` | Enable Total Memory Encryption (TME) |
| `cc_enable_mktme()` | Enable Multi-Key TME (MKTME) |
| `cc_register_encrypted_region()` | Register encrypted memory region |
| `cc_rotate_encryption_keys()` | Rotate all encryption keys |
| `cc_probe_platform()` | Probe platform capabilities |

### Vulnerability Management

| Function | Description |
|----------|-------------|
| `cc_check_vulnerability()` | Check if a vulnerability exists |
| `cc_get_sgx_vulnerabilities()` | List SGX-specific vulnerabilities |
| `cc_get_sev_vulnerabilities()` | List SEV-specific vulnerabilities |
| `cc_enable_patch_for_vuln()` | Enable mitigation for known vulnerability |
| `cc_is_mitigated()` | Check if vulnerability is mitigated |
| `cc_mitigate_cache_side_channel()` | Apply cache partitioning mitigation |
| `cc_mitigate_page_fault_channel()` | Apply page-fault channel mitigation |

### Constant-Time Crypto

| Function | Description |
|----------|-------------|
| `cc_constant_time_compare()` | Constant-time byte comparison |
| `cc_constant_time_select()` | Constant-time conditional select |
| `cc_constant_time_copy()` | Constant-time memory copy |
| `cc_constant_time_zero()` | Constant-time zero |
| `cc_constant_time_is_zero()` | Constant-time zero check |
| `cc_constant_time_increment()` | Constant-time increment |
| `cc_constant_time_equal()` | Constant-time equality check |

### Secure I/O

| Function | Description |
|----------|-------------|
| `cc_secure_io_negotiate()` | Establish secure I/O session |
| `cc_secure_io_send()` | Send data over secure channel |
| `cc_secure_io_receive()` | Receive data over secure channel |

### State Management

| Function | Description |
|----------|-------------|
| `cc_seal_entire_state()` | Seal entire context state |
| `cc_unseal_entire_state()` | Unseal context state |
| `cc_attest_platform()` | Generate platform attestation evidence |
| `cc_verify_attestation()` | Verify platform attestation evidence |
| `cc_get_trust_boundary()` | Get trust boundary info |
| `cc_free()` | Free confidential computing context |

### Known Vulnerabilities

| ID | Name | CVE | Affects |
|----|------|-----|---------|
| `CC_VULN_LVI` | Load Value Injection | CVE-2020-0551 | SGX |
| `CC_VULN_SGAXE` | SGAxe | CVE-2020-0549 | SGX |
| `CC_VULN_PLUNDERVOLT` | Plundervolt | CVE-2019-11157 | SGX |
| `CC_VULN_CROSSTALK` | CrossTalk | CVE-2020-12967 | SGX |
| `CC_VULN_MMIO_STALE` | MMIO Stale Data | CVE-2022-21180 | SGX |
| `CC_VULN_SEVERED` | SEVered | CVE-2020-0001 | SEV |

## Module 5: tpm_trust (TPM 2.0)

### PCR Operations

| Function | Description |
|----------|-------------|
| `tpm_pcr_extend()` | TPM2_PCR_Extend |
| `tpm_pcr_read()` | TPM2_PCR_Read |
| `tpm_pcr_reset()` | TPM2_PCR_Reset |
| `tpm_pcr_set_auth_policy()` | Set PCR authorization policy |
| `tpm_pcr_set_auth_value()` | Set PCR authorization value |

### Key Management

| Function | Description |
|----------|-------------|
| `tpm_create_primary()` | TPM2_CreatePrimary (SRK/EK) |
| `tpm_create_key()` | Create ordinary key |
| `tpm_load_key()` | Load encrypted key |
| `tpm_sign()` | Sign with TPM-resident key |
| `tpm_verify_signature()` | Verify TPM signature |

### Endorsement & Attestation Keys

| Function | Description |
|----------|-------------|
| `tpm_create_ek()` | Create Endorsement Key |
| `tpm_create_ak()` | Create Attestation Key |
| `tpm_certify_ek()` | Certify EK |
| `tpm_certify_ak()` | Certify AK via EK |

### Quote & Attestation

| Function | Description |
|----------|-------------|
| `tpm_quote()` | TPM2_Quote: sign PCR state |
| `tpm_verify_quote()` | Verify Quote signature |
| `tpm_attest()` | TPM2_Certify / TPM2_GetSessionAuditDigest |

### Sealing

| Function | Description |
|----------|-------------|
| `tpm_seal()` | Seal data to PCR values |
| `tpm_unseal()` | Unseal data (PCRs must match) |
| `tpm_seal_policy()` | Seal data to authorization policy |

### NV Storage

| Function | Description |
|----------|-------------|
| `tpm_nv_define_space()` | TPM2_NV_DefineSpace |
| `tpm_nv_write()` | TPM2_NV_Write |
| `tpm_nv_read()` | TPM2_NV_Read |
| `tpm_nv_lock()` | TPM2_NV_WriteLock |
| `tpm_nv_undefine_space()` | TPM2_NV_UndefineSpace |

### Measured Boot

| Function | Description |
|----------|-------------|
| `tpm_measured_boot_start()` | Start measured boot sequence |
| `tpm_measured_boot_extend()` | Extend measurement (CRTM, firmware, OS) |
| `tpm_measured_boot_complete()` | Mark measured boot complete |
| `tpm_measured_boot_verify()` | Verify entire boot chain integrity |

### DICE (Device Identifier Composition Engine)

| Function | Description |
|----------|-------------|
| `tpm_dice_compute_cdi()` | Compute Compound Device Identifier |
| `tpm_dice_derive_key()` | Derive layer-specific key from CDI |
| `tpm_dice_create_alias_cert()` | Create alias certificate |
| `tpm_dice_verify_chain()` | Verify DICE certificate chain |
| `tpm_dice_seal_to_cdi()` | Seal data to CDI |

### Provisioning

| Function | Description |
|----------|-------------|
| `tpm_provision()` | Provision TPM with EK cert |
| `tpm_get_ek_certificate()` | Retrieve EK certificate |
| `tpm_get_event_log()` | Retrieve measured boot event log |
| `tpm_replay_event_log()` | Replay and verify event log |

### Lifecycle

| Function | Description |
|----------|-------------|
| `tpm_init()` | Initialize TPM (optionally as simulator) |
| `tpm_startup()` | TPM2_Startup |
| `tpm_self_test()` | TPM2_SelfTest |
| `tpm_get_random()` | TPM2_GetRandom |
| `tpm_device_free()` | Free TPM device resources |
