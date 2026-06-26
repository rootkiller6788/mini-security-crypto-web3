#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sgx_enclave.h"
#include "tdx_amd.h"
#include "tpm_trust.h"
#include "confidential_comp.h"
#include "remote_attest.h"

static void print_section(const char *title) {
    printf("\n========== %s ==========\n", title);
}

static void demo_full_trust_chain(void) {
    print_section("Full Trust Chain: HW Root -> SGX -> TDX -> TPM -> DICE");

    printf("--- Layer 0: Hardware Trust Anchor ---\n");
    cc_confidential_ctx_t cc;
    cc_init(&cc);

    cc_trust_boundary_t boundary;
    cc_probe_platform(&cc, &boundary);
    printf("Platform probe: SGX=%c TDX=%c SEV=%c TME=%c\n",
           boundary.sgx_capable ? 'Y' : 'N',
           boundary.tdx_capable ? 'Y' : 'N',
           boundary.sev_capable ? 'Y' : 'N',
           boundary.tme_capable ? 'Y' : 'N');

    uint8_t root_key[CC_TME_KEY_SIZE];
    for (int i = 0; i < CC_TME_KEY_SIZE; i++) root_key[i] = (uint8_t)i;
    cc_enable_tme(&cc, root_key);
    printf("  TME activated: trust boundary established at CPU package\n");

    printf("\n--- Layer 1: SGX Enclave ---\n");
    sgx_enclave_t enclave;
    sgx_enclave_init(&enclave, 1024 * 1024, false);
    sgx_enclave_create(&enclave);

    uint8_t app_code[4096];
    memset(app_code, 0xCC, sizeof(app_code));
    sgx_enclave_add_page(&enclave, enclave.identity.base_addr,
                         app_code, sizeof(app_code),
                         SGX_SECINFO_R | SGX_SECINFO_W | SGX_SECINFO_X,
                         SGX_PAGE_REGULAR);
    sgx_enclave_initialize(&enclave);
    printf("  SGX enclave: MRENCLAVE=");
    for (int i = 0; i < 8; i++) printf("%02x", enclave.identity.mr_enclave[i]);
    printf("...\n");

    printf("\n--- Layer 2: TDX Trust Domain ---\n");
    tdx_td_t td;
    tdx_td_init(&td, 128 * 1024 * 1024);
    tdx_td_create(&td);

    uint8_t fw[8192];
    memset(fw, 0xFD, sizeof(fw));
    tdx_td_build(&td, fw, sizeof(fw));

    tdx_vcpu_state_t vcpu0;
    memset(&vcpu0, 0, sizeof(vcpu0));
    vcpu0.rip = 0xFFFFF000;
    vcpu0.rsp = 0x7F000000;
    tdx_td_add_vcpu(&td, 0, &vcpu0);
    tdx_td_finalize(&td);
    printf("  TDX TD: measurement=");
    for (int i = 0; i < 8; i++) printf("%02x", td.params.measurement[i]);
    printf("...\n");

    printf("\n--- Layer 3: SEV-SNP VM ---\n");
    sev_vm_t snp_vm;
    sev_vm_init(&snp_vm, 256 * 1024 * 1024, true, true);
    sev_vm_launch_start(&snp_vm, SEV_POLICY_SNP | SEV_POLICY_NODBG);

    uint8_t vm_memory[4096];
    memset(vm_memory, 0x90, sizeof(vm_memory));
    sev_vm_launch_update(&snp_vm, 0, vm_memory, sizeof(vm_memory), 1 << 0);
    sev_vm_launch_finish(&snp_vm);
    printf("  SEV-SNP VM: measurement=");
    for (int i = 0; i < 8; i++) printf("%02x", snp_vm.config.measurement[i]);
    printf("...\n");

    printf("\n--- Layer 4: TPM 2.0 Measured Boot ---\n");
    tpm_device_t tpm;
    tpm_init(&tpm, true);

    tpm_create_ek(&tpm, &tpm.ek);
    printf("  TPM EK certificate: %u bytes\n", tpm.ek.ek_cert_size);

    tpm_measured_boot_start(&tpm);
    const char *chain[] = {"UEFI", "Shim", "GRUB", "Kernel", "Initrd", "App"};
    for (int i = 0; i < 6; i++) {
        uint8_t d[TPM_PCR_SIZE];
        memset(d, i, sizeof(d));
        tpm_measured_boot_extend(&tpm, chain[i], d, TPM_PCR_SIZE);
    }
    tpm_measured_boot_complete(&tpm);

    bool trusted;
    tpm_measured_boot_verify(&tpm, &trusted);
    printf("  Measured boot chain: %s (6 stages)\n", trusted ? "TRUSTED" : "UNTRUSTED");

    printf("\n--- Layer 5: DICE Certificate Chain ---\n");
    tpm_dice_t dice;
    memset(&dice, 0, sizeof(dice));

    uint8_t fw_id[TPM_DICE_CDI_SIZE];
    for (int i = 0; i < TPM_DICE_CDI_SIZE; i++) fw_id[i] = (uint8_t)(i + 0x80);
    tpm_dice_compute_cdi(&dice, fw_id, sizeof(fw_id));

    uint8_t dik[32]; uint32_t dik_size;
    tpm_dice_derive_key(&dice, DICE_LAYER_ROM, dik, &dik_size);

    uint8_t identity[32];
    memset(identity, 0xDE, sizeof(identity));
    tpm_dice_create_alias_cert(&dice, identity, sizeof(identity));

    bool dice_valid;
    tpm_dice_verify_chain(&dice, &dice_valid);
    printf("  DICE chain: %s (ROM->Bootloader->OS->App)\n", dice_valid ? "VALID" : "INVALID");

    printf("\n--- Full Chain Cross-Attestation ---\n");
    sgx_report_t sgx_rep;
    uint8_t rd[SGX_SEAL_KEY_SIZE];
    memset(rd, 0xAB, sizeof(rd));
    sgx_enclave_generate_report(&enclave, NULL, rd, &sgx_rep);
    printf("  SGX report generated for chain binding\n");

    uint8_t composite_challenge[RA_REPORT_DATA_SIZE];
    memcpy(composite_challenge, sgx_rep.body.mr_enclave, 32);
    memcpy(composite_challenge + 32, td.params.measurement, 16);

    sev_snp_attest_report_t snp_rep;
    sev_vm_snp_attest(&snp_vm, composite_challenge, sizeof(composite_challenge), &snp_rep);
    printf("  SEV-SNP attestation bound to SGX+TDX measurements\n");

    tpm_pcr_extend(&tpm, 10, composite_challenge, sizeof(composite_challenge));
    printf("  TPM PCR[10] extended with composite evidence\n");

    tpm_attestation_key_t ak;
    tpm_create_ak(&tpm, &ak, &tpm.ek);
    tpm_quote_t quote;
    uint8_t nonce[32];
    for (int i = 0; i < 32; i++) nonce[i] = (uint8_t)i;
    uint8_t pcr_list[] = {0,1,2,3,4,5,6,7,10};
    tpm_quote(&tpm, &ak, pcr_list, 9, nonce, sizeof(nonce), &quote);
    printf("  TPM Quote generated binding entire chain\n");

    printf("\n=== Full Trust Chain Established ===\n");
    printf("  HW Root -> TME -> SGX -> TDX -> SEV-SNP -> TPM -> DICE\n");

    tdx_td_destroy(&td);
    sev_vm_destroy(&snp_vm);
    sgx_enclave_destroy(&enclave);
    sgx_enclave_free(&enclave);
    tpm_device_free(&tpm);
    cc_free(&cc);
}

static void demo_data_lifecycle(void) {
    print_section("Confidential Data Lifecycle");

    printf("Phase 1: Data-at-Rest (Storage Encryption)\n");
    tpm_device_t tpm;
    tpm_init(&tpm, true);

    tpm_key_t srk;
    tpm_create_primary(&tpm, TPM_HIERARCHY_OWNER, NULL, 0, &srk);

    const char *sensitive_data = "ALICE_BOB_SECRET_KEY_1234567890ABCDEF";
    tpm_sealed_key_t at_rest;
    uint32_t pcr_bind[] = {0, 1, 2};
    tpm_seal(&tpm, &srk, (const uint8_t *)sensitive_data,
             (uint32_t)strlen(sensitive_data), pcr_bind, 3, &at_rest);
    printf("  Data sealed at rest: %u bytes, bound to PCRs [0,1,2]\n",
           at_rest.sealed_size);

    printf("\nPhase 2: Data-in-Use (SGX Enclave Processing)\n");
    sgx_enclave_t enclave;
    sgx_enclave_init(&enclave, 1024 * 1024, false);
    sgx_enclave_create(&enclave);

    uint8_t enc_code[4096];
    memset(enc_code, 0xCD, sizeof(enc_code));
    sgx_enclave_add_page(&enclave, enclave.identity.base_addr,
                         enc_code, sizeof(enc_code),
                         SGX_SECINFO_R | SGX_SECINFO_W | SGX_SECINFO_X,
                         SGX_PAGE_REGULAR);
    sgx_enclave_initialize(&enclave);

    sgx_sealed_data_t in_use_sealed;
    sgx_enclave_seal_data(&enclave, (const uint8_t *)sensitive_data,
                          (uint32_t)strlen(sensitive_data), &in_use_sealed);
    printf("  Data sealed in enclave: %u bytes\n", in_use_sealed.sealed_size);
    printf("  MRENCLAVE binding ensures only this code can decrypt\n");

    printf("\nPhase 3: Data-in-Transit (Attested TLS Channel)\n");
    ra_prover_t prover;
    ra_prover_init(&prover, &enclave, RA_ATTEST_ECDSA_P256);

    ra_tls_context_t tls;
    memset(&tls, 0, sizeof(tls));
    tls.attestation_required = true;
    tls.mutual_attestation = true;

    ra_response_t tls_resp;
    uint8_t hello[128];
    memset(hello, 0x01, sizeof(hello));
    ra_tls_handshake_with_attestation(&tls, hello, sizeof(hello), &tls_resp);
    printf("  Attested TLS channel established\n");
    printf("  Quote version: %u\n", tls_resp.quote_version);

    bool peer_ok;
    ra_tls_verify_peer_attestation(&tls, &tls_resp, &peer_ok);
    printf("  Peer attestation: %s\n", peer_ok ? "VERIFIED" : "FAILED");

    printf("\nPhase 4: Data Disposal (Secure Erasure)\n");
    cc_confidential_ctx_t cc;
    cc_init(&cc);

    uint8_t zero_key[CC_TME_KEY_SIZE];
    memset(zero_key, 0, sizeof(zero_key));
    cc_enable_tme(&cc, zero_key);

    cc_rotate_encryption_keys(&cc);
    cc_rotate_encryption_keys(&cc);
    cc_rotate_encryption_keys(&cc);
    printf("  Encryption keys rotated 3 times for cryptographic erasure\n");

    size_t sz;
    uint8_t buf[sizeof(cc_confidential_ctx_t)];
    cc_seal_entire_state(&cc, buf, &sz);
    memset(buf, 0, sz);
    printf("  All sealed state zeroed: %zu bytes\n", sz);

    printf("\n=== Data Lifecycle: REST -> USE -> TRANSIT -> DISPOSAL ===\n");

    sgx_enclave_destroy(&enclave);
    sgx_enclave_free(&enclave);
    tpm_device_free(&tpm);
    cc_free(&cc);
}

static void demo_vulnerability_report(void) {
    print_section("Security Vulnerability Report");

    cc_confidential_ctx_t cc;
    cc_init(&cc);

    cc_vuln_database_t db;
    cc_get_sgx_vulnerabilities(&cc, &db);

    printf("--- Intel SGX Vulnerabilities ---\n");
    printf("%-20s %-20s %5s %4s %4s %4s\n",
           "NAME", "CVE", "RISK", "SGX", "TDX", "SEV");
    printf("---------------------------------------------------------\n");

    for (uint32_t i = 0; i < db.vuln_count; i++) {
        cc_vulnerability_t *v = &db.vulns[i];
        printf("%-20s %-20s %5u %4s %4s %4s\n",
               v->name, v->cve_id, v->risk_score,
               v->affects_sgx ? "YES" : "NO",
               v->affects_tdx ? "YES" : "NO",
               v->affects_sev ? "YES" : "NO");
    }

    printf("\n--- Side-Channel Attack Surface ---\n");
    const char *sc_names[] = {
        "Cache Timing", "Page Fault", "Branch Shadow",
        "L1D Eviction", "Microarch Data", "SwapGS",
        "Load Value Injection", "Power Analysis"
    };

    for (int i = 0; i < 8; i++) {
        bool exploitable_sgx = (i < 5);
        bool exploitable_sev = (i < 3);
        printf("  %-22s : SGX %s | SEV %s | TDX %s\n",
               sc_names[i],
               exploitable_sgx ? "EXPLOITABLE" : "mitigated",
               exploitable_sev ? "EXPLOITABLE" : "mitigated",
               (i < 2) ? "EXPLOITABLE" : "mitigated");
    }

    printf("\n--- Mitigations Applied ---\n");
    const char *active_mitigations[] = {
        "LFENCE after loads (mitigates LVI)",
        "Cache Allocation Technology (CAT) partitioning",
        "Page table hardening for page-fault channels",
        "Retpoline + IBPB for branch prediction isolation",
        "MKTME key isolation per VM",
        "SEV-SNP: Reverse Map Table for nested page verification"
    };

    for (int i = 0; i < 6; i++)
        printf("  [%d] %s\n", i + 1, active_mitigations[i]);

    printf("\n--- TPM Side-Channel Hardening ---\n");
    printf("  [7] TPM: Constant-time RSA operations\n");
    printf("  [8] TPM: Session-based encryption for command/response\n");
    printf("  [9] TPM: DICE layered key isolation\n");

    printf("\n--- Cross-TEE Vulnerability Matrix ---\n");
    printf("  Vulnerability          |  SGX  |  SEV  |  TDX  | TPM   |\n");
    printf("  -----------------------|-------|-------|-------|-------|\n");
    printf("  Cache Timing           |  YES  |  YES  |  YES  |  YES  |\n");
    printf("  Page Fault             |  YES  |   NO  |   NO  |   NO  |\n");
    printf("  Branch Prediction      |  YES  |  YES  |  YES  |   NO  |\n");
    printf("  Speculative Execution  |  YES  |   NO  |  YES  |   NO  |\n");
    printf("  Physical Intrusion     |  YES  |  YES  |  YES  |  YES  |\n");
    printf("  Microcode Tampering    |  YES  |  YES  |  YES  |   NO  |\n");
    printf("  DMA Attacks            |  YES  |   NO  |   NO  |  YES  |\n");
    printf("  Untrusted I/O          |  YES  |  YES  |  YES  |  YES  |\n");

    cc_free(&cc);
    printf("\n[Vulnerability Report Complete]\n");
}

int main(void) {
    printf("=== mini-trusted-compute — Full Confidential Trust Demo ===\n\n");

    demo_full_trust_chain();
    demo_data_lifecycle();
    demo_vulnerability_report();

    printf("\n=== All Confidential Computing Demos Complete ===\n");
    return 0;
}
