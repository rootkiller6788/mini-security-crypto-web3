/*
 * mini-trusted-compute — Full Demo: Trusted Computing
 *
 * Demonstrates: TPM (PCR, EK/AK, quote/attest, seal/unseal, DICE),
 *               SGX enclave lifecycle, TDX/SEV confidential VMs,
 *               remote attestation (EPID/DCAP), confidential computing.
 */
#include "../include/tpm_trust.h"
#include "../include/sgx_enclave.h"
#include "../include/tdx_amd.h"
#include "../include/remote_attest.h"
#include "../include/confidential_comp.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    printf("=== mini-trusted-compute: Trusted Computing Demo ===\n\n");

    /* Step 1: TPM (Trusted Platform Module) */
    printf("-- Step 1: TPM Operations --\n");
    tpm_device_t tpm;
    tpm_init(&tpm, true);
    tpm_startup(&tpm, TPM_SU_CLEAR);
    printf("TPM: initialized (simulator mode)\n");

    /* PCR extend */
    uint8_t digest[TPM_PCR_SIZE]; memset(digest, 0xAB, TPM_PCR_SIZE);
    tpm_pcr_extend(&tpm, 0, digest, TPM_PCR_SIZE);
    tpm_pcr_extend(&tpm, 7, digest, TPM_PCR_SIZE);
    printf("PCR[0] and PCR[7] extended\n");

    uint8_t pcr_val[TPM_PCR_SIZE]; uint32_t val_size = TPM_PCR_SIZE;
    tpm_pcr_read(&tpm, 0, pcr_val, &val_size);
    printf("PCR[0] = ");
    for (uint32_t i = 0; i < 8; i++) printf("%02x", pcr_val[i]);
    printf("...\n");

    /* EK + AK */
    tpm_create_ek(&tpm, &tpm.ek);
    printf("EK: %s\n", tpm.ek.ek_certified ? "certified" : "generated (sim)");

    tpm_create_ak(&tpm, &tpm.ak, &tpm.ek);
    printf("AK: %s\n", tpm.ak.ak_certified ? "certified" : "generated (sim)");

    /* Quote */
    uint8_t nonce[TPM_NONCE_SIZE]; memset(nonce, 0xDE, TPM_NONCE_SIZE);
    tpm_quote_t quote;
    tpm_quote(&tpm, &tpm.ak, nonce, TPM_NONCE_SIZE, nonce, TPM_NONCE_SIZE, &quote);
    printf("Quote: signed_by_ak=%s, valid=%s\n",
           quote.signed_by_ak ? "YES" : "NO", quote.valid ? "YES" : "NO");

    /* Seal / Unseal */
    tpm_key_t primary;
    tpm_create_primary(&tpm, TPM_HIERARCHY_OWNER, NULL, 0, &primary);
    const char *sealed_secret = "master-key-1234567890ABCDEF";
    tpm_sealed_key_t sealed;
    uint32_t pcr_idx = 7;
    tpm_seal(&tpm, &primary, (const uint8_t *)sealed_secret, 32, &pcr_idx, 1, &sealed);
    printf("Data sealed to PCR[7]\n");

    uint8_t unsealed[128]; uint32_t unsealed_size;
    tpm_unseal(&tpm, &sealed, unsealed, &unsealed_size);
    printf("Unsealed: \"%s\" (%u bytes)\n", unsealed, unsealed_size);

    /* DICE */
    tpm_dice_t dice;
    memset(&dice, 0, sizeof(dice));
    tpm_dice_compute_cdi(&dice, (const uint8_t *)"firmware-v2.1", 13);
    printf("DICE: CDI computed for firmware-v2.1\n");
    printf("  Layer: current=%d\n", dice.current_layer);

    uint8_t dice_key[64]; uint32_t dice_key_size;
    tpm_dice_derive_key(&dice, DICE_LAYER_APPLICATION, dice_key, &dice_key_size);
    printf("  Key derived at layer=%d, size=%u\n", DICE_LAYER_APPLICATION, dice_key_size);

    /* Step 2: SGX Enclave */
    printf("\n-- Step 2: SGX Enclave Lifecycle --\n");
    sgx_enclave_t enclave;
    sgx_enclave_init(&enclave, 64 * 4096, false);
    sgx_enclave_create(&enclave);
    printf("SGX enclave: created (%llu pages, debug=%s)\n",
           (unsigned long long)enclave.identity.page_count,
           enclave.debug ? "ON" : "OFF");

    sgx_enclave_identity_t identity;
    sgx_enclave_get_identity(&enclave, &identity);
    printf("  MRENCLAVE: ");
    for (int i = 0; i < 8; i++) printf("%02x", identity.mr_enclave[i]);
    printf("...\n");
    printf("  MRSIGNER: ");
    for (int i = 0; i < 8; i++) printf("%02x", identity.mr_signer[i]);
    printf("...\n");
    printf("  ISV_PROD_ID=%u, ISV_SVN=%u\n", identity.isv_prod_id, identity.isv_svn);

    /* Sealing */
    sgx_enclave_derive_seal_key(&enclave, SGX_KEY_POLICY_MRENCLAVE);
    sgx_sealed_data_t sgx_sealed;
    const char *sgx_data = "enclave-state-data";
    sgx_enclave_seal_data(&enclave, (const uint8_t *)sgx_data, strlen(sgx_data), &sgx_sealed);
    printf("SGX sealed data: %s (policy=MRENCLAVE)\n", sgx_sealed.is_sealed ? "SEALED" : "ERROR");

    /* Report */
    sgx_report_t report;
    uint8_t report_data[64]; memset(report_data, 0x01, 64);
    sgx_enclave_generate_report(&enclave, NULL, report_data, &report);
    printf("SGX report: generated (report_data filled)\n");

    sgx_enclave_destroy(&enclave);

    /* Step 3: TDX / AMD SEV */
    printf("\n-- Step 3: TDX & AMD SEV Confidential VMs --\n");
    /* TDX */
    tdx_td_t td;
    tdx_td_init(&td, 256 * 4096);
    tdx_td_create(&td);
    printf("TDX TD: created (state=%d)\n", td.state);

    uint8_t ext_data[TDX_HASH_SIZE]; memset(ext_data, 0xCC, TDX_HASH_SIZE);
    tdx_td_extend_mr(&td, ext_data);
    tdx_td_finalize(&td);
    printf("TDX: measurement extended and finalized\n");

    tdx_td_info_t td_info;
    tdx_td_get_info(&td, &td_info);
    printf("  MR: ");
    for (int i = 0; i < 8; i++) printf("%02x", td_info.measurement[i]);
    printf("...\n");
    tdx_td_destroy(&td);

    /* SEV */
    sev_vm_t sev;
    sev_vm_init(&sev, 256 * 4096, true, true);
    printf("AMD SEV-SNP VM: initialized (ES=%s, SNP=%s)\n",
           sev.es_enabled ? "YES" : "NO", sev.snp_enabled ? "YES" : "NO");

    sev_vm_launch_start(&sev, SEV_POLICY_NODBG);
    sev_vm_launch_finish(&sev);
    printf("SEV launch: completed\n");

    sev_attest_report_t sev_report;
    uint8_t sev_nonce[32]; memset(sev_nonce, 0xEE, 32);
    sev_vm_attest(&sev, sev_nonce, 32, &sev_report);
    printf("SEV attestation: version=%u, guest_svn=%u\n", sev_report.version, sev_report.guest_svn);
    sev_vm_destroy(&sev);

    /* Step 4: Remote Attestation */
    printf("\n-- Step 4: Remote Attestation --\n");
    ra_verifier_t verifier;
    uint8_t mr_enclave[SGX_MEASUREMENT_SIZE]; memset(mr_enclave, 0xAB, SGX_MEASUREMENT_SIZE);
    uint8_t mr_signer[SGX_MEASUREMENT_SIZE]; memset(mr_signer, 0xCD, SGX_MEASUREMENT_SIZE);
    ra_verifier_init(&verifier, mr_enclave, mr_signer);
    printf("RA verifier: initialized with expected MRENCLAVE/MRSIGNER\n");

    ra_challenge_t challenge;
    uint8_t chall_nonce[RA_NONCE_SIZE];
    uint32_t nonce_len;
    ra_generate_nonce(chall_nonce, &nonce_len);
    ra_generate_challenge(chall_nonce, nonce_len, &challenge);
    printf("Challenge generated: nonce_len=%u, timeout=%us\n",
           challenge.nonce_len, challenge.timeout_seconds);

    ra_prover_t prover;
    prover.attest_type = RA_ATTEST_ECDSA_P256;
    printf("RA prover: attest type=%s\n",
           prover.attest_type == RA_ATTEST_EPID ? "EPID" : "ECDSA");

    uint8_t report_data_out[RA_REPORT_DATA_SIZE];
    ra_create_report_data(chall_nonce, nonce_len, NULL, 0, report_data_out);
    printf("Report data: created from nonce\n");

    /* Step 5: Confidential Computing */
    printf("\n-- Step 5: Confidential Computing --\n");
    cc_confidential_ctx_t cc;
    cc_init(&cc);

    /* Platform probe */
    bool sgx_ok, tdx_ok, sev_ok, tme_ok;
    cc_is_sgx_supported(&cc, &sgx_ok);
    cc_is_tdx_supported(&cc, &tdx_ok);
    cc_is_sev_supported(&cc, &sev_ok);
    cc_is_tme_supported(&cc, &tme_ok);
    printf("Platform: SGX=%s, TDX=%s, SEV=%s, TME=%s\n",
           sgx_ok ? "YES" : "NO", tdx_ok ? "YES" : "NO",
           sev_ok ? "YES" : "NO", tme_ok ? "YES" : "NO");

    /* Vulnerability check */
    bool meltdown, spectre_v1, spectre_v2, l1tf;
    cc_check_vulnerability(&cc, CC_VULN_MELTDOWN, &meltdown);
    cc_check_vulnerability(&cc, CC_VULN_SPECTRE_V1, &spectre_v1);
    cc_check_vulnerability(&cc, CC_VULN_SPECTRE_V2, &spectre_v2);
    cc_check_vulnerability(&cc, CC_VULN_L1TF, &l1tf);
    printf("Vulnerabilities: Meltdown=%s, SpectreV1=%s, SpectreV2=%s, L1TF=%s\n",
           meltdown ? "YES" : "NO", spectre_v1 ? "YES" : "NO",
           spectre_v2 ? "YES" : "NO", l1tf ? "YES" : "NO");

    /* Constant-time operations */
    uint8_t ct_a[32], ct_b[32];
    memset(ct_a, 0x5A, 32); memset(ct_b, 0x5A, 32);
    ct_b[16] = 0x01;
    bool ct_equal;
    cc_constant_time_equal(ct_a, ct_b, 32, &ct_equal);
    printf("Constant-time equal: %s (array diff at byte 16)\n", ct_equal ? "EQUAL" : "NOT EQUAL");

    cc_constant_time_zero(ct_a, 32);
    bool is_zero;
    cc_constant_time_is_zero(ct_a, 32, &is_zero);
    printf("Constant-time zero check: %s\n", is_zero ? "ALL ZERO" : "NOT ZERO");

    /* Trust boundary */
    cc_trust_boundary_t boundary;
    cc_probe_platform(&cc, &boundary);
    printf("Trust boundary: region_count=%u\n", boundary.region_count);

    /* Cleanup */
    tpm_device_free(&tpm);
    cc_free(&cc);

    printf("\nTrusted computing demo complete!\n");
    return 0;
}
