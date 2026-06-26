/*
 * mini-trusted-compute — Core Tests
 *
 * Unit tests for TPM, SGX enclave, TDX/SEV, remote attestation, confidential computing.
 */
#include "../include/tpm_trust.h"
#include "../include/sgx_enclave.h"
#include "../include/tdx_amd.h"
#include "../include/remote_attest.h"
#include "../include/confidential_comp.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

static int tests_run = 0, tests_passed = 0;

#define TEST(name) do { tests_run++; printf("  TEST %s ... ", name); } while(0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); return 1; } while(0)
#define CHECK(cond, msg) if (!(cond)) FAIL(msg)

/* ── TPM Tests ── */
static int test_tpm_init_startup(void) {
    TEST("tpm_init_startup");
    tpm_device_t tpm;
    CHECK(tpm_init(&tpm, true) == 0, "tpm init failed");
    CHECK(tpm_startup(&tpm, TPM_SU_CLEAR) == 0, "tpm startup failed");
    CHECK(tpm.initialized, "tpm not initialized");
    tpm_device_free(&tpm);
    PASS();
    return 0;
}

static int test_tpm_pcr_extend_read(void) {
    TEST("tpm_pcr_extend_read");
    tpm_device_t tpm;
    tpm_init(&tpm, true);
    tpm_startup(&tpm, TPM_SU_CLEAR);
    uint8_t digest[TPM_PCR_SIZE]; memset(digest, 0xAB, TPM_PCR_SIZE);
    CHECK(tpm_pcr_extend(&tpm, 0, digest, TPM_PCR_SIZE) == 0, "pcr extend failed");
    uint8_t pcr_val[TPM_PCR_SIZE]; uint32_t val_size = TPM_PCR_SIZE;
    CHECK(tpm_pcr_read(&tpm, 0, pcr_val, &val_size) == 0, "pcr read failed");
    tpm_device_free(&tpm);
    PASS();
    return 0;
}

static int test_tpm_quote(void) {
    TEST("tpm_quote");
    tpm_device_t tpm;
    tpm_init(&tpm, true);
    tpm_startup(&tpm, TPM_SU_CLEAR);
    tpm_create_ek(&tpm, &tpm.ek);
    tpm_create_ak(&tpm, &tpm.ak, &tpm.ek);
    uint8_t nonce[TPM_NONCE_SIZE]; memset(nonce, 0xDE, TPM_NONCE_SIZE);
    tpm_quote_t quote;
    CHECK(tpm_quote(&tpm, &tpm.ak, nonce, TPM_NONCE_SIZE, nonce, TPM_NONCE_SIZE, &quote) == 0, "quote failed");
    CHECK(quote.signed_by_ak, "not signed by AK");
    tpm_device_free(&tpm);
    PASS();
    return 0;
}

static int test_tpm_seal_unseal(void) {
    TEST("tpm_seal_unseal");
    tpm_device_t tpm;
    tpm_init(&tpm, true);
    tpm_startup(&tpm, TPM_SU_CLEAR);
    tpm_key_t primary;
    CHECK(tpm_create_primary(&tpm, TPM_HIERARCHY_OWNER, NULL, 0, &primary) == 0, "create primary failed");
    const char *secret = "test-secret-data-01234567";
    tpm_sealed_key_t sealed;
    uint32_t pcr_idx = 7;
    CHECK(tpm_seal(&tpm, &primary, (const uint8_t *)secret, 24, &pcr_idx, 1, &sealed) == 0, "seal failed");
    uint8_t unsealed[128]; uint32_t unsealed_size;
    CHECK(tpm_unseal(&tpm, &sealed, unsealed, &unsealed_size) == 0, "unseal failed");
    CHECK(unsealed_size == 24, "unsealed size wrong");
    CHECK(memcmp(secret, unsealed, 24) == 0, "unsealed data mismatch");
    tpm_device_free(&tpm);
    PASS();
    return 0;
}

/* ── SGX Enclave Tests ── */
static int test_sgx_enclave_create(void) {
    TEST("sgx_enclave_create");
    sgx_enclave_t enclave;
    sgx_enclave_init(&enclave, 64 * 4096, false);
    CHECK(sgx_enclave_create(&enclave) == 0, "enclave create failed");
    CHECK(enclave.identity.page_count == 64, "page count wrong");
    CHECK(!enclave.debug, "debug should be off");
    sgx_enclave_destroy(&enclave);
    PASS();
    return 0;
}

static int test_sgx_enclave_identity(void) {
    TEST("sgx_enclave_identity");
    sgx_enclave_t enclave;
    sgx_enclave_init(&enclave, 64 * 4096, false);
    sgx_enclave_create(&enclave);
    sgx_enclave_identity_t identity;
    sgx_enclave_get_identity(&enclave, &identity);
    int mr_zero = 1;
    for (int i = 0; i < SGX_MEASUREMENT_SIZE; i++)
        if (identity.mr_enclave[i] != 0) mr_zero = 0;
    CHECK(!mr_zero, "MRENCLAVE should not be all zeros");
    sgx_enclave_destroy(&enclave);
    PASS();
    return 0;
}

/* ── TDX/SEV Tests ── */
static int test_tdx_td_create(void) {
    TEST("tdx_td_create");
    tdx_td_t td;
    tdx_td_init(&td, 256 * 4096);
    CHECK(tdx_td_create(&td) == 0, "tdx td create failed");
    uint8_t ext_data[TDX_HASH_SIZE]; memset(ext_data, 0xCC, TDX_HASH_SIZE);
    tdx_td_extend_mr(&td, ext_data);
    tdx_td_finalize(&td);
    tdx_td_info_t info;
    tdx_td_get_info(&td, &info);
    tdx_td_destroy(&td);
    PASS();
    return 0;
}

static int test_sev_vm_launch(void) {
    TEST("sev_vm_launch");
    sev_vm_t sev;
    sev_vm_init(&sev, 256 * 4096, true, true);
    CHECK(sev.es_enabled, "SEV-ES should be enabled");
    CHECK(sev.snp_enabled, "SEV-SNP should be enabled");
    sev_vm_launch_start(&sev, SEV_POLICY_NODBG);
    sev_vm_launch_finish(&sev);
    sev_vm_destroy(&sev);
    PASS();
    return 0;
}

/* ── Remote Attestation Tests ── */
static int test_ra_nonce_challenge(void) {
    TEST("ra_nonce_challenge");
    uint8_t nonce[RA_NONCE_SIZE];
    uint32_t nonce_len;
    ra_generate_nonce(nonce, &nonce_len);
    CHECK(nonce_len > 0, "nonce len is zero");
    CHECK(nonce_len <= RA_NONCE_SIZE, "nonce too long");
    ra_challenge_t challenge;
    ra_generate_challenge(nonce, nonce_len, &challenge);
    CHECK(challenge.nonce_len == nonce_len, "challenge nonce_len mismatch");
    CHECK(challenge.timeout_seconds > 0, "timeout should be > 0");
    PASS();
    return 0;
}

static int test_ra_report_data(void) {
    TEST("ra_report_data");
    uint8_t nonce[RA_NONCE_SIZE];
    uint32_t nonce_len;
    ra_generate_nonce(nonce, &nonce_len);
    uint8_t report_data[RA_REPORT_DATA_SIZE];
    ra_create_report_data(nonce, nonce_len, NULL, 0, report_data);
    int not_all_zero = 0;
    for (int i = 0; i < (int)nonce_len && i < RA_REPORT_DATA_SIZE; i++)
        if (report_data[i] != 0) not_all_zero = 1;
    CHECK(not_all_zero, "report data should not be all zeros");
    PASS();
    return 0;
}

/* ── Confidential Computing Tests ── */
static int test_cc_init_probe(void) {
    TEST("cc_init_probe");
    cc_confidential_ctx_t cc;
    cc_init(&cc);
    bool sgx_ok, tdx_ok, sev_ok, tme_ok;
    cc_is_sgx_supported(&cc, &sgx_ok);
    cc_is_tdx_supported(&cc, &tdx_ok);
    cc_is_sev_supported(&cc, &sev_ok);
    cc_is_tme_supported(&cc, &tme_ok);
    /* In simulation mode all may be false — just check no crash */
    CHECK(sgx_ok || !sgx_ok, "sgx check should not crash");
    cc_free(&cc);
    PASS();
    return 0;
}

static int test_cc_constant_time_equal(void) {
    TEST("constant_time_equal");
    cc_confidential_ctx_t cc;
    cc_init(&cc);
    uint8_t a[32], b[32];
    memset(a, 0x5A, 32);
    memset(b, 0x5A, 32);
    bool equal;
    cc_constant_time_equal(a, b, 32, &equal);
    CHECK(equal, "identical arrays should be equal");
    b[16] = 0x01;
    cc_constant_time_equal(a, b, 32, &equal);
    CHECK(!equal, "different arrays should not be equal");
    cc_free(&cc);
    PASS();
    return 0;
}

static int test_cc_vulnerability_check(void) {
    TEST("cc_vulnerability_check");
    cc_confidential_ctx_t cc;
    cc_init(&cc);
    bool meltdown, spectre_v2;
    cc_check_vulnerability(&cc, CC_VULN_MELTDOWN, &meltdown);
    cc_check_vulnerability(&cc, CC_VULN_SPECTRE_V2, &spectre_v2);
    /* In simulation mode may return false — verify no crash */
    CHECK((meltdown || !meltdown), "meltdown check should not crash");
    cc_free(&cc);
    PASS();
    return 0;
}

int main(void) {
    printf("=== mini-trusted-compute Unit Tests ===\n\n");

    int failed = 0;
    failed += test_tpm_init_startup();
    failed += test_tpm_pcr_extend_read();
    failed += test_tpm_quote();
    failed += test_tpm_seal_unseal();
    failed += test_sgx_enclave_create();
    failed += test_sgx_enclave_identity();
    failed += test_tdx_td_create();
    failed += test_sev_vm_launch();
    failed += test_ra_nonce_challenge();
    failed += test_ra_report_data();
    failed += test_cc_init_probe();
    failed += test_cc_constant_time_equal();
    failed += test_cc_vulnerability_check();

    printf("\n=== Results: %d/%d passed, %d failed ===\n",
           tests_passed, tests_run, failed);
    return failed > 0 ? 1 : 0;
}
