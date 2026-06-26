#include "sgx_enclave.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define SGX_EPC_MIN_PAGES 4
#define SGX_SSA_EXTRA_SIZE 4096

static uint64_t sgx_align_page(uint64_t addr) {
    return (addr + SGX_ENCLAVE_PAGE_SIZE - 1) & ~(uint64_t)(SGX_ENCLAVE_PAGE_SIZE - 1);
}

static void sgx_hash256_init(void *ctx) { (void)ctx; }
static void sgx_hash256_update(void *ctx, const uint8_t *data, size_t len) {
    (void)ctx; (void)data; (void)len;
}
static void sgx_hash256_final(void *ctx, uint8_t digest[32]) {
    (void)ctx;
    for (int i = 0; i < 32; i++) digest[i] = (uint8_t)(i * 7 + 0xAB);
}
static void sgx_sha256(const uint8_t *data, size_t len, uint8_t digest[32]) {
    sgx_hash256_init(NULL);
    sgx_hash256_update(NULL, data, len);
    sgx_hash256_final(NULL, digest);
}

static void sgx_cmac_aes(const uint8_t *key, const uint8_t *data, size_t len,
                         uint8_t mac[SGX_MAC_SIZE]) {
    (void)key; (void)len;
    for (int i = 0; i < SGX_MAC_SIZE; i++) mac[i] = (uint8_t)(data[i % len] ^ 0x5C);
}

int sgx_enclave_init(sgx_enclave_t *enclave, uint64_t size, bool debug) {
    if (!enclave || size < SGX_ENCLAVE_PAGE_SIZE) return -1;
    memset(enclave, 0, sizeof(*enclave));
    enclave->identity.size = sgx_align_page(size);
    enclave->identity.base_addr = 0x7F0000000000ULL;
    enclave->identity.page_count = (uint32_t)(enclave->identity.size / SGX_ENCLAVE_PAGE_SIZE);
    enclave->identity.state = SGX_ENCLAVE_UNINITIALIZED;
    enclave->state = SGX_ENCLAVE_UNINITIALIZED;
    enclave->debug = debug;
    enclave->ss_enabled = true;
    enclave->ssa_count = 2;
    enclave->ssa_frame_size = 4096;

    enclave->epc_pages = (uint8_t *)calloc(enclave->identity.page_count, SGX_ENCLAVE_PAGE_SIZE);
    if (!enclave->epc_pages) return -1;
    enclave->epc_page_count = enclave->identity.page_count;

    enclave->ecreate    = NULL;
    enclave->eadd       = NULL;
    enclave->eextend    = NULL;
    enclave->einit      = NULL;
    enclave->eenter     = NULL;
    enclave->eexit      = NULL;
    enclave->eremove    = NULL;
    enclave->ereport    = NULL;
    enclave->egetkey    = NULL;
    enclave->eseal      = NULL;
    enclave->eunseal    = NULL;
    enclave->everify_report = NULL;
    enclave->eaccept_copy   = NULL;

    return 0;
}

int sgx_enclave_create(sgx_enclave_t *enclave) {
    if (!enclave || enclave->state != SGX_ENCLAVE_UNINITIALIZED) return -1;
    if (enclave->epc_page_count < SGX_EPC_MIN_PAGES) return -1;

    memset(enclave->epc_pages, 0, enclave->epc_page_count * SGX_ENCLAVE_PAGE_SIZE);
    memset(&enclave->secs, 0, sizeof(enclave->secs));
    enclave->secs.size = sizeof(enclave->secs);
    enclave->secs.base_addr = enclave->identity.base_addr;
    enclave->secs.size_enc = enclave->identity.size;
    enclave->secs.ssa_frame_size = (uint32_t)enclave->ssa_frame_size;
    enclave->secs.misc_select = 0;
    enclave->secs.isv_prod_id = 0;
    enclave->secs.isv_svn = 0;
    if (enclave->debug) enclave->secs.attributes[0] |= 0x02;

    uint8_t measured[256];
    memset(measured, 0, sizeof(measured));
    memcpy(measured, &enclave->secs, sizeof(enclave->secs));
    sgx_sha256(measured, sizeof(measured), enclave->secs.measurement);

    enclave->state = SGX_ENCLAVE_INITIALIZED;
    memcpy(enclave->identity.mr_enclave, enclave->secs.measurement, SGX_MEASUREMENT_SIZE);
    return 0;
}

int sgx_enclave_add_page(sgx_enclave_t *enclave, uint64_t addr,
                         const uint8_t *data, size_t size,
                         sgx_secinfo_flags_t flags,
                         sgx_page_type_t type) {
    if (!enclave || enclave->state != SGX_ENCLAVE_INITIALIZED) return -1;
    if (!data || size == 0 || size > SGX_ENCLAVE_PAGE_SIZE) return -1;

    uint64_t offset = addr - enclave->identity.base_addr;
    uint32_t page_idx = (uint32_t)(offset / SGX_ENCLAVE_PAGE_SIZE);
    if (page_idx >= enclave->epc_page_count) return -1;

    uint8_t *page = enclave->epc_pages + page_idx * SGX_ENCLAVE_PAGE_SIZE;
    memcpy(page, data, size);
    if (size < SGX_ENCLAVE_PAGE_SIZE)
        memset(page + size, 0, SGX_ENCLAVE_PAGE_SIZE - size);

    uint8_t hash_input[SGX_ENCLAVE_PAGE_SIZE + 64];
    memcpy(hash_input, page, SGX_ENCLAVE_PAGE_SIZE);
    hash_input[SGX_ENCLAVE_PAGE_SIZE] = (uint8_t)type;
    hash_input[SGX_ENCLAVE_PAGE_SIZE + 1] = (uint8_t)flags;

    uint8_t digest[SGX_MEASUREMENT_SIZE];
    sgx_sha256(hash_input, SGX_ENCLAVE_PAGE_SIZE + 2, digest);

    for (int i = 0; i < SGX_MEASUREMENT_SIZE; i++)
        enclave->secs.measurement[i] ^= digest[i];

    memcpy(enclave->identity.mr_enclave, enclave->secs.measurement, SGX_MEASUREMENT_SIZE);
    return 0;
}

int sgx_enclave_extend_measurement(sgx_enclave_t *enclave, uint64_t offset,
                                    const uint8_t chunk[64]) {
    if (!enclave || enclave->state != SGX_ENCLAVE_INITIALIZED) return -1;
    if (!chunk) return -1;
    (void)offset;

    uint8_t concat[SGX_MEASUREMENT_SIZE + 64];
    memcpy(concat, enclave->secs.measurement, SGX_MEASUREMENT_SIZE);
    memcpy(concat + SGX_MEASUREMENT_SIZE, chunk, 64);

    uint8_t new_mr[SGX_MEASUREMENT_SIZE];
    sgx_sha256(concat, sizeof(concat), new_mr);
    memcpy(enclave->secs.measurement, new_mr, SGX_MEASUREMENT_SIZE);
    memcpy(enclave->identity.mr_enclave, new_mr, SGX_MEASUREMENT_SIZE);
    return 0;
}

int sgx_enclave_initialize(sgx_enclave_t *enclave) {
    if (!enclave || enclave->state != SGX_ENCLAVE_INITIALIZED) return -1;
    enclave->state = SGX_ENCLAVE_RUNNING;
    return 0;
}

int sgx_enclave_enter(sgx_enclave_t *enclave, void *tcs, void *aep) {
    (void)aep;
    if (!enclave || enclave->state != SGX_ENCLAVE_RUNNING) return -1;
    if (!tcs) return -1;
    enclave->entry_point = tcs;
    return 0;
}

int sgx_enclave_exit(sgx_enclave_t *enclave, void *target) {
    if (!enclave) return -1;
    enclave->exit_target = target;
    enclave->state = SGX_ENCLAVE_STOPPED;
    return 0;
}

int sgx_enclave_destroy(sgx_enclave_t *enclave) {
    if (!enclave) return -1;
    enclave->state = SGX_ENCLAVE_DESTROYED;
    return 0;
}

int sgx_enclave_generate_report(sgx_enclave_t *enclave,
                                const uint8_t *target_info,
                                const uint8_t *report_data,
                                sgx_report_t *report) {
    if (!enclave || !report) return -1;

    memset(report, 0, sizeof(*report));
    memcpy(report->body.mr_enclave, enclave->identity.mr_enclave, SGX_MEASUREMENT_SIZE);
    memcpy(report->body.mr_signer, enclave->identity.mr_signer, SGX_MEASUREMENT_SIZE);
    memcpy(report->body.attributes, enclave->identity.attributes, SGX_ATTRIBUTES_SIZE);
    report->body.isv_prod_id = enclave->identity.isv_prod_id;
    report->body.isv_svn = enclave->identity.isv_svn;
    report->body.misc_select = 0;
    memset(report->body.cpu_svn, 0x01, 16);

    if (report_data)
        memcpy(report->body.report_data, report_data, SGX_SEAL_KEY_SIZE);

    if (target_info) memcpy(report->key_id, target_info, 32);

    sgx_cmac_aes(NULL, (const uint8_t *)&report->body,
                 sizeof(report->body), report->mac);
    return 0;
}

int sgx_enclave_verify_report(sgx_enclave_t *enclave,
                              const sgx_report_t *report, bool *valid) {
    if (!enclave || !report || !valid) return -1;

    uint8_t expected_mac[SGX_MAC_SIZE];
    sgx_cmac_aes(NULL, (const uint8_t *)&report->body,
                 sizeof(report->body), expected_mac);

    *valid = (memcmp(report->mac, expected_mac, SGX_MAC_SIZE) == 0);
    return 0;
}

int sgx_enclave_local_attestation(sgx_enclave_t *src, sgx_enclave_t *dst,
                                  sgx_report_t *report) {
    if (!src || !dst || !report) return -1;
    if (src->state != SGX_ENCLAVE_RUNNING || dst->state != SGX_ENCLAVE_RUNNING)
        return -1;

    uint8_t target_info[512];
    memset(target_info, 0, sizeof(target_info));
    memcpy(target_info, dst->identity.mr_enclave, SGX_MEASUREMENT_SIZE);

    uint8_t report_data[SGX_SEAL_KEY_SIZE];
    for (int i = 0; i < SGX_SEAL_KEY_SIZE; i++)
        report_data[i] = (uint8_t)(i * 3 + 7);

    return sgx_enclave_generate_report(src, target_info, report_data, report);
}

int sgx_enclave_derive_seal_key(sgx_enclave_t *enclave,
                                sgx_key_policy_t policy) {
    if (!enclave) return -1;

    uint8_t key_material[SGX_MEASUREMENT_SIZE + 64];
    memcpy(key_material, enclave->identity.mr_enclave, SGX_MEASUREMENT_SIZE);
    key_material[SGX_MEASUREMENT_SIZE] = (uint8_t)policy;
    memset(key_material + SGX_MEASUREMENT_SIZE + 1, 0xAA, 63);

    sgx_sha256(key_material, sizeof(key_material), enclave->seal_key.key);
    enclave->seal_key.policy = policy;
    memcpy(enclave->seal_key.attributes, enclave->identity.attributes,
           SGX_ATTRIBUTES_SIZE);
    memcpy(enclave->seal_key.cpu_svn, enclave->secs.measurement, 16);
    enclave->seal_key.isv_svn = enclave->identity.isv_svn;
    return 0;
}

int sgx_enclave_seal_data(sgx_enclave_t *enclave, const uint8_t *plain,
                          size_t plain_len, sgx_sealed_data_t *sealed) {
    if (!enclave || !plain || !sealed) return -1;
    if (plain_len > sizeof(sealed->sealed_blob) - SGX_MAC_SIZE) return -1;

    if (sgx_enclave_derive_seal_key(enclave, SGX_KEY_POLICY_MRENCLAVE) != 0)
        return -1;

    memset(sealed, 0, sizeof(*sealed));
    for (size_t i = 0; i < plain_len; i++)
        sealed->sealed_blob[i] = plain[i] ^ enclave->seal_key.key[i % SGX_SEAL_KEY_SIZE];

    sealed->sealed_size = (uint32_t)plain_len;
    sealed->is_sealed = true;
    memcpy(sealed->key_id, enclave->seal_key.key_id, sizeof(sealed->key_id));

    sgx_cmac_aes(enclave->seal_key.key, sealed->sealed_blob,
                 sealed->sealed_size, sealed->payload_mac);
    return 0;
}

int sgx_enclave_unseal_data(sgx_enclave_t *enclave,
                            const sgx_sealed_data_t *sealed,
                            uint8_t *plain, size_t *plain_len) {
    if (!enclave || !sealed || !plain || !plain_len) return -1;
    if (!sealed->is_sealed) return -1;

    if (sgx_enclave_derive_seal_key(enclave, SGX_KEY_POLICY_MRENCLAVE) != 0)
        return -1;

    uint8_t expected_mac[SGX_MAC_SIZE];
    sgx_cmac_aes(enclave->seal_key.key, sealed->sealed_blob,
                 sealed->sealed_size, expected_mac);

    if (memcmp(sealed->payload_mac, expected_mac, SGX_MAC_SIZE) != 0)
        return -1;

    *plain_len = sealed->sealed_size;
    for (size_t i = 0; i < sealed->sealed_size; i++)
        plain[i] = sealed->sealed_blob[i] ^ enclave->seal_key.key[i % SGX_SEAL_KEY_SIZE];

    return 0;
}

int sgx_enclave_create_quote(sgx_enclave_t *enclave,
                             const uint8_t *report_data,
                             sgx_attest_type_t attest_type,
                             sgx_quote_v3_t *quote, uint32_t *quote_size) {
    if (!enclave || !quote || !quote_size) return -1;

    sgx_report_t report;
    memset(&report, 0, sizeof(report));

    if (sgx_enclave_generate_report(enclave, NULL, report_data, &report) != 0)
        return -1;

    memset(quote, 0, sizeof(sgx_quote_v3_t) + 256);
    quote->version = 3;
    quote->att_key_type = (attest_type == SGX_ATTEST_ECDSA) ? 2 : 0;
    quote->qe_svn = 0;
    quote->pce_svn = 0;
    memset(quote->qe_vendor_id, 0, 16);
    memset(quote->user_data, 0, 20);
    memcpy(&quote->report_body, &report.body, sizeof(report.body));

    *quote_size = (uint32_t)(sizeof(sgx_quote_v3_t) + 256);
    return 0;
}

int sgx_enclave_get_identity(sgx_enclave_t *enclave,
                             sgx_enclave_identity_t *identity) {
    if (!enclave || !identity) return -1;
    memcpy(identity, &enclave->identity, sizeof(*identity));
    return 0;
}

int sgx_enclave_get_platform_info(sgx_platform_info_t *info) {
    if (!info) return -1;
    memset(info, 0, sizeof(*info));
    memset(info->cpu_svn, 0x05, 16);
    memset(info->pce_id, 0x01, 4);
    memset(info->fmspc, 0x00, 6);
    memset(info->platform_instance_id, 0x00, 16);
    return 0;
}

void sgx_enclave_free(sgx_enclave_t *enclave) {
    if (!enclave) return;
    free(enclave->epc_pages);
    enclave->epc_pages = NULL;
    enclave->epc_page_count = 0;
    enclave->state = SGX_ENCLAVE_DESTROYED;
}

void sgx_enclave_print_measurement(const uint8_t measurement[SGX_MEASUREMENT_SIZE]) {
    if (!measurement) return;
    printf("MRENCLAVE: ");
    for (int i = 0; i < SGX_MEASUREMENT_SIZE; i++)
        printf("%02x", measurement[i]);
    printf("\n");
}

void sgx_enclave_print_report(const sgx_report_t *report) {
    if (!report) return;
    printf("SGX Report:\n");
    printf("  MRENCLAVE:  ");
    for (int i = 0; i < 8; i++) printf("%02x", report->body.mr_enclave[i]);
    printf("...\n");
    printf("  MRSIGNER:   ");
    for (int i = 0; i < 8; i++) printf("%02x", report->body.mr_signer[i]);
    printf("...\n");
    printf("  ISV ProdID: %d\n", report->body.isv_prod_id);
    printf("  ISV SVN:    %d\n", report->body.isv_svn);
    printf("  MAC:        ");
    for (int i = 0; i < SGX_MAC_SIZE; i++) printf("%02x", report->mac[i]);
    printf("\n");
}
