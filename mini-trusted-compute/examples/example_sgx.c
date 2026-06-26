#include <stdio.h>
#include <string.h>
#include "sgx_enclave.h"

int main(void) {
    printf("=== mini-trusted-compute — SGX Enclave Example ===\n\n");

    sgx_enclave_t enclave;
    if (sgx_enclave_init(&enclave, 1024 * 1024, false) != 0) {
        printf("FAILED: sgx_enclave_init\n");
        return 1;
    }
    printf("[OK] Enclave initialized: %llu pages\n",
           (unsigned long long)enclave.identity.page_count);

    if (sgx_enclave_create(&enclave) != 0) {
        printf("FAILED: sgx_enclave_create\n");
        return 1;
    }
    printf("[OK] SECS created, MRENCLAVE computed\n");
    sgx_enclave_print_measurement(enclave.identity.mr_enclave);

    uint8_t code_page[4096];
    memset(code_page, 0xCC, sizeof(code_page));
    if (sgx_enclave_add_page(&enclave, enclave.identity.base_addr,
                             code_page, sizeof(code_page),
                             SGX_SECINFO_R | SGX_SECINFO_W | SGX_SECINFO_X,
                             SGX_PAGE_REGULAR) != 0) {
        printf("FAILED: sgx_enclave_add_page\n");
        return 1;
    }
    printf("[OK] Page added, measurement extended\n");

    uint8_t chunk[64];
    for (int i = 0; i < 64; i++) chunk[i] = (uint8_t)i;
    if (sgx_enclave_extend_measurement(&enclave, 0, chunk) == 0)
        printf("[OK] EEXTEND executed (256-byte chunk)\n");

    if (sgx_enclave_initialize(&enclave) != 0) {
        printf("FAILED: sgx_enclave_initialize\n");
        return 1;
    }
    printf("[OK] EINIT: enclave is now RUNNING\n");

    uint8_t sealed_plain[] = "Hello, Trusted World! This is sealed data.";
    sgx_sealed_data_t sealed;
    if (sgx_enclave_seal_data(&enclave, sealed_plain,
                              sizeof(sealed_plain), &sealed) == 0) {
        printf("[OK] Data sealed with MRENCLAVE-derived key\n");
        printf("     Sealed size: %u bytes\n", sealed.sealed_size);

        uint8_t unsealed[256];
        size_t unsealed_len = 0;
        if (sgx_enclave_unseal_data(&enclave, &sealed,
                                    unsealed, &unsealed_len) == 0) {
            unsealed[unsealed_len] = '\0';
            printf("[OK] Data unsealed: \"%s\"\n", unsealed);
        }
    }

    uint8_t report_data[SGX_SEAL_KEY_SIZE];
    for (int i = 0; i < SGX_SEAL_KEY_SIZE; i++) report_data[i] = (uint8_t)i;
    sgx_report_t report;
    if (sgx_enclave_generate_report(&enclave, NULL, report_data,
                                    &report) == 0) {
        printf("[OK] EREPORT generated\n");
        sgx_enclave_print_report(&report);

        bool valid = false;
        sgx_enclave_verify_report(&enclave, &report, &valid);
        printf("[OK] Report verification: %s\n", valid ? "PASS" : "FAIL");
    }

    sgx_quote_v3_t quote_buf[1];
    uint32_t quote_size;
    if (sgx_enclave_create_quote(&enclave, report_data,
                                 SGX_ATTEST_ECDSA,
                                 (sgx_quote_v3_t *)quote_buf,
                                 &quote_size) == 0)
        printf("[OK] Remote attestation quote created (%u bytes)\n", quote_size);

    sgx_enclave_identity_t id;
    sgx_enclave_get_identity(&enclave, &id);
    printf("\nEnclave Identity:\n");
    printf("  State:      %d\n", id.state);
    printf("  Base:       0x%llx\n", (unsigned long long)id.base_addr);
    printf("  Size:       %llu bytes\n", (unsigned long long)id.size);
    printf("  ISV ProdID: %u\n", id.isv_prod_id);
    printf("  ISV SVN:    %u\n", id.isv_svn);

    sgx_enclave_destroy(&enclave);
    sgx_enclave_free(&enclave);
    printf("\n[DONE] Enclave destroyed and freed.\n");
    return 0;
}
