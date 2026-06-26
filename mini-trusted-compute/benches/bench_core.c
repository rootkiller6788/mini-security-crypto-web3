/*
 * mini-trusted-compute — Benchmark: TPM, SGX, TDX/SEV, remote attestation, confidential computing
 *
 * Usage: bench_core [iterations]
 */
#include "../include/tpm_trust.h"
#include "../include/sgx_enclave.h"
#include "../include/tdx_amd.h"
#include "../include/remote_attest.h"
#include "../include/confidential_comp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now_ms(void) {
    return (double)clock() / (double)(CLOCKS_PER_SEC / 1000);
}

int main(int argc, char **argv) {
    int N = (argc > 1) ? atoi(argv[1]) : 5000;
    printf("=== mini-trusted-compute Benchmarks (iterations=%d) ===\n\n", N);

    /* TPM PCR operations */
    {
        tpm_device_t tpm;
        tpm_init(&tpm, true);
        tpm_startup(&tpm, TPM_SU_CLEAR);
        uint8_t digest[TPM_PCR_SIZE]; memset(digest, 0xAB, TPM_PCR_SIZE);
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            tpm_pcr_extend(&tpm, i % TPM_PCR_COUNT, digest, TPM_PCR_SIZE);
        }
        double dt = now_ms() - t0;
        printf("  tpm_pcr_extend:                       %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
        tpm_device_free(&tpm);
    }

    /* TPM quote + attest */
    {
        tpm_device_t tpm;
        tpm_init(&tpm, true);
        tpm_startup(&tpm, TPM_SU_CLEAR);
        tpm_create_ek(&tpm, &tpm.ek);
        tpm_create_ak(&tpm, &tpm.ak, &tpm.ek);
        uint8_t nonce[TPM_NONCE_SIZE]; memset(nonce, 0x42, TPM_NONCE_SIZE);
        tpm_quote_t quote;
        double t0 = now_ms();
        for (int i = 0; i < N / 10; i++) {
            tpm_quote(&tpm, &tpm.ak, nonce, TPM_NONCE_SIZE, nonce, TPM_NONCE_SIZE, &quote);
        }
        double dt = now_ms() - t0;
        int k = N / 10 > 0 ? N / 10 : 1;
        printf("  tpm_quote:                            %d ops in %.1f ms  (%.1f µs/op)\n",
               k, dt, dt * 1000.0 / (double)k);
        tpm_device_free(&tpm);
    }

    /* TPM seal/unseal */
    {
        tpm_device_t tpm;
        tpm_init(&tpm, true);
        tpm_startup(&tpm, TPM_SU_CLEAR);
        tpm_key_t parent; tpm_create_primary(&tpm, TPM_HIERARCHY_OWNER, NULL, 0, &parent);
        tpm_sealed_key_t sealed;
        uint8_t data[64] = "sealed benchmark data for throughput testing";
        uint32_t pcr_idx = 7;
        tpm_seal(&tpm, &parent, data, 32, &pcr_idx, 1, &sealed);
        uint8_t out[128]; uint32_t out_size;
        double t0 = now_ms();
        for (int i = 0; i < N / 10; i++) {
            tpm_unseal(&tpm, &sealed, out, &out_size);
        }
        double dt = now_ms() - t0;
        int k = N / 10 > 0 ? N / 10 : 1;
        printf("  tpm_unseal:                           %d ops in %.1f ms  (%.1f µs/op)\n",
               k, dt, dt * 1000.0 / (double)k);
        tpm_device_free(&tpm);
    }

    /* SGX enclave operations */
    {
        sgx_enclave_t enclave;
        sgx_enclave_init(&enclave, 64 * 4096, false);
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            sgx_enclave_create(&enclave);
            sgx_enclave_destroy(&enclave);
        }
        double dt = now_ms() - t0;
        printf("  sgx_enclave_create+destroy:           %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    /* SGX measurement verification */
    {
        uint8_t measurement[SGX_MEASUREMENT_SIZE]; memset(measurement, 0xCC, SGX_MEASUREMENT_SIZE);
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            sgx_enclave_print_measurement(measurement);
        }
        double dt = now_ms() - t0;
        printf("  sgx_enclave_print_measurement:        %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    /* SEV attestation */
    {
        sev_vm_t vm;
        sev_vm_init(&vm, 256 * 4096, true, true);
        sev_attest_report_t report;
        uint8_t nonce[32]; memset(nonce, 0xDE, 32);
        double t0 = now_ms();
        for (int i = 0; i < N / 10; i++) {
            sev_vm_attest(&vm, nonce, 32, &report);
        }
        double dt = now_ms() - t0;
        int k = N / 10 > 0 ? N / 10 : 1;
        printf("  sev_vm_attest:                        %d ops in %.1f ms  (%.1f µs/op)\n",
               k, dt, dt * 1000.0 / (double)k);
        sev_vm_destroy(&vm);
    }

    /* Remote attestation: nonce generation */
    {
        uint8_t nonce[RA_NONCE_SIZE]; uint32_t nonce_len;
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            ra_generate_nonce(nonce, &nonce_len);
        }
        double dt = now_ms() - t0;
        printf("  ra_generate_nonce:                    %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    /* Confidential computing: constant-time operations */
    {
        uint8_t a[CC_CONST_TIME_BUFFER_SIZE], b[CC_CONST_TIME_BUFFER_SIZE];
        memset(a, 0x5A, CC_CONST_TIME_BUFFER_SIZE); memset(b, 0x5A, CC_CONST_TIME_BUFFER_SIZE);
        b[128] = 0x01;
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            cc_constant_time_compare(a, b, CC_CONST_TIME_BUFFER_SIZE);
        }
        double dt = now_ms() - t0;
        printf("  cc_constant_time_compare (256 bytes): %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    /* Confidential computing: vulnerability check */
    {
        cc_confidential_ctx_t ctx;
        cc_init(&ctx);
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            bool present;
            cc_check_vulnerability(&ctx, CC_VULN_MELTDOWN, &present);
            cc_check_vulnerability(&ctx, CC_VULN_SPECTRE_V1, &present);
        }
        double dt = now_ms() - t0;
        printf("  cc_check_vulnerability (meltdown+spectre): %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
        cc_free(&ctx);
    }

    printf("\n=== Benchmarks complete ===\n");
    return 0;
}
