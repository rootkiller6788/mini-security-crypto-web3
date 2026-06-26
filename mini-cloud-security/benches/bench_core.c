/*
 * mini-cloud-security — Benchmark: IAM, KMS, WAF, DDoS, container security
 *
 * Usage: bench_core [iterations]
 */
#include "../include/iam_policy.h"
#include "../include/kms_key.h"
#include "../include/waf_rules.h"
#include "../include/ddos_protect.h"
#include "../include/container_security.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now_ms(void) {
    return (double)clock() / (double)(CLOCKS_PER_SEC / 1000);
}

int main(int argc, char **argv) {
    int N = (argc > 1) ? atoi(argv[1]) : 5000;
    printf("=== mini-cloud-security Benchmarks (iterations=%d) ===\n\n", N);

    /* IAM policy evaluation */
    {
        iam_policy_t *p = iam_policy_create("bench-policy", IAM_POLICY_IDENTITY);
        iam_policy_add_statement(p, IAM_EFFECT_ALLOW, "s3:GetObject", "arn:aws:s3:::bucket/*");
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            iam_evaluate_policy(p, "s3:GetObject", "arn:aws:s3:::bucket/file.txt", NULL);
        }
        double dt = now_ms() - t0;
        printf("  iam_evaluate_policy:                  %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
        iam_policy_free(p);
    }

    /* KMS encrypt/decrypt */
    {
        kms_key_t *key = kms_create_key("bench-key", KMS_KEY_SPEC_SYMMETRIC_DEFAULT,
                                         KMS_KEY_USAGE_ENCRYPT_DECRYPT, KMS_KEY_MATERIAL_KMS, 0, 0);
        unsigned char pt[] = "benchmark secret data for KMS encryption test";
        kms_encrypt_result_t enc;
        kms_decrypt_result_t dec;
        int k = N / 10 > 0 ? N / 10 : 1;
        double t0 = now_ms();
        for (int i = 0; i < k; i++) {
            kms_encrypt(key, pt, sizeof(pt), &enc);
            kms_decrypt(key, enc.ciphertext_blob, enc.ciphertext_len, &dec);
        }
        double dt = now_ms() - t0;
        printf("  kms encrypt+decrypt:                  %d ops in %.1f ms  (%.1f µs/op)\n",
               k, dt, dt * 1000.0 / (double)k);
    }

    /* WAF rule evaluation */
    {
        waf_state_t state; waf_init_state(&state);
        waf_request_t req = {.method = "GET", .uri = "/api/users?id=1' OR '1'='1",
                              .client_ip = "10.0.0.1", .body_len = 0};
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            waf_check_sql_injection(req.uri);
        }
        double dt = now_ms() - t0;
        printf("  waf_check_sql_injection:              %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    /* DDoS traffic recording */
    {
        ddos_protection_t dp; ddos_init(&dp);
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            ddos_record_traffic(&dp, "192.168.1.100", 443, 1500, 6);
        }
        double dt = now_ms() - t0;
        printf("  ddos_record_traffic:                  %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    /* Container image scan */
    {
        cs_state_t state; cs_init_state(&state);
        int k = N / 20 > 0 ? N / 20 : 1;
        double t0 = now_ms();
        for (int i = 0; i < k; i++) {
            cs_image_t *img = cs_scan_image("bench-image", "latest");
            cs_add_vulnerability(img, "CVE-2024-0001", "openssl", CS_SEVERITY_HIGH, 7.5f, 1);
            cs_has_critical_vulns(img);
        }
        double dt = now_ms() - t0;
        printf("  cs_scan_image+add_vuln:               %d ops in %.1f ms  (%.1f µs/op)\n",
               k, dt, dt * 1000.0 / (double)k);
    }

    printf("\n=== Benchmarks complete ===\n");
    return 0;
}
