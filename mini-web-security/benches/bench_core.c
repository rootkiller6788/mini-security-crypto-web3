/*
 * mini-web-security — Benchmark: XSS, SQLi, OWASP, input validation, auth
 *
 * Usage: bench_core [iterations]
 */
#include "../include/xss_csrf.h"
#include "../include/sqli_inject.h"
#include "../include/owasp_top10.h"
#include "../include/input_validation.h"
#include "../include/auth_session.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now_ms(void) {
    return (double)clock() / (double)(CLOCKS_PER_SEC / 1000);
}

int main(int argc, char **argv) {
    int N = (argc > 1) ? atoi(argv[1]) : 5000;
    printf("=== mini-web-security Benchmarks (iterations=%d) ===\n\n", N);

    /* HTML encode */
    {
        char out[256];
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            html_encode("<script>alert('xss')</script>", out, sizeof(out));
        }
        double dt = now_ms() - t0;
        printf("  html_encode:                          %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    /* XSS sanitize */
    {
        char out[256];
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            xss_sanitize_html("<img src=x onerror=alert(1)>", out, sizeof(out));
        }
        double dt = now_ms() - t0;
        printf("  xss_sanitize_html:                    %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    /* SQLi detection */
    {
        sqli_detect_result_t r;
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            sqli_detect("' OR '1'='1' --", &r);
        }
        double dt = now_ms() - t0;
        printf("  sqli_detect:                          %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    /* CSP header generation */
    {
        csp_policy_t policy;
        csp_init(&policy, false);
        csp_add_directive(&policy, CSP_SRC_DEFAULT, "'self'");
        csp_add_directive(&policy, CSP_SRC_SCRIPT, "'self' 'nonce-abc'");
        char out[512];
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            csp_generate_header(&policy, out, sizeof(out));
        }
        double dt = now_ms() - t0;
        printf("  csp_generate_header:                  %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    /* Input validation */
    {
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            ival_validate_email("user@example.com");
            ival_is_integer("12345");
            ival_is_alphanum("abc123");
        }
        double dt = now_ms() - t0;
        printf("  ival_validate (email+int+alphanum):   %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    /* PBKDF2 password hash */
    {
        auth_password_t pw;
        int k = N / 20 > 0 ? N / 20 : 1;
        double t0 = now_ms();
        for (int i = 0; i < k; i++) {
            auth_password_hash("benchmark-password-123", &pw);
        }
        double dt = now_ms() - t0;
        printf("  auth_password_hash (PBKDF2):          %d ops in %.1f ms  (%.1f µs/op)\n",
               k, dt, dt * 1000.0 / (double)k);
    }

    /* TOTP code generation */
    {
        totp_config_t cfg;
        totp_init(&cfg, 6, 30);
        char secret[64];
        totp_generate_secret(secret, sizeof(secret));
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            totp_generate_code(&cfg, time(NULL));
        }
        double dt = now_ms() - t0;
        printf("  totp_generate_code:                   %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    /* OWASP scan */
    {
        owasp_report_t report;
        const char *headers[] = {"Server: nginx/1.18", "X-XSS-Protection: 0"};
        double t0 = now_ms();
        for (int i = 0; i < N / 10; i++) {
            owasp_report_init(&report);
            owasp_scan_headers(headers, 2, &report);
        }
        double dt = now_ms() - t0;
        printf("  owasp_scan_headers:                   %d ops in %.1f ms  (%.1f µs/op)\n",
               N / 10, dt, dt * 1000.0 / (double)(N / 10));
    }

    printf("\n=== Benchmarks complete ===\n");
    return 0;
}
