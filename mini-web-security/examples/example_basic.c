#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "xss_csrf.h"
#include "sqli_inject.h"
#include "owasp_top10.h"
#include "input_validation.h"
#include "auth_session.h"

int main(void) {
    srand((unsigned)time(NULL));
    printf("========================================\n");
    printf("  mini-web-security: Basic Example\n");
    printf("========================================\n\n");

    /* ── XSS: HTML Entity Encoding ── */
    printf("--- XSS: HTML Entity Encoding ---\n");
    const char* user_input = "<script>alert('XSS')</script>";
    char encoded[256];
    html_encode(user_input, encoded, sizeof(encoded));
    printf("  Input:   %s\n", user_input);
    printf("  Encoded: %s\n\n", encoded);

    /* ── XSS Detection ── */
    printf("--- XSS Detection ---\n");
    xss_report_t rpt;
    xss_detect_reflected("<img src=x onerror=alert(1)>", "query", &rpt);
    printf("  Reflected XSS detected: %s\n", rpt.detected ? "YES" : "NO");
    xss_detect_stored("<h1>Safe content</h1>", &rpt);
    printf("  Stored XSS detected:    %s\n\n", rpt.detected ? "YES" : "NO");

    /* ── SQL Injection Detection ── */
    printf("--- SQL Injection Detection ---\n");
    sqli_detect_result_t sqli_r;
    sqli_detect("admin' OR 1=1--", &sqli_r);
    printf("  Input:  admin' OR 1=1--\n");
    printf("  Type:   %s\n", sqli_type_name(sqli_r.type));
    printf("  Risk:   %d/100\n\n", sqli_r.risk_score);

    /* ── Input Validation ── */
    printf("--- Input Validation ---\n");
    printf("  Email 'user@example.com': %s\n",
           ival_validate_email("user@example.com") ? "valid" : "invalid");
    printf("  Email 'not-an-email':      %s\n",
           ival_validate_email("not-an-email") ? "valid" : "invalid");
    printf("  Credit Card '4111111111111111': %s (Luhn)\n",
           ival_validate_credit_card("4111111111111111") ? "valid" : "invalid");
    printf("  IPv4 '192.168.1.1': %s\n",
           ival_validate_ipv4("192.168.1.1") ? "valid" : "invalid\n");

    /* ── CSRF Token ── */
    printf("\n--- CSRF Token ---\n");
    csrf_token_t csrf_tok;
    csrf_token_generate(&csrf_tok);
    char tok_hex[65];
    csrf_token_to_hex(&csrf_tok, tok_hex, sizeof(tok_hex));
    printf("  Generated CSRF token: %.64s\n\n", tok_hex);

    /* ── Password Hashing ── */
    printf("--- Password Hashing (PBKDF2-SHA256) ---\n");
    auth_password_t pw;
    if (auth_password_hash("MySecureP@ssw0rd", &pw)) {
        printf("  Hash computed (iterations=%d)\n", pw.iterations);
        printf("  Verify correct password: %s\n",
               auth_password_verify("MySecureP@ssw0rd", &pw) ? "OK" : "FAIL");
        printf("  Verify wrong password:   %s\n",
               auth_password_verify("WrongPassword", &pw) ? "OK" : "FAIL");
    }
    printf("  Strength of 'abc123':     %d/100\n", auth_password_strength("abc123"));
    printf("  Strength of 'P@ssw0rd!!': %d/100\n\n", auth_password_strength("P@ssw0rd!!"));

    /* ── OWASP Top 10 ── */
    printf("--- OWASP Top 10 ---\n");
    for (int i = 0; i <= OWASP_A10_SSRF; i++) {
        printf("  %s\n", owasp_category_name((owasp_category_t)i));
    }

    /* ── SSRF Detection ── */
    printf("\n--- SSRF Detection ---\n");
    ssrf_analysis_t ssrf_a;
    ssrf_analyze_url("http://127.0.0.1/admin", &ssrf_a);
    printf("  URL: http://127.0.0.1/admin\n");
    printf("  Internal:  %s\n", ssrf_a.is_internal ? "YES" : "NO");
    printf("  Blocked:   %s\n", ssrf_a.is_blocked ? "YES" : "NO");
    printf("  Risk:      %d/100\n\n", ssrf_a.risk_score);

    /* ── Directory Traversal ── */
    printf("--- Directory Traversal ---\n");
    dt_result_t dt_r;
    dt_detect("../../../etc/passwd", &dt_r);
    printf("  Input: ../../../etc/passwd\n");
    printf("  Detected: %s\n", dt_r.detected ? "YES" : "NO");
    printf("  Depth:    %d\n\n", dt_r.depth_attempted);

    printf("========================================\n");
    printf("  All basic examples completed.\n");
    printf("========================================\n");
    return 0;
}
