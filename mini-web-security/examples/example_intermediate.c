#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "xss_csrf.h"
#include "sqli_inject.h"
#include "owasp_top10.h"
#include "input_validation.h"
#include "auth_session.h"

static void test_csp(void) {
    printf("=== Content Security Policy ===\n");
    csp_policy_t csp;
    csp_init(&csp, false);
    csp_add_directive(&csp, CSP_SRC_DEFAULT, "'self'");
    csp_add_directive(&csp, CSP_SRC_SCRIPT, "'self' 'nonce-abc123'");
    csp_add_directive(&csp, CSP_SRC_STYLE, "'self' 'unsafe-inline'");
    csp_add_directive(&csp, CSP_SRC_IMG, "'self' https:");
    csp_add_directive(&csp, CSP_SRC_FRAME_ANCESTORS, "'none'");
    char csp_header[512];
    csp_generate_header(&csp, csp_header, sizeof(csp_header));
    printf("  %s\n", csp_header);
    char nonce[32];
    csp_generate_nonce(nonce, sizeof(nonce));
    printf("  Generated nonce: %s\n", nonce);
    char hash_buf[64];
    csp_generate_hash("console.log('hello');", hash_buf, sizeof(hash_buf));
    printf("  Script hash:     %s\n\n", hash_buf);
}

static void test_sqli_prepared(void) {
    printf("=== SQL Prepared Statement ===\n");
    sqli_prepared_t stmt;
    sqli_prepared_init(&stmt,
        "SELECT id, name, email FROM users WHERE id = ? AND status = ?");
    sqli_prepared_bind_int(&stmt, 42);
    sqli_prepared_bind_text(&stmt, "active");
    sqli_prepared_build(&stmt);
    printf("  Template: %s\n", stmt.query_template);
    printf("  Compiled: %s\n\n", stmt.sanitized_query);
}

static void test_nosqli(void) {
    printf("=== NoSQL Injection Detection ===\n");
    const char* nosql_payloads[] = {
        "{\"$gt\": \"\"}",
        "{\"$ne\": null}",
        "{\"$regex\": \".*\"}",
        "{\"$where\": \"1==1\"}",
        "{\"username\": \"admin\"}",
        NULL
    };
    for (int i = 0; nosql_payloads[i]; i++) {
        nosqli_type_t t = nosqli_detect(nosql_payloads[i]);
        const char* tn = "NONE";
        if (t == NOSQLI_GT_NE) tn = "GT/NE";
        else if (t == NOSQLI_REGEX) tn = "REGEX";
        else if (t == NOSQLI_WHERE) tn = "WHERE";
        printf("  Payload: %-25s -> %s\n", nosql_payloads[i], tn);
    }
    printf("\n");
}

static void test_utf8(void) {
    printf("=== UTF-8 Validation ===\n");
    const char* tests[] = {
        "Hello, World!",
        "\x80\x80\x80",
        "S\xc3\xa9" "curit\xc3\xa9",
        NULL
    };
    for (int i = 0; tests[i]; i++) {
        bool valid = utf8_validate(tests[i], strlen(tests[i]));
        printf("  \"%s\" %s\n", tests[i], valid ? "valid" : "INVALID");
    }
    printf("\n");
}

static void test_double_encoding(void) {
    printf("=== Double Encoding Detection ===\n");
    const char* encoded = "%25%33%63script%25%33%65";
    printf("  Input:    %s\n", encoded);
    char decoded[256];
    double_enc_decode_once(encoded, decoded, sizeof(decoded));
    printf("  Decoded:  %s\n", decoded);
    double_enc_t dbl;
    double_enc_detect(encoded, &dbl);
    printf("  Detected: %s (depth=%d)\n\n",
           dbl.detected ? "YES" : "NO", dbl.depth);
}

static void test_param_pollution(void) {
    printf("=== Parameter Pollution ===\n");
    const char* qs = "user=admin&user=guest&role=user&role=admin&page=1";
    param_pollution_t pp;
    param_pollution_init(&pp);
    param_pollution_parse(qs, &pp);
    printf("  Query: %s\n", qs);
    printf("  Params found: %d\n", pp.count);
    printf("  Polluted params: %d\n", param_pollution_detect(&pp));
    for (int i = 0; i < pp.count; i++) {
        printf("    '%s' =", pp.params[i].name);
        for (int j = 0; j < pp.params[i].count; j++)
            printf(" [%s]", pp.params[i].values[j]);
        printf("\n");
    }
    printf("\n");
}

static void test_mass_assignment(void) {
    printf("=== Mass Assignment Protection ===\n");
    const char* allowed[] = {"username", "email", "bio", "avatar"};
    mass_assignment_t ma;
    mass_assign_init(&ma, allowed, 4);
    const char* input[] = {"username", "email", "is_admin", "password", "bio"};
    printf("  Input fields: username, email, is_admin, password, bio\n");
    printf("  Allowed only: username, email, bio, avatar\n");
    printf("  Validate 'is_admin': %s\n",
           mass_assign_validate(&ma, "is_admin") ? "allowed" : "BLOCKED");
    printf("  Validate 'username': %s\n",
           mass_assign_validate(&ma, "username") ? "allowed" : "BLOCKED");
    const char* output[8];
    int found = mass_assign_filter(&ma, input, 5, output, 8);
    printf("  Filtered fields (%d):", found);
    for (int i = 0; i < found; i++) printf(" %s", output[i]);
    printf("\n\n");
}

static void test_totp(void) {
    printf("=== TOTP (MFA) ===\n");
    totp_config_t totp;
    totp_init(&totp, 6, 30);
    char secret[32];
    totp_generate_secret(secret, sizeof(secret));
    strncpy(totp.secret_base32, secret, sizeof(totp.secret_base32) - 1);
    printf("  Secret:     %s\n", totp.secret_base32);
    time_t now = time(NULL);
    uint32_t code = totp_generate_code(&totp, now);
    printf("  TOTP code:  %06u\n", (unsigned)code);
    printf("  Valid code: %s\n", totp_validate_code(&totp, now, code) ? "YES" : "NO");
    printf("  Valid (window=1): %s\n\n",
           totp_validate_window(&totp, now, code, 1) ? "YES" : "NO");
}

static void test_rate_limit(void) {
    printf("=== Rate Limiting (Brute Force Protection) ===\n");
    rate_limiter_t rl;
    ratelimit_init(&rl, 5, 60, 300);
    printf("  Max attempts: %d per %ds, Block: %ds\n", 5, 60, 300);
    printf("  Remaining: %d\n", ratelimit_remaining(&rl));
    int passed = 0;
    for (int i = 0; i < 6; i++) {
        if (ratelimit_check(&rl)) passed++;
    }
    printf("  After 6 attempts: %d passed\n", passed);
    printf("  Blocked: %s\n\n", ratelimit_is_blocked(&rl) ? "YES" : "NO");
}

static void test_jwt(void) {
    printf("=== JWT Security ===\n");
    jwt_token_t jwt;
    const char* jwt_str = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.signature";
    if (jwt_parse(jwt_str, &jwt)) {
        printf("  Parsed JWT\n");
        printf("  Algorithm: %d\n", jwt.algorithm);
    }
    printf("  None attack check: %s\n",
           jwt_none_attack_check("{\"alg\":\"none\",\"typ\":\"JWT\"}") ? "VULNERABLE" : "OK");
    printf("  None attack (HS256): %s\n",
           jwt_none_attack_check("{\"alg\":\"HS256\",\"typ\":\"JWT\"}") ? "VULNERABLE" : "OK");
    uint8_t weak_key[8];
    memset(weak_key, 0, 8);
    printf("  Weak key check (8 bytes): %s\n",
           jwt_weak_key_check(weak_key, 8, JWT_ALG_HS256) ? "WEAK" : "OK");
    printf("  Weak key check (32 bytes): %s\n\n",
           jwt_weak_key_check(weak_key, 32, JWT_ALG_HS256) ? "WEAK" : "OK");
}

static void test_owasp_scan(void) {
    printf("=== OWASP Header Scan ===\n");
    const char* headers[] = {
        "Content-Type: text/html",
        "X-Frame-Options: DENY",
        "Cache-Control: no-cache",
        NULL
    };
    owasp_report_t report;
    owasp_report_init(&report);
    int found = owasp_scan_headers(headers, 3, &report);
    printf("  Headers scanned: 3, issues found: %d\n", found);
    for (int i = 0; i < report.count; i++) {
        printf("  [%s] %s: %s\n",
               report.findings[i].risk == RISK_HIGH ? "HIGH" : "MED",
               owasp_category_name(report.findings[i].category),
               report.findings[i].detail);
    }
    printf("\n");
}

int main(void) {
    srand((unsigned)time(NULL));
    printf("========================================\n");
    printf("  mini-web-security: Intermediate Demo\n");
    printf("========================================\n\n");

    test_csp();
    test_sqli_prepared();
    test_nosqli();
    test_utf8();
    test_double_encoding();
    test_param_pollution();
    test_mass_assignment();
    test_totp();
    test_rate_limit();
    test_jwt();
    test_owasp_scan();

    printf("========================================\n");
    printf("  All intermediate tests completed.\n");
    printf("========================================\n");
    return 0;
}
