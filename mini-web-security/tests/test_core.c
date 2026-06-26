/*
 * mini-web-security — Core Tests
 *
 * Unit tests for XSS/CSRF, SQL injection, input validation, auth/session, OWASP top 10.
 */
#include "../include/xss_csrf.h"
#include "../include/sqli_inject.h"
#include "../include/input_validation.h"
#include "../include/auth_session.h"
#include "../include/owasp_top10.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

static int tests_run = 0, tests_passed = 0;

#define TEST(name) do { tests_run++; printf("  TEST %s ... ", name); } while(0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); return 1; } while(0)
#define CHECK(cond, msg) if (!(cond)) FAIL(msg)

/* ── XSS Tests ── */
static int test_html_encode(void) {
    TEST("html_encode");
    char out[256];
    size_t len = html_encode("<script>", out, sizeof(out));
    CHECK(len > 0, "encode returned 0");
    CHECK(strstr(out, "&lt;") != NULL, "missing &lt;");
    CHECK(strstr(out, "&gt;") != NULL, "missing &gt;");
    PASS();
    return 0;
}

static int test_xss_detect_reflected(void) {
    TEST("xss_detect_reflected");
    xss_report_t report;
    xss_detect_reflected("<img src=x onerror=alert(1)>", "html", &report);
    CHECK(report.detected, "should detect reflected XSS");
    CHECK(report.type == XSS_TYPE_REFLECTED, "type wrong");
    PASS();
    return 0;
}

static int test_csrf_token_generate_validate(void) {
    TEST("csrf_token_generate_validate");
    csrf_token_t tok1, tok2;
    CHECK(csrf_token_generate(&tok1), "generate failed");
    CHECK(csrf_token_generate(&tok2), "generate2 failed");
    CHECK(csrf_token_validate(&tok1, &tok1), "same token should validate");
    CHECK(!csrf_token_validate(&tok1, &tok2), "different tokens should not validate");
    PASS();
    return 0;
}

static int test_csp_policy(void) {
    TEST("csp_policy");
    csp_policy_t policy;
    csp_init(&policy, false);
    CHECK(csp_add_directive(&policy, CSP_SRC_DEFAULT, "'self'") == 0, "add directive failed");
    CHECK(policy.count == 1, "count wrong");
    char header[512];
    int len = csp_generate_header(&policy, header, sizeof(header));
    CHECK(len > 0, "generate header failed");
    PASS();
    return 0;
}

/* ── SQL Injection Tests ── */
static int test_sqli_detect_classic(void) {
    TEST("sqli_detect_classic");
    sqli_detect_result_t result;
    sqli_detect("' OR '1'='1", &result);
    CHECK(result.type != SQLI_NONE, "should detect SQLi");
    CHECK(result.risk_score > 0, "risk score should be >0");
    PASS();
    return 0;
}

static int test_sqli_prepared_statement(void) {
    TEST("sqli_prepared_statement");
    sqli_prepared_t stmt;
    sqli_prepared_init(&stmt, "SELECT * FROM users WHERE id = ?");
    CHECK(sqli_prepared_bind_int(&stmt, 42) == 0, "bind int failed");
    CHECK(sqli_prepared_build(&stmt) == 0, "build failed");
    CHECK(strstr(stmt.sanitized_query, "42") != NULL, "query missing bound value");
    PASS();
    return 0;
}

/* ── Input Validation Tests ── */
static int test_ival_validate_email(void) {
    TEST("ival_validate_email");
    CHECK(ival_validate_email("user@example.com"), "valid email rejected");
    CHECK(!ival_validate_email("not-an-email"), "invalid email accepted");
    PASS();
    return 0;
}

static int test_ival_check_type(void) {
    TEST("ival_check_type");
    CHECK(ival_is_integer("12345"), "integer rejected");
    CHECK(!ival_is_integer("12.34"), "float accepted as int");
    CHECK(ival_is_float("3.14"), "float rejected");
    CHECK(ival_is_alphanum("abc123"), "alphanum rejected");
    CHECK(!ival_is_alphanum("abc<script>"), "XSS in alphanum not rejected");
    PASS();
    return 0;
}

/* ── Auth/Session Tests ── */
static int test_auth_password_hash_verify(void) {
    TEST("auth_password_hash_verify");
    auth_password_t pw;
    CHECK(auth_password_hash("MyS3cureP@ss!", &pw), "hash failed");
    CHECK(auth_password_verify("MyS3cureP@ss!", &pw), "verify failed");
    CHECK(!auth_password_verify("WrongPassword", &pw), "wrong password accepted");
    PASS();
    return 0;
}

static int test_session_generate(void) {
    TEST("session_generate");
    session_t sess;
    session_init(&sess);
    CHECK(session_generate_id(&sess), "generate id failed");
    CHECK(strlen(sess.id) > 0, "empty session id");
    CHECK(!session_is_expired(&sess), "new session expired");
    PASS();
    return 0;
}

static int test_ratelimit_check(void) {
    TEST("ratelimit_check");
    rate_limiter_t rl;
    ratelimit_init(&rl, 5, 60, 300);
    CHECK(ratelimit_check(&rl), "first request blocked");
    CHECK(ratelimit_check(&rl), "second request blocked");
    CHECK(!ratelimit_is_blocked(&rl), "should not be blocked yet");
    CHECK(ratelimit_remaining(&rl) == 3, "remaining wrong");
    PASS();
    return 0;
}

/* ── OWASP Tests ── */
static int test_owasp_ssrf_internal(void) {
    TEST("owasp_ssrf_internal");
    CHECK(ssrf_is_internal_ip("10.0.0.1"), "10.x should be internal");
    CHECK(ssrf_is_internal_ip("192.168.1.1"), "192.168.x should be internal");
    CHECK(ssrf_is_loopback("127.0.0.1"), "loopback not detected");
    CHECK(!ssrf_is_internal_ip("8.8.8.8"), "public IP flagged as internal");
    PASS();
    return 0;
}

static int test_owasp_directory_traversal(void) {
    TEST("owasp_directory_traversal");
    dt_result_t result;
    dt_detect("../../../etc/passwd", &result);
    CHECK(result.detected, "traversal not detected");
    CHECK(result.depth_attempted >= 2, "depth wrong");
    PASS();
    return 0;
}

int main(void) {
    printf("=== mini-web-security Unit Tests ===\n\n");

    int failed = 0;
    failed += test_html_encode();
    failed += test_xss_detect_reflected();
    failed += test_csrf_token_generate_validate();
    failed += test_csp_policy();
    failed += test_sqli_detect_classic();
    failed += test_sqli_prepared_statement();
    failed += test_ival_validate_email();
    failed += test_ival_check_type();
    failed += test_auth_password_hash_verify();
    failed += test_session_generate();
    failed += test_ratelimit_check();
    failed += test_owasp_ssrf_internal();
    failed += test_owasp_directory_traversal();

    printf("\n=== Results: %d/%d passed, %d failed ===\n",
           tests_passed, tests_run, failed);
    return failed > 0 ? 1 : 0;
}
