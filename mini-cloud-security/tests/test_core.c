/*
 * mini-cloud-security — Core Tests
 *
 * Unit tests for IAM, KMS, WAF, container security, DDoS protection.
 */
#include "../include/iam_policy.h"
#include "../include/kms_key.h"
#include "../include/waf_rules.h"
#include "../include/container_security.h"
#include "../include/ddos_protect.h"
#include <stdio.h>
#include <string.h>

static int tests_run = 0, tests_passed = 0;

#define TEST(name) do { tests_run++; printf("  TEST %s ... ", name); } while(0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); return 1; } while(0)
#define CHECK(cond, msg) if (!(cond)) FAIL(msg)

/* ── IAM Tests ── */
static int test_iam_policy_create_evaluate(void) {
    TEST("iam_policy_create_evaluate");
    iam_policy_t *p = iam_policy_create("test-policy", IAM_POLICY_IDENTITY);
    CHECK(p != NULL, "create failed");
    iam_policy_add_statement(p, IAM_EFFECT_ALLOW, "s3:GetObject", "arn:aws:s3:::my-bucket/*");
    CHECK(p->statement_count == 1, "statement count wrong");
    iam_result_t r = iam_evaluate_policy(p, "s3:GetObject", "arn:aws:s3:::my-bucket/file.txt", "{}");
    CHECK(r == IAM_RESULT_ALLOW, "should allow matching action");
    r = iam_evaluate_policy(p, "s3:PutObject", "arn:aws:s3:::my-bucket/file.txt", "{}");
    CHECK(r == IAM_RESULT_DENY, "should deny non-matching action");
    iam_policy_free(p);
    PASS();
    return 0;
}

static int test_iam_explicit_deny(void) {
    TEST("iam_explicit_deny");
    iam_policy_t *allow = iam_policy_create("allow-all", IAM_POLICY_IDENTITY);
    iam_policy_add_statement(allow, IAM_EFFECT_ALLOW, "s3:*", "arn:aws:s3:::*");
    iam_policy_t *deny = iam_policy_create("deny-delete", IAM_POLICY_IDENTITY);
    iam_policy_add_statement(deny, IAM_EFFECT_DENY, "s3:DeleteBucket", "arn:aws:s3:::*");
    const iam_policy_t *policies[] = {allow, deny};
    iam_result_t r = iam_evaluate_all(policies, 2, "s3:DeleteBucket", "arn:aws:s3:::my-bucket", "{}");
    CHECK(r == IAM_RESULT_DENY, "explicit deny should win");
    iam_policy_free(allow);
    iam_policy_free(deny);
    PASS();
    return 0;
}

/* ── KMS Tests ── */
static int test_kms_create_key(void) {
    TEST("kms_create_key");
    kms_key_t *key = kms_create_key("test-key", KMS_KEY_SPEC_SYMMETRIC_DEFAULT,
                                     KMS_KEY_USAGE_ENCRYPT_DECRYPT, KMS_KEY_MATERIAL_KMS, 0, 0);
    CHECK(key != NULL, "create key failed");
    CHECK(key->state == KMS_KEY_STATE_ENABLED, "key not enabled");
    CHECK(key->spec == KMS_KEY_SPEC_SYMMETRIC_DEFAULT, "spec wrong");
    PASS();
}

static int test_kms_encrypt_decrypt(void) {
    TEST("kms_encrypt_decrypt");
    kms_key_t *key = kms_create_key("enc-key", KMS_KEY_SPEC_SYMMETRIC_DEFAULT,
                                     KMS_KEY_USAGE_ENCRYPT_DECRYPT, KMS_KEY_MATERIAL_KMS, 0, 0);
    const char *plaintext = "sensitive cloud data";
    kms_encrypt_result_t enc_result;
    CHECK(kms_encrypt(key, (const unsigned char *)plaintext, strlen(plaintext), &enc_result) == 0, "encrypt failed");
    CHECK(enc_result.ciphertext_len > 0, "ciphertext empty");
    kms_decrypt_result_t dec_result;
    CHECK(kms_decrypt(key, enc_result.ciphertext_blob, enc_result.ciphertext_len, &dec_result) == 0, "decrypt failed");
    CHECK(dec_result.plaintext_len == strlen(plaintext), "decrypt len mismatch");
    CHECK(memcmp(plaintext, dec_result.plaintext, dec_result.plaintext_len) == 0, "decrypt mismatch");
    PASS();
    return 0;
}

static int test_kms_envelope_encrypt(void) {
    TEST("kms_envelope_encrypt");
    kms_key_t *cmk = kms_create_key("cmk", KMS_KEY_SPEC_SYMMETRIC_DEFAULT,
                                     KMS_KEY_USAGE_ENCRYPT_DECRYPT, KMS_KEY_MATERIAL_KMS, 0, 0);
    const char *data = "large data encrypted with envelope encryption";
    kms_data_key_t dk;
    unsigned char ciphertext[8192];
    size_t ct_len;
    CHECK(kms_envelope_encrypt(cmk, (const unsigned char *)data, strlen(data), &dk, ciphertext, &ct_len) == 0, "envelope encrypt failed");
    unsigned char recovered[8192];
    size_t rec_len;
    CHECK(kms_envelope_decrypt(cmk, &dk, ciphertext, ct_len, recovered, &rec_len) == 0, "envelope decrypt failed");
    CHECK(rec_len == strlen(data), "recovered len mismatch");
    CHECK(memcmp(data, recovered, rec_len) == 0, "recovered data mismatch");
    PASS();
    return 0;
}

/* ── WAF Tests ── */
static int test_waf_sqli_detection(void) {
    TEST("waf_sqli_detection");
    CHECK(waf_check_sql_injection("' OR 1=1 --"), "SQLi not detected");
    CHECK(waf_check_sql_injection("1; DROP TABLE users"), "DROP TABLE not detected");
    CHECK(!waf_check_sql_injection("hello world"), "false positive on normal text");
    PASS();
    return 0;
}

static int test_waf_xss_detection(void) {
    TEST("waf_xss_detection");
    CHECK(waf_check_xss("<script>alert(1)</script>"), "XSS not detected");
    CHECK(waf_check_xss("javascript:alert(1)"), "javascript URI not detected");
    CHECK(!waf_check_xss("normal text without tags"), "false positive");
    PASS();
    return 0;
}

static int test_waf_rate_check(void) {
    TEST("waf_rate_check");
    waf_state_t state;
    waf_init_state(&state);
    for (int i = 0; i < 10; i++) {
        waf_rate_check(&state, "192.168.1.100");
    }
    CHECK(state.rate_entry_count > 0, "no rate entries");
    PASS();
    return 0;
}

/* ── Container Security Tests ── */
static int test_container_scan_image(void) {
    TEST("container_scan_image");
    cs_image_t *img = cs_scan_image("nginx", "1.25");
    CHECK(img != NULL, "scan failed");
    CHECK(strcmp(img->image_name, "nginx") == 0, "image name wrong");
    PASS();
}

static int test_container_seccomp_profile(void) {
    TEST("container_seccomp_profile");
    cs_seccomp_profile_t *prof = cs_create_seccomp_profile("default", "ERRNO");
    CHECK(prof != NULL, "create profile failed");
    cs_seccomp_add_syscall(prof, "read");
    cs_seccomp_add_syscall(prof, "write");
    CHECK(prof->syscall_count == 2, "syscall count wrong");
    PASS();
    return 0;
}

/* ── DDoS Protection Tests ── */
static int test_ddos_init_detect(void) {
    TEST("ddos_init_and_detect");
    ddos_protection_t dp;
    ddos_init(&dp);
    ddos_set_shield_tier(&dp, DDOS_SHIELD_STANDARD);
    ddos_add_detection_rule(&dp, DDOS_SYN_FLOOD, 200, 100000, 5);
    CHECK(dp.detection_rule_count == 1, "detection rule count wrong");
    CHECK(dp.shield_tier == DDOS_SHIELD_STANDARD, "shield tier wrong");
    PASS();
    return 0;
}

static int test_ddos_record_traffic(void) {
    TEST("ddos_record_traffic");
    ddos_protection_t dp;
    ddos_init(&dp);
    for (int i = 0; i < 50; i++) {
        ddos_record_traffic(&dp, "10.0.0.99", 12345, 1400, 6);
    }
    CHECK(dp.traffic.packets_in == 50, "packet count wrong");
    PASS();
    return 0;
}

int main(void) {
    printf("=== mini-cloud-security Unit Tests ===\n\n");

    int failed = 0;
    failed += test_iam_policy_create_evaluate();
    failed += test_iam_explicit_deny();
    failed += test_kms_create_key();
    failed += test_kms_encrypt_decrypt();
    failed += test_kms_envelope_encrypt();
    failed += test_waf_sqli_detection();
    failed += test_waf_xss_detection();
    failed += test_waf_rate_check();
    failed += test_container_scan_image();
    failed += test_container_seccomp_profile();
    failed += test_ddos_init_detect();
    failed += test_ddos_record_traffic();

    printf("\n=== Results: %d/%d passed, %d failed ===\n",
           tests_passed, tests_run, failed);
    return failed > 0 ? 1 : 0;
}
