/*
 * mini-cloud-security — Core Tests
 *
 * Unit tests for IAM, KMS, WAF, container security, DDoS protection.
 */
#include "iam_policy.h"
#include "kms_key.h"
#include "waf_rules.h"
#include "container_security.h"
#include "ddos_protect.h"
#include "cloud_audit.h"
#include "vpc_security.h"
#include <stdio.h>
#include <stdlib.h>
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
    return 0;
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
    waf_state_t *state = calloc(1, sizeof(waf_state_t));
    CHECK(state != NULL, "state alloc failed");
    waf_init_state(state);
    for (int i = 0; i < 10; i++) {
        waf_rate_check(state, "192.168.1.100");
    }
    CHECK(state->rate_entry_count > 0, "no rate entries");
    free(state);
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
    return 0;
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
    ddos_protection_t *dp = calloc(1, sizeof(ddos_protection_t));
    CHECK(dp != NULL, "alloc failed");
    ddos_init(dp);
    ddos_set_shield_tier(dp, DDOS_SHIELD_STANDARD);
    int before = dp->detection_rule_count;
    ddos_add_detection_rule(dp, DDOS_SYN_FLOOD, 200, 100000, 5);
    CHECK(dp->detection_rule_count == before + 1, "detection rule count wrong");
    CHECK(dp->shield_tier == DDOS_SHIELD_STANDARD, "shield tier wrong");
    free(dp);
    PASS();
    return 0;
}

static int test_ddos_record_traffic(void) {
    TEST("ddos_record_traffic");
    ddos_protection_t *dp = calloc(1, sizeof(ddos_protection_t));
    CHECK(dp != NULL, "alloc failed");
    ddos_init(dp);
    for (int i = 0; i < 50; i++) {
        ddos_record_traffic(dp, "10.0.0.99", 12345, 1400, 6);
    }
    CHECK(dp->traffic.packets_in == 50, "packet count wrong");
    free(dp);
    PASS();
    return 0;
}

/* ── Cloud Audit Tests ── */
static int test_audit_trail_create_log(void) {
    TEST("audit_trail_create_log");
    ca_audit_trail_t *trail = ca_trail_create("main-trail", "s3://audit-logs-bucket");
    CHECK(trail != NULL, "trail create failed");
    CHECK(ca_trail_log_event(trail, CA_EVENT_MANAGEMENT, CA_EV_API_CALL,
          "ec2.amazonaws.com", "arn:aws:iam::123:user/admin",
          "us-east-1", "{\"action\":\"DescribeInstances\"}") == 0, "log event failed");
    CHECK(trail->event_count == 1, "event count wrong");
    CHECK(ca_trail_verify_chain(trail) == 1, "chain verification failed");
    ca_trail_print_summary(trail);
    free(trail);
    PASS();
    return 0;
}

static int test_audit_tamper_detection(void) {
    TEST("audit_tamper_detection");
    ca_audit_trail_t *trail = ca_trail_create("test-trail", "s3://test-bucket");
    ca_trail_log_event(trail, CA_EVENT_MANAGEMENT, CA_EV_WRITE,
        "s3.amazonaws.com", "arn:aws:iam::123:user/test",
        "us-west-2", "{\"bucket\":\"test\"}");
    ca_trail_log_event(trail, CA_EVENT_MANAGEMENT, CA_EV_WRITE,
        "s3.amazonaws.com", "arn:aws:iam::123:user/test",
        "us-west-2", "{\"bucket\":\"test2\"}");

    int tampered = 0;
    CHECK(ca_trail_detect_tamper(trail, &tampered) == 0, "false tamper detection");

    trail->events[0].request_params[0] = 'X';
    CHECK(ca_trail_detect_tamper(trail, &tampered) == 1, "should detect tamper");
    CHECK(tampered == 0, "tampered index should be 0");

    free(trail);
    PASS();
    return 0;
}

static int test_merkle_tree(void) {
    TEST("merkle_tree");
    unsigned char leaves[4][CA_HASH_LEN];
    ca_merkle_tree_t tree;

    for (int i = 0; i < 4; i++) {
        char buf[32];
        snprintf(buf, sizeof(buf), "leaf-%d", i);
        ca_hash_data(buf, strlen(buf), leaves[i]);
    }

    ca_merkle_build(&tree, leaves, 4);
    CHECK(tree.leaf_count == 4, "leaf count wrong");
    CHECK(tree.node_count > 4, "node count too low");

    unsigned char proof[10][CA_HASH_LEN];
    int proof_len = 0;
    CHECK(ca_merkle_generate_proof(&tree, 0, proof, &proof_len) == 0, "proof generation failed");
    CHECK(ca_merkle_verify_proof(tree.root_hash, leaves[0], proof, proof_len, 0) == 1, "proof verification failed");
    PASS();
    return 0;
}

static int test_compliance_engine(void) {
    TEST("compliance_engine");
    ca_state_t *cs = calloc(1, sizeof(ca_state_t));
    CHECK(cs != NULL, "state alloc failed");
    ca_state_init(cs);

    ca_compliance_add_pci_dss_rules(cs);
    ca_compliance_add_cis_aws_rules(cs);
    ca_compliance_add_hipaa_rules(cs);
    CHECK(cs->rule_count > 10, "too few compliance rules");

    ca_compliance_check_encryption(cs, "arn:aws:s3:::my-bucket", 0);
    ca_compliance_check_encryption(cs, "arn:aws:s3:::encrypted-bucket", 1);
    ca_compliance_check_public_access(cs, "arn:aws:s3:::public-bucket", 1);
    ca_compliance_check_mfa(cs, "arn:aws:iam::123:user/admin", 0);
    ca_compliance_check_mfa(cs, "arn:aws:iam::123:user/secure", 1);
    CHECK(cs->finding_count > 0, "no findings generated");

    int pci_score = ca_compliance_score(cs, CA_FRAMEWORK_PCI_DSS);
    CHECK(pci_score >= 0, "PCI score invalid");
    ca_state_print_summary(cs);
    free(cs);
    PASS();
    return 0;
}

/* ── VPC Security Tests ── */
static int test_vpc_sg_create_evaluate(void) {
    TEST("vpc_sg_create_evaluate");
    vpc_security_group_t *sg = vpc_sg_create("sg-test01", "web-sg", "vpc-12345", "Web server security group");
    CHECK(sg != NULL, "SG create failed");

    vpc_sg_add_rule(sg, VPC_INBOUND, VPC_TCP, 80, 80, "0.0.0.0/0");
    vpc_sg_add_rule(sg, VPC_INBOUND, VPC_TCP, 443, 443, "0.0.0.0/0");
    vpc_sg_add_rule(sg, VPC_INBOUND, VPC_TCP, 22, 22, "10.0.0.0/8");
    CHECK(sg->inbound_count == 3, "inbound rule count wrong");

    CHECK(vpc_sg_evaluate(sg, VPC_INBOUND, VPC_TCP, 80, "192.168.1.1") == 1, "HTTP should be allowed");
    CHECK(vpc_sg_evaluate(sg, VPC_INBOUND, VPC_TCP, 22, "192.168.1.1") == 0, "SSH from public should be denied");
    CHECK(vpc_sg_evaluate(sg, VPC_INBOUND, VPC_TCP, 22, "10.0.0.50") == 1, "SSH from internal should be allowed");
    CHECK(vpc_sg_evaluate(sg, VPC_INBOUND, VPC_TCP, 3306, "10.0.0.50") == 0, "MySQL should be denied");

    free(sg);
    PASS();
    return 0;
}

static int test_vpc_nacl_evaluate(void) {
    TEST("vpc_nacl_evaluate");
    vpc_network_acl_t *nacl = vpc_nacl_create("acl-test01", "vpc-12345", 0);
    vpc_nacl_add_rule(nacl, VPC_INBOUND, 100, VPC_RULE_ALLOW, VPC_TCP, 80, 80, "0.0.0.0/0");
    vpc_nacl_add_rule(nacl, VPC_INBOUND, 200, VPC_RULE_DENY, VPC_TCP, 22, 22, "0.0.0.0/0");
    vpc_nacl_add_rule(nacl, VPC_INBOUND, 300, VPC_RULE_ALLOW, VPC_TCP, 443, 443, "0.0.0.0/0");
    CHECK(nacl->inbound_count == 3, "NACL rule count wrong");

    int matched = 0;
    CHECK(vpc_nacl_evaluate(nacl, VPC_INBOUND, VPC_TCP, 80, "192.168.1.1", &matched) == 1, "HTTP should be allowed");
    CHECK(vpc_nacl_evaluate(nacl, VPC_INBOUND, VPC_TCP, 22, "10.0.0.1", &matched) == 0, "SSH should be denied");

    free(nacl);
    PASS();
    return 0;
}

static int test_vpc_cidr_operations(void) {
    TEST("vpc_cidr_operations");
    vpc_cidr_t c1_copy, c2_copy, c3_copy;
    vpc_cidr_t *c1 = vpc_cidr_parse("10.0.0.0/16");
    CHECK(c1 != NULL, "CIDR parse c1 failed");
    memcpy(&c1_copy, c1, sizeof(vpc_cidr_t));
    vpc_cidr_t *c2 = vpc_cidr_parse("10.0.1.0/24");
    CHECK(c2 != NULL, "CIDR parse c2 failed");
    memcpy(&c2_copy, c2, sizeof(vpc_cidr_t));
    vpc_cidr_t *c3 = vpc_cidr_parse("192.168.0.0/16");
    CHECK(c3 != NULL, "CIDR parse c3 failed");
    memcpy(&c3_copy, c3, sizeof(vpc_cidr_t));

    CHECK(vpc_cidr_contains(&c1_copy, "10.0.5.5") == 1, "10.0.5.5 should be in 10.0.0.0/16");
    CHECK(vpc_cidr_contains(&c1_copy, "192.168.1.1") == 0, "192.168.1.1 should NOT be in 10.0.0.0/16");
    CHECK(vpc_cidr_subset(&c2_copy, &c1_copy) == 1, "10.0.1.0/24 should be subset of 10.0.0.0/16");
    CHECK(vpc_cidr_overlap(&c1_copy, &c3_copy) == 0, "10/16 and 192.168/16 should not overlap");

    vpc_cidr_t a, b;
    CHECK(vpc_cidr_split(&c1_copy, &a, &b) == 0, "CIDR split failed");
    CHECK(a.prefix_length == 17, "split prefix wrong");
    CHECK(b.prefix_length == 17, "split prefix wrong");
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
    failed += test_audit_trail_create_log();
    failed += test_audit_tamper_detection();
    failed += test_merkle_tree();
    failed += test_compliance_engine();
    failed += test_vpc_sg_create_evaluate();
    failed += test_vpc_nacl_evaluate();
    failed += test_vpc_cidr_operations();

    printf("\n=== Results: %d/%d passed, %d failed ===\n",
           tests_passed, tests_run, failed);
    return failed > 0 ? 1 : 0;
}
