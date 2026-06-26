/*
 * mini-cloud-security — Full Demo: Cloud Security
 *
 * Demonstrates: IAM policy management, KMS key lifecycle,
 *               WAF rules, DDoS protection, container security scanning.
 */
#include "../include/iam_policy.h"
#include "../include/kms_key.h"
#include "../include/waf_rules.h"
#include "../include/ddos_protect.h"
#include "../include/container_security.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    printf("╔══════════════════════════════════════════╗\n");
    printf("║   mini-cloud-security: Cloud Security   ║\n");
    printf("╚══════════════════════════════════════════╝\n\n");

    /* Step 1: IAM Policy Management */
    printf("── Step 1: IAM Policy Management ──\n");
    iam_policy_t *policy = iam_policy_create("ReadOnlyS3", IAM_POLICY_IDENTITY);
    iam_policy_add_statement(policy, IAM_EFFECT_ALLOW, "s3:GetObject", "arn:aws:s3:::my-bucket/*");
    iam_policy_add_statement(policy, IAM_EFFECT_DENY, "s3:DeleteObject", "arn:aws:s3:::my-bucket/*");
    printf("Policy '%s' created with 2 statements\n", policy->name);

    bool allowed = iam_evaluate_policy(policy, "s3:GetObject", "arn:aws:s3:::my-bucket/photo.jpg", NULL);
    bool denied  = iam_evaluate_policy(policy, "s3:DeleteObject", "arn:aws:s3:::my-bucket/photo.jpg", NULL);
    printf("s3:GetObject on photo.jpg: %s\n", allowed ? "ALLOW" : "DENY");
    printf("s3:DeleteObject on photo.jpg: %s\n", denied ? "ALLOW (unexpected)" : "DENY");

    iam_policy_add_condition(policy, "s3:GetObject", IAM_COND_IP_ADDRESS, "10.0.0.0/8");
    printf("Added IP condition: only 10.0.0.0/8 can access\n");

    /* Step 2: KMS Key Lifecycle */
    printf("\n── Step 2: KMS Key Management ──\n");
    kms_key_t *key = kms_create_key("app-encryption-key", KMS_KEY_SPEC_SYMMETRIC_DEFAULT,
                                     KMS_KEY_USAGE_ENCRYPT_DECRYPT, KMS_KEY_MATERIAL_KMS, 0, 1);
    printf("KMS key '%s' created (spec=Symmetric, rotation=enabled)\n", key->key_id);

    unsigned char plaintext[] = "Payment card: 4111-1111-1111-1111 | SSN: 123-45-6789";
    kms_encrypt_result_t enc_result;
    kms_encrypt(key, plaintext, sizeof(plaintext), &enc_result);
    printf("Encrypted: %zu bytes (key: %s)\n", enc_result.ciphertext_len, enc_result.key_id);

    kms_decrypt_result_t dec_result;
    kms_decrypt(key, enc_result.ciphertext_blob, enc_result.ciphertext_len, &dec_result);
    printf("Decrypted: \"%s\"\n", dec_result.plaintext);

    kms_enable_key_rotation(key, 90);
    printf("Key rotation: every 90 days\n");

    /* Step 3: WAF Rules */
    printf("\n── Step 3: WAF Rule Evaluation ──\n");
    waf_state_t waf;
    waf_init_state(&waf);

    waf_request_t req1 = {.method = "GET", .uri = "/api/users?id=1' OR '1'='1",
                           .client_ip = "192.168.1.100", .body_len = 0};
    printf("Request: GET %s\n", req1.uri);
    bool sqli_blocked = waf_check_sql_injection(req1.uri);
    printf("  SQL injection check: %s\n", sqli_blocked ? "BLOCKED" : "PASSED");

    waf_request_t req2 = {.method = "POST", .uri = "/api/comment",
                           .client_ip = "10.0.0.5",
                           .body = "<script>alert(document.cookie)</script>", .body_len = 40};
    printf("Request: POST %s (body has XSS payload)\n", req2.uri);
    bool xss_blocked = waf_check_xss(req2.body);
    printf("  XSS check: %s\n", xss_blocked ? "BLOCKED" : "PASSED");

    /* Step 4: DDoS Protection */
    printf("\n── Step 4: DDoS Protection ──\n");
    ddos_protection_t dp;
    ddos_init(&dp);

    for (int i = 0; i < 200; i++) {
        ddos_record_traffic(&dp, "203.0.113.42", 443, 1500, 6);
    }
    bool ddos_detected = ddos_is_under_attack(&dp);
    printf("After 200 TCP packets: attack detected = %s\n", ddos_detected ? "YES" : "NO");

    ddos_mitigation_action_t action = ddos_recommend_action(&dp);
    printf("Recommended action: %d\n", action);

    /* Step 5: Container Security */
    printf("\n── Step 5: Container Security ──\n");
    cs_state_t cs;
    cs_init_state(&cs);

    cs_image_t *img = cs_scan_image("nginx", "1.25.3");
    printf("Scanned image: %s:%s\n", img->name, img->tag);

    cs_add_vulnerability(img, "CVE-2024-3094", "liblzma", CS_SEVERITY_CRITICAL, 9.8f, 1);
    cs_add_vulnerability(img, "CVE-2024-21626", "runc", CS_SEVERITY_HIGH, 7.6f, 1);
    cs_add_vulnerability(img, "CVE-2024-24557", "buildkit", CS_SEVERITY_MEDIUM, 5.5f, 1);
    printf("Found %d vulnerabilities\n", img->vuln_count);

    bool has_critical = cs_has_critical_vulns(img);
    printf("Has critical vulns: %s\n", has_critical ? "YES" : "NO");

    cs_seccomp_profile_t seccomp;
    cs_generate_seccomp_profile(img, &seccomp);
    printf("Seccomp profile: %zu syscalls allowed (default=%zu blocked)\n",
           seccomp.allowed_count, seccomp.denied_count);

    cs_apparmor_profile_t apparmor;
    cs_generate_apparmor_profile(img, &apparmor);
    printf("AppArmor profile: '%s' generated\n", apparmor.profile_name);

    /* Cleanup */
    iam_policy_free(policy);
    kms_free_key(key);

    printf("\n✓ Full cloud security demo complete!\n");
    return 0;
}
