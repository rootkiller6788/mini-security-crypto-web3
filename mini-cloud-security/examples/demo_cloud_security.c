#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "iam_policy.h"
#include "kms_key.h"
#include "waf_rules.h"
#include "ddos_protect.h"
#include "container_security.h"

static void section(const char *title) {
    printf("\n========================================\n");
    printf("  %s\n", title);
    printf("========================================\n\n");
}

static void scenario_iam(void) {
    section("SCENARIO 1: IAM - Multi-Account Access Control");

    iam_policy_t *dev_policy = iam_policy_create("DeveloperAccess", IAM_POLICY_IDENTITY);
    iam_policy_add_statement(dev_policy, IAM_EFFECT_ALLOW, "ec2:Describe*", "*");
    iam_policy_add_statement(dev_policy, IAM_EFFECT_ALLOW, "ec2:StartInstances", "arn:aws:ec2:*:*:instance/i-*");
    iam_policy_add_statement(dev_policy, IAM_EFFECT_ALLOW, "ec2:StopInstances", "arn:aws:ec2:*:*:instance/i-*");
    iam_policy_add_statement(dev_policy, IAM_EFFECT_ALLOW, "s3:GetObject", "arn:aws:s3:::dev-bucket/*");
    iam_policy_add_statement(dev_policy, IAM_EFFECT_ALLOW, "s3:PutObject", "arn:aws:s3:::dev-bucket/*");
    iam_policy_add_statement(dev_policy, IAM_EFFECT_ALLOW, "logs:CreateLogGroup", "*");
    iam_policy_add_statement(dev_policy, IAM_EFFECT_ALLOW, "logs:PutLogEvents", "*");

    iam_policy_t *deny_delete = iam_policy_create("DenyProductionDelete", IAM_POLICY_IDENTITY);
    iam_policy_add_statement(deny_delete, IAM_EFFECT_DENY, "ec2:TerminateInstances", "*");
    iam_policy_add_statement(deny_delete, IAM_EFFECT_DENY, "s3:DeleteBucket", "*");
    iam_policy_add_statement(deny_delete, IAM_EFFECT_DENY, "rds:DeleteDBInstance", "*");

    iam_policy_t *boundary = iam_policy_create("SandboxBoundary", IAM_POLICY_PERMISSION_BOUNDARY);
    iam_policy_add_statement(boundary, IAM_EFFECT_ALLOW, "ec2:Describe*", "*");
    iam_policy_add_statement(boundary, IAM_EFFECT_ALLOW, "ec2:StartInstances", "*");
    iam_policy_add_statement(boundary, IAM_EFFECT_ALLOW, "ec2:StopInstances", "*");
    iam_policy_add_statement(boundary, IAM_EFFECT_ALLOW, "s3:GetObject", "*");
    iam_policy_add_statement(boundary, IAM_EFFECT_ALLOW, "s3:PutObject", "*");
    iam_policy_add_statement(boundary, IAM_EFFECT_ALLOW, "lambda:InvokeFunction", "*");

    iam_policy_t *scp = iam_policy_create("DenyDataExfiltration", IAM_POLICY_SCP);
    iam_policy_add_statement(scp, IAM_EFFECT_DENY, "s3:PutObject", "arn:aws:s3:::production-*");
    iam_policy_add_statement(scp, IAM_EFFECT_DENY, "s3:DeleteObject", "arn:aws:s3:::production-*");
    iam_policy_add_statement(scp, IAM_EFFECT_DENY, "rds:DeleteDBSnapshot", "*");

    iam_user_t *alice = iam_user_create("alice.developer");
    iam_user_attach_policy(alice, dev_policy->id);
    iam_user_attach_policy(alice, deny_delete->id);
    iam_user_set_boundary(alice, boundary);

    printf("Created user: %s\n", alice->name);
    printf("Attached policies: DeveloperAccess, DenyProductionDelete\n");
    printf("Permission boundary: SandboxBoundary\n");

    const iam_policy_t *user_policies[] = {dev_policy, deny_delete};
    const char *actions[] = {
        "ec2:DescribeInstances", "ec2:StartInstances",
        "ec2:TerminateInstances", "s3:GetObject",
        "s3:PutObject", "rds:DeleteDBInstance",
        "lambda:InvokeFunction", "rds:DeleteDBSnapshot"
    };

    printf("\nAction Evaluation for alice.developer:\n");
    for (int i = 0; i < 8; i++) {
        iam_result_t base = iam_evaluate_all(user_policies, 2, actions[i],
                                              "arn:aws:ec2:us-east-1:123456789012:instance/i-abc123",
                                              NULL);
        iam_result_t after_boundary = iam_check_permission_boundary(base, boundary,
                                              actions[i], "*", NULL);
        iam_result_t after_scp = iam_evaluate_scp(scp, actions[i],
                                              "arn:aws:s3:::production-logs/*", NULL);
        iam_result_t final = (after_scp == IAM_RESULT_DENY) ? IAM_RESULT_DENY :
                              (after_boundary == IAM_RESULT_DENY) ? IAM_RESULT_DENY : base;

        printf("  %-30s => %s", actions[i], iam_result_to_string(final));
        if (strcmp(iam_result_to_string(base), iam_result_to_string(final)) != 0) {
            printf(" (boundary/SCP modified from %s)", iam_result_to_string(base));
        }
        printf("\n");
    }

    iam_policy_free(dev_policy);
    iam_policy_free(deny_delete);
    iam_policy_free(boundary);
    iam_policy_free(scp);
    iam_user_free(alice);
}

static void scenario_kms(void) {
    section("SCENARIO 2: KMS - Envelope Encryption for Sensitive Data");

    kms_key_t *app_cmk = kms_create_key("CustomerAppKey", KMS_KEY_SPEC_SYMMETRIC_DEFAULT,
        KMS_KEY_USAGE_ENCRYPT_DECRYPT, KMS_KEY_MATERIAL_KMS, 1, 0);
    kms_enable_rotation(app_cmk, 90);

    printf("Created CMK: %s\n", app_cmk->key_id);
    printf("Multi-region: yes\n");
    printf("Auto-rotation: 90 days\n");

    const char *samples[] = {
        "CreditCard=4111-1111-1111-1111",
        "SSN=123-45-6789",
        "DB_PASSWORD=SuperSecureP@ssw0rd!",
        "API_KEY=sk_live_abc123def456ghi789"
    };

    printf("\nEnvelope encrypting %d sensitive records:\n", 4);
    kms_data_key_t dks[4];
    unsigned char ciphertexts[4][2048];
    size_t ct_lens[4];

    for (int i = 0; i < 4; i++) {
        kms_envelope_encrypt(app_cmk, (const unsigned char *)samples[i],
                              strlen(samples[i]), &dks[i],
                              ciphertexts[i], &ct_lens[i]);
        printf("  [%d] '%s...' -> %zu bytes encrypted\n",
               i, samples[i], ct_lens[i]);
    }

    printf("\nEnvelope decrypting all records:\n");
    for (int i = 0; i < 4; i++) {
        unsigned char plain[2048];
        size_t plen;
        kms_envelope_decrypt(app_cmk, &dks[i], ciphertexts[i], ct_lens[i],
                              plain, &plen);
        plain[plen] = '\0';
        printf("  [%d] recovered -> '%s'\n", i, (char *)plain);
    }

    printf("\nRotating key on-demand (simulating security incident)...\n");
    kms_rotate_key_on_demand(app_cmk);
    printf("Key rotated. New material generated.\n");

    kms_grant_t *g = kms_create_grant(app_cmk,
        "arn:aws:iam::123456789012:role/DataProcessorLambda",
        KMS_GRANT_OP_ENCRYPT | KMS_GRANT_OP_DECRYPT | KMS_GRANT_OP_GENERATE_DATA_KEY,
        NULL);
    printf("Created grant for Lambda role: %s\n", g->grant_id);
}

static void scenario_waf(void) {
    section("SCENARIO 3: WAF - Protecting a Web Application");

    waf_state_t state;
    waf_init_state(&state);
    waf_add_managed_groups(&state);

    waf_rule_group_t *custom = waf_create_rule_group("AppSpecificRules",
        WAF_GROUP_CUSTOM, WAF_ACTION_ALLOW);

    waf_rule_t *r = waf_add_rule(custom, "BlockAdminScraping", 1, WAF_ACTION_BLOCK);
    waf_rule_add_condition(r, WAF_COND_STRING_MATCH, "uri", "/admin");
    waf_rule_add_condition(r, WAF_COND_STRING_MATCH, "header:User-Agent", "scraper");

    r = waf_add_rule(custom, "RateLimitPerIP", 2, WAF_ACTION_BLOCK);
    waf_rule_set_rate_limit(r, 5, 60);

    state.groups[state.group_count++] = *custom;
    free(custom);

    printf("WAF configured with AWS Managed Rules + custom group\n\n");

    const char *attack_requests[][4] = {
        {"GET", "/", "Normal request", "normal"},
        {"GET", "/users?id=1' OR 1=1--", "SQLi in query", "blocked"},
        {"POST", "/comment", "Nice post <script>alert(1)</script>", "blocked"},
        {"GET", "/admin", "Admin path ok USER", "allowed"},
        {"GET", "/../../../etc/shadow", "Path traversal", "blocked"},
        {"POST", "/login", "user=<img src=x onerror=alert(1)>", "blocked"},
        {"GET", "/data", "Normal API call", "normal"},
    };

    waf_request_t req;
    for (int i = 0; i < 7; i++) {
        memset(&req, 0, sizeof(req));
        strcpy(req.method, attack_requests[i][0]);
        strcpy(req.uri, attack_requests[i][1]);
        strcpy(req.client_ip, "10.0.0.100");
        strcpy(req.client_country, "US");
        if (strcmp(attack_requests[i][0], "POST") == 0) {
            strcpy(req.body, attack_requests[i][2]);
        } else {
            req.query_string = strchr(attack_requests[i][1], '?');
            if (req.query_string) req.query_string++;
        }
        waf_action_t result = waf_evaluate_all(&state, &req);
        printf("  [%d] %s %s\n      %s -> %s\n\n",
               i + 1, attack_requests[i][0], attack_requests[i][1],
               attack_requests[i][2], waf_action_name(result));
    }

    waf_print_stats(&state);
}

static void scenario_ddos(void) {
    section("SCENARIO 4: DDoS - Detecting SYN Flood Attack");

    ddos_protection_t dp;
    ddos_init(&dp);
    ddos_set_shield_tier(&dp, DDOS_SHIELD_ADVANCED);

    printf("DDoS Protection initialized (Shield Advanced)\n");
    printf("Simulating normal traffic (50 sources, 20 packets each)...\n");

    for (int src = 0; src < 50; src++) {
        char ip[16];
        snprintf(ip, 15, "10.0.%d.%d", src / 256, src % 256);
        for (int p = 0; p < 20; p++) {
            ddos_record_traffic(&dp, ip, (uint16_t)(1024 + p), 64, 6);
        }
    }

    ddos_attack_type_t detected = ddos_detect_anomaly(&dp);
    printf("Detection result: %s\n", ddos_attack_type_name(detected));

    printf("\nSimulating SYN flood (10000 SYNs from single source)...\n");
    for (int p = 0; p < 10000; p++) {
        ddos_record_traffic(&dp, "203.0.113.42", 80, 40, 6);
    }

    detected = ddos_detect_anomaly(&dp);
    printf("Detection result: %s\n", ddos_attack_type_name(detected));

    ddos_action_t action = ddos_decide_action(&dp, "203.0.113.42");
    printf("Mitigation action: %s\n", ddos_action_name(action));
    ddos_apply_action(&dp, "203.0.113.42", action);
    ddos_update_mitigation(&dp);

    printf("\n");
    ddos_print_status(&dp);
}

static void scenario_container(void) {
    section("SCENARIO 5: Container Security - Image Scanning & Runtime Protection");

    cs_image_t *nginx = cs_scan_image("nginx", "1.25-alpine");
    cs_image_t *webapp = cs_scan_image("mycompany/webapp", "v3.2.1");
    cs_set_malware(webapp, "Trojan.Miner detected in /usr/local/bin/xmrig");
    cs_set_readonly_rootfs(webapp, 1);
    cs_set_run_as_non_root(webapp, 0);
    cs_add_capability(webapp, 21); 
    cs_add_capability(webapp, 24); 

    printf("Image scans complete:\n\n");
    cs_print_scan_report(nginx);
    printf("\n");
    cs_print_scan_report(webapp);

    cs_seccomp_profile_t *seccomp = cs_create_seccomp_profile("restricted-nginx", "ERRNO");
    cs_seccomp_allow_network(seccomp);
    cs_seccomp_allow_filesystem(seccomp);
    printf("\nSeccomp profile '%s': %d allowed syscalls (default=%s)\n",
           seccomp->name, seccomp->syscall_count, seccomp->default_action);

    cs_apparmor_profile_t *aa = cs_create_apparmor_profile("docker-default", "enforce");
    cs_apparmor_default_docker(aa);
    printf("AppArmor profile '%s': %d deny rules\n\n", aa->name, aa->rule_count);

    cs_container_t privileged_ctr;
    memset(&privileged_ctr, 0, sizeof(privileged_ctr));
    strcpy(privileged_ctr.name, "unsafe-web-server");
    strcpy(privileged_ctr.namespace, "production");
    strcpy(privileged_ctr.image_name, "mycompany/webapp:v3.2.1");
    privileged_ctr.privileged = 1;
    privileged_ctr.host_network = 1;
    privileged_ctr.host_pid = 1;
    privileged_ctr.allow_privilege_escalation = 1;

    cs_container_t secure_ctr;
    memset(&secure_ctr, 0, sizeof(secure_ctr));
    strcpy(secure_ctr.name, "safe-web-server");
    strcpy(secure_ctr.namespace, "production");
    strcpy(secure_ctr.image_name, "nginx:1.25-alpine");
    secure_ctr.run_as_non_root = 1;
    secure_ctr.read_only_rootfs = 1;
    secure_ctr.uid = 1001;
    secure_ctr.gid = 1001;
    strcpy(secure_ctr.seccomp_profile, "restricted-nginx");
    strcpy(secure_ctr.apparmor_profile, "docker-default");

    printf("--- Container Security Assessment ---\n\n");
    cs_print_container_report(&privileged_ctr);
    printf("  SECURITY VIOLATIONS: privileged + host_network + host_pid\n");

    printf("\n");
    cs_print_container_report(&secure_ctr);

    const char *v = cs_pod_security_violations(&privileged_ctr, CS_POD_RESTRICTED);
    printf("  Pod security check (target=restricted): %s\n\n", v ? v : "PASS");

    cs_network_policy_t *np = cs_create_network_policy("allow-nginx-ingress", CS_INGRESS, 1);
    cs_network_policy_set_namespace(np, "external", "production");
    cs_network_policy_set_port(np, 443, 443, "TCP");
    printf("Network Policy '%s': ingress from external:443 -> production:443\n", np->name);
    int eval = cs_evaluate_network_policy(np, "external", "production", 443, "ingress");
    printf("  Evaluate (external->production:443 ingress): %s\n",
           eval == 2 ? "ALLOW" : eval < 0 ? "DENY" : "NO MATCH");
    eval = cs_evaluate_network_policy(np, "production", "external", 80, "egress");
    printf("  Evaluate (production->external:80 egress): %s\n",
           eval == 2 ? "ALLOW" : eval < 0 ? "DENY" : "NO MATCH");

    free(np);

    printf("\n--- Secrets Check ---\n");
    cs_add_secret_to_container(&secure_ctr, "db-password");
    cs_add_secret_to_container(&secure_ctr, "arn:aws:secretsmanager:us-east-1:123456789012:secret:api-key");
    cs_add_secret_to_container(&secure_ctr, "vault:secret/data/prod/tls-cert");
    printf("Has external secrets: %s\n\n", cs_check_external_secrets(&secure_ctr) ? "yes" : "no");

    free(seccomp);
    free(aa);
    free(nginx);
    free(webapp);
}

int main(void) {
    srand((unsigned int)time(NULL));
    printf("==================================================\n");
    printf("   MINI-CLOUD-SECURITY : COMPREHENSIVE DEMO\n");
    printf("   Cloud Security Simulation Framework (C99)\n");
    printf("==================================================\n");

    scenario_iam();
    scenario_kms();
    scenario_waf();
    scenario_ddos();
    scenario_container();

    printf("\n========================================\n");
    printf("  All scenarios completed successfully.\n");
    printf("========================================\n");
    return 0;
}
