#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include "iam_policy.h"
#include "kms_key.h"
#include "waf_rules.h"
#include "ddos_protect.h"
#include "container_security.h"

#define SIM_SECONDS 10
#define MAX_LOG 512

static const char *event_log[MAX_LOG];
static int log_count = 0;
static time_t sim_start;

static void log_event(const char *fmt, ...) {
    if (log_count >= MAX_LOG) return;
    char *buf = malloc(512);
    if (!buf) return;
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, 511, fmt, args);
    va_end(args);
    event_log[log_count++] = buf;
}

static void print_header(const char *title) {
    printf("\n+-------------------------------------------------+\n");
    printf("| %-47s |\n", title);
    printf("+-------------------------------------------------+\n");
}

static void sim_iam_policy_conflict(void) {
    print_header("SIM 1: IAM Policy Conflict Resolution");

    iam_policy_t *admin = iam_policy_create("FullAdmin", IAM_POLICY_IDENTITY);
    iam_policy_add_statement(admin, IAM_EFFECT_ALLOW, "*", "*");

    iam_policy_t *deny_s3 = iam_policy_create("DenyS3", IAM_POLICY_IDENTITY);
    iam_policy_add_statement(deny_s3, IAM_EFFECT_DENY, "s3:*", "*");

    iam_policy_t *allow_s3_read = iam_policy_create("AllowS3Read", IAM_POLICY_IDENTITY);
    iam_policy_add_statement(allow_s3_read, IAM_EFFECT_ALLOW, "s3:GetObject", "arn:aws:s3:::bucket/*");
    iam_policy_add_statement(allow_s3_read, IAM_EFFECT_ALLOW, "s3:ListBucket", "arn:aws:s3:::bucket");

    const iam_policy_t *conflict_policies[] = {admin, deny_s3, allow_s3_read};

    log_event("IAM conflict: admin(Allow *) + deny_s3(Deny s3:*) + allow_s3_read(Allow s3:GetObject)");

    const char *test_actions[] = {"ec2:DescribeInstances", "s3:GetObject",
                                   "s3:PutObject", "lambda:InvokeFunction",
                                   "s3:DeleteObject", "iam:CreateUser"};
    printf("  Policy Stack: FullAdmin(Allow *) + DenyS3(Deny s3:*) + AllowS3Read(Allow s3:GetObject/ListBucket)\n\n");
    printf("  %-25s => %s\n", "Requested Action", "Result");
    printf("  %-25s => %s\n", "----------------", "------");

    for (int i = 0; i < 6; i++) {
        iam_result_t r = iam_evaluate_all(conflict_policies, 3, test_actions[i],
                                           "arn:aws:s3:::bucket/file.txt", NULL);
        printf("  %-25s => %s\n", test_actions[i], iam_result_to_string(r));
        if (r == IAM_RESULT_DENY) {
            log_event("  Blocked: %s (explicit deny overrides all allows)", test_actions[i]);
        }
    }

    printf("\n  Key: Deny always wins when conflicts exist.\n");

    iam_policy_free(admin);
    iam_policy_free(deny_s3);
    iam_policy_free(allow_s3_read);
}

static void sim_ddos_attack_sequence(void) {
    print_header("SIM 2: DDoS Attack Pattern Detection");

    ddos_protection_t dp;
    ddos_init(&dp);
    ddos_set_shield_tier(&dp, DDOS_SHIELD_ADVANCED);

    const char *attackers[] = {"203.0.113.1", "203.0.113.2", "203.0.113.3",
                                "203.0.113.4", "203.0.113.5"};
    int attacker_count = 5;
    int legit_count = 20;

    log_event("DDoS simulation: %d attackers + %d legitimate clients (10 seconds)", attacker_count, legit_count);
    printf("  Phase 1: Normal traffic (t=0..2s)\n");

    for (int t = 0; t < 3; t++) {
        for (int i = 0; i < legit_count; i++) {
            char ip[16];
            snprintf(ip, 15, "10.0.0.%d", i + 1);
            for (int p = 0; p < 5; p++) {
                ddos_record_traffic(&dp, ip, (uint16_t)(80 + i), 64, 6);
            }
        }
        ddos_attack_type_t det = ddos_detect_anomaly(&dp);
        printf("    t=%ds: traffic normal, detection=%s\n", t,
               det == DDOS_UNKNOWN ? "none" : ddos_attack_type_name(det));
    }

    printf("\n  Phase 2: SYN flood begins (t=3..4s)\n");
    log_event("  [ALERT] SYN flood starting from %d attacker IPs", attacker_count);
    for (int t = 3; t < 5; t++) {
        for (int a = 0; a < attacker_count; a++) {
            for (int p = 0; p < 150; p++) {
                ddos_record_traffic(&dp, attackers[a], 80, 40, 6);
            }
        }
        ddos_attack_type_t det = ddos_detect_anomaly(&dp);
        printf("    t=%ds: SYN flood detected=%s\n", t,
               det != DDOS_UNKNOWN ? ddos_attack_type_name(det) : "none");

        for (int a = 0; a < attacker_count; a++) {
            ddos_action_t act = ddos_decide_action(&dp, attackers[a]);
            if (act != DDOS_ACTION_NONE) {
                ddos_apply_action(&dp, attackers[a], act);
                log_event("  Mitigation: %s -> %s (action=%s)", attackers[a],
                          ddos_attack_type_name(det), ddos_action_name(act));
            }
        }
    }

    printf("\n  Phase 3: Blackhole activation + traffic subsidence (t=5..7s)\n");
    ddos_activate_blackhole(&dp);
    log_event("  Blackhole routing activated for target");
    for (int t = 5; t < 8; t++) {
        ddos_update_mitigation(&dp);
        if (!dp.under_attack && t > 5) {
            printf("    t=%ds: Attack subsided\n", t);
            break;
        }
    }

    printf("\n  Phase 4: Post-attack recovery (t=8..9s)\n");
    ddos_deactivate_blackhole(&dp);
    log_event("  Blackhole deactivated, normal traffic resumed");
    printf("    Traffic restored to normal levels\n");

    printf("\n");
    ddos_print_status(&dp);
}

static void sim_kms_key_compromise(void) {
    print_header("SIM 3: KMS Key Compromise & Rotation");

    kms_key_t *master = kms_create_key("SensitiveDataKey", KMS_KEY_SPEC_SYMMETRIC_DEFAULT,
        KMS_KEY_USAGE_ENCRYPT_DECRYPT, KMS_KEY_MATERIAL_KMS, 0, 0);
    kms_enable_rotation(master, 180);

    log_event("KMS key '%s' created with 180-day auto-rotation", master->key_id);

    const char *customer_data[] = {
        "customer_001: Visa ending 1234",
        "customer_002: DOB=1990-01-15",
        "customer_003: Passport A12345678"
    };
    kms_data_key_t dks[3];
    unsigned char encrypted[3][2048];
    size_t encrypted_lens[3];

    printf("  Phase 1: Encrypting %d customer records (envelope encryption)...\n", 3);
    for (int i = 0; i < 3; i++) {
        kms_envelope_encrypt(master, (const unsigned char *)customer_data[i],
                              strlen(customer_data[i]), &dks[i],
                              encrypted[i], &encrypted_lens[i]);
        printf("    [%d] encrypted: %zu bytes\n", i, encrypted_lens[i]);
    }

    printf("\n  Phase 2: SECURITY INCIDENT - key suspected compromised at t+30 days\n");
    log_event("  KEY COMPROMISE detected! Initiating on-demand rotation");
    kms_rotate_key_on_demand(master);
    printf("    CMK rotated (new key material generated)\n");

    printf("\n  Phase 3: Re-encrypting data with new key version\n");
    for (int i = 0; i < 3; i++) {
        unsigned char plain[2048];
        size_t plen;
        if (kms_envelope_decrypt(master, &dks[i], encrypted[i], encrypted_lens[i],
                                  plain, &plen) == 0) {
            plain[plen] = '\0';
            printf("    [%d] Decrypted: '%s...'\n", i, (char *)plain);

            kms_envelope_encrypt(master, plain, plen, &dks[i],
                                  encrypted[i], &encrypted_lens[i]);
            printf("    [%d] Re-encrypted with new key: %zu bytes\n", i, encrypted_lens[i]);
        }
    }

    printf("\n  Phase 4: Post-incident audit\n");
    printf("    Key state: %s\n", kms_key_state_name(master->state));
    printf("    Rotation on: %d days\n", master->rotation_days);
    log_event("  Key recovery complete. All data re-encrypted.");
}

static void sim_waf_attack_patterns(void) {
    print_header("SIM 4: WAF Attack Pattern Analysis");

    waf_state_t state;
    waf_init_state(&state);
    waf_add_managed_groups(&state);

    waf_rule_group_t *custom = waf_create_rule_group("CustomRules", WAF_GROUP_CUSTOM, WAF_ACTION_ALLOW);
    waf_rule_t *b = waf_add_rule(custom, "BlockParamInjection", 1, WAF_ACTION_BLOCK);
    waf_rule_add_condition(b, WAF_COND_STRING_MATCH, "body", "exec(");

    state.groups[state.group_count++] = *custom;
    free(custom);

    log_event("WAF loaded: %d rule groups (SQLi + XSS + Rate-based + custom)", state.group_count);

    const char *patterns[][3] = {
        {"SQL Injection",     "body",   "username=' OR 1=1--"},
        {"XSS Reflected",     "query",  "search=<svg onload=alert(1)>"},
        {"Path Traversal",    "uri",    "/app/../../../etc/passwd"},
        {"Command Injection", "body",   "name=test; cat /etc/passwd"},
        {"Normal Request",    "body",   "{\"action\":\"view\",\"id\":42}"},
        {"Blind SQLi",        "body",   "id=1 AND SLEEP(5)"},
        {"XSS Stored",        "body",   "comment=<img src=x onerror=prompt('xss')>"},
    };

    printf("  Analyzing %d attack pattern requests:\n", 7);
    for (int i = 0; i < 7; i++) {
        waf_request_t req;
        memset(&req, 0, sizeof(req));
        strcpy(req.method, (i % 2 == 0) ? "GET" : "POST");
        strcpy(req.client_ip, "10.0.0.99");
        strcpy(req.client_country, "US");

        if (strcmp(patterns[i][0], "Path Traversal") == 0) {
            strcpy(req.uri, patterns[i][2]);
        } else {
            strcpy(req.uri, "/api/endpoint");
        }

        if (strcmp(patterns[i][1], "body") == 0) {
            strcpy(req.body, patterns[i][2]);
        } else {
            req.query_string = patterns[i][2];
        }

        int sqli = waf_check_sql_injection(patterns[i][2]);
        int xss = waf_check_xss(patterns[i][2]);
        int pt = waf_check_path_traversal(patterns[i][2]);
        int ci = waf_check_command_injection(patterns[i][2]);
        waf_action_t result = waf_evaluate_all(&state, &req);

        printf("    [%d] %s\n", i + 1, patterns[i][0]);
        printf("        SQLi=%s  XSS=%s  Path=%s  Cmd=%s\n",
               sqli ? "YES" : "no", xss ? "YES" : "no",
               pt ? "YES" : "no", ci ? "YES" : "no");
        printf("        WAF verdict: %s\n", waf_action_name(result));

        if (result == WAF_ACTION_BLOCK) {
            log_event("  WAF blocked: %s payload='%s'", patterns[i][0], patterns[i][2]);
        }
    }

    printf("\n  Rate limiting stress test...\n");
    for (int i = 0; i < 10; i++) {
        int exceeded = waf_rate_check(&state, "10.99.99.99");
        if (exceeded) {
            log_event("  Rate limit exceeded for 10.99.99.99 after %d requests", i + 1);
        }
    }

    printf("\n");
    waf_print_stats(&state);
}

static void sim_container_cve_alert(void) {
    print_header("SIM 5: Container CVE Alert & Compliance Check");

    cs_image_t *alpine = cs_scan_image("alpine", "3.18");
    cs_image_t *node_js = cs_scan_image("node", "18-slim");
    cs_image_t *python = cs_scan_image("python", "3.11");
    cs_add_vulnerability(python, "CVE-2024-0450", "pip", CS_SEVERITY_CRITICAL, 9.8f, 1);
    cs_set_malware(node_js, "CryptoMiner.Win64.XMRig in /tmp/.miner/xmrig");

    log_event("Container scan: 3 images analyzed (alpine, node:18-slim, python:3.11)");

    cs_image_t *images[] = {alpine, node_js, python};
    const char *image_names[] = {"alpine:3.18", "node:18-slim", "python:3.11"};

    printf("  Container Image Vulnerability Report:\n");
    printf("  %-20s %8s %8s %8s %8s %8s %8s\n",
           "IMAGE", "CRIT", "HIGH", "MED", "LOW", "MALWARE", "VERDICT");
    printf("  %-20s %8s %8s %8s %8s %8s %8s\n",
           "-----", "----", "----", "---", "---", "-------", "-------");

    for (int i = 0; i < 3; i++) {
        int crit = cs_count_severity(images[i], CS_SEVERITY_CRITICAL);
        int high = cs_count_severity(images[i], CS_SEVERITY_HIGH);
        int med = cs_count_severity(images[i], CS_SEVERITY_MEDIUM);
        int low = cs_count_severity(images[i], CS_SEVERITY_LOW);
        int mal = cs_image_has_malware(images[i]);
        const char *verdict = (crit > 0 || mal) ? "BLOCK" : "ALLOW";

        printf("  %-20s %8d %8d %8d %8d %8s %8s\n",
               image_names[i], crit, high, med, low,
               mal ? "YES!!" : "no", verdict);

        if (crit > 0) {
            log_event("  CVE ALERT: %s has %d critical vulnerabilities!", image_names[i], crit);
        }
        if (mal) {
            log_event("  MALWARE ALERT: %s infected: %s", image_names[i], images[i]->malware_detail);
        }
    }

    cs_container_t prod_ctr;
    memset(&prod_ctr, 0, sizeof(prod_ctr));
    strcpy(prod_ctr.name, "production-api");
    strcpy(prod_ctr.namespace, "prod");
    strcpy(prod_ctr.image_name, "python:3.11");
    prod_ctr.privileged = 1;
    prod_ctr.host_network = 0;
    prod_ctr.read_only_rootfs = 0;
    prod_ctr.run_as_non_root = 0;
    prod_ctr.allow_privilege_escalation = 1;
    strcpy(prod_ctr.seccomp_profile, "default");
    strcpy(prod_ctr.apparmor_profile, "docker-default");

    cs_pod_security_level_t level = cs_validate_pod_security(&prod_ctr);
    printf("\n  Pod Security Assessment:\n");
    printf("    Container: %s\n", prod_ctr.name);
    printf("    Pod Security Level: %s\n", cs_pod_level_name(level));

    if (level == CS_POD_PRIVILEGED) {
        printf("    !! WARNING: Privileged mode detected!\n");
        log_event("  SECURITY WARNING: Container '%s' running in privileged mode", prod_ctr.name);
    }
    if (prod_ctr.allow_privilege_escalation) {
        printf("    !! WARNING: Privilege escalation allowed!\n");
    }
    if (!prod_ctr.read_only_rootfs) {
        printf("    !! WARNING: Writable root filesystem!\n");
    }
    if (!prod_ctr.run_as_non_root) {
        printf("    !! WARNING: Running as root!\n");
    }

    printf("\n  Compliance Recommendations:\n");
    printf("    1. Set runAsNonRoot: true\n");
    printf("    2. Set readOnlyRootFilesystem: true\n");
    printf("    3. Set allowPrivilegeEscalation: false\n");
    printf("    4. Remove privileged: true\n");
    printf("    5. Apply seccomp/AppArmor profiles\n");

    free(alpine);
    free(node_js);
    free(python);
}

int main(void) {
    srand((unsigned int)time(NULL));
    sim_start = time(NULL);

    printf("+=================================================+\n");
    printf("|   MINI-CLOUD-SECURITY : INCIDENT SIMULATOR      |\n");
    printf("|   Cloud Security Event Simulation (C99)          |\n");
    printf("+=================================================+\n");
    log_event("=== Security Event Simulator Started ===");

    sim_iam_policy_conflict();
    sim_ddos_attack_sequence();
    sim_kms_key_compromise();
    sim_waf_attack_patterns();
    sim_container_cve_alert();

    print_header("EVENT LOG SUMMARY");
    for (int i = 0; i < log_count; i++) {
        printf("  [%02d] %s\n", i + 1, event_log[i]);
        free((void *)event_log[i]);
    }

    printf("\n+=================================================+\n");
    printf("|  Simulator completed. %d events logged.          |\n", log_count);
    printf("+=================================================+\n");

    return 0;
}
