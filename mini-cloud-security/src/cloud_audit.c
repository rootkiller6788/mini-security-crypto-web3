#include "cloud_audit.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int g_next_rule_id = 1;
static int g_next_finding_id = 1;

/* ?? L5: Deterministic hash function (simplified SHA-256 concept) ??
 * Uses Merkle-Damgard-like iterative compression with a simple mixing function.
 * Each call updates the 32-byte state through a Sponge-like absorb step.
 * Based on: FIPS 180-4 (SHA-256 specification concepts)
 */
static uint32_t rotate32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

static void mix_block(const unsigned char *block, unsigned char *state, size_t block_len) {
    uint32_t w[8];
    for (int i = 0; i < 8; i++) {
        w[i] = ((uint32_t)state[i*4] << 24) | ((uint32_t)state[i*4+1] << 16) |
               ((uint32_t)state[i*4+2] << 8) | (uint32_t)state[i*4+3];
    }
    for (size_t i = 0; i < block_len; i++) {
        int idx = i % 8;
        w[idx] ^= ((uint32_t)block[i] << ((i % 4) * 8));
        w[idx] = rotate32(w[idx], 7) + rotate32(w[(idx+1)%8], 11) +
                 rotate32(w[(idx+3)%8], 13) + w[(idx+5)%8] ^ 0x9E3779B9;
        w[(idx+4)%8] ^= rotate32(w[idx], 17);
    }
    for (int i = 0; i < 8; i++) {
        uint32_t orig = ((uint32_t)state[i*4] << 24) | ((uint32_t)state[i*4+1] << 16) |
                        ((uint32_t)state[i*4+2] << 8) | (uint32_t)state[i*4+3];
        uint32_t mixed = orig ^ w[i];
        state[i*4]   = (unsigned char)((mixed >> 24) & 0xFF);
        state[i*4+1] = (unsigned char)((mixed >> 16) & 0xFF);
        state[i*4+2] = (unsigned char)((mixed >> 8) & 0xFF);
        state[i*4+3] = (unsigned char)(mixed & 0xFF);
    }
}

void ca_hash_init(unsigned char *hash_out) {
    if (!hash_out) return;
    const unsigned char iv[CA_HASH_LEN] = {
        0x6a,0x09,0xe6,0x67, 0xbb,0x67,0xae,0x85,
        0x3c,0x6e,0xf3,0x72, 0xa5,0x4f,0xf5,0x3a,
        0x51,0x0e,0x52,0x7f, 0x9b,0x05,0x68,0x8c,
        0x1f,0x83,0xd9,0xab, 0x5b,0xe0,0xcd,0x19
    };
    memcpy(hash_out, iv, CA_HASH_LEN);
}

void ca_hash_update(unsigned char *hash, const void *data, size_t len) {
    if (!hash || !data || len == 0) return;
    mix_block((const unsigned char *)data, hash, len);
}

void ca_hash_final(unsigned char *hash_inout) {
    if (!hash_inout) return;
    unsigned char pad = 0x80;
    mix_block(&pad, hash_inout, 1);
}

void ca_hash_data(const void *data, size_t len, unsigned char *hash_out) {
    ca_hash_init(hash_out);
    ca_hash_update(hash_out, data, len);
    ca_hash_final(hash_out);
}

void ca_hash_to_hex(const unsigned char *hash, char *hex_out) {
    if (!hash || !hex_out) return;
    for (int i = 0; i < CA_HASH_LEN; i++) {
        sprintf(hex_out + i * 2, "%02x", hash[i]);
    }
    hex_out[CA_HASH_HEX_LEN - 1] = '\0';
}

int ca_hash_equal(const unsigned char *a, const unsigned char *b) {
    if (!a || !b) return 0;
    return memcmp(a, b, CA_HASH_LEN) == 0;
}

void ca_hash_concat(const unsigned char *a, size_t alen,
                     const unsigned char *b, size_t blen,
                     unsigned char *out) {
    if (!a || !b || !out) return;
    unsigned char state[CA_HASH_LEN];
    ca_hash_init(state);
    ca_hash_update(state, a, alen);
    ca_hash_update(state, b, blen);
    ca_hash_final(state);
    memcpy(out, state, CA_HASH_LEN);
}

/* ?? L5: Hash-chain audit trail (like blockchain block linking) ??
 * Theorem: If H is collision-resistant, then modifying any event E_k
 * invalidates all chain_hashes for j >= k (tamper-evident property).
 * Ref: Haber & Stornetta (1991) "How to Time-Stamp a Digital Document"
 */
ca_audit_trail_t* ca_trail_create(const char *name, const char *s3_bucket) {
    ca_audit_trail_t *trail = calloc(1, sizeof(ca_audit_trail_t));
    if (!trail) return NULL;
    if (name) strncpy(trail->trail_name, name, CA_EVENT_NAME_LEN - 1);
    if (s3_bucket) strncpy(trail->s3_bucket, s3_bucket, CA_ARN_LEN - 1);
    trail->creation_time = time(NULL);
    trail->next_event_id = 1;
    trail->log_file_validation_enabled = 1;
    trail->s3_encryption_enabled = 1;

    unsigned char seed[CA_HASH_LEN];
    const char *genesis_input = "CLOUD_AUDIT_GENESIS";
    ca_hash_data(genesis_input, strlen(genesis_input), seed);
    memcpy(trail->genesis_hash, seed, CA_HASH_LEN);
    return trail;
}

static void hash_event_fields(const ca_event_record_t *ev, unsigned char *out) {
    unsigned char state[CA_HASH_LEN];
    ca_hash_init(state);
    char buf[64];
    snprintf(buf, sizeof(buf), "%llu", (unsigned long long)ev->event_id);
    ca_hash_update(state, buf, strlen(buf));
    ca_hash_update(state, &ev->category, sizeof(ev->category));
    ca_hash_update(state, &ev->type, sizeof(ev->type));
    ca_hash_update(state, ev->event_source, strlen(ev->event_source));
    ca_hash_update(state, ev->user_arn, strlen(ev->user_arn));
    ca_hash_update(state, ev->region, strlen(ev->region));
    ca_hash_update(state, ev->request_params, strlen(ev->request_params));
    snprintf(buf, sizeof(buf), "%lld", (long long)ev->event_time);
    ca_hash_update(state, buf, strlen(buf));
    ca_hash_update(state, ev->source_ip, strlen(ev->source_ip));
    ca_hash_final(state);
    memcpy(out, state, CA_HASH_LEN);
}

int ca_trail_log_event(ca_audit_trail_t *trail,
                        ca_event_category_t cat, ca_event_type_t type,
                        const char *source, const char *user_arn,
                        const char *region, const char *params) {
    if (!trail || trail->event_count >= CA_MAX_EVENTS) return -1;
    ca_event_record_t *ev = &trail->events[trail->event_count];
    memset(ev, 0, sizeof(ca_event_record_t));

    ev->event_id = trail->next_event_id++;
    ev->category = cat;
    ev->type = type;
    if (source) strncpy(ev->event_source, source, CA_EVENT_SOURCE_LEN - 1);
    if (user_arn) strncpy(ev->user_arn, user_arn, CA_ARN_LEN - 1);
    if (region) strncpy(ev->region, region, CA_REGION_LEN - 1);
    if (params) strncpy(ev->request_params, params, CA_JSON_MAX - 1);
    snprintf(ev->event_name, CA_EVENT_NAME_LEN, "%s:%s",
             ca_event_type_name(type), source ? source : "unknown");
    ev->event_time = time(NULL);
    strncpy(ev->source_ip, "0.0.0.0", 63);

    const unsigned char *prev = (trail->event_count == 0)
        ? trail->genesis_hash : trail->events[trail->event_count - 1].chain_hash;
    memcpy(ev->prev_hash, prev, CA_HASH_LEN);

    hash_event_fields(ev, ev->event_hash);
    ca_hash_concat(ev->prev_hash, CA_HASH_LEN, ev->event_hash, CA_HASH_LEN, ev->chain_hash);

    ev->integrity_verified = 1;
    trail->event_count++;
    trail->last_event_time = ev->event_time;
    return 0;
}

int ca_trail_verify_chain(const ca_audit_trail_t *trail) {
    if (!trail) return -1;
    for (int i = 0; i < trail->event_count; i++) {
        ca_event_record_t *ev = &trail->events[i];
        unsigned char expected_prev[CA_HASH_LEN];
        if (i == 0) {
            memcpy(expected_prev, trail->genesis_hash, CA_HASH_LEN);
        } else {
            memcpy(expected_prev, trail->events[i - 1].chain_hash, CA_HASH_LEN);
        }
        if (!ca_hash_equal(ev->prev_hash, expected_prev)) return 0;

        unsigned char expected_event_hash[CA_HASH_LEN];
        hash_event_fields(ev, expected_event_hash);
        if (!ca_hash_equal(ev->event_hash, expected_event_hash)) return 0;

        unsigned char expected_chain[CA_HASH_LEN];
        ca_hash_concat(ev->prev_hash, CA_HASH_LEN, ev->event_hash, CA_HASH_LEN, expected_chain);
        if (!ca_hash_equal(ev->chain_hash, expected_chain)) return 0;
    }
    return 1;
}

int ca_trail_detect_tamper(const ca_audit_trail_t *trail, int *tampered_index) {
    if (!trail) return -1;
    for (int i = 0; i < trail->event_count; i++) {
        unsigned char recomputed[CA_HASH_LEN];
        hash_event_fields(&trail->events[i], recomputed);
        if (!ca_hash_equal(trail->events[i].event_hash, recomputed)) {
            if (tampered_index) *tampered_index = i;
            return 1;
        }
    }
    return 0;
}

int ca_trail_export_json(const ca_audit_trail_t *trail, char *out_buf, size_t buf_size) {
    if (!trail || !out_buf || buf_size < 256) return -1;
    int pos = snprintf(out_buf, buf_size,
        "{\"trail\":\"%s\",\"s3_bucket\":\"%s\",\"event_count\":%d,\n \"events\":[",
        trail->trail_name, trail->s3_bucket, trail->event_count);
    for (int i = 0; i < trail->event_count && (size_t)pos < buf_size - 512; i++) {
        ca_event_record_t *ev = &trail->events[i];
        char hex_chain[CA_HASH_HEX_LEN];
        ca_hash_to_hex(ev->chain_hash, hex_chain);
        pos += snprintf(out_buf + pos, buf_size - pos,
            "{\"id\":%llu,\"type\":\"%s\",\"chain\":\"%s\"}%s",
            (unsigned long long)ev->event_id,
            ca_event_type_name(ev->type), hex_chain,
            (i < trail->event_count - 1) ? ",\n  " : "\n");
    }
    snprintf(out_buf + pos, buf_size - pos, "]}");
    return 0;
}

void ca_trail_print_summary(const ca_audit_trail_t *trail) {
    if (!trail) return;
    printf("Audit Trail: %s\n", trail->trail_name);
    printf("  S3 Bucket:      %s\n", trail->s3_bucket);
    printf("  Events:         %d\n", trail->event_count);
    printf("  Chain Verified: %s\n",
           ca_trail_verify_chain(trail) ? "YES" : "TAMPERED!");
    printf("  Multi-Region:   %s\n", trail->multi_region ? "yes" : "no");
    printf("  Encryption:     %s\n", trail->s3_encryption_enabled ? "enabled" : "disabled");
    if (trail->event_count > 0) {
        time_t first = trail->events[0].event_time;
        time_t last = trail->events[trail->event_count-1].event_time;
        printf("  Time Range:     %s", ctime(&first));
        printf("               -> %s", ctime(&last));
    }
}

/* ?? L5: Merkle Tree (RFC 6962 ?2.1) ??
 * The Merkle Tree enables O(log n) verification that a leaf is included
 * in a set without revealing the entire set.
 * Theorem: Given a collision-resistant hash H, a Merkle proof of length
 * ceil(log2 n) uniquely binds a leaf to the root hash. (Merkle, 1980)
 */
void ca_merkle_build(ca_merkle_tree_t *tree,
                      const unsigned char leaves[][CA_HASH_LEN],
                      int leaf_count) {
    if (!tree || !leaves || leaf_count < 1) return;
    memset(tree, 0, sizeof(ca_merkle_tree_t));
    tree->leaf_count = leaf_count;

    for (int i = 0; i < leaf_count; i++) {
        memcpy(tree->nodes[i].hash, leaves[i], CA_HASH_LEN);
        tree->nodes[i].left_idx = -1;
        tree->nodes[i].right_idx = -1;
    }
    tree->node_count = leaf_count;

    int level_start = 0;
    int level_size = leaf_count;
    while (level_size > 1) {
        int next_level_start = tree->node_count;
        for (int i = 0; i < level_size; i += 2) {
            int left = level_start + i;
            int right = (i + 1 < level_size) ? level_start + i + 1 : left;

            ca_merkle_node_t *node = &tree->nodes[tree->node_count++];
            node->left_idx = left;
            node->right_idx = right;
            ca_hash_concat(tree->nodes[left].hash, CA_HASH_LEN,
                           tree->nodes[right].hash, CA_HASH_LEN,
                           node->hash);
        }
        level_start = next_level_start;
        level_size = (level_size + 1) / 2;
    }

    memcpy(tree->root_hash, tree->nodes[tree->node_count - 1].hash, CA_HASH_LEN);
}

int ca_merkle_generate_proof(const ca_merkle_tree_t *tree,
                               int leaf_index,
                               unsigned char proof[][CA_HASH_LEN],
                               int *proof_len) {
    if (!tree || leaf_index < 0 || leaf_index >= tree->leaf_count || !proof || !proof_len)
        return -1;

    *proof_len = 0;
    int node_idx = leaf_index;
    int level_start = 0;
    int level_size = tree->leaf_count;

    while (level_size > 1) {
        int relative_idx = node_idx - level_start;
        int sibling_rel;
        if (relative_idx % 2 == 0) {
            sibling_rel = (relative_idx + 1 < level_size) ? relative_idx + 1 : relative_idx;
        } else {
            sibling_rel = relative_idx - 1;
        }
        int sibling_idx = level_start + sibling_rel;

        if (sibling_idx != node_idx) {
            memcpy(proof[*proof_len], tree->nodes[sibling_idx].hash, CA_HASH_LEN);
            (*proof_len)++;
        }

        int next_level_start = level_start + level_size;
        node_idx = next_level_start + (relative_idx / 2);
        level_start = next_level_start;
        level_size = (level_size + 1) / 2;
    }
    return 0;
}

int ca_merkle_verify_proof(const unsigned char root[CA_HASH_LEN],
                             const unsigned char leaf[CA_HASH_LEN],
                             const unsigned char proof[][CA_HASH_LEN],
                             int proof_len,
                             int leaf_index) {
    if (!root || !leaf || !proof || proof_len < 0) return 0;

    unsigned char current[CA_HASH_LEN];
    memcpy(current, leaf, CA_HASH_LEN);
    int idx = leaf_index;

    for (int i = 0; i < proof_len; i++) {
        unsigned char combined[CA_HASH_LEN];
        if (idx % 2 == 0) {
            ca_hash_concat(current, CA_HASH_LEN, proof[i], CA_HASH_LEN, combined);
        } else {
            ca_hash_concat(proof[i], CA_HASH_LEN, current, CA_HASH_LEN, combined);
        }
        memcpy(current, combined, CA_HASH_LEN);
        idx /= 2;
    }

    return ca_hash_equal(current, root);
}

void ca_merkle_print(const ca_merkle_tree_t *tree) {
    if (!tree) return;
    printf("Merkle Tree: %d leaves, %d nodes\n", tree->leaf_count, tree->node_count);
    char hex[CA_HASH_HEX_LEN];
    ca_hash_to_hex(tree->root_hash, hex);
    printf("  Root Hash: %s\n", hex);
}

/* ?? L4: Compliance Framework Implementations ??
 * PCI-DSS: Payment Card Industry Data Security Standard v4.0
 *   Req 3.4: Encrypt cardholder data at rest
 *   Req 8.3: MFA for all admin access
 *   Req 10.5: Retain audit logs for >= 1 year
 * CIS AWS Foundations Benchmark v1.4
 *   CIS 2.1.1: Ensure S3 buckets do not allow public access
 *   CIS 2.1.5: Ensure CloudTrail log file validation is enabled
 *   CIS 3.1:  Ensure VPC flow logging is enabled
 * HIPAA Security Rule (45 CFR ?164.312)
 *   ?164.312(a)(2)(iv): Encryption of ePHI at rest
 *   ?164.312(d):     Audit controls for systems handling ePHI
 */

ca_compliance_rule_t* ca_compliance_add_rule(ca_state_t *state,
                                              ca_framework_t framework,
                                              const char *rule_id,
                                              const char *title,
                                              ca_finding_severity_t sev) {
    if (!state || state->rule_count >= CA_MAX_COMPLIANCE_RULES) return NULL;
    ca_compliance_rule_t *r = &state->rules[state->rule_count++];
    memset(r, 0, sizeof(ca_compliance_rule_t));
    r->id = g_next_rule_id++;
    r->framework = framework;
    if (rule_id) strncpy(r->rule_id, rule_id, 63);
    if (title) strncpy(r->title, title, CA_EVENT_NAME_LEN - 1);
    r->severity = sev;
    r->enabled = 1;
    return r;
}

void ca_compliance_add_pci_dss_rules(ca_state_t *state) {
    if (!state) return;
    ca_compliance_rule_t *r;

    r = ca_compliance_add_rule(state, CA_FRAMEWORK_PCI_DSS, "PCI-3.4",
        "Encrypt cardholder data at rest (AES-256)", CA_SEVERITY_CRITICAL);
    r->required_encryption = 1;

    r = ca_compliance_add_rule(state, CA_FRAMEWORK_PCI_DSS, "PCI-7.2.1",
        "Implement least-privilege access control", CA_SEVERITY_HIGH);
    r->max_public_access = 0;

    r = ca_compliance_add_rule(state, CA_FRAMEWORK_PCI_DSS, "PCI-8.3.1",
        "Multi-factor authentication for all admin access", CA_SEVERITY_CRITICAL);
    r->required_mfa = 1;

    r = ca_compliance_add_rule(state, CA_FRAMEWORK_PCI_DSS, "PCI-10.5",
        "Retain audit log history for at least 1 year", CA_SEVERITY_MEDIUM);
    r->required_log_retention_days = 365;

    r = ca_compliance_add_rule(state, CA_FRAMEWORK_PCI_DSS, "PCI-10.5.3",
        "Audit logs must be tamper-proof (hash-chained)", CA_SEVERITY_HIGH);
    r->required_encryption = 1;

    r = ca_compliance_add_rule(state, CA_FRAMEWORK_PCI_DSS, "PCI-1.2.1",
        "Restrict traffic to only necessary protocols/ports", CA_SEVERITY_HIGH);
}

void ca_compliance_add_cis_aws_rules(ca_state_t *state) {
    if (!state) return;
    ca_compliance_rule_t *r;

    r = ca_compliance_add_rule(state, CA_FRAMEWORK_CIS_AWS, "CIS-1.1",
        "Avoid use of root account for daily tasks", CA_SEVERITY_CRITICAL);

    r = ca_compliance_add_rule(state, CA_FRAMEWORK_CIS_AWS, "CIS-2.1.1",
        "Ensure S3 Buckets are not publicly accessible", CA_SEVERITY_CRITICAL);
    r->max_public_access = 0;

    r = ca_compliance_add_rule(state, CA_FRAMEWORK_CIS_AWS, "CIS-2.1.5",
        "Ensure CloudTrail log file validation is enabled", CA_SEVERITY_HIGH);

    r = ca_compliance_add_rule(state, CA_FRAMEWORK_CIS_AWS, "CIS-2.2.1",
        "Ensure EBS volumes are encrypted", CA_SEVERITY_HIGH);
    r->required_encryption = 1;

    r = ca_compliance_add_rule(state, CA_FRAMEWORK_CIS_AWS, "CIS-3.1",
        "Ensure VPC Flow Logs are enabled in all VPCs", CA_SEVERITY_MEDIUM);

    r = ca_compliance_add_rule(state, CA_FRAMEWORK_CIS_AWS, "CIS-4.1",
        "Ensure no security groups allow 0.0.0.0/0 to port 22", CA_SEVERITY_CRITICAL);

    r = ca_compliance_add_rule(state, CA_FRAMEWORK_CIS_AWS, "CIS-4.3",
        "Ensure MFA is enabled for all IAM users", CA_SEVERITY_HIGH);
    r->required_mfa = 1;

    r = ca_compliance_add_rule(state, CA_FRAMEWORK_CIS_AWS, "CIS-5.1",
        "Ensure IAM password policy requires min 14 chars", CA_SEVERITY_MEDIUM);
}

void ca_compliance_add_hipaa_rules(ca_state_t *state) {
    if (!state) return;
    ca_compliance_rule_t *r;

    r = ca_compliance_add_rule(state, CA_FRAMEWORK_HIPAA, "HIPAA-164.312(a)(2)(iv)",
        "Encrypt ePHI at rest and in transit", CA_SEVERITY_CRITICAL);
    r->required_encryption = 1;

    r = ca_compliance_add_rule(state, CA_FRAMEWORK_HIPAA, "HIPAA-164.312(a)(1)",
        "Unique user identification (no shared accounts)", CA_SEVERITY_HIGH);

    r = ca_compliance_add_rule(state, CA_FRAMEWORK_HIPAA, "HIPAA-164.312(b)",
        "Audit controls: record and examine system activity", CA_SEVERITY_HIGH);

    r = ca_compliance_add_rule(state, CA_FRAMEWORK_HIPAA, "HIPAA-164.312(d)",
        "Person/entity authentication (MFA for ePHI access)", CA_SEVERITY_CRITICAL);
    r->required_mfa = 1;

    r = ca_compliance_add_rule(state, CA_FRAMEWORK_HIPAA, "HIPAA-164.312(e)(1)",
        "Transmission security: encrypt data in transit (HTTPS/TLS)", CA_SEVERITY_CRITICAL);
    r->require_https_only = 1;
}

/* ?? L5: Compliance Check Engine with risk scoring ??
 * Each check evaluates a resource against a compliance rule and
 * produces a finding with a risk score (0.0 = no risk, 100.0 = critical).
 */
int ca_compliance_check_encryption(ca_state_t *state,
                                    const char *resource_arn,
                                    int is_encrypted) {
    if (!state || !resource_arn) return 0;
    int failures = 0;
    for (int i = 0; i < state->rule_count; i++) {
        ca_compliance_rule_t *r = &state->rules[i];
        if (!r->enabled || !r->required_encryption) continue;
        ca_check_status_t status = is_encrypted ? CA_STATUS_PASS : CA_STATUS_FAIL;
        if (status != CA_STATUS_PASS) failures++;
        ca_compliance_run_check(state, r->id, resource_arn, "encryption", status,
            is_encrypted ? "OK: encrypted at rest" : "FAIL: no encryption at rest");
    }
    return failures;
}

int ca_compliance_check_public_access(ca_state_t *state,
                                       const char *resource_arn,
                                       int is_public) {
    if (!state || !resource_arn) return 0;
    int failures = 0;
    for (int i = 0; i < state->rule_count; i++) {
        ca_compliance_rule_t *r = &state->rules[i];
        if (!r->enabled || r->max_public_access) continue;
        ca_check_status_t status;
        if (is_public && r->max_public_access == 0) {
            status = CA_STATUS_FAIL;
            failures++;
        } else {
            status = CA_STATUS_PASS;
        }
        ca_compliance_run_check(state, r->id, resource_arn, "public_access", status,
            is_public ? "WARN: publicly accessible" : "OK: not public");
    }
    return failures;
}

int ca_compliance_check_mfa(ca_state_t *state,
                             const char *user_arn, int mfa_enabled) {
    if (!state || !user_arn) return 0;
    int failures = 0;
    for (int i = 0; i < state->rule_count; i++) {
        ca_compliance_rule_t *r = &state->rules[i];
        if (!r->enabled || !r->required_mfa) continue;
        ca_check_status_t status = mfa_enabled ? CA_STATUS_PASS : CA_STATUS_FAIL;
        if (status != CA_STATUS_PASS) failures++;
        ca_compliance_run_check(state, r->id, user_arn, "mfa", status,
            mfa_enabled ? "OK: MFA enabled" : "FAIL: MFA not enabled");
    }
    return failures;
}

int ca_compliance_run_check(ca_state_t *state, int rule_id,
                             const char *resource_arn,
                             const char *resource_type,
                             ca_check_status_t status,
                             const char *detail) {
    if (!state || !resource_arn || state->finding_count >= CA_MAX_FINDINGS) return -1;
    ca_compliance_finding_t *f = &state->findings[state->finding_count++];
    memset(f, 0, sizeof(ca_compliance_finding_t));
    f->id = g_next_finding_id++;
    f->rule_id = rule_id;
    f->status = status;
    strncpy(f->resource_arn, resource_arn, CA_ARN_LEN - 1);
    if (resource_type) strncpy(f->resource_type, resource_type, 127);
    if (detail) strncpy(f->details, detail, CA_JSON_MAX - 1);

    ca_compliance_rule_t *rule = NULL;
    for (int i = 0; i < state->rule_count; i++) {
        if (state->rules[i].id == rule_id) { rule = &state->rules[i]; break; }
    }

    float base_risk = 0;
    switch (status) {
        case CA_STATUS_FAIL: base_risk = 80.0f; break;
        case CA_STATUS_WARN: base_risk = 40.0f; break;
        case CA_STATUS_ERROR: base_risk = 60.0f; break;
        default: base_risk = 5.0f; break;
    }
    if (rule) {
        switch (rule->severity) {
            case CA_SEVERITY_CRITICAL: base_risk *= 1.25f; break;
            case CA_SEVERITY_HIGH:     base_risk *= 1.0f; break;
            case CA_SEVERITY_MEDIUM:   base_risk *= 0.75f; break;
            case CA_SEVERITY_LOW:      base_risk *= 0.5f; break;
            default: break;
        }
    }
    if (base_risk > 100.0f) base_risk = 100.0f;
    f->risk_score = base_risk;

    time_t now = time(NULL);
    f->checked_at = now;
    f->created_at = now;
    state->total_checks++;
    if (status == CA_STATUS_PASS) state->checks_passed++;
    else if (status == CA_STATUS_FAIL) state->checks_failed++;

    if (status == CA_STATUS_FAIL && detail) {
        snprintf(f->remediation, CA_JSON_MAX - 1, "Fix: %s", detail);
    }
    return 0;
}

int ca_compliance_score(const ca_state_t *state, ca_framework_t framework) {
    if (!state) return -1;
    int total = 0, passed = 0;
    for (int i = 0; i < state->finding_count; i++) {
        if (state->rules[i].framework != framework) continue;
        total++;
        if (state->findings[i].status == CA_STATUS_PASS) passed++;
    }
    if (total == 0) return -1;
    return (passed * 100) / total;
}

/* ?? Utility Functions ?? */
void ca_state_init(ca_state_t *state) {
    if (!state) return;
    memset(state, 0, sizeof(ca_state_t));
}

void ca_state_print_summary(const ca_state_t *state) {
    if (!state) return;
    printf("Compliance State Summary:\n");
    printf("  Trails:         %d\n", state->trail_count);
    printf("  Rules:          %d\n", state->rule_count);
    printf("  Findings:       %d\n", state->finding_count);
    printf("  Total Checks:   %d\n", state->total_checks);
    printf("  Passed:         %d\n", state->checks_passed);
    printf("  Failed:         %d\n", state->checks_failed);
    if (state->total_checks > 0) {
        printf("  Pass Rate:      %d%%\n",
               (state->checks_passed * 100) / state->total_checks);
    }
    for (int i = 0; i < state->finding_count && i < 10; i++) {
        printf("  [%c] %s on %s (risk=%.1f)\n",
               state->findings[i].status == CA_STATUS_PASS ? 'P' :
               state->findings[i].status == CA_STATUS_FAIL ? 'F' : 'W',
               state->findings[i].resource_type,
               state->findings[i].resource_arn,
               state->findings[i].risk_score);
    }
}

const char* ca_framework_name(ca_framework_t f) {
    switch (f) {
        case CA_FRAMEWORK_PCI_DSS:  return "PCI-DSS v4.0";
        case CA_FRAMEWORK_SOC2:     return "SOC 2 Type II";
        case CA_FRAMEWORK_HIPAA:    return "HIPAA Security Rule";
        case CA_FRAMEWORK_CIS_AWS:  return "CIS AWS Foundations v1.4";
        case CA_FRAMEWORK_GDPR:     return "GDPR";
        case CA_FRAMEWORK_ISO27001: return "ISO/IEC 27001:2022";
        case CA_FRAMEWORK_NIST_800: return "NIST SP 800-53 Rev 5";
        case CA_FRAMEWORK_FEDRAMP:  return "FedRAMP High";
        case CA_FRAMEWORK_CUSTOM:   return "Custom Framework";
        default: return "Unknown";
    }
}

const char* ca_event_type_name(ca_event_type_t t) {
    switch (t) {
        case CA_EV_READ:        return "Read";
        case CA_EV_WRITE:       return "Write";
        case CA_EV_AUTH_LOGIN:  return "AuthLogin";
        case CA_EV_AUTH_LOGOUT: return "AuthLogout";
        case CA_EV_KEY_ROTATE:  return "KeyRotate";
        case CA_EV_KEY_DELETE:  return "KeyDelete";
        case CA_EV_POLICY_CHG:  return "PolicyChange";
        case CA_EV_SG_CHANGE:   return "SecurityGroupChange";
        case CA_EV_NACL_CHANGE: return "NetworkAclChange";
        case CA_EV_CONSOLE:     return "ConsoleLogin";
        case CA_EV_API_CALL:    return "ApiCall";
        case CA_EV_COMPLIANCE:  return "ComplianceCheck";
        case CA_EV_ANOMALY:     return "AnomalyDetected";
        default: return "Unknown";
    }
}

const char* ca_severity_name(ca_finding_severity_t s) {
    switch (s) {
        case CA_SEVERITY_CRITICAL: return "CRITICAL";
        case CA_SEVERITY_HIGH:     return "HIGH";
        case CA_SEVERITY_MEDIUM:   return "MEDIUM";
        case CA_SEVERITY_LOW:      return "LOW";
        case CA_SEVERITY_INFO:     return "INFO";
        default: return "UNKNOWN";
    }
}

const char* ca_status_name(ca_check_status_t s) {
    switch (s) {
        case CA_STATUS_PASS:  return "PASS";
        case CA_STATUS_FAIL:  return "FAIL";
        case CA_STATUS_WARN:  return "WARN";
        case CA_STATUS_SKIP:  return "SKIP";
        case CA_STATUS_ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}
