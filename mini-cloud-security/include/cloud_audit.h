#ifndef CLOUD_AUDIT_H
#define CLOUD_AUDIT_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define CA_MAX_EVENTS            256
#define CA_MAX_TRAILS              4
#define CA_MAX_COMPLIANCE_RULES  128
#define CA_MAX_FINDINGS          256
#define CA_HASH_LEN               32
#define CA_HASH_HEX_LEN           (CA_HASH_LEN * 2 + 1)
#define CA_EVENT_SOURCE_LEN      128
#define CA_EVENT_NAME_LEN        128
#define CA_ARN_LEN               128
#define CA_REGION_LEN             32
#define CA_JSON_MAX             1024
#define CA_MERKLE_MAX_LEAVES     128

typedef enum {
    CA_EVENT_MANAGEMENT = 0,
    CA_EVENT_DATA        = 1,
    CA_EVENT_INSIGHT     = 2,
    CA_EVENT_AUTH        = 3,
    CA_EVENT_ERROR       = 4
} ca_event_category_t;

typedef enum {
    CA_EV_READ       = 0,
    CA_EV_WRITE      = 1,
    CA_EV_AUTH_LOGIN = 2,
    CA_EV_AUTH_LOGOUT= 3,
    CA_EV_KEY_ROTATE = 4,
    CA_EV_KEY_DELETE = 5,
    CA_EV_POLICY_CHG = 6,
    CA_EV_SG_CHANGE  = 7,
    CA_EV_NACL_CHANGE= 8,
    CA_EV_CONSOLE    = 9,
    CA_EV_API_CALL   = 10,
    CA_EV_COMPLIANCE = 11,
    CA_EV_ANOMALY    = 12
} ca_event_type_t;

typedef enum {
    CA_FRAMEWORK_PCI_DSS  = 0,
    CA_FRAMEWORK_SOC2     = 1,
    CA_FRAMEWORK_HIPAA    = 2,
    CA_FRAMEWORK_CIS_AWS  = 3,
    CA_FRAMEWORK_GDPR     = 4,
    CA_FRAMEWORK_ISO27001 = 5,
    CA_FRAMEWORK_NIST_800 = 6,
    CA_FRAMEWORK_FEDRAMP  = 7,
    CA_FRAMEWORK_CUSTOM   = 8
} ca_framework_t;

typedef enum {
    CA_SEVERITY_CRITICAL = 0,
    CA_SEVERITY_HIGH     = 1,
    CA_SEVERITY_MEDIUM   = 2,
    CA_SEVERITY_LOW      = 3,
    CA_SEVERITY_INFO     = 4
} ca_finding_severity_t;

typedef enum {
    CA_STATUS_PASS  = 0,
    CA_STATUS_FAIL  = 1,
    CA_STATUS_WARN  = 2,
    CA_STATUS_SKIP  = 3,
    CA_STATUS_ERROR = 4
} ca_check_status_t;

typedef struct {
    uint64_t    event_id;
    ca_event_category_t category;
    ca_event_type_t     type;
    char        event_source[CA_EVENT_SOURCE_LEN];
    char        event_name[CA_EVENT_NAME_LEN];
    char        user_arn[CA_ARN_LEN];
    char        source_ip[64];
    char        user_agent[256];
    char        region[CA_REGION_LEN];
    char        request_params[CA_JSON_MAX];
    char        response_elements[CA_JSON_MAX];
    time_t      event_time;
    int64_t     latency_ms;
    unsigned char prev_hash[CA_HASH_LEN];
    unsigned char event_hash[CA_HASH_LEN];
    unsigned char chain_hash[CA_HASH_LEN];
    int         integrity_verified;
} ca_event_record_t;

typedef struct {
    char              trail_name[CA_EVENT_NAME_LEN];
    char              s3_bucket[CA_ARN_LEN];
    unsigned char     genesis_hash[CA_HASH_LEN];
    ca_event_record_t events[CA_MAX_EVENTS];
    int               event_count;
    uint64_t          next_event_id;
    time_t            creation_time;
    time_t            last_event_time;
    int               log_file_validation_enabled;
    int               s3_encryption_enabled;
    int               multi_region;
    char              log_group[CA_EVENT_NAME_LEN];
} ca_audit_trail_t;

typedef struct {
    unsigned char hash[CA_HASH_LEN];
    int           left_idx;
    int           right_idx;
} ca_merkle_node_t;

typedef struct {
    ca_merkle_node_t nodes[2 * CA_MERKLE_MAX_LEAVES - 1];
    int              leaf_count;
    int              node_count;
    unsigned char    root_hash[CA_HASH_LEN];
} ca_merkle_tree_t;

typedef struct {
    int             id;
    ca_framework_t  framework;
    char            rule_id[64];
    char            title[CA_EVENT_NAME_LEN];
    char            description[CA_JSON_MAX];
    ca_finding_severity_t severity;
    int             required_encryption;
    int             required_mfa;
    int             required_rotation_days;
    int             required_log_retention_days;
    int             max_public_access;
    int             require_vpc_only;
    int             require_https_only;
    int             enabled;
} ca_compliance_rule_t;

typedef struct {
    int             id;
    int             rule_id;
    ca_check_status_t status;
    char            resource_arn[CA_ARN_LEN];
    char            resource_type[128];
    char            details[CA_JSON_MAX];
    char            remediation[CA_JSON_MAX];
    time_t          checked_at;
    time_t          created_at;
    float           risk_score;
} ca_compliance_finding_t;

typedef struct {
    ca_audit_trail_t      *trails[CA_MAX_TRAILS];
    int                    trail_count;
    ca_compliance_rule_t   rules[CA_MAX_COMPLIANCE_RULES];
    int                    rule_count;
    ca_compliance_finding_t findings[CA_MAX_FINDINGS];
    int                    finding_count;
    int                    total_checks;
    int                    checks_passed;
    int                    checks_failed;
} ca_state_t;

void  ca_hash_init(unsigned char *hash_out);
void  ca_hash_update(unsigned char *hash, const void *data, size_t len);
void  ca_hash_final(unsigned char *hash_inout);
void  ca_hash_data(const void *data, size_t len, unsigned char *hash_out);
void  ca_hash_to_hex(const unsigned char *hash, char *hex_out);
int   ca_hash_equal(const unsigned char *a, const unsigned char *b);
void  ca_hash_concat(const unsigned char *a, size_t alen, const unsigned char *b, size_t blen, unsigned char *out);

ca_audit_trail_t* ca_trail_create(const char *name, const char *s3_bucket);
int   ca_trail_log_event(ca_audit_trail_t *trail, ca_event_category_t cat, ca_event_type_t type, const char *source, const char *user_arn, const char *region, const char *params);
int   ca_trail_verify_chain(const ca_audit_trail_t *trail);
int   ca_trail_detect_tamper(const ca_audit_trail_t *trail, int *tampered_index);
int   ca_trail_export_json(const ca_audit_trail_t *trail, char *out_buf, size_t buf_size);
void  ca_trail_print_summary(const ca_audit_trail_t *trail);

void  ca_merkle_build(ca_merkle_tree_t *tree, const unsigned char leaves[][CA_HASH_LEN], int leaf_count);
int   ca_merkle_generate_proof(const ca_merkle_tree_t *tree, int leaf_index, unsigned char proof[][CA_HASH_LEN], int *proof_len);
int   ca_merkle_verify_proof(const unsigned char root[CA_HASH_LEN], const unsigned char leaf[CA_HASH_LEN], const unsigned char proof[][CA_HASH_LEN], int proof_len, int leaf_index);
void  ca_merkle_print(const ca_merkle_tree_t *tree);

ca_compliance_rule_t* ca_compliance_add_rule(ca_state_t *state, ca_framework_t framework, const char *rule_id, const char *title, ca_finding_severity_t sev);
void  ca_compliance_add_pci_dss_rules(ca_state_t *state);
void  ca_compliance_add_cis_aws_rules(ca_state_t *state);
void  ca_compliance_add_hipaa_rules(ca_state_t *state);

int   ca_compliance_check_encryption(ca_state_t *state, const char *resource_arn, int is_encrypted);
int   ca_compliance_check_public_access(ca_state_t *state, const char *resource_arn, int is_public);
int   ca_compliance_check_mfa(ca_state_t *state, const char *user_arn, int mfa_enabled);
int   ca_compliance_run_check(ca_state_t *state, int rule_id, const char *resource_arn, const char *resource_type, ca_check_status_t status, const char *detail);
int   ca_compliance_score(const ca_state_t *state, ca_framework_t framework);

void  ca_state_init(ca_state_t *state);
void  ca_state_print_summary(const ca_state_t *state);

const char* ca_framework_name(ca_framework_t f);
const char* ca_event_type_name(ca_event_type_t t);
const char* ca_severity_name(ca_finding_severity_t s);
const char* ca_status_name(ca_check_status_t s);

#endif
