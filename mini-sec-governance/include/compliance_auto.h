#ifndef COMPLIANCE_AUTO_H
#define COMPLIANCE_AUTO_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define COMP_MAX_POLICIES      64
#define COMP_MAX_CHECKS       128
#define COMP_MAX_DRIFTS       256
#define COMP_MAX_AUDIT_LOGS   512
#define COMP_MAX_REGS          16
#define COMP_MAX_CONTROLS     256
#define COMP_MAX_DASHBOARD     32

typedef enum {
    COMP_STATUS_PASS      = 0,
    COMP_STATUS_FAIL      = 1,
    COMP_STATUS_WARN      = 2,
    COMP_STATUS_ERROR     = 3,
    COMP_STATUS_NOT_APPLICABLE = 4
} Compliance_Status;

typedef enum {
    COMP_REG_GDPR   = 0,
    COMP_REG_HIPAA  = 1,
    COMP_REG_PCI_DSS = 2,
    COMP_REG_SOX    = 3,
    COMP_REG_NIST   = 4,
    COMP_REG_ISO27001 = 5,
    COMP_REG_CUSTOM = 6
} Compliance_Regulation;

typedef struct {
    int             policy_id;
    const char     *name;
    const char     *description;
    const char     *rule_expression;  /* OPA/Rego-like rule expression */
    const char     *resource_path;    /* e.g. "config.db.encryption" */
    const char     *expected_value;
    int             severity;
    Compliance_Regulation regs[4];
    int             reg_count;
} Compliance_Policy;

typedef struct {
    int             check_id;
    int             policy_id;
    Compliance_Status status;
    const char     *resource_value;
    const char     *message;
    time_t          timestamp;
} Compliance_CheckResult;

typedef struct {
    int             drift_id;
    int             check_id;
    int             policy_id;
    const char     *drifted_value;
    const char     *expected_value;
    const char     *resource_path;
    time_t          detected_at;
    int             acknowledged;
    const char     *remediated_by;
    time_t          remediated_at;
} Compliance_Drift;

typedef struct {
    int             log_id;
    time_t          timestamp;
    const char     *actor;
    const char     *action;
    const char     *resource;
    const char     *result;
    int             immutable;  /* hash-linked for integrity */
    uint64_t        prev_hash;
    uint64_t        curr_hash;
} Compliance_AuditLog;

typedef struct {
    const char     *control_id;
    Compliance_Regulation reg;
    const char     *description;
    Compliance_Status status;
    int             pass_count;
    int             fail_count;
    int             last_checked;
} Compliance_Control;

typedef struct {
    Compliance_Regulation reg;
    const char     *name;
    const char     *description;
    int             total_controls;
    int             compliant_controls;
    int             non_compliant_controls;
    int             total_policies;
    int             passing_policies;
    Compliance_Status overall_status;
} Compliance_Dashboard;

typedef struct {
    Compliance_Policy       policies[COMP_MAX_POLICIES];
    int                     policy_count;
    Compliance_CheckResult  checks[COMP_MAX_CHECKS];
    int                     check_count;
    Compliance_Drift        drifts[COMP_MAX_DRIFTS];
    int                     drift_count;
    Compliance_AuditLog     logs[COMP_MAX_AUDIT_LOGS];
    int                     log_count;
    Compliance_Regulation   active_regs[COMP_MAX_REGS];
    int                     active_reg_count;
    Compliance_Control      controls[COMP_MAX_CONTROLS];
    int                     control_count;
    Compliance_Dashboard    dashboard;
    uint64_t                chain_hash;
    int                     monitoring_active;
} Compliance_Engine;

int  comp_init(Compliance_Engine *eng);
int  comp_add_regulation(Compliance_Engine *eng, Compliance_Regulation reg);
int  comp_add_policy(Compliance_Engine *eng, const char *name,
                      const char *desc, const char *rule, const char *path,
                      const char *expected, int severity, const Compliance_Regulation *regs, int reg_count);
int  comp_check_policy(Compliance_Engine *eng, int policy_id,
                        const char *current_value);
int  comp_check_all(Compliance_Engine *eng);
int  comp_detect_drift(Compliance_Engine *eng);
int  comp_add_log(Compliance_Engine *eng, const char *actor,
                   const char *action, const char *resource, const char *result);
int  comp_add_control(Compliance_Engine *eng, const char *ctrl_id,
                       Compliance_Regulation reg, const char *desc);
int  comp_update_dashboard(Compliance_Engine *eng);
void comp_dashboard_display(const Compliance_Engine *eng);
int  comp_generate_evidence(Compliance_Engine *eng, int control_id);
void comp_audit_trail(const Compliance_Engine *eng);
void comp_continuous_monitor(Compliance_Engine *eng, int interval_sec);
const char* comp_status_name(Compliance_Status s);
const char* comp_reg_name(Compliance_Regulation r);
double comp_compliance_score(const Compliance_Engine *eng);
void comp_remediation_report(const Compliance_Engine *eng);
uint64_t comp_compute_hash(const char *data);

#endif
