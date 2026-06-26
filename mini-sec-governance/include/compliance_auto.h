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
#define COMP_MAX_RULE_OPS      16
#define COMP_MAX_REMEDIATION   64
#define COMP_MAX_BENCHMARKS    16
#define COMP_MAX_TREND_POINTS  32

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

/* ── Policy Rule Evaluation ── L3: Composite rule engine */
typedef enum {
    COMP_OP_EQ       = 0,   /* == */
    COMP_OP_NEQ      = 1,   /* != */
    COMP_OP_GT       = 2,   /* > */
    COMP_OP_GTE      = 3,   /* >= */
    COMP_OP_LT       = 4,   /* < */
    COMP_OP_LTE      = 5,   /* <= */
    COMP_OP_CONTAINS = 6,   /* substring match */
    COMP_OP_AND      = 7,   /* logical AND of sub-rules */
    COMP_OP_OR       = 8,   /* logical OR of sub-rules */
    COMP_OP_NOT      = 9,   /* logical NOT */
    COMP_OP_REGEX    = 10   /* posix-like basic pattern */
} Compliance_RuleOp;

typedef struct {
    int               rule_id;
    const char       *field;
    Compliance_RuleOp op;
    const char       *value;
    int               severity;       /* 1-5, higher = more severe */
    int               sub_rules[COMP_MAX_RULE_OPS];
    int               sub_rule_count;
} Compliance_Rule;

/* ── Remediation Plan ── L7: Automated remediation tracking */
typedef enum {
    COMP_REM_PENDING    = 0,
    COMP_REM_IN_PROGRESS = 1,
    COMP_REM_VERIFIED   = 2,
    COMP_REM_CLOSED     = 3,
    COMP_REM_DEFERRED   = 4
} Compliance_RemediationState;

typedef struct {
    int    remed_id;
    int    drift_id;
    int    policy_id;
    const char *action_plan;
    const char *assigned_to;
    Compliance_RemediationState state;
    int    priority;               /* 1=critical, 5=low */
    int    target_days;
    time_t opened_at;
    time_t resolved_at;
    double cost_estimate;
} Compliance_Remediation;

/* ── GRC Maturity Model ── L8: Capability maturity levels */
typedef enum {
    COMP_MATURITY_INITIAL      = 0,
    COMP_MATURITY_MANAGED      = 1,
    COMP_MATURITY_DEFINED      = 2,
    COMP_MATURITY_QUANTITATIVE = 3,
    COMP_MATURITY_OPTIMIZING   = 4
} Compliance_MaturityLevel;

typedef struct {
    Compliance_Regulation reg;
    Compliance_MaturityLevel governance;
    Compliance_MaturityLevel risk_mgmt;
    Compliance_MaturityLevel compliance;
    Compliance_MaturityLevel audit;
    Compliance_MaturityLevel overall;
    double score;                /* 0-100 composite maturity score */
} Compliance_MaturityAssessment;

/* ── Trend / Benchmark Data ── L7: Compliance score time-series */
typedef struct {
    time_t timestamp;
    double compliance_score;
    int    policies_passing;
    int    policies_total;
    int    drifts_open;
} Compliance_TrendPoint;

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
    Compliance_Remediation  remediations[COMP_MAX_REMEDIATION];
    int                     remediation_count;
    Compliance_MaturityAssessment maturity;
    Compliance_TrendPoint   trends[COMP_MAX_TREND_POINTS];
    int                     trend_count;
    uint64_t                chain_hash;
    int                     monitoring_active;
    int                     monitoring_cycles;
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

/* ── Rule Evaluation Engine ── L3: Composite policy rule evaluator */
int  comp_rule_add(Compliance_Engine *eng, const char *field,
                    Compliance_RuleOp op, const char *value, int severity,
                    int *sub_rules, int sub_count);
int  comp_rule_evaluate(const Compliance_Rule *rule,
                         const char *field, const char *actual_value);
int  comp_evaluate_composite(const Compliance_Rule *rules, int rule_count,
                              const char *field, const char *actual_value);

/* ── Control Mapping ── L4: Map policies to regulatory controls recursively */
int  comp_map_policy_to_control(Compliance_Engine *eng, int policy_id,
                                 int control_id);
int  comp_control_coverage(const Compliance_Engine *eng,
                            Compliance_Regulation reg, double *coverage_pct);
int  comp_crosswalk_matrix(const Compliance_Engine *eng,
                            Compliance_Regulation reg_a,
                            Compliance_Regulation reg_b,
                            int *common_controls);

/* ── Remediation Plan ── L7: Automated remediation workflow */
int  comp_add_remediation(Compliance_Engine *eng, int drift_id,
                           int policy_id, const char *action_plan,
                           const char *assigned_to, int priority,
                           int target_days, double cost_estimate);
int  comp_remediate_close(Compliance_Engine *eng, int remed_id);
void comp_remediation_backlog(const Compliance_Engine *eng);

/* ── GRC Maturity Model ── L8: Capability maturity assessment */
void comp_assess_maturity(Compliance_Engine *eng);
const char* comp_maturity_level_name(Compliance_MaturityLevel ml);
int  comp_maturity_improvement_plan(const Compliance_MaturityAssessment *ma,
                                     Compliance_MaturityLevel target,
                                     char *plan_buf, int buf_size);

/* ── Compliance Trending ── L7: Time-series compliance analysis */
int  comp_record_trend(Compliance_Engine *eng);
int  comp_forecast_compliance(const Compliance_Engine *eng,
                               int days_ahead, double *predicted_score);
void comp_trend_report(const Compliance_Engine *eng);

/* ── Evidence Verification ── L8: Hash-chain integrity verification */
int  comp_verify_chain(const Compliance_Engine *eng);
int  comp_export_evidence_package(const Compliance_Engine *eng,
                                   char *out_buf, int buf_size);

#endif
