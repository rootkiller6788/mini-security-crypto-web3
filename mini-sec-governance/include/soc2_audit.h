#ifndef SOC2_AUDIT_H
#define SOC2_AUDIT_H

#include <stddef.h>
#include <stdint.h>

#define SOC2_MAX_CONTROLS  128
#define SOC2_MAX_EVIDENCE  256
#define SOC2_MAX_CONTROL_ACTIVITIES 128
#define SOC2_MAX_SAMPLES    64
#define SOC2_MAX_BRIDGE_PERIODS 4

typedef enum {
    SOC2_TC_SECURITY      = 0x01,
    SOC2_TC_AVAILABILITY  = 0x02,
    SOC2_TC_CONFIDENTIAL  = 0x04,
    SOC2_TC_INTEGRITY     = 0x08,
    SOC2_TC_PRIVACY       = 0x10
} SOC2_TrustCriteria;

typedef enum {
    SOC2_REPORT_TYPE_I  = 1,
    SOC2_REPORT_TYPE_II = 2
} SOC2_ReportType;

typedef enum {
    SOC2_EVAL_DESIGNED_CORRECTLY   = 0,
    SOC2_EVAL_OPERATING_EFFECTIVE  = 1,
    SOC2_EVAL_DEFICIENCY           = 2,
    SOC2_EVAL_SIGNIFICANT_DEFICIENCY = 3,
    SOC2_EVAL_MATERIAL_WEAKNESS    = 4
} SOC2_EvaluationResult;

typedef enum {
    SOC2_CTRL_DESIGNED    = 0,
    SOC2_CTRL_IMPLEMENTED = 1,
    SOC2_CTRL_TESTED      = 2,
    SOC2_CTRL_REMEDIATED  = 3
} SOC2_ControlState;

typedef struct {
    int             control_id;
    SOC2_TrustCriteria category;
    const char     *name;
    const char     *description;
    const char     *test_procedure;
    SOC2_ControlState state;
    SOC2_EvaluationResult evaluation;
} SOC2_ControlActivity;

typedef struct {
    int             evidence_id;
    int             control_ref;
    SOC2_TrustCriteria category;
    const char     *description;
    const char     *source;
    const char     *collection_method;
    int             collected_year;
    int             collected_month;
    int             approved;
} SOC2_Evidence;

typedef struct {
    int             activity_id;
    SOC2_TrustCriteria category;
    const char     *control_description;
    const char     *test_result;
    SOC2_EvaluationResult auditor_eval;
    int             evidence_count;
    int             evidence_refs[8];
} SOC2_ControlTestResult;

typedef struct {
    SOC2_ReportType report_type;
    int             report_year;
    int             report_period_months;
    SOC2_TrustCriteria scope;
    const char     *auditor_name;
    const char     *service_org_name;
    const char     *opinion;
    SOC2_ControlActivity controls[SOC2_MAX_CONTROL_ACTIVITIES];
    int             control_count;
    SOC2_Evidence   evidence[SOC2_MAX_EVIDENCE];
    int             evidence_count;
    SOC2_ControlTestResult test_results[SOC2_MAX_CONTROLS];
    int             test_count;
    int             findings;
    int             deficiencies;
    int             material_weaknesses;
} SOC2_AuditReport;

typedef struct {
    SOC2_ControlActivity  activities[SOC2_MAX_CONTROLS];
    int                   activity_count;
    SOC2_Evidence         evidence[SOC2_MAX_EVIDENCE];
    int                   evidence_count;
} SOC2_Engagement;

/* ── Statistical Audit Sampling ── L5: AICPA audit sampling methodology */
typedef struct {
    int population_size;
    int sample_size;
    double confidence_level;    /* e.g., 0.95 */
    double tolerable_error_rate; /* e.g., 0.05 */
    double expected_error_rate;  /* e.g., 0.02 */
    int errors_found;
    double upper_error_limit;
    int is_acceptable;          /* 1 if upper_limit <= tolerable */
} SOC2_AuditSample;

/* ── Bridge Letter ── L7: SOC 2 bridge (gap) letter for reporting period */
typedef struct {
    int    letter_id;
    int    report_year;
    int    bridge_start_month;
    int    bridge_end_month;
    const char *service_org;
    const char *auditor;
    int    has_material_changes;
    const char *change_description;
    const char *opinion;
    int    controls_reviewed;
    int    controls_changed;
    int    new_controls_added;
} SOC2_BridgeLetter;

int  soc2_init_engagement(SOC2_Engagement *eng);
int  soc2_add_control(SOC2_Engagement *eng, SOC2_TrustCriteria cat,
                       const char *name, const char *desc,
                       const char *test_proc);
int  soc2_collect_evidence(SOC2_Engagement *eng, int control_ref,
                            SOC2_TrustCriteria cat, const char *desc,
                            const char *source, const char *method,
                            int year, int month);
int  soc2_evaluate_control(SOC2_Engagement *eng, int control_id,
                            SOC2_EvaluationResult result);
int  soc2_generate_report(SOC2_Engagement *eng, SOC2_AuditReport *report,
                           SOC2_ReportType type, int year,
                           SOC2_TrustCriteria scope,
                           const char *auditor, const char *org);
void soc2_summary(const SOC2_AuditReport *report);
int  soc2_deficiency_tally(const SOC2_AuditReport *report);
const char* soc2_trust_criteria_name(SOC2_TrustCriteria tc);
const char* soc2_eval_result_name(SOC2_EvaluationResult r);

/* ── Statistical Audit Sampling ── L5: AICPA sampling methodology */
int  soc2_calculate_sample_size(int population, double confidence,
                                 double tolerable_error, double expected_error,
                                 SOC2_AuditSample *sample);
void soc2_sample_report(const SOC2_AuditSample *sample);
int  soc2_evaluate_sample(SOC2_AuditSample *sample, int errors_found);
int  soc2_attribute_sampling(const SOC2_Engagement *eng,
                               SOC2_TrustCriteria category,
                               SOC2_AuditSample *sample);

/* ── Bridge Letter ── L7: Gap period communication between SOC2 reports */
int  soc2_generate_bridge_letter(const SOC2_AuditReport *prev_report,
                                  const SOC2_Engagement *current,
                                  int start_month, int end_month,
                                  int has_changes, const char *changes_desc,
                                  SOC2_BridgeLetter *letter);
void soc2_bridge_letter_display(const SOC2_BridgeLetter *letter);

/* ── Trust Services Criteria Mapping ── L2: TSC cross-reference */
int  soc2_tsc_coverage(const SOC2_AuditReport *report,
                        SOC2_TrustCriteria tc, double *coverage_pct);

#endif
