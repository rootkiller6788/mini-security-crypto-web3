#ifndef SOC2_AUDIT_H
#define SOC2_AUDIT_H

#include <stddef.h>
#include <stdint.h>

#define SOC2_MAX_CONTROLS  128
#define SOC2_MAX_EVIDENCE  256
#define SOC2_MAX_CONTROL_ACTIVITIES 128

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

#endif
