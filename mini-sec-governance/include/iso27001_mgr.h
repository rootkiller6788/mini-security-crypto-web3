#ifndef ISO27001_MGR_H
#define ISO27001_MGR_H

#include <stddef.h>
#include <stdint.h>

#define ISO27001_ANNEX_A_DOMAINS  14
#define ISO27001_ANNEX_A_CONTROLS 114
#define ISO27001_MAX_ASSETS       256
#define ISO27001_MAX_THREATS      128
#define ISO27001_MAX_RISKS        512
#define ISO27001_SOA_MAX_CLASSES  64
#define ISO27001_MAX_KPIS         32
#define ISO27001_MAX_INCIDENTS   128
#define ISO27001_MAX_CLAUSES      10

typedef enum {
    ISO27001_STATUS_NOT_IMPL,
    ISO27001_STATUS_PARTIAL,
    ISO27001_STATUS_FULL,
    ISO27001_STATUS_NA
} ISO27001_ControlStatus;

typedef enum {
    ISO27001_DOMAIN_A5  = 0,
    ISO27001_DOMAIN_A6  = 1,
    ISO27001_DOMAIN_A7  = 2,
    ISO27001_DOMAIN_A8  = 3,
    ISO27001_DOMAIN_A9  = 4,
    ISO27001_DOMAIN_A10 = 5,
    ISO27001_DOMAIN_A11 = 6,
    ISO27001_DOMAIN_A12 = 7,
    ISO27001_DOMAIN_A13 = 8,
    ISO27001_DOMAIN_A14 = 9,
    ISO27001_DOMAIN_A15 = 10,
    ISO27001_DOMAIN_A16 = 11,
    ISO27001_DOMAIN_A17 = 12,
    ISO27001_DOMAIN_A18 = 13
} ISO27001_AnnexADomain;

typedef struct {
    int             control_id;
    ISO27001_AnnexADomain domain;
    const char     *name;
    const char     *description;
    ISO27001_ControlStatus status;
    const char     *evidence_ref;
    int             last_reviewed;
} ISO27001_Control;

typedef struct {
    int             asset_id;
    const char     *name;
    const char     *owner;
    char            classification[16];
    double          value;
    int             is_critical;
} ISO27001_Asset;

typedef struct {
    int             threat_id;
    const char     *name;
    const char     *source;
    double          capability;
    double          motivation;
} ISO27001_Threat;

typedef struct {
    int             vuln_id;
    const char     *name;
    double          severity;
    int             has_control;
    int             control_ref;
} ISO27001_Vulnerability;

typedef struct {
    int             risk_id;
    int             asset_id;
    int             threat_id;
    int             vuln_id;
    double          inherent_risk;
    double          residual_risk;
    int             control_ref;
    ISO27001_ControlStatus status;
} ISO27001_Risk;

typedef struct {
    int             control_id;
    int             applicable;
    const char     *justification;
    ISO27001_ControlStatus implement_status;
} ISO27001_SoAEntry;

typedef struct {
    int             audit_id;
    const char     *scope;
    const char     *auditor;
    int             scheduled_month;
    int             completed;
    int             findings;
    int             nonconformities;
} ISO27001_Audit;

typedef struct {
    const char     *topic;
    const char     *input_data;
    const char     *output_data;
    const char     *decisions;
    int             review_year;
} ISO27001_ManagementReview;

/* ── Control KPI (Key Performance Indicator) ── */
typedef struct {
    int        kpi_id;
    const char *name;
    const char *metric;
    double     current_value;
    double     target_value;
    double     threshold_warn;  /* below this → warning */
    double     threshold_crit;  /* below this → critical */
    int        control_ref;     /* linked Annex A control ID */
    int        trending;        /* 1=improving, 0=stable, -1=declining */
} ISO27001_KPI;

/* ── Incident Record ── */
typedef enum {
    ISO27001_INC_OPEN       = 0,
    ISO27001_INC_ANALYZING  = 1,
    ISO27001_INC_CONTAINED  = 2,
    ISO27001_INC_RESOLVED   = 3,
    ISO27001_INC_CLOSED     = 4
} ISO27001_IncidentState;

typedef struct {
    int    inc_id;
    const char *title;
    const char *description;
    const char *reported_by;
    int    reported_year;
    int    reported_month;
    int    severity;          /* 1-5 */
    ISO27001_IncidentState state;
    const char *root_cause;
    const char *corrective_action;
    double containment_hours;
    double recovery_hours;
} ISO27001_Incident;

/* ── Risk Appetite Statement (L2) ── */
typedef struct {
    double max_acceptable_ale;
    double max_single_risk_score;
    int    max_critical_risks;
    int    max_high_risks;
    double risk_capacity;
    int    active;
} ISO27001_RiskAppetite;

/* ── Clause Compliance Tracker (ISO 27001:2022 clauses 4-10) ── */
typedef struct {
    int clause_number;     /* 4 through 10 */
    const char *clause_name;
    int requirements_total;
    int requirements_met;
    int documentary_evidence;
    int implemented;
} ISO27001_ClauseStatus;

typedef struct {
    ISO27001_Control    controls[ISO27001_ANNEX_A_CONTROLS];
    int                 control_count;
    ISO27001_Asset      assets[ISO27001_MAX_ASSETS];
    int                 asset_count;
    ISO27001_Threat     threats[ISO27001_MAX_THREATS];
    int                 threat_count;
    ISO27001_Risk       risks[ISO27001_MAX_RISKS];
    int                 risk_count;
    ISO27001_SoAEntry   soa[ISO27001_ANNEX_A_CONTROLS];
    int                 soa_count;
    ISO27001_Audit      audits[16];
    int                 audit_count;
    ISO27001_ManagementReview reviews[4];
    int                 review_count;
    ISO27001_KPI        kpis[ISO27001_MAX_KPIS];
    int                 kpi_count;
    ISO27001_Incident   incidents[ISO27001_MAX_INCIDENTS];
    int                 incident_count;
    ISO27001_RiskAppetite risk_appetite;
    ISO27001_ClauseStatus clauses[ISO27001_MAX_CLAUSES];
    int                 clause_count;
    int                 cert_year;
    int                 cert_stage;
    int                 active;
    int                 incident_response_plan_active;
} ISO27001_ISMS;

int  iso27001_init(ISO27001_ISMS *isms, int cert_year);
void iso27001_load_annex_a(ISO27001_ISMS *isms);
int  iso27001_add_asset(ISO27001_ISMS *isms, const char *name, const char *owner,
                         const char *classification, double value, int is_critical);
int  iso27001_add_threat(ISO27001_ISMS *isms, const char *name, const char *source,
                          double capability, double motivation);
int  iso27001_add_vulnerability(ISO27001_ISMS *isms, ISO27001_Risk *risk,
                                 const char *vuln_name, double severity);
int  iso27001_add_risk(ISO27001_ISMS *isms, int asset_id, int threat_id,
                        double severity, int control_ref);
int  iso27001_generate_soa(ISO27001_ISMS *isms);
void iso27001_risks_by_asset(const ISO27001_ISMS *isms, int asset_id,
                              int *out_ids, int *out_count, int max_count);
int  iso27001_schedule_audit(ISO27001_ISMS *isms, const char *scope,
                              const char *auditor, int month);
int  iso27001_add_review(ISO27001_ISMS *isms, const char *topic,
                          const char *input, const char *output,
                          const char *decisions, int year);
void iso27001_pdca_report(const ISO27001_ISMS *isms);
int  iso27001_certification_readiness(const ISO27001_ISMS *isms);

/* ── Control Effectiveness ── L5: KPI-based measurement */
int  iso27001_add_kpi(ISO27001_ISMS *isms, const char *name, const char *metric,
                       double target, double warn, double crit, int control_ref);
int  iso27001_update_kpi(ISO27001_ISMS *isms, int kpi_id, double current_value);
int  iso27001_kpi_trending(ISO27001_ISMS *isms, int kpi_id, int trend);
void iso27001_kpi_scorecard(const ISO27001_ISMS *isms);
double iso27001_control_effectiveness(const ISO27001_ISMS *isms, int domain);

/* ── Incident Management ── L2: ISO 27001 A.16 Incident Management */
int  iso27001_add_incident(ISO27001_ISMS *isms, const char *title,
                            const char *description, const char *reported_by,
                            int year, int month, int severity);
int  iso27001_resolve_incident(ISO27001_ISMS *isms, int inc_id,
                                const char *root_cause, const char *corrective,
                                double contain_hours, double recover_hours);
void iso27001_incident_report(const ISO27001_ISMS *isms);
int  iso27001_mean_time_to_resolve(const ISO27001_ISMS *isms, double *mttr_hours);

/* ── Risk Appetite ── L2: Board-level risk tolerance framework */
void iso27001_set_risk_appetite(ISO27001_ISMS *isms, double max_ale,
                                 double max_score, int max_crit, int max_high);
int  iso27001_check_risk_appetite(const ISO27001_ISMS *isms,
                                   double total_ale, int crit_risks,
                                   int high_risks);
void iso27001_risk_appetite_report(const ISO27001_ISMS *isms,
                                    double current_ale, int crit, int high);

/* ── Clause Compliance ── L4: ISO 27001:2022 clause 4-10 tracking */
void iso27001_init_clauses(ISO27001_ISMS *isms);
int  iso27001_update_clause(ISO27001_ISMS *isms, int clause_num,
                              int requirements_met);
int  iso27001_clause_compliance_pct(const ISO27001_ISMS *isms, int clause_num);
void iso27001_clause_matrix(const ISO27001_ISMS *isms);

#endif
