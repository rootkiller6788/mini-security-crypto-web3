#ifndef NIST_CSF_H
#define NIST_CSF_H

#include <stddef.h>
#include <stdint.h>

#define NIST_CSF_MAX_CATEGORIES    32
#define NIST_CSF_MAX_SUBCATEGORIES 128
#define NIST_CSF_MAX_CONTROLS      256
#define NIST_CSF_MAX_PROFILE_ITEMS 256
#define NIST_CSF_MAX_GAP_ITEMS     256
#define NIST_CSF_MAX_MATURITY_LEVELS 5
#define NIST_CSF_MAX_FUNCTIONS      5

typedef enum {
    NIST_CSF_IDENTIFY = 0,
    NIST_CSF_PROTECT  = 1,
    NIST_CSF_DETECT   = 2,
    NIST_CSF_RESPOND  = 3,
    NIST_CSF_RECOVER  = 4
} NIST_CSF_Function;

typedef enum {
    NIST_TIER_1_PARTIAL       = 1,
    NIST_TIER_2_RISK_INFORMED = 2,
    NIST_TIER_3_REPEATABLE    = 3,
    NIST_TIER_4_ADAPTIVE      = 4
} NIST_CSF_Tier;

typedef enum {
    NIST_80053_FAM_AC = 0,
    NIST_80053_FAM_AT = 1,
    NIST_80053_FAM_AU = 2,
    NIST_80053_FAM_CA = 3,
    NIST_80053_FAM_CM = 4,
    NIST_80053_FAM_CP = 5,
    NIST_80053_FAM_IA = 6,
    NIST_80053_FAM_IR = 7,
    NIST_80053_FAM_MA = 8,
    NIST_80053_FAM_MP = 9,
    NIST_80053_FAM_PE = 10,
    NIST_80053_FAM_PL = 11,
    NIST_80053_FAM_PS = 12,
    NIST_80053_FAM_RA = 13,
    NIST_80053_FAM_SA = 14,
    NIST_80053_FAM_SC = 15,
    NIST_80053_FAM_SI = 16,
    NIST_80053_FAM_SR = 17
} NIST_80053_Family;

typedef struct {
    NIST_CSF_Function function;
    const char *name;
    const char *category_id;
    const char *description;
} NIST_CSF_Category;

typedef struct {
    NIST_CSF_Function function;
    const char *subcategory_id;
    const char *description;
    int         nist_refs[8];
    int         nist_ref_count;
} NIST_CSF_Subcategory;

typedef struct {
    const char      *control_id;
    NIST_80053_Family family;
    const char      *title;
    const char      *description;
    int              priority;
} NIST_80053_Control;

typedef struct {
    int             item_id;
    const char     *subcategory_id;
    NIST_CSF_Tier   current_tier;
    NIST_CSF_Tier   target_tier;
    int             gap;
    const char     *remediation;
    int             priority;
} NIST_CSF_ProfileItem;

/* ── Supply Chain Risk Management (NIST SP 800-161) ── L8 */
typedef enum {
    NIST_SCRM_TIER1_DIRECT     = 0,
    NIST_SCRM_TIER2_INDIRECT   = 1,
    NIST_SCRM_TIER3_SUBCONTRACT = 2,
    NIST_SCRM_TIER4_MATERIAL   = 3
} NIST_SCRM_Tier;

typedef struct {
    int supplier_id;
    const char *name;
    NIST_SCRM_Tier tier;
    int is_critical;
    double assessed_risk;
    int last_assessment_year;
    int has_bcp;
    int has_incident_response;
} NIST_SCRM_Supplier;

typedef struct {
    NIST_CSF_Category    categories[NIST_CSF_MAX_CATEGORIES];
    int                  category_count;
    NIST_CSF_Subcategory subcategories[NIST_CSF_MAX_SUBCATEGORIES];
    int                  subcategory_count;
    NIST_80053_Control   controls[NIST_CSF_MAX_CONTROLS];
    int                  control_count;
    NIST_CSF_Tier        org_tier;
    NIST_CSF_ProfileItem profile[NIST_CSF_MAX_PROFILE_ITEMS];
    int                  profile_count;
    NIST_SCRM_Supplier   suppliers[64];
    int                  supplier_count;
} NIST_CSF_Framework;

/* ── Maturity Assessment ── L5: Quantitative maturity scoring per function */
typedef struct {
    NIST_CSF_Function function;
    double policy_score;      /* 0-100 */
    double process_score;     /* 0-100 */
    double technology_score;  /* 0-100 */
    double people_score;      /* 0-100 */
    double overall_score;     /* weighted average */
} NIST_CSF_FunctionMaturity;

typedef struct {
    NIST_CSF_FunctionMaturity functions[NIST_CSF_MAX_FUNCTIONS];
    int function_count;
    NIST_CSF_Tier assessed_tier;
    double composite_score;   /* 0-100 overall maturity */
} NIST_CSF_MaturityAssessment;

/* ── Profile Comparison ── L5: Target vs Current profile diff */
typedef struct {
    const char *subcategory_id;
    NIST_CSF_Tier current;
    NIST_CSF_Tier target;
    int gap_levels;
    double implementation_pct;
    const char *recommendation;
} NIST_CSF_ProfileGap;

int  nist_csf_init(NIST_CSF_Framework *fw);
void nist_csf_load_core(NIST_CSF_Framework *fw);
int  nist_csf_set_org_tier(NIST_CSF_Framework *fw, NIST_CSF_Tier tier);
int  nist_csf_add_profile_item(NIST_CSF_Framework *fw, const char *subcat_id,
                                NIST_CSF_Tier current, NIST_CSF_Tier target,
                                const char *remediation, int priority);
int  nist_csf_gap_analysis(const NIST_CSF_Framework *fw,
                            NIST_CSF_ProfileItem *gaps, int max_gaps);
void nist_csf_gap_report(const NIST_CSF_ProfileItem *gaps, int gap_count);
int  nist_csf_add_80053_control(NIST_CSF_Framework *fw, const char *id,
                                 NIST_80053_Family family, const char *title,
                                 const char *desc, int priority);
const char* nist_csf_function_name(NIST_CSF_Function f);
const char* nist_csf_tier_name(NIST_CSF_Tier t);
const char* nist_80053_family_name(NIST_80053_Family fam);
int  nist_fisma_assessment(const NIST_CSF_Framework *fw);

/* ── Maturity Assessment ── L5: Function-level maturity scoring */
int  nist_csf_assess_maturity(const NIST_CSF_Framework *fw,
                               NIST_CSF_MaturityAssessment *ma);
void nist_csf_maturity_report(const NIST_CSF_MaturityAssessment *ma);
int  nist_csf_function_score(const NIST_CSF_Framework *fw,
                              NIST_CSF_Function func, double *score);

/* ── Profile Comparison ── L5: Gap closure planning */
int  nist_csf_profile_diff(const NIST_CSF_Framework *fw,
                            NIST_CSF_ProfileGap *gaps, int max_gaps);
void nist_csf_profile_diff_report(const NIST_CSF_ProfileGap *gaps,
                                   int gap_count);
int  nist_csf_implementation_pct(const NIST_CSF_Framework *fw,
                                  NIST_CSF_Function func);

/* ── Supply Chain Risk (NIST SP 800-161) ── L8: SCRM integration */
int  nist_scrm_add_supplier(NIST_CSF_Framework *fw, const char *name,
                             NIST_SCRM_Tier tier, int is_critical,
                             double assessed_risk, int year,
                             int has_bcp, int has_ir);
void nist_scrm_risk_heatmap(const NIST_CSF_Framework *fw);
int  nist_scrm_critical_suppliers(const NIST_CSF_Framework *fw,
                                   int *supplier_ids, int max_count);
double nist_scrm_aggregate_risk(const NIST_CSF_Framework *fw);

#endif
