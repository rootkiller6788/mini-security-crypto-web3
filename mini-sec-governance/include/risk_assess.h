#ifndef RISK_ASSESS_H
#define RISK_ASSESS_H

#include <stddef.h>
#include <stdint.h>

#define RISK_MAX_ASSETS       128
#define RISK_MAX_THREATS      64
#define RISK_MAX_RISKS        256
#define RISK_MAX_STRIDE_MODELS 16
#define RISK_MAX_TREATMENTS   256

typedef enum {
    RISK_CLASS_PUBLIC    = 0,
    RISK_CLASS_INTERNAL  = 1,
    RISK_CLASS_CONFIDENT = 2,
    RISK_CLASS_RESTRICTED = 3
} Risk_DataClass;

typedef enum {
    RISK_PROB_VERY_LOW   = 1,
    RISK_PROB_LOW        = 2,
    RISK_PROB_MODERATE   = 3,
    RISK_PROB_HIGH       = 4,
    RISK_PROB_VERY_HIGH  = 5
} Risk_Probability;

typedef enum {
    RISK_IMPACT_NEGLIGIBLE = 1,
    RISK_IMPACT_MINOR      = 2,
    RISK_IMPACT_MODERATE   = 3,
    RISK_IMPACT_MAJOR      = 4,
    RISK_IMPACT_CATASTROPHIC = 5
} Risk_Impact;

typedef enum {
    RISK_TREATMENT_ACCEPT  = 0,
    RISK_TREATMENT_MITIGATE = 1,
    RISK_TREATMENT_TRANSFER = 2,
    RISK_TREATMENT_AVOID   = 3
} Risk_Treatment;

typedef enum {
    RISK_STRIDE_SPOOFING    = 0,
    RISK_STRIDE_TAMPERING   = 1,
    RISK_STRIDE_REPUDIATION = 2,
    RISK_STRIDE_INFO_DISCL  = 3,
    RISK_STRIDE_DOS         = 4,
    RISK_STRIDE_ELEVATION   = 5
} Risk_StrideCategory;

typedef struct {
    int             asset_id;
    const char     *name;
    Risk_DataClass  data_class;
    const char     *owner;
    double          monetary_value;
    int             is_critical;
} Risk_Asset;

typedef struct {
    int             threat_id;
    Risk_StrideCategory stride_cat;
    const char     *name;
    const char     *description;
    const char     *threat_actor;
    Risk_Probability prob;
    double          capability;
    double          annual_rate;  /* ARO - Annualized Rate of Occurrence */
} Risk_Threat;

typedef struct {
    int             risk_id;
    int             asset_id;
    int             threat_id;
    Risk_Probability likelihood;
    Risk_Impact     impact;
    int             risk_score;        /* likelihood * impact */
    double          ale;               /* Annualized Loss Expectancy = SLE * ARO */
    double          single_loss;       /* SLE - Single Loss Expectancy */
    Risk_Treatment  treatment;
    const char     *control_description;
    double          control_cost;
    Risk_Probability residual_likelihood;
    Risk_Impact     residual_impact;
    int             residual_score;
    double          residual_ale;
    int             accepted;
    const char     *accepted_by;
} Risk_Entry;

typedef struct {
    Risk_StrideCategory category;
    const char     *asset_name;
    const char     *threat_desc;
    const char     *mitigation;
} Risk_StrideEntry;

typedef struct {
    Risk_Asset      assets[RISK_MAX_ASSETS];
    int             asset_count;
    Risk_Threat     threats[RISK_MAX_THREATS];
    int             threat_count;
    Risk_Entry      risks[RISK_MAX_RISKS];
    int             risk_count;
    Risk_StrideEntry stride_models[RISK_MAX_STRIDE_MODELS];
    int             stride_count;
    double          risk_threshold;
    double          total_ale;
    double          total_control_cost;
} Risk_Register;

int  risk_init(Risk_Register *reg, double risk_threshold);
int  risk_add_asset(Risk_Register *reg, const char *name, Risk_DataClass dc,
                     const char *owner, double value, int is_critical);
int  risk_add_threat(Risk_Register *reg, Risk_StrideCategory cat,
                      const char *name, const char *desc, const char *actor,
                      Risk_Probability prob, double cap, double aro);
int  risk_add_entry(Risk_Register *reg, int asset_id, int threat_id,
                     Risk_Probability likelihood, Risk_Impact impact,
                     double single_loss);
int  risk_add_stride(Risk_Register *reg, Risk_StrideCategory cat,
                      const char *asset, const char *threat, const char *mitigation);
int  risk_set_treatment(Risk_Register *reg, int risk_id, Risk_Treatment treatment,
                         const char *ctrl_desc, double ctrl_cost);
void risk_recalculate(Risk_Register *reg);
int  risk_heatmap(const Risk_Register *reg, int matrix[5][5]);
void risk_report(const Risk_Register *reg);
int  risk_high_priority(const Risk_Register *reg, int *ids, int max_ids);
void risk_matrix_display(const int matrix[5][5]);
const char* risk_treatment_name(Risk_Treatment t);
const char* risk_stride_name(Risk_StrideCategory c);
const char* risk_class_name(Risk_DataClass dc);
double risk_cost_benefit(const Risk_Register *reg, int risk_id);

#endif
