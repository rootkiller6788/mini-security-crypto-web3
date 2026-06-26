#ifndef RISK_ASSESS_H
#define RISK_ASSESS_H

#include <stddef.h>
#include <stdint.h>

#define RISK_MAX_ASSETS       128
#define RISK_MAX_THREATS      64
#define RISK_MAX_RISKS        256
#define RISK_MAX_STRIDE_MODELS 16
#define RISK_MAX_TREATMENTS   256
#define RISK_MAX_MONTE_CARLO_ITER 100000
#define RISK_MAX_CORRELATIONS 64
#define RISK_MAX_BOWTIE_ITEMS 32
#define RISK_MAX_PORTFOLIO_ITEMS 64

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

/* ── FAIR Model (Factor Analysis of Information Risk) ── */
/* L4: FAIR is the standard quantitative risk model (Open Group O-RA) */
typedef enum {
    RISK_THREAT_EVENT_FREQ = 0,
    RISK_VULNERABILITY_PROB = 1,
    RISK_LOSS_EVENT_FREQ = 2,
    RISK_LOSS_MAGNITUDE = 3,
    RISK_ANNUALIZED_LOSS = 4
} Risk_FAIR_Factor;

typedef struct {
    double threat_event_frequency;    /* TEF: events per year */
    double threat_capability;         /* TCAP: 0-1 scale */
    double control_strength;          /* CS: 0-1 scale, 1=perfect */
    double vulnerability;             /* Vuln = TCAP * (1 - CS) */
    double loss_event_frequency;      /* LEF = TEF * Vuln */
    double loss_event_magnitude_min;  /* minimum loss per event */
    double loss_event_magnitude_ml;   /* most likely loss per event */
    double loss_event_magnitude_max;  /* maximum loss per event */
    double annualized_loss;           /* ALE from FAIR = LEF * LM */
    double risk_exposure;
} Risk_FAIR_Model;

/* ── Monte Carlo Simulation ── */
typedef struct {
    double mean;
    double stddev;
    double p5;     /* 5th percentile */
    double p25;    /* 25th percentile */
    double p50;    /* median */
    double p75;    /* 75th percentile */
    double p95;    /* 95th percentile */
    double max_val;
    double min_val;
    int    iterations;
} Risk_MonteCarloResult;

/* ── Risk Correlation (formal dependency modeling) ── */
typedef struct {
    int     risk_id_a;
    int     risk_id_b;
    double  correlation;     /* -1.0 to 1.0 Pearson correlation */
    const char *dependency_desc;
} Risk_Correlation;

/* ── Bow-Tie Risk Analysis ── */
typedef enum {
    RISK_BARRIER_PREVENTIVE = 0,
    RISK_BARRIER_DETECTIVE  = 1,
    RISK_BARRIER_CORRECTIVE = 2
} Risk_BarrierType;

typedef struct {
    const char *name;
    const char *description;
    Risk_BarrierType barrier_type;
    double effectiveness;    /* 0-1 probability of successful prevention */
    int is_implemented;
} Risk_Barrier;

typedef struct {
    const char *top_event;
    const char *hazard;
    int threat_count;
    Risk_Barrier preventive_barriers[RISK_MAX_BOWTIE_ITEMS];
    int preventive_count;
    int consequence_count;
    Risk_Barrier corrective_barriers[RISK_MAX_BOWTIE_ITEMS];
    int corrective_count;
} Risk_BowtieModel;

/* ── Risk Portfolio Optimization (Knapsack-based) ── */
typedef struct {
    int    risk_id;
    double cost;           /* control cost */
    double risk_reduction; /* ALE reduction achieved */
    double roi;            /* risk_reduction / cost */
    int    selected;       /* 1 if part of optimal portfolio */
} Risk_PortfolioItem;

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
void risk_matrix_display(int matrix[5][5]);
const char* risk_treatment_name(Risk_Treatment t);
const char* risk_stride_name(Risk_StrideCategory c);
const char* risk_class_name(Risk_DataClass dc);
double risk_cost_benefit(const Risk_Register *reg, int risk_id);

/* ── FAIR Model ── L4: Factor Analysis of Information Risk (Open Group O-RA) */
int  risk_fair_init(Risk_FAIR_Model *fair, double tef, double tcap,
                     double cs, double lm_min, double lm_ml, double lm_max);
void risk_fair_compute(Risk_FAIR_Model *fair);
int  risk_fair_from_register(const Risk_Register *reg, int risk_id,
                              Risk_FAIR_Model *fair);

/* ── Monte Carlo Simulation ── L5: Stochastic risk modeling */
int  risk_monte_carlo_ale(const Risk_Register *reg, int risk_id,
                           int iterations, Risk_MonteCarloResult *result);
void risk_mc_summary(const Risk_MonteCarloResult *res);

/* ── Risk Correlation ── L3: Dependency modeling */
int  risk_add_correlation(Risk_Register *reg, int risk_a, int risk_b,
                           double correlation, const char *desc);
int  risk_correlated_ale(const Risk_Register *reg, double *total_ale,
                          double confidence);

/* ── Bow-Tie Analysis ── L3: Hazard-barrier-consequence chain */
void risk_bowtie_init(Risk_BowtieModel *model, const char *top_event,
                       const char *hazard);
int  risk_bowtie_add_preventive(Risk_BowtieModel *model, const char *name,
                                 const char *desc, double effectiveness, int impl);
int  risk_bowtie_add_corrective(Risk_BowtieModel *model, const char *name,
                                 const char *desc, double effectiveness, int impl);
double risk_bowtie_risk_score(const Risk_BowtieModel *model);
void risk_bowtie_report(const Risk_BowtieModel *model);

/* ── Portfolio Optimization ── L5: Cost-benefit knapsack for risk controls */
int  risk_portfolio_build(const Risk_Register *reg, Risk_PortfolioItem *items,
                           int max_items, double budget);
int  risk_portfolio_optimize(Risk_PortfolioItem *items, int item_count,
                              double budget);
void risk_portfolio_report(const Risk_PortfolioItem *items, int item_count);

/* ── Bayesian Risk Inference ── L5: Bayesian updating for threat likelihood */
double risk_bayesian_update(double prior_prob, double evidence_strength,
                             int positive_evidence);
void risk_bayesian_network_inference(const Risk_Register *reg, int threat_id,
                                      double *posterior_prob, double confidence);

/* ── Aggregate Risk Metrics ── L2: Total exposure computation */
double risk_total_exposure(const Risk_Register *reg);
double risk_value_at_risk(const Risk_Register *reg, double confidence_level);
double risk_expected_shortfall(const Risk_Register *reg, double confidence_level);

#endif
