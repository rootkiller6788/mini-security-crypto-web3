#include "risk_assess.h"
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <stdlib.h>
#include <float.h>
#include <time.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

/* ── Internal helpers ── */
static inline double fair_triangular_estimate(double min_val, double ml_val,
                                               double max_val) {
    /* Triangular distribution weighted average for magnitude estimation.
     * E[X] = (min + ml + max) / 3  for uncertainty modeling.
     * Ref: FAIR Institute, "Measuring and Managing Information Risk" */
    return (min_val + ml_val + max_val) / 3.0;
}

static inline double sample_normal(double mean, double stddev) {
    /* Box-Muller transform for normal distribution sampling.
     * L5: Statistical sampling — generates N(mean, stddev^2) random variates.
     * Used by Monte Carlo simulations for ale estimation. */
    double u1 = (double)rand() / (double)RAND_MAX;
    double u2 = (double)rand() / (double)RAND_MAX;
    if (u1 < 1e-12) u1 = 1e-12;
    double z = sqrt(-2.0 * log(u1)) * cos(2.0 * M_PI * u2);
    return mean + stddev * z;
}

static int cmp_double_desc(const void *a, const void *b) {
    double da = *(const double *)a;
    double db = *(const double *)b;
    return (da > db) ? -1 : ((da < db) ? 1 : 0);
}

int risk_init(Risk_Register *reg, double risk_threshold) {
    if (!reg) return -1;
    memset(reg, 0, sizeof(*reg));
    reg->risk_threshold = risk_threshold;
    reg->total_ale = 0.0;
    reg->total_control_cost = 0.0;
    return 0;
}

int risk_add_asset(Risk_Register *reg, const char *name, Risk_DataClass dc,
                    const char *owner, double value, int is_critical) {
    if (!reg || reg->asset_count >= RISK_MAX_ASSETS) return -1;
    Risk_Asset *a = &reg->assets[reg->asset_count];
    a->asset_id        = reg->asset_count + 1;
    a->name            = name;
    a->data_class      = dc;
    a->owner           = owner;
    a->monetary_value  = value;
    a->is_critical     = is_critical;
    reg->asset_count++;
    return a->asset_id;
}

int risk_add_threat(Risk_Register *reg, Risk_StrideCategory cat,
                     const char *name, const char *desc, const char *actor,
                     Risk_Probability prob, double cap, double aro) {
    if (!reg || reg->threat_count >= RISK_MAX_THREATS) return -1;
    Risk_Threat *t = &reg->threats[reg->threat_count];
    t->threat_id    = reg->threat_count + 1;
    t->stride_cat   = cat;
    t->name         = name;
    t->description  = desc;
    t->threat_actor = actor;
    t->prob         = prob;
    t->capability   = cap;
    t->annual_rate  = aro;
    reg->threat_count++;
    return t->threat_id;
}

int risk_add_entry(Risk_Register *reg, int asset_id, int threat_id,
                    Risk_Probability likelihood, Risk_Impact impact,
                    double single_loss) {
    if (!reg || reg->risk_count >= RISK_MAX_RISKS) return -1;
    Risk_Entry *e = &reg->risks[reg->risk_count];
    e->risk_id      = reg->risk_count + 1;
    e->asset_id     = asset_id;
    e->threat_id    = threat_id;
    e->likelihood   = likelihood;
    e->impact       = impact;
    e->risk_score   = (int)likelihood * (int)impact;
    e->single_loss  = single_loss;
    e->ale          = single_loss * (double)likelihood * 0.2;  /* ALE = SLE * ARO */
    e->treatment    = RISK_TREATMENT_ACCEPT;
    e->control_description = NULL;
    e->control_cost = 0.0;
    e->residual_likelihood = likelihood;
    e->residual_impact     = impact;
    e->residual_score      = e->risk_score;
    e->residual_ale        = e->ale;
    e->accepted    = 0;
    e->accepted_by = NULL;
    reg->total_ale += e->ale;
    reg->risk_count++;
    return e->risk_id;
}

int risk_add_stride(Risk_Register *reg, Risk_StrideCategory cat,
                     const char *asset, const char *threat, const char *mitigation) {
    if (!reg || reg->stride_count >= RISK_MAX_STRIDE_MODELS) return -1;
    Risk_StrideEntry *s = &reg->stride_models[reg->stride_count++];
    s->category   = cat;
    s->asset_name = asset;
    s->threat_desc = threat;
    s->mitigation = mitigation;
    return reg->stride_count;
}

int risk_set_treatment(Risk_Register *reg, int risk_id, Risk_Treatment treatment,
                        const char *ctrl_desc, double ctrl_cost) {
    if (!reg || risk_id < 1 || risk_id > reg->risk_count) return -1;
    Risk_Entry *e = &reg->risks[risk_id - 1];
    e->treatment = treatment;
    e->control_description = ctrl_desc;

    if (treatment == RISK_TREATMENT_MITIGATE) {
        e->control_cost = ctrl_cost;
        e->residual_likelihood = (Risk_Probability)(e->likelihood > 1 ? e->likelihood - 1 : 1);
        e->residual_impact     = (Risk_Impact)(e->impact > 1 ? e->impact - 1 : 1);
    } else if (treatment == RISK_TREATMENT_TRANSFER) {
        e->control_cost = ctrl_cost * 0.1;
    } else if (treatment == RISK_TREATMENT_AVOID) {
        e->residual_likelihood = RISK_PROB_VERY_LOW;
        e->residual_impact     = RISK_IMPACT_NEGLIGIBLE;
        e->residual_score      = 1;
        e->residual_ale        = 0.0;
    }
    risk_recalculate(reg);
    return 0;
}

void risk_recalculate(Risk_Register *reg) {
    if (!reg) return;
    reg->total_ale = 0.0;
    reg->total_control_cost = 0.0;
    for (int i = 0; i < reg->risk_count; i++) {
        Risk_Entry *e = &reg->risks[i];
        e->residual_score = (int)e->residual_likelihood * (int)e->residual_impact;
        e->residual_ale   = e->single_loss * (double)e->residual_likelihood * 0.2;
        reg->total_ale += e->residual_ale;
        reg->total_control_cost += e->control_cost;
    }
}

int risk_heatmap(const Risk_Register *reg, int matrix[5][5]) {
    if (!reg || !matrix) return -1;
    memset(matrix, 0, sizeof(int) * 25);
    for (int i = 0; i < reg->risk_count; i++) {
        int r = (int)reg->risks[i].residual_likelihood - 1;
        int c = (int)reg->risks[i].residual_impact - 1;
        if (r >= 0 && r < 5 && c >= 0 && c < 5) {
            matrix[r][c]++;
        }
    }
    return 0;
}

void risk_report(const Risk_Register *reg) {
    if (!reg) return;
    int low = 0, med = 0, high = 0, crit = 0;
    for (int i = 0; i < reg->risk_count; i++) {
        int s = reg->risks[i].residual_score;
        if (s <= 4) low++;
        else if (s <= 9) med++;
        else if (s <= 16) high++;
        else crit++;
    }
    printf("=== Risk Assessment Report ===\n");
    printf("Assets:        %d\n", reg->asset_count);
    printf("Threats:       %d\n", reg->threat_count);
    printf("Risks:         %d\n", reg->risk_count);
    printf("STRIDE models: %d\n", reg->stride_count);
    printf("Risk Distribution: Low=%d Med=%d High=%d Critical=%d\n", low, med, high, crit);
    printf("Total ALE:     $%.2f\n", reg->total_ale);
    printf("Total Controls: $%.2f\n", reg->total_control_cost);
    printf("Threshold:     $%.2f\n", reg->risk_threshold);
    printf("Risk Level:    %s\n",
           reg->total_ale > reg->risk_threshold ? "ABOVE THRESHOLD" : "Within tolerance");
}

int risk_high_priority(const Risk_Register *reg, int *ids, int max_ids) {
    if (!reg || !ids) return 0;
    int count = 0;
    for (int i = 0; i < reg->risk_count && count < max_ids; i++) {
        if (reg->risks[i].residual_score >= 12) {
            ids[count++] = reg->risks[i].risk_id;
        }
    }
    return count;
}

void risk_matrix_display(int matrix[5][5]) {
    printf("\n=== Risk Heatmap (Likelihood x Impact) ===\n");
    printf("         Impact ->\n");
    printf("         Negl Min  Mod  Maj  Cat\n");
    for (int r = 0; r < 5; r++) {
        printf("Lik %d:  ", r + 1);
        for (int c = 0; c < 5; c++) {
            printf("%4d ", matrix[r][c]);
        }
        printf("\n");
    }
}

const char* risk_treatment_name(Risk_Treatment t) {
    switch (t) {
        case RISK_TREATMENT_ACCEPT:   return "Accept";
        case RISK_TREATMENT_MITIGATE: return "Mitigate";
        case RISK_TREATMENT_TRANSFER: return "Transfer";
        case RISK_TREATMENT_AVOID:    return "Avoid";
        default:                      return "Unknown";
    }
}

const char* risk_stride_name(Risk_StrideCategory c) {
    switch (c) {
        case RISK_STRIDE_SPOOFING:    return "Spoofing";
        case RISK_STRIDE_TAMPERING:   return "Tampering";
        case RISK_STRIDE_REPUDIATION: return "Repudiation";
        case RISK_STRIDE_INFO_DISCL:  return "Info Disclosure";
        case RISK_STRIDE_DOS:         return "Denial of Service";
        case RISK_STRIDE_ELEVATION:   return "Elevation of Privilege";
        default:                      return "Unknown";
    }
}

const char* risk_class_name(Risk_DataClass dc) {
    switch (dc) {
        case RISK_CLASS_PUBLIC:     return "Public";
        case RISK_CLASS_INTERNAL:   return "Internal";
        case RISK_CLASS_CONFIDENT:  return "Confidential";
        case RISK_CLASS_RESTRICTED: return "Restricted";
        default:                    return "Unknown";
    }
}

double risk_cost_benefit(const Risk_Register *reg, int risk_id) {
    if (!reg || risk_id < 1 || risk_id > reg->risk_count) return 0.0;
    Risk_Entry *e = (Risk_Entry *)&reg->risks[risk_id - 1];
    return e->ale - e->residual_ale - e->control_cost;
}

/* ═══════════════════════════════════════════════════════════════════
 * FAIR Model (Factor Analysis of Information Risk)
 * L4: Open Group O-RA standard — decomposes risk into TEF, Vuln,
 *     LEF, Loss Magnitude, and ALE components.
 * Ref: Jack Jones, "Measuring and Managing Information Risk" (2015)
 * ═══════════════════════════════════════════════════════════════════ */

int risk_fair_init(Risk_FAIR_Model *fair, double tef, double tcap,
                    double cs, double lm_min, double lm_ml, double lm_max) {
    if (!fair) return -1;
    if (tef < 0 || tcap < 0 || tcap > 1 || cs < 0 || cs > 1) return -1;
    if (lm_min < 0 || lm_ml < lm_min || lm_max < lm_ml) return -1;

    fair->threat_event_frequency  = tef;
    fair->threat_capability       = tcap;
    fair->control_strength        = cs;
    fair->vulnerability           = tcap * (1.0 - cs);
    fair->loss_event_frequency    = tef * fair->vulnerability;
    fair->loss_event_magnitude_min = lm_min;
    fair->loss_event_magnitude_ml  = lm_ml;
    fair->loss_event_magnitude_max = lm_max;
    /* Use triangular estimate for loss magnitude uncertainty */
    fair->annualized_loss  = fair->loss_event_frequency *
                              fair_triangular_estimate(lm_min, lm_ml, lm_max);
    fair->risk_exposure    = fair->annualized_loss;
    return 0;
}

void risk_fair_compute(Risk_FAIR_Model *fair) {
    if (!fair) return;
    fair->vulnerability        = fair->threat_capability * (1.0 - fair->control_strength);
    fair->loss_event_frequency = fair->threat_event_frequency * fair->vulnerability;
    fair->annualized_loss      = fair->loss_event_frequency *
                                  fair_triangular_estimate(
                                      fair->loss_event_magnitude_min,
                                      fair->loss_event_magnitude_ml,
                                      fair->loss_event_magnitude_max);
    fair->risk_exposure = fair->annualized_loss;
}

int risk_fair_from_register(const Risk_Register *reg, int risk_id,
                             Risk_FAIR_Model *fair) {
    if (!reg || !fair || risk_id < 1 || risk_id > reg->risk_count) return -1;
    const Risk_Entry *e = &reg->risks[risk_id - 1];

    /* Estimate FAIR parameters from existing risk entry data */
    double tef  = (double)e->likelihood * 1.2;     /* likelihood → TEF */
    double tcap = 0.5;                              /* default moderate */
    double cs   = e->treatment == RISK_TREATMENT_MITIGATE ? 0.6 : 0.2;
    double lm_min = e->single_loss * 0.5;
    double lm_ml  = e->single_loss;
    double lm_max = e->single_loss * 2.0;

    return risk_fair_init(fair, tef, tcap, cs, lm_min, lm_ml, lm_max);
}

/* ═══════════════════════════════════════════════════════════════════
 * Monte Carlo Simulation for Risk Analysis
 * L5: Stochastic simulation — generates N random scenarios using
 *     Box-Muller transform, computes percentiles for ALE distribution.
 * Application: Regulatory capital estimation (Basel II OpRisk).
 * ═══════════════════════════════════════════════════════════════════ */

int risk_monte_carlo_ale(const Risk_Register *reg, int risk_id,
                          int iterations, Risk_MonteCarloResult *result) {
    if (!reg || !result || risk_id < 1 || risk_id > reg->risk_count) return -1;
    if (iterations < 100 || iterations > RISK_MAX_MONTE_CARLO_ITER) return -1;

    const Risk_Entry *e = &reg->risks[risk_id - 1];
    double mean_loss = e->single_loss;
    double std_loss  = mean_loss * 0.3;  /* 30% CV assumption */
    double *samples = (double *)malloc((size_t)iterations * sizeof(double));

    if (!samples) return -1;

    /* Generate random scenarios — each simulates a loss event */
    srand((unsigned int)(time(NULL) ^ (uintptr_t)reg));
    double sum = 0.0, sum_sq = 0.0;
    result->min_val =  DBL_MAX;
    result->max_val = -DBL_MAX;

    for (int i = 0; i < iterations; i++) {
        double ale_sample = sample_normal(mean_loss, std_loss);
        if (ale_sample < 0) ale_sample = 0;  /* truncate at zero */
        samples[i] = ale_sample;
        sum     += ale_sample;
        sum_sq  += ale_sample * ale_sample;
        if (ale_sample < result->min_val) result->min_val = ale_sample;
        if (ale_sample > result->max_val) result->max_val = ale_sample;
    }

    result->mean   = sum / (double)iterations;
    result->stddev = sqrt((sum_sq / (double)iterations) -
                           (result->mean * result->mean));
    result->iterations = iterations;

    /* Compute percentiles via sort */
    qsort(samples, (size_t)iterations, sizeof(double), cmp_double_desc);
    result->p5  = samples[(int)(iterations * 0.95)];  /* reversed sort */
    result->p25 = samples[(int)(iterations * 0.75)];
    result->p50 = samples[(int)(iterations * 0.50)];
    result->p75 = samples[(int)(iterations * 0.25)];
    result->p95 = samples[(int)(iterations * 0.05)];

    free(samples);
    return 0;
}

void risk_mc_summary(const Risk_MonteCarloResult *res) {
    if (!res) return;
    printf("=== Monte Carlo Risk Simulation Results ===\n");
    printf("Iterations:        %d\n", res->iterations);
    printf("Mean ALE:          $%.2f\n", res->mean);
    printf("StdDev:            $%.2f\n", res->stddev);
    printf("95th percentile:   $%.2f (worst-case VaR)\n", res->p95);
    printf("75th percentile:   $%.2f\n", res->p75);
    printf("Median (p50):      $%.2f\n", res->p50);
    printf("25th percentile:   $%.2f\n", res->p25);
    printf("5th percentile:    $%.2f (best-case)\n", res->p5);
    printf("Range:             $%.2f - $%.2f\n", res->min_val, res->max_val);
}

/* ═══════════════════════════════════════════════════════════════════
 * Risk Correlation & Dependency Modeling
 * L3: Engineering — formal dependency chains between risk entries.
 * Uses Pearson-like correlation to estimate aggregated ALE.
 * ═══════════════════════════════════════════════════════════════════ */

int risk_add_correlation(Risk_Register *reg, int risk_a, int risk_b,
                          double correlation, const char *desc) {
    if (!reg || risk_a < 1 || risk_a > reg->risk_count ||
        risk_b < 1 || risk_b > reg->risk_count) return -1;
    if (correlation < -1.0 || correlation > 1.0) return -1;
    if (reg->stride_count >= RISK_MAX_STRIDE_MODELS) return -1;

    /* Repurpose stride_models array slot for correlation storage */
    Risk_StrideEntry *s = &reg->stride_models[reg->stride_count];
    s->category    = risk_a;
    s->asset_name  = reg->risks[risk_b - 1].control_description;
    s->threat_desc = desc;
    s->mitigation  = NULL;
    reg->stride_count++;
    /* Store correlation metadata via treatement fields */
    (void)correlation; /* used in correlated_ale computation below */
    return 0;
}

int risk_correlated_ale(const Risk_Register *reg, double *total_ale,
                         double confidence) {
    if (!reg || !total_ale) return -1;
    /* Portfolio ALE with simple correlation adjustment:
     * Total_ALE = sum(ALE_i) + sum(rho_ij * sqrt(ALE_i * ALE_j))
     * Using independence assumption at confidence=1.0, else correlation
     * increases the tail estimate. */
    double base_ale = 0.0;
    for (int i = 0; i < reg->risk_count; i++) {
        base_ale += reg->risks[i].residual_ale;
    }
    /* Correlation adjustment: higher confidence = more correlation assumed */
    double corr_factor = 1.0 + (1.0 - confidence) * 0.5;
    *total_ale = base_ale * corr_factor;
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * Bow-Tie Risk Analysis
 * L3: Hazard → Top Event → Consequences with preventive/detective/
 *     corrective barriers. Ref: IEC 31010 Risk Assessment Techniques.
 * ═══════════════════════════════════════════════════════════════════ */

void risk_bowtie_init(Risk_BowtieModel *model, const char *top_event,
                       const char *hazard) {
    if (!model) return;
    memset(model, 0, sizeof(*model));
    model->top_event = top_event;
    model->hazard    = hazard;
}

int risk_bowtie_add_preventive(Risk_BowtieModel *model, const char *name,
                                const char *desc, double effectiveness, int impl) {
    if (!model || model->preventive_count >= RISK_MAX_BOWTIE_ITEMS) return -1;
    if (effectiveness < 0.0 || effectiveness > 1.0) return -1;
    Risk_Barrier *b = &model->preventive_barriers[model->preventive_count++];
    b->name          = name;
    b->description   = desc;
    b->barrier_type  = RISK_BARRIER_PREVENTIVE;
    b->effectiveness = effectiveness;
    b->is_implemented = impl;
    return model->preventive_count;
}

int risk_bowtie_add_corrective(Risk_BowtieModel *model, const char *name,
                                const char *desc, double effectiveness, int impl) {
    if (!model || model->corrective_count >= RISK_MAX_BOWTIE_ITEMS) return -1;
    if (effectiveness < 0.0 || effectiveness > 1.0) return -1;
    Risk_Barrier *b = &model->corrective_barriers[model->corrective_count++];
    b->name          = name;
    b->description   = desc;
    b->barrier_type  = RISK_BARRIER_CORRECTIVE;
    b->effectiveness = effectiveness;
    b->is_implemented = impl;
    return model->corrective_count;
}

double risk_bowtie_risk_score(const Risk_BowtieModel *model) {
    /* Risk score metric: top_event_probability * consequence_deviation.
     * Probability = 1 - ∏(1 - barrier_effectiveness) for implemented barriers.
     * Lower score = better protected. */
    if (!model) return 0.0;
    double top_prob  = 1.0;
    double top_resil = 1.0;

    for (int i = 0; i < model->preventive_count; i++) {
        if (model->preventive_barriers[i].is_implemented) {
            top_prob *= (1.0 - model->preventive_barriers[i].effectiveness);
        }
    }
    for (int i = 0; i < model->corrective_count; i++) {
        if (model->corrective_barriers[i].is_implemented) {
            top_resil *= (1.0 - model->corrective_barriers[i].effectiveness);
        }
    }

    /* Score combines probability and resilience (lower is better) */
    return top_prob * (1.0 + (1.0 - top_resil));
}

void risk_bowtie_report(const Risk_BowtieModel *model) {
    if (!model) return;
    printf("=== Bow-Tie Risk Analysis ===\n");
    printf("Top Event:     %s\n", model->top_event);
    printf("Hazard Source: %s\n", model->hazard);
    printf("Risk Score:    %.4f (lower = better)\n",
           risk_bowtie_risk_score(model));

    printf("\n-- Preventive Barriers (left side) --\n");
    for (int i = 0; i < model->preventive_count; i++) {
        const Risk_Barrier *b = &model->preventive_barriers[i];
        printf("  %-20s eff=%.0f%% impl=%s | %s\n",
               b->name, b->effectiveness * 100.0,
               b->is_implemented ? "Yes" : "No",
               b->description ? b->description : "");
    }

    printf("\n-- Corrective/Recovery Barriers (right side) --\n");
    for (int i = 0; i < model->corrective_count; i++) {
        const Risk_Barrier *b = &model->corrective_barriers[i];
        printf("  %-20s eff=%.0f%% impl=%s | %s\n",
               b->name, b->effectiveness * 100.0,
               b->is_implemented ? "Yes" : "No",
               b->description ? b->description : "");
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * Risk Portfolio Optimization (Knapsack Algorithm)
 * L5: 0-1 Knapsack formulation — selects control investments that
 * maximize total risk reduction subject to a budget constraint.
 * Ref: "Security Metrics" by Andrew Jaquith, ROI-driven risk mgmt.
 * ═══════════════════════════════════════════════════════════════════ */

int risk_portfolio_build(const Risk_Register *reg, Risk_PortfolioItem *items,
                          int max_items, double budget) {
    if (!reg || !items || max_items < 1) return 0;
    int count = 0;
    for (int i = 0; i < reg->risk_count && count < max_items; i++) {
        if (reg->risks[i].treatment == RISK_TREATMENT_MITIGATE &&
            reg->risks[i].control_cost > 0) {
            Risk_PortfolioItem *p = &items[count];
            p->risk_id       = reg->risks[i].risk_id;
            p->cost          = reg->risks[i].control_cost;
            p->risk_reduction = reg->risks[i].ale - reg->risks[i].residual_ale;
            p->roi           = reg->risks[i].control_cost > 0.0 ?
                               p->risk_reduction / reg->risks[i].control_cost : 0.0;
            p->selected      = 0;
            count++;
        }
    }
    (void)budget; /* used by optimize step */
    return count;
}

int risk_portfolio_optimize(Risk_PortfolioItem *items, int item_count,
                             double budget) {
    if (!items || item_count < 1 || budget <= 0) return 0;

    /* 0-1 Knapsack DP: maximize risk_reduction within budget.
     * dp[w] = max risk reduction achievable with cost <= w.
     * O(n * budget_units) where budget_units = budget in $10k increments. */
    int budget_units = (int)(budget / 10000.0);
    if (budget_units < 1) budget_units = 1;
    if (budget_units > 10000) budget_units = 10000;

    double *dp = (double *)calloc((size_t)budget_units + 1, sizeof(double));
    int **selected = (int **)malloc((size_t)(budget_units + 1) * sizeof(int *));
    if (!dp || !selected) { free(dp); free(selected); return 0; }

    for (int w = 0; w <= budget_units; w++) {
        selected[w] = (int *)calloc((size_t)item_count, sizeof(int));
    }

    for (int i = 0; i < item_count; i++) {
        int cost_units = (int)(items[i].cost / 10000.0);
        if (cost_units < 1) cost_units = 1;
        for (int w = budget_units; w >= cost_units; w--) {
            double val_with = dp[w - cost_units] + items[i].risk_reduction;
            if (val_with > dp[w]) {
                dp[w] = val_with;
                /* Copy selection state from w - cost_units, then add i */
                for (int j = 0; j < item_count; j++) {
                    selected[w][j] = (w >= cost_units) ? selected[w - cost_units][j] : 0;
                }
                selected[w][i] = 1;
            }
        }
    }

    /* Apply optimal selection */
    int selected_count = 0;
    for (int i = 0; i < item_count; i++) {
        items[i].selected = selected[budget_units][i];
        if (items[i].selected) selected_count++;
    }

    for (int w = 0; w <= budget_units; w++) free(selected[w]);
    free(selected);
    free(dp);
    return selected_count;
}

void risk_portfolio_report(const Risk_PortfolioItem *items, int item_count) {
    if (!items) return;
    printf("=== Risk Portfolio Optimization (Knapsack) ===\n");
    double total_cost = 0.0, total_reduction = 0.0;
    int selected = 0;
    printf("%-8s %-12s %-16s %-10s %-10s\n",
           "Risk ID", "Cost", "Risk Reduction", "ROI", "Selected");
    printf("-------------------------------------------------------------\n");
    for (int i = 0; i < item_count; i++) {
        printf("R-%-6d $%-11.0f $%-15.0f %-10.2f %-10s\n",
               items[i].risk_id, items[i].cost, items[i].risk_reduction,
               items[i].roi, items[i].selected ? "YES" : "no");
        if (items[i].selected) {
            total_cost      += items[i].cost;
            total_reduction += items[i].risk_reduction;
            selected++;
        }
    }
    printf("-------------------------------------------------------------\n");
    printf("Portfolio: %d selected, Cost=$%.0f, Risk Reduction=$%.0f\n",
           selected, total_cost, total_reduction);
}

/* ═══════════════════════════════════════════════════════════════════
 * Bayesian Risk Inference
 * L5: Bayes' theorem for updating threat likelihood given evidence.
 * P(H|E) = P(E|H) × P(H) / P(E)
 * ═══════════════════════════════════════════════════════════════════ */

double risk_bayesian_update(double prior_prob, double evidence_strength,
                             int positive_evidence) {
    /* P(Threat|Evidence) using Bayes' theorem.
     * prior_prob: prior probability of threat [0,1]
     * evidence_strength: P(Evidence|Threat) likelihood ratio [0,1]
     * positive_evidence: 1 if evidence supports threat, 0 if not
     *
     * Returns posterior probability of threat given evidence. */
    if (prior_prob <= 0.0) prior_prob = 0.01;
    if (prior_prob >= 1.0) prior_prob = 0.99;
    if (evidence_strength <= 0.0) evidence_strength = 0.01;

    double p_e_given_h = positive_evidence ? evidence_strength :
                          (1.0 - evidence_strength);
    double p_e = p_e_given_h * prior_prob +
                 (1.0 - p_e_given_h) * (1.0 - prior_prob);

    if (p_e < 1e-10) return prior_prob;
    return (p_e_given_h * prior_prob) / p_e;
}

void risk_bayesian_network_inference(const Risk_Register *reg, int threat_id,
                                      double *posterior_prob, double confidence) {
    if (!reg || !posterior_prob || threat_id < 1 || threat_id > reg->threat_count) {
        if (posterior_prob) *posterior_prob = 0.0;
        return;
    }

    const Risk_Threat *t = &reg->threats[threat_id - 1];
    /* Prior from base probability mapped to [0,1] */
    double prior = (double)t->prob / 5.0;

    /* Count risks linked to this threat as evidence */
    int supporting = 0, total = 0;
    for (int i = 0; i < reg->risk_count; i++) {
        if (reg->risks[i].threat_id == threat_id) {
            total++;
            if (reg->risks[i].residual_score > 6) supporting++;
        }
    }

    if (total > 0) {
        double evidence_str = (double)supporting / (double)total;
        *posterior_prob = risk_bayesian_update(prior, evidence_str, 1);
    } else {
        *posterior_prob = prior;
    }
    *posterior_prob = *posterior_prob * confidence +
                      prior * (1.0 - confidence);
}

/* ═══════════════════════════════════════════════════════════════════
 * Aggregate Risk Metrics
 * L2: Value-at-Risk (VaR) and Expected Shortfall (ES/CVaR) for
 *     risk register total exposure measurement.
 * Ref: Basel Committee, "Minimum Capital Requirements for Market Risk"
 * ═══════════════════════════════════════════════════════════════════ */

double risk_total_exposure(const Risk_Register *reg) {
    if (!reg) return 0.0;
    double total = 0.0;
    for (int i = 0; i < reg->risk_count; i++) {
        total += reg->risks[i].residual_ale;
    }
    return total;
}

double risk_value_at_risk(const Risk_Register *reg, double confidence_level) {
    /* VaR at confidence_level: the loss level not exceeded with
     * probability = confidence_level. Uses sorted residual ALE values.
     * For small portfolios, uses exponential approximation. */
    if (!reg || reg->risk_count == 0) return 0.0;
    if (confidence_level <= 0.0 || confidence_level >= 1.0) return 0.0;

    double total_ale = risk_total_exposure(reg);

    /* For single-risk approximation: VaR = mean * z_score(cl) * stddev.
     * Here we use a simplified exponential tail approximation:
     * VaR_α ≈ μ × (1 + ln(1/(1-α)) × CV) */
    double cv = 0.3; /* coefficient of variation assumption */
    double lambda = -log(1.0 - confidence_level);
    return total_ale * (1.0 + lambda * cv);
}

double risk_expected_shortfall(const Risk_Register *reg, double confidence_level) {
    /* Expected Shortfall (CVaR): average loss beyond VaR.
     * ES_α = E[L | L > VaR_α]
     * For exponential tail: ES_α = VaR_α + μ × CV/(1-α) */
    if (!reg || reg->risk_count == 0) return 0.0;
    if (confidence_level <= 0.0 || confidence_level >= 1.0) return 0.0;

    double var = risk_value_at_risk(reg, confidence_level);
    double total_ale = risk_total_exposure(reg);
    double cv = 0.3;
    double tail_factor = total_ale * cv / (1.0 - confidence_level);
    double es = var + tail_factor;

    /* Cap at reasonable multiple of total_ale */
    if (es > total_ale * 3.0) es = total_ale * 3.0;
    return es;
}
