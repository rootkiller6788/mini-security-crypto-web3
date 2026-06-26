#include "risk_assess.h"
#include <stdio.h>
#include <string.h>
#include <math.h>

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

void risk_matrix_display(const int matrix[5][5]) {
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
