#include "soc2_audit.h"
#include <stdio.h>
#include <string.h>
#include <math.h>

int soc2_init_engagement(SOC2_Engagement *eng) {
    if (!eng) return -1;
    memset(eng, 0, sizeof(*eng));
    return 0;
}

int soc2_add_control(SOC2_Engagement *eng, SOC2_TrustCriteria cat,
                      const char *name, const char *desc,
                      const char *test_proc) {
    if (!eng || eng->activity_count >= SOC2_MAX_CONTROLS) return -1;
    SOC2_ControlActivity *a = &eng->activities[eng->activity_count];
    a->control_id     = eng->activity_count + 1;
    a->category       = cat;
    a->name           = name;
    a->description    = desc;
    a->test_procedure = test_proc;
    a->state          = SOC2_CTRL_DESIGNED;
    a->evaluation     = SOC2_EVAL_DESIGNED_CORRECTLY;
    eng->activity_count++;
    return a->control_id;
}

int soc2_collect_evidence(SOC2_Engagement *eng, int control_ref,
                           SOC2_TrustCriteria cat, const char *desc,
                           const char *source, const char *method,
                           int year, int month) {
    if (!eng || eng->evidence_count >= SOC2_MAX_EVIDENCE) return -1;
    SOC2_Evidence *e = &eng->evidence[eng->evidence_count];
    e->evidence_id       = eng->evidence_count + 1;
    e->control_ref       = control_ref;
    e->category          = cat;
    e->description       = desc;
    e->source            = source;
    e->collection_method = method;
    e->collected_year    = year;
    e->collected_month   = month;
    e->approved          = 0;
    eng->evidence_count++;
    return e->evidence_id;
}

int soc2_evaluate_control(SOC2_Engagement *eng, int control_id,
                           SOC2_EvaluationResult result) {
    if (!eng || control_id < 1 || control_id > eng->activity_count) return -1;
    SOC2_ControlActivity *a = &eng->activities[control_id - 1];
    a->evaluation = result;
    if (result <= SOC2_EVAL_OPERATING_EFFECTIVE) {
        a->state = SOC2_CTRL_TESTED;
    } else {
        a->state = SOC2_CTRL_REMEDIATED;
    }
    return 0;
}

int soc2_generate_report(SOC2_Engagement *eng, SOC2_AuditReport *report,
                          SOC2_ReportType type, int year,
                          SOC2_TrustCriteria scope,
                          const char *auditor, const char *org) {
    if (!eng || !report) return -1;
    memset(report, 0, sizeof(*report));
    report->report_type   = type;
    report->report_year   = year;
    report->report_period_months = (type == SOC2_REPORT_TYPE_II) ? 12 : 0;
    report->scope         = scope;
    report->auditor_name  = auditor;
    report->service_org_name = org;
    report->control_count = eng->activity_count;
    memcpy(report->controls, eng->activities,
           (size_t)eng->activity_count * sizeof(SOC2_ControlActivity));
    report->evidence_count = eng->evidence_count;
    memcpy(report->evidence, eng->evidence,
           (size_t)eng->evidence_count * sizeof(SOC2_Evidence));

    int deficiencies = 0, material = 0;
    for (int i = 0; i < eng->activity_count; i++) {
        if (eng->activities[i].evaluation == SOC2_EVAL_DEFICIENCY ||
            eng->activities[i].evaluation == SOC2_EVAL_SIGNIFICANT_DEFICIENCY) {
            deficiencies++;
        } else if (eng->activities[i].evaluation == SOC2_EVAL_MATERIAL_WEAKNESS) {
            material++;
        }
    }
    report->findings            = deficiencies + material;
    report->deficiencies        = deficiencies;
    report->material_weaknesses = material;

    if (material > 0) {
        report->opinion = "Adverse opinion - material weaknesses identified";
    } else if (deficiencies > 0) {
        report->opinion = "Qualified opinion - deficiencies noted";
    } else {
        report->opinion = "Unqualified opinion - controls suitably designed and operating effectively";
    }
    return 0;
}

void soc2_summary(const SOC2_AuditReport *report) {
    if (!report) return;
    printf("=== SOC 2 Audit Report Summary ===\n");
    printf("Type:        Type %s\n",
           report->report_type == SOC2_REPORT_TYPE_I ? "I" : "II");
    printf("Year:        %d [%d months]\n", report->report_year, report->report_period_months);
    printf("Scope:       Security=%d Availability=%d Confidentiality=%d Integrity=%d Privacy=%d\n",
           !!(report->scope & SOC2_TC_SECURITY),
           !!(report->scope & SOC2_TC_AVAILABILITY),
           !!(report->scope & SOC2_TC_CONFIDENTIAL),
           !!(report->scope & SOC2_TC_INTEGRITY),
           !!(report->scope & SOC2_TC_PRIVACY));
    printf("Auditor:     %s\n", report->auditor_name);
    printf("Organization: %s\n", report->service_org_name);
    printf("Controls:    %d tested\n", report->control_count);
    printf("Evidence:    %d items collected\n", report->evidence_count);
    printf("Findings:    %d (deficiencies=%d, material=%d)\n",
           report->findings, report->deficiencies, report->material_weaknesses);
    printf("Opinion:     %s\n", report->opinion);
}

int soc2_deficiency_tally(const SOC2_AuditReport *report) {
    if (!report) return -1;
    return report->deficiencies + report->material_weaknesses;
}

const char* soc2_trust_criteria_name(SOC2_TrustCriteria tc) {
    switch (tc) {
        case SOC2_TC_SECURITY:     return "Security";
        case SOC2_TC_AVAILABILITY: return "Availability";
        case SOC2_TC_CONFIDENTIAL: return "Confidentiality";
        case SOC2_TC_INTEGRITY:    return "Processing Integrity";
        case SOC2_TC_PRIVACY:      return "Privacy";
        default:                   return "Unknown";
    }
}

const char* soc2_eval_result_name(SOC2_EvaluationResult r) {
    switch (r) {
        case SOC2_EVAL_DESIGNED_CORRECTLY:   return "Designed Correctly";
        case SOC2_EVAL_OPERATING_EFFECTIVE:  return "Operating Effectively";
        case SOC2_EVAL_DEFICIENCY:           return "Deficiency";
        case SOC2_EVAL_SIGNIFICANT_DEFICIENCY: return "Significant Deficiency";
        case SOC2_EVAL_MATERIAL_WEAKNESS:    return "Material Weakness";
        default:                             return "Unknown";
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * Statistical Audit Sampling
 * L5: AICPA Audit Sampling methodology — uses binomial distribution
 *     to determine sample size for control testing.
 * Formula: n = N * z² * p(1-p) / ((N-1) * e² + z² * p(1-p))
 * Where N=population, z=confidence coefficient, p=expected error,
 *       e=tolerable error (precision).
 * Ref: AICPA Audit Guide: Audit Sampling (2017).
 * ═══════════════════════════════════════════════════════════════════ */

static double z_score_for_confidence(double confidence) {
    /* Approximate z-scores for common confidence levels */
    if (confidence >= 0.99) return 2.576;
    if (confidence >= 0.95) return 1.960;
    if (confidence >= 0.90) return 1.645;
    if (confidence >= 0.85) return 1.440;
    return 1.960; /* default 95% */
}

int soc2_calculate_sample_size(int population, double confidence,
                                double tolerable_error, double expected_error,
                                SOC2_AuditSample *sample) {
    if (!sample || population < 1 || confidence <= 0.0 || confidence >= 1.0
        || tolerable_error <= 0.0 || tolerable_error >= 1.0
        || expected_error < 0.0 || expected_error > tolerable_error)
        return -1;

    double z = z_score_for_confidence(confidence);
    double p = expected_error;
    double e = tolerable_error;

    /* Cochran formula for finite population */
    double numerator   = (double)population * z * z * p * (1.0 - p);
    double denominator = ((double)(population - 1) * e * e) + (z * z * p * (1.0 - p));
    double n = numerator / denominator;

    /* Round up, with minimum sample of 1 */
    int n_int = (int)ceil(n);
    if (n_int < 1) n_int = 1;
    if (n_int > population) n_int = population;

    sample->population_size     = population;
    sample->sample_size         = n_int;
    sample->confidence_level    = confidence;
    sample->tolerable_error_rate = tolerable_error;
    sample->expected_error_rate  = expected_error;
    sample->errors_found        = 0;
    sample->upper_error_limit   = (double)n_int * expected_error;
    sample->is_acceptable       = 1;

    return n_int;
}

void soc2_sample_report(const SOC2_AuditSample *sample) {
    if (!sample) return;
    printf("=== AICPA Audit Sampling Plan ===\n");
    printf("Population:          %d\n", sample->population_size);
    printf("Confidence Level:    %.0f%%\n", sample->confidence_level * 100.0);
    printf("Tolerable Error:     %.1f%%\n",
           sample->tolerable_error_rate * 100.0);
    printf("Expected Error:      %.1f%%\n",
           sample->expected_error_rate * 100.0);
    printf("Required Sample:     %d\n", sample->sample_size);
    printf("Sampling Ratio:      %.1f%%\n",
           100.0 * (double)sample->sample_size /
           (double)sample->population_size);
    printf("Errors Found:        %d\n", sample->errors_found);
    printf("Upper Error Limit:   %.1f%%\n",
           sample->upper_error_limit * 100.0);
    printf("Conclusion:          %s\n",
           sample->is_acceptable ? "ACCEPTABLE (within tolerance)"
                                 : "UNACCEPTABLE (exceeds tolerance)");
}

int soc2_evaluate_sample(SOC2_AuditSample *sample, int errors_found) {
    if (!sample) return -1;
    sample->errors_found = errors_found;
    /* Upper error limit using binomial model:
     * UEL = (errors + z * sqrt(errors * (1 - errors/N))) / N */
    double error_rate = (double)errors_found / (double)sample->sample_size;
    double z = z_score_for_confidence(sample->confidence_level);
    double se = sqrt(error_rate * (1.0 - error_rate) /
                     (double)sample->sample_size);
    sample->upper_error_limit = error_rate + z * se;
    if (sample->upper_error_limit < 0.0) sample->upper_error_limit = 0.0;
    if (sample->upper_error_limit > 1.0) sample->upper_error_limit = 1.0;

    sample->is_acceptable = (sample->upper_error_limit <=
                              sample->tolerable_error_rate) ? 1 : 0;
    return sample->is_acceptable;
}

int soc2_attribute_sampling(const SOC2_Engagement *eng,
                              SOC2_TrustCriteria category,
                              SOC2_AuditSample *sample) {
    if (!eng || !sample) return -1;
    /* Count population size: activities matching category */
    int population = 0;
    for (int i = 0; i < eng->activity_count; i++) {
        if (eng->activities[i].category & category) population++;
    }
    if (population == 0) return -1;

    /* Default parameters: 95% confidence, 5% tolerable, 2% expected */
    int sample_size = soc2_calculate_sample_size(
        population, 0.95, 0.05, 0.02, sample);
    return sample_size;
}

/* ═══════════════════════════════════════════════════════════════════
 * SOC 2 Bridge Letter (Gap Letter)
 * L7: Between Type II report periods, service organizations issue
 *     bridge letters confirming no material changes to controls.
 * Ref: AICPA SOC 2 Guide, Section 3.5 Bridge Letters.
 * ═══════════════════════════════════════════════════════════════════ */

int soc2_generate_bridge_letter(const SOC2_AuditReport *prev_report,
                                 const SOC2_Engagement *current,
                                 int start_month, int end_month,
                                 int has_changes, const char *changes_desc,
                                 SOC2_BridgeLetter *letter) {
    if (!prev_report || !letter) return -1;
    memset(letter, 0, sizeof(*letter));
    letter->letter_id           = 1;
    letter->report_year         = prev_report->report_year;
    letter->bridge_start_month  = start_month;
    letter->bridge_end_month    = end_month;
    letter->service_org         = prev_report->service_org_name;
    letter->auditor             = prev_report->auditor_name;
    letter->has_material_changes = has_changes;
    letter->change_description  = changes_desc;
    letter->controls_reviewed   = current ? current->activity_count :
                                   prev_report->control_count;
    letter->controls_changed    = has_changes ? 1 : 0;
    letter->new_controls_added  = 0;

    if (has_changes && changes_desc) {
        letter->opinion =
            "Qualified assurance — material changes noted during bridge period";
    } else {
        letter->opinion =
            "No material changes to control environment during bridge period";
    }
    return 0;
}

void soc2_bridge_letter_display(const SOC2_BridgeLetter *letter) {
    if (!letter) return;
    printf("=== SOC 2 Bridge Letter ===\n");
    printf("Service Organization: %s\n", letter->service_org);
    printf("Auditor:              %s\n", letter->auditor);
    printf("Report Year:          %d\n", letter->report_year);
    printf("Bridge Period:        Month %d - Month %d\n",
           letter->bridge_start_month, letter->bridge_end_month);
    printf("Controls Reviewed:    %d\n", letter->controls_reviewed);
    printf("Controls Changed:     %d\n", letter->controls_changed);
    printf("Material Changes:     %s\n",
           letter->has_material_changes ? "YES" : "NO");
    if (letter->change_description) {
        printf("Changes:              %s\n", letter->change_description);
    }
    printf("Opinion:              %s\n", letter->opinion);
}

/* ═══════════════════════════════════════════════════════════════════
 * Trust Services Criteria Coverage Analysis
 * L2: Measures per-TSC coverage across control activities.
 * ═══════════════════════════════════════════════════════════════════ */

int soc2_tsc_coverage(const SOC2_AuditReport *report,
                       SOC2_TrustCriteria tc, double *coverage_pct) {
    if (!report || !coverage_pct) return -1;
    int total = 0, covered = 0;
    for (int i = 0; i < report->control_count; i++) {
        if (report->controls[i].category & tc) {
            total++;
            if (report->controls[i].evaluation <= SOC2_EVAL_OPERATING_EFFECTIVE)
                covered++;
        }
    }
    if (total == 0) { *coverage_pct = 0.0; return 0; }
    *coverage_pct = 100.0 * (double)covered / (double)total;
    return 0;
}
