#include "soc2_audit.h"
#include <stdio.h>
#include <string.h>

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
