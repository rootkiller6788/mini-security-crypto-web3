#include "iso27001_mgr.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int iso27001_init(ISO27001_ISMS *isms, int cert_year) {
    if (!isms) return -1;
    memset(isms, 0, sizeof(*isms));
    isms->cert_year = cert_year;
    isms->cert_stage = 0;
    isms->active = 1;
    iso27001_load_annex_a(isms);
    return 0;
}

void iso27001_load_annex_a(ISO27001_ISMS *isms) {
    static const struct { ISO27001_AnnexADomain d; int id; const char *name; } ctrls[] = {
        {ISO27001_DOMAIN_A5,  1, "Policies for information security"},
        {ISO27001_DOMAIN_A5,  2, "Review of the policies for information security"},
        {ISO27001_DOMAIN_A6,  3, "Information security roles and responsibilities"},
        {ISO27001_DOMAIN_A6,  4, "Segregation of duties"},
        {ISO27001_DOMAIN_A6,  5, "Contact with authorities"},
        {ISO27001_DOMAIN_A6,  6, "Contact with special interest groups"},
        {ISO27001_DOMAIN_A6,  7, "Information security in project management"},
        {ISO27001_DOMAIN_A7,  8, "Screening"},
        {ISO27001_DOMAIN_A7,  9, "Terms and conditions of employment"},
        {ISO27001_DOMAIN_A8, 10, "Inventory of assets"},
        {ISO27001_DOMAIN_A8, 11, "Ownership of assets"},
        {ISO27001_DOMAIN_A8, 12, "Acceptable use of assets"},
        {ISO27001_DOMAIN_A8, 13, "Return of assets"},
        {ISO27001_DOMAIN_A8, 14, "Classification of information"},
        {ISO27001_DOMAIN_A9, 15, "Access control policy"},
        {ISO27001_DOMAIN_A9, 16, "Access to networks and network services"},
        {ISO27001_DOMAIN_A9, 17, "User access provisioning"},
        {ISO27001_DOMAIN_A10,18, "Policy on the use of cryptographic controls"},
        {ISO27001_DOMAIN_A10,19, "Key management"},
        {ISO27001_DOMAIN_A11,20, "Physical security perimeter"},
        {ISO27001_DOMAIN_A11,21, "Physical entry controls"},
        {ISO27001_DOMAIN_A12,22, "Documented operating procedures"},
        {ISO27001_DOMAIN_A12,23, "Change management"},
        {ISO27001_DOMAIN_A12,24, "Capacity management"},
        {ISO27001_DOMAIN_A13,25, "Network controls"},
        {ISO27001_DOMAIN_A13,26, "Security of network services"},
        {ISO27001_DOMAIN_A14,27, "Info security requirements analysis and specification"},
        {ISO27001_DOMAIN_A14,28, "Securing application services on public networks"},
        {ISO27001_DOMAIN_A15,29, "Info security policy for supplier relationships"},
        {ISO27001_DOMAIN_A15,30, "Addressing security within supplier agreements"},
        {ISO27001_DOMAIN_A16,31, "Responsibilities and procedures"},
        {ISO27001_DOMAIN_A16,32, "Reporting information security events"},
        {ISO27001_DOMAIN_A17,33, "Planning information security continuity"},
        {ISO27001_DOMAIN_A17,34, "Implementing information security continuity"},
        {ISO27001_DOMAIN_A18,35, "Identification of applicable legislation"},
        {ISO27001_DOMAIN_A18,36, "Intellectual property rights"},
        {ISO27001_DOMAIN_A18,37, "Protection of records"},
        {ISO27001_DOMAIN_A18,38, "Privacy and protection of PII"},
        {ISO27001_DOMAIN_A18,39, "Regulation of cryptographic controls"},
        {ISO27001_DOMAIN_A5, 40, "Information security continual improvement"},
    };
    int n = (int)(sizeof(ctrls) / sizeof(ctrls[0]));
    for (int i = 0; i < n && isms->control_count < ISO27001_ANNEX_A_CONTROLS; i++) {
        ISO27001_Control *c = &isms->controls[isms->control_count++];
        c->control_id  = ctrls[i].id;
        c->domain      = ctrls[i].d;
        c->name        = ctrls[i].name;
        c->description = "";
        c->status      = ISO27001_STATUS_NOT_IMPL;
        c->evidence_ref = NULL;
        c->last_reviewed = 0;
    }
}

int iso27001_add_asset(ISO27001_ISMS *isms, const char *name, const char *owner,
                        const char *classification, double value, int is_critical) {
    if (!isms || isms->asset_count >= ISO27001_MAX_ASSETS) return -1;
    ISO27001_Asset *a = &isms->assets[isms->asset_count];
    a->asset_id = isms->asset_count + 1;
    a->name     = name;
    a->owner    = owner;
    strncpy(a->classification, classification, sizeof(a->classification) - 1);
    a->classification[sizeof(a->classification) - 1] = '\0';
    a->value       = value;
    a->is_critical = is_critical;
    isms->asset_count++;
    return a->asset_id;
}

int iso27001_add_threat(ISO27001_ISMS *isms, const char *name, const char *source,
                         double capability, double motivation) {
    if (!isms || isms->threat_count >= ISO27001_MAX_THREATS) return -1;
    ISO27001_Threat *t = &isms->threats[isms->threat_count];
    t->threat_id  = isms->threat_count + 1;
    t->name       = name;
    t->source     = source;
    t->capability = capability;
    t->motivation = motivation;
    isms->threat_count++;
    return t->threat_id;
}

int iso27001_add_vulnerability(ISO27001_ISMS *isms, ISO27001_Risk *risk,
                                const char *vuln_name, double severity) {
    (void)isms;
    (void)risk;
    (void)vuln_name;
    (void)severity;
    return 0;
}

int iso27001_add_risk(ISO27001_ISMS *isms, int asset_id, int threat_id,
                       double severity, int control_ref) {
    if (!isms || isms->risk_count >= ISO27001_MAX_RISKS) return -1;
    ISO27001_Risk *r = &isms->risks[isms->risk_count];
    r->risk_id       = isms->risk_count + 1;
    r->asset_id      = asset_id;
    r->threat_id     = threat_id;
    r->vuln_id       = 0;
    r->inherent_risk = severity * 0.8;
    r->residual_risk = r->inherent_risk;
    r->control_ref   = control_ref;
    r->status        = ISO27001_STATUS_NOT_IMPL;
    if (control_ref > 0 && (size_t)control_ref <= (size_t)isms->control_count) {
        r->residual_risk *= 0.4;
        r->status = ISO27001_STATUS_PARTIAL;
    }
    isms->risk_count++;
    return r->risk_id;
}

int iso27001_generate_soa(ISO27001_ISMS *isms) {
    if (!isms) return -1;
    isms->soa_count = 0;
    for (int i = 0; i < isms->control_count; i++) {
        ISO27001_SoAEntry *e = &isms->soa[isms->soa_count++];
        e->control_id       = isms->controls[i].control_id;
        e->applicable       = 1;
        e->justification    = "In-scope for ISMS";
        e->implement_status = isms->controls[i].status;
    }
    return isms->soa_count;
}

void iso27001_risks_by_asset(const ISO27001_ISMS *isms, int asset_id,
                              int *out_ids, int *out_count, int max_count) {
    if (!isms || !out_ids || !out_count) return;
    *out_count = 0;
    for (int i = 0; i < isms->risk_count && *out_count < max_count; i++) {
        if (isms->risks[i].asset_id == asset_id) {
            out_ids[(*out_count)++] = isms->risks[i].risk_id;
        }
    }
}

int iso27001_schedule_audit(ISO27001_ISMS *isms, const char *scope,
                             const char *auditor, int month) {
    if (!isms || isms->audit_count >= 16) return -1;
    ISO27001_Audit *a = &isms->audits[isms->audit_count];
    a->audit_id        = isms->audit_count + 1;
    a->scope           = scope;
    a->auditor         = auditor;
    a->scheduled_month = month;
    a->completed       = 0;
    a->findings        = 0;
    a->nonconformities = 0;
    isms->audit_count++;
    return a->audit_id;
}

int iso27001_add_review(ISO27001_ISMS *isms, const char *topic,
                         const char *input, const char *output,
                         const char *decisions, int year) {
    if (!isms || isms->review_count >= 4) return -1;
    ISO27001_ManagementReview *r = &isms->reviews[isms->review_count++];
    r->topic      = topic;
    r->input_data = input;
    r->output_data = output;
    r->decisions  = decisions;
    r->review_year = year;
    return isms->review_count;
}

void iso27001_pdca_report(const ISO27001_ISMS *isms) {
    if (!isms) return;
    int implemented = 0;
    for (int i = 0; i < isms->control_count; i++) {
        if (isms->controls[i].status >= ISO27001_STATUS_PARTIAL) implemented++;
    }
    printf("=== ISO 27001 PDCA Report ===\n");
    printf("Plan:   %d risk(s) identified, %d controls defined\n",
           isms->risk_count, isms->control_count);
    printf("Do:     %d/%d controls implemented, %d audit(s) scheduled\n",
           implemented, isms->control_count, isms->audit_count);
    printf("Check:  %d management review(s), %d SoA entries\n",
           isms->review_count, isms->soa_count);
    printf("Act:    Certification stage %d (year %d)\n",
           isms->cert_stage, isms->cert_year);
    printf("Status: %s\n", isms->active ? "Active" : "Inactive");
}

int iso27001_certification_readiness(const ISO27001_ISMS *isms) {
    if (!isms) return 0;
    int ready_score = 0;
    int impl = 0;
    for (int i = 0; i < isms->control_count; i++) {
        if (isms->controls[i].status >= ISO27001_STATUS_PARTIAL) impl++;
    }
    if (isms->risk_count > 0) ready_score += 10;
    if (isms->soa_count > 0) ready_score += 20;
    if (isms->audit_count > 0) ready_score += 15;
    if (isms->review_count > 0) ready_score += 15;
    if (isms->control_count > 0)
        ready_score += (int)(40.0 * impl / isms->control_count);
    return ready_score;
}

/* ═══════════════════════════════════════════════════════════════════
 * Control Effectiveness Measurement (KPI Scorecard)
 * L5: Balanced scorecard approach — maps controls to KPIs,
 *     measures effectiveness via threshold-based scoring.
 * Ref: ISO 27004 Information Security Management Measurement.
 * ═══════════════════════════════════════════════════════════════════ */

int iso27001_add_kpi(ISO27001_ISMS *isms, const char *name, const char *metric,
                      double target, double warn, double crit, int control_ref) {
    if (!isms || isms->kpi_count >= ISO27001_MAX_KPIS) return -1;
    ISO27001_KPI *k = &isms->kpis[isms->kpi_count];
    k->kpi_id         = isms->kpi_count + 1;
    k->name           = name;
    k->metric         = metric;
    k->current_value  = 0.0;
    k->target_value   = target;
    k->threshold_warn = warn;
    k->threshold_crit = crit;
    k->control_ref    = control_ref;
    k->trending       = 0;
    isms->kpi_count++;
    return k->kpi_id;
}

int iso27001_update_kpi(ISO27001_ISMS *isms, int kpi_id, double current_value) {
    if (!isms || kpi_id < 1 || kpi_id > isms->kpi_count) return -1;
    ISO27001_KPI *k = &isms->kpis[kpi_id - 1];
    double old = k->current_value;
    k->current_value = current_value;
    /* Update trending based on value direction */
    if (current_value > old * 1.02) k->trending = 1;
    else if (current_value < old * 0.98) k->trending = -1;
    else k->trending = 0;
    return 0;
}

int iso27001_kpi_trending(ISO27001_ISMS *isms, int kpi_id, int trend) {
    if (!isms || kpi_id < 1 || kpi_id > isms->kpi_count) return -1;
    if (trend < -1 || trend > 1) return -1;
    isms->kpis[kpi_id - 1].trending = trend;
    return 0;
}

void iso27001_kpi_scorecard(const ISO27001_ISMS *isms) {
    if (!isms) return;
    printf("=== ISO 27001 KPI Scorecard ===\n");
    int green = 0, yellow = 0, red = 0;
    printf("%-4s %-25s %-8s %-8s %-8s %-10s\n",
           "KPI", "Name", "Current", "Target", "Status", "Trend");
    printf("-------------------------------------------------------------\n");
    for (int i = 0; i < isms->kpi_count; i++) {
        const ISO27001_KPI *k = &isms->kpis[i];
        const char *status;
        if (k->current_value >= k->target_value)      { status = "GREEN"; green++; }
        else if (k->current_value >= k->threshold_warn) { status = "YELLOW"; yellow++; }
        else                                           { status = "RED"; red++; }
        const char *trend_str = k->trending == 1 ? "▲" :
                                 k->trending == -1 ? "▼" : "─";
        printf("%-4d %-25s %-8.2f %-8.2f %-8s %-10s\n",
               k->kpi_id, k->name, k->current_value, k->target_value,
               status, trend_str);
    }
    printf("\nScorecard: Green=%d Yellow=%d Red=%d (of %d KPIs)\n",
           green, yellow, red, isms->kpi_count);
}

double iso27001_control_effectiveness(const ISO27001_ISMS *isms, int domain) {
    if (!isms || domain < 0 || domain >= ISO27001_ANNEX_A_DOMAINS) return 0.0;
    int total = 0, implemented = 0;
    for (int i = 0; i < isms->control_count; i++) {
        if ((int)isms->controls[i].domain == domain) {
            total++;
            if (isms->controls[i].status >= ISO27001_STATUS_PARTIAL)
                implemented++;
        }
    }
    if (total == 0) return 0.0;
    return 100.0 * (double)implemented / (double)total;
}

/* ═══════════════════════════════════════════════════════════════════
 * Incident Management (ISO 27001 A.16)
 * L2: Information security incident lifecycle — open → analyze →
 *     contain → resolve → close, with metrics tracking.
 * Ref: ISO 27035 Information security incident management.
 * ═══════════════════════════════════════════════════════════════════ */

int iso27001_add_incident(ISO27001_ISMS *isms, const char *title,
                           const char *description, const char *reported_by,
                           int year, int month, int severity) {
    if (!isms || isms->incident_count >= ISO27001_MAX_INCIDENTS) return -1;
    if (severity < 1 || severity > 5) return -1;
    ISO27001_Incident *inc = &isms->incidents[isms->incident_count];
    inc->inc_id         = isms->incident_count + 1;
    inc->title          = title;
    inc->description    = description;
    inc->reported_by    = reported_by;
    inc->reported_year  = year;
    inc->reported_month = month;
    inc->severity       = severity;
    inc->state          = ISO27001_INC_OPEN;
    inc->root_cause     = NULL;
    inc->corrective_action = NULL;
    inc->containment_hours = 0.0;
    inc->recovery_hours    = 0.0;
    isms->incident_count++;
    return inc->inc_id;
}

int iso27001_resolve_incident(ISO27001_ISMS *isms, int inc_id,
                               const char *root_cause, const char *corrective,
                               double contain_hours, double recover_hours) {
    if (!isms || inc_id < 1 || inc_id > isms->incident_count) return -1;
    ISO27001_Incident *inc = &isms->incidents[inc_id - 1];
    inc->state             = ISO27001_INC_RESOLVED;
    inc->root_cause        = root_cause;
    inc->corrective_action  = corrective;
    inc->containment_hours  = contain_hours;
    inc->recovery_hours     = recover_hours;
    return 0;
}

void iso27001_incident_report(const ISO27001_ISMS *isms) {
    if (!isms) return;
    printf("=== ISO 27001 Incident Management Report ===\n");
    int open_count = 0, resolved = 0, sev1 = 0;
    double total_contain = 0.0, total_recover = 0.0;
    int resolved_count = 0;

    for (int i = 0; i < isms->incident_count; i++) {
        const ISO27001_Incident *inc = &isms->incidents[i];
        if (inc->state < ISO27001_INC_RESOLVED) open_count++;
        else resolved++;
        if (inc->severity == 1) sev1++;
        if (inc->state >= ISO27001_INC_RESOLVED) {
            total_contain += inc->containment_hours;
            total_recover += inc->recovery_hours;
            resolved_count++;
        }
    }

    printf("Total Incidents:   %d\n", isms->incident_count);
    printf("Open/Active:       %d\n", open_count);
    printf("Resolved:          %d\n", resolved);
    printf("Severity-1:        %d\n", sev1);
    if (resolved_count > 0) {
        printf("Avg Containment:   %.1f hours\n",
               total_contain / (double)resolved_count);
        printf("Avg Recovery:      %.1f hours\n",
               total_recover / (double)resolved_count);
    }

    printf("\nIncident Details:\n");
    for (int i = 0; i < isms->incident_count && i < 10; i++) {
        const ISO27001_Incident *inc = &isms->incidents[i];
        const char *state_str;
        switch (inc->state) {
            case ISO27001_INC_OPEN:      state_str = "Open";      break;
            case ISO27001_INC_ANALYZING: state_str = "Analyzing"; break;
            case ISO27001_INC_CONTAINED: state_str = "Contained"; break;
            case ISO27001_INC_RESOLVED:  state_str = "Resolved";  break;
            case ISO27001_INC_CLOSED:    state_str = "Closed";    break;
            default:                     state_str = "Unknown";   break;
        }
        printf("  #%d [Sev%d] %-30s | %s | %s\n",
               inc->inc_id, inc->severity, inc->title, state_str,
               inc->reported_by ? inc->reported_by : "");
    }
}

int iso27001_mean_time_to_resolve(const ISO27001_ISMS *isms, double *mttr_hours) {
    if (!isms || !mttr_hours) return -1;
    double total = 0.0;
    int count = 0;
    for (int i = 0; i < isms->incident_count; i++) {
        if (isms->incidents[i].state >= ISO27001_INC_RESOLVED) {
            total += isms->incidents[i].containment_hours +
                     isms->incidents[i].recovery_hours;
            count++;
        }
    }
    if (count == 0) { *mttr_hours = 0.0; return 0; }
    *mttr_hours = total / (double)count;
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * Risk Appetite Framework
 * L2: Board-level risk tolerance — defines thresholds for acceptable
 *     residual risk, triggers escalation when exceeded.
 * Ref: COSO ERM 2017 — Enterprise Risk Management framework.
 * ═══════════════════════════════════════════════════════════════════ */

void iso27001_set_risk_appetite(ISO27001_ISMS *isms, double max_ale,
                                 double max_score, int max_crit, int max_high) {
    if (!isms) return;
    isms->risk_appetite.max_acceptable_ale   = max_ale;
    isms->risk_appetite.max_single_risk_score = max_score;
    isms->risk_appetite.max_critical_risks    = max_crit;
    isms->risk_appetite.max_high_risks        = max_high;
    isms->risk_appetite.risk_capacity         = max_ale * 2.0;
    isms->risk_appetite.active                = 1;
}

int iso27001_check_risk_appetite(const ISO27001_ISMS *isms,
                                  double total_ale, int crit_risks,
                                  int high_risks) {
    if (!isms || !isms->risk_appetite.active) return 1; /* no threshold set */
    const ISO27001_RiskAppetite *ra = &isms->risk_appetite;
    if (total_ale   > ra->max_acceptable_ale)   return 0;
    if (crit_risks  > ra->max_critical_risks)    return 0;
    if (high_risks  > ra->max_high_risks)        return 0;
    return 1; /* within appetite */
}

void iso27001_risk_appetite_report(const ISO27001_ISMS *isms,
                                    double current_ale, int crit, int high) {
    if (!isms) return;
    const ISO27001_RiskAppetite *ra = &isms->risk_appetite;
    printf("=== Risk Appetite Statement ===\n");
    printf("Appetite Active:       %s\n", ra->active ? "Yes" : "No");
    printf("Max Acceptable ALE:    $%.0f\n", ra->max_acceptable_ale);
    printf("Max Single Risk Score: %.0f\n", ra->max_single_risk_score);
    printf("Max Critical Risks:    %d\n", ra->max_critical_risks);
    printf("Max High Risks:        %d\n", ra->max_high_risks);
    printf("Risk Capacity:         $%.0f\n", ra->risk_capacity);
    printf("\nCurrent Position:\n");
    printf("Current ALE:           $%.0f\n", current_ale);
    printf("Critical Risks:        %d\n", crit);
    printf("High Risks:            %d\n", high);
    printf("Within Appetite:       %s\n",
           iso27001_check_risk_appetite(isms, current_ale, crit, high)
           ? "YES ✓" : "NO ✗ (Escalation required)");
}

/* ═══════════════════════════════════════════════════════════════════
 * ISO 27001:2022 Clause Compliance Tracking
 * L4: ISO/IEC 27001:2022 clauses 4-10 — mandatory requirements
 *     checklist with documentary evidence tracking.
 * ═══════════════════════════════════════════════════════════════════ */

void iso27001_init_clauses(ISO27001_ISMS *isms) {
    if (!isms) return;
    static const struct {
        int num; const char *name; int reqs;
    } clause_defs[] = {
        {4,  "Context of the Organization",  8},
        {5,  "Leadership",                   6},
        {6,  "Planning",                     8},
        {7,  "Support",                     12},
        {8,  "Operation",                   10},
        {9,  "Performance Evaluation",       8},
        {10, "Improvement",                  5},
    };
    int n = (int)(sizeof(clause_defs) / sizeof(clause_defs[0]));
    isms->clause_count = 0;
    for (int i = 0; i < n && isms->clause_count < ISO27001_MAX_CLAUSES; i++) {
        ISO27001_ClauseStatus *c = &isms->clauses[isms->clause_count++];
        c->clause_number        = clause_defs[i].num;
        c->clause_name          = clause_defs[i].name;
        c->requirements_total   = clause_defs[i].reqs;
        c->requirements_met     = 0;
        c->documentary_evidence = 0;
        c->implemented          = 0;
    }
}

int iso27001_update_clause(ISO27001_ISMS *isms, int clause_num,
                             int requirements_met) {
    if (!isms) return -1;
    for (int i = 0; i < isms->clause_count; i++) {
        if (isms->clauses[i].clause_number == clause_num) {
            if (requirements_met >= 0 &&
                requirements_met <= isms->clauses[i].requirements_total) {
                isms->clauses[i].requirements_met = requirements_met;
                isms->clauses[i].implemented = 1;
            }
            return 0;
        }
    }
    return -1;
}

int iso27001_clause_compliance_pct(const ISO27001_ISMS *isms, int clause_num) {
    if (!isms) return -1;
    for (int i = 0; i < isms->clause_count; i++) {
        if (isms->clauses[i].clause_number == clause_num) {
            if (isms->clauses[i].requirements_total == 0) return 0;
            return (100 * isms->clauses[i].requirements_met) /
                   isms->clauses[i].requirements_total;
        }
    }
    return -1;
}

void iso27001_clause_matrix(const ISO27001_ISMS *isms) {
    if (!isms) return;
    printf("=== ISO 27001:2022 Clause Compliance Matrix ===\n");
    printf("%-8s %-30s %-12s %-12s %-10s\n",
           "Clause", "Name", "Requirements", "Met", "Status");
    printf("-------------------------------------------------------------\n");
    int total_req = 0, total_met = 0;
    for (int i = 0; i < isms->clause_count; i++) {
        const ISO27001_ClauseStatus *c = &isms->clauses[i];
        int pct = c->requirements_total > 0 ?
                  (100 * c->requirements_met) / c->requirements_total : 0;
        const char *status = pct >= 80 ? "COMPLIANT" :
                              pct >= 50 ? "PARTIAL" : "GAP";
        printf("Clause %-3d %-30s %-12d %-12d %-10s (%d%%)\n",
               c->clause_number, c->clause_name,
               c->requirements_total, c->requirements_met, status, pct);
        total_req += c->requirements_total;
        total_met += c->requirements_met;
    }
    int overall_pct = total_req > 0 ? (100 * total_met) / total_req : 0;
    printf("-------------------------------------------------------------\n");
    printf("Overall: %d/%d requirements met (%.0f%%)\n",
           total_met, total_req, (double)(100 * total_met) / (double)total_req);
    printf("Certification readiness: %s\n",
           overall_pct >= 80 ? "Likely ready" :
           overall_pct >= 60 ? "Approaching readiness" :
           "Significant work required");
}
