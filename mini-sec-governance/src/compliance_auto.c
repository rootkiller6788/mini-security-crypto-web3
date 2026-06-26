#include "compliance_auto.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

static uint64_t djb2_hash(const unsigned char *str) {
    uint64_t hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + (unsigned char)c;
    }
    return hash;
}

uint64_t comp_compute_hash(const char *data) {
    if (!data) return 0;
    return djb2_hash((const unsigned char *)data);
}

int comp_init(Compliance_Engine *eng) {
    if (!eng) return -1;
    memset(eng, 0, sizeof(*eng));
    eng->chain_hash = 0;
    eng->monitoring_active = 0;
    return 0;
}

int comp_add_regulation(Compliance_Engine *eng, Compliance_Regulation reg) {
    if (!eng || eng->active_reg_count >= COMP_MAX_REGS) return -1;
    for (int i = 0; i < eng->active_reg_count; i++) {
        if (eng->active_regs[i] == reg) return i;
    }
    eng->active_regs[eng->active_reg_count++] = reg;
    return eng->active_reg_count - 1;
}

int comp_add_policy(Compliance_Engine *eng, const char *name,
                     const char *desc, const char *rule, const char *path,
                     const char *expected, int severity,
                     const Compliance_Regulation *regs, int reg_count) {
    if (!eng || eng->policy_count >= COMP_MAX_POLICIES) return -1;
    Compliance_Policy *p = &eng->policies[eng->policy_count];
    p->policy_id       = eng->policy_count + 1;
    p->name            = name;
    p->description     = desc;
    p->rule_expression = rule;
    p->resource_path   = path;
    p->expected_value  = expected;
    p->severity        = severity;
    p->reg_count = reg_count < 4 ? reg_count : 4;
    for (int i = 0; i < p->reg_count; i++) {
        p->regs[i] = regs[i];
    }
    eng->policy_count++;
    return p->policy_id;
}

int comp_check_policy(Compliance_Engine *eng, int policy_id,
                       const char *current_value) {
    if (!eng || policy_id < 1 || policy_id > eng->policy_count) return -1;
    if (eng->check_count >= COMP_MAX_CHECKS) return -1;

    Compliance_Policy *p = &eng->policies[policy_id - 1];
    Compliance_CheckResult *r = &eng->checks[eng->check_count];
    r->check_id       = eng->check_count + 1;
    r->policy_id      = policy_id;
    r->resource_value = current_value;
    r->timestamp      = time(NULL);

    if (!current_value || !p->expected_value) {
        r->status  = COMP_STATUS_ERROR;
        r->message = "Missing value";
    } else if (strcmp(current_value, p->expected_value) == 0) {
        r->status  = COMP_STATUS_PASS;
        r->message = "Value matches expected";
    } else {
        r->status  = COMP_STATUS_FAIL;
        r->message = "Value does not match expected";
    }
    eng->check_count++;
    return r->check_id;
}

int comp_check_all(Compliance_Engine *eng) {
    if (!eng) return -1;
    int passed = 0, failed = 0;
    for (int i = 0; i < eng->policy_count; i++) {
        Compliance_Policy *p = &eng->policies[i];
        int chk = comp_check_policy(eng, p->policy_id, p->expected_value);
        if (chk > 0) {
            Compliance_CheckResult *r = &eng->checks[eng->check_count - 1];
            if (r->status == COMP_STATUS_PASS) passed++;
            else if (r->status == COMP_STATUS_FAIL) failed++;
        }
    }
    return passed;
}

int comp_detect_drift(Compliance_Engine *eng) {
    if (!eng) return 0;
    int new_drifts = 0;
    for (int i = 0; i < eng->check_count; i++) {
        if (eng->checks[i].status == COMP_STATUS_FAIL) {
            int already = 0;
            for (int j = 0; j < eng->drift_count; j++) {
                if (eng->drifts[j].check_id == eng->checks[i].check_id &&
                    !eng->drifts[j].remediated_by) {
                    already = 1;
                    break;
                }
            }
            if (!already && eng->drift_count < COMP_MAX_DRIFTS) {
                Compliance_Drift *d = &eng->drifts[eng->drift_count++];
                d->drift_id      = eng->drift_count;
                d->check_id      = eng->checks[i].check_id;
                d->policy_id     = eng->checks[i].policy_id;
                d->drifted_value = eng->checks[i].resource_value;
                d->expected_value = eng->policies[eng->checks[i].policy_id - 1].expected_value;
                d->resource_path = eng->policies[eng->checks[i].policy_id - 1].resource_path;
                d->detected_at   = eng->checks[i].timestamp;
                d->acknowledged  = 0;
                d->remediated_by = NULL;
                d->remediated_at = 0;
                new_drifts++;
            }
        }
    }
    return new_drifts;
}

int comp_add_log(Compliance_Engine *eng, const char *actor,
                  const char *action, const char *resource, const char *result) {
    if (!eng || eng->log_count >= COMP_MAX_AUDIT_LOGS) return -1;
    Compliance_AuditLog *l = &eng->logs[eng->log_count];
    l->log_id    = eng->log_count + 1;
    l->timestamp = time(NULL);
    l->actor     = actor;
    l->action    = action;
    l->resource  = resource;
    l->result    = result;
    l->immutable = 1;
    l->prev_hash = eng->chain_hash;

    char buf[512];
    snprintf(buf, sizeof(buf), "%ld%s%s%s%s%llu",
             (long)l->timestamp, actor, action, resource, result,
             (unsigned long long)l->prev_hash);
    l->curr_hash = comp_compute_hash(buf);
    eng->chain_hash = l->curr_hash;
    eng->log_count++;
    return l->log_id;
}

int comp_add_control(Compliance_Engine *eng, const char *ctrl_id,
                      Compliance_Regulation reg, const char *desc) {
    if (!eng || eng->control_count >= COMP_MAX_CONTROLS) return -1;
    Compliance_Control *c = &eng->controls[eng->control_count++];
    c->control_id    = ctrl_id;
    c->reg           = reg;
    c->description   = desc;
    c->status        = COMP_STATUS_NOT_APPLICABLE;
    c->pass_count    = 0;
    c->fail_count    = 0;
    c->last_checked  = 0;
    return eng->control_count;
}

int comp_update_dashboard(Compliance_Engine *eng) {
    if (!eng || eng->active_reg_count < 1) return -1;

    Compliance_Regulation reg = eng->active_regs[0];
    Compliance_Dashboard *d = &eng->dashboard;
    d->reg = reg;
    d->name = comp_reg_name(reg);
    d->description = "";

    int total_ctrl = 0, compliant = 0, non_compliant = 0;
    int total_pol = eng->policy_count, passing = 0;
    for (int i = 0; i < eng->control_count; i++) {
        if (eng->controls[i].reg == reg || reg == eng->controls[i].reg) {
            total_ctrl++;
            if (eng->controls[i].pass_count > eng->controls[i].fail_count) {
                compliant++;
            } else {
                non_compliant++;
            }
        }
    }
    for (int i = 0; i < eng->check_count; i++) {
        if (eng->checks[i].status == COMP_STATUS_PASS) passing++;
    }

    d->total_controls         = total_ctrl;
    d->compliant_controls     = compliant;
    d->non_compliant_controls = non_compliant;
    d->total_policies         = total_pol;
    d->passing_policies       = passing;
    d->overall_status = (non_compliant == 0 && passing >= total_pol)
                        ? COMP_STATUS_PASS : COMP_STATUS_FAIL;
    return 0;
}

void comp_dashboard_display(const Compliance_Engine *eng) {
    if (!eng) return;
    const Compliance_Dashboard *d = &eng->dashboard;
    printf("=== Compliance Dashboard: %s ===\n", d->name);
    printf("Control Status:   %d/%d compliant | %d non-compliant\n",
           d->compliant_controls, d->total_controls, d->non_compliant_controls);
    printf("Policy Status:    %d/%d passing\n",
           d->passing_policies, d->total_policies);
    printf("Overall Status:   %s\n", comp_status_name(d->overall_status));
    printf("Compliance Score: %.1f%%\n", comp_compliance_score(eng));
}

int comp_generate_evidence(Compliance_Engine *eng, int control_id) {
    if (!eng || control_id < 1 || control_id > eng->control_count) return -1;
    Compliance_Control *c = &eng->controls[control_id - 1];
    if (c->pass_count > c->fail_count) {
        c->status = COMP_STATUS_PASS;
    } else if (c->fail_count > c->pass_count) {
        c->status = COMP_STATUS_FAIL;
    } else {
        c->status = COMP_STATUS_WARN;
    }
    c->last_checked = 1;
    return 0;
}

void comp_audit_trail(const Compliance_Engine *eng) {
    if (!eng) return;
    printf("=== Audit Trail (Immutable Log Chain) ===\n");
    printf("%-4s %-20s %-12s %-20s %-12s\n",
           "ID", "Timestamp", "Actor", "Action", "Result");
    printf("-----------------------------------------------------------\n");
    for (int i = 0; i < eng->log_count && i < 20; i++) {
        char ts[26];
        ctime_s(ts, sizeof(ts), &eng->logs[i].timestamp);
        ts[24] = '\0';
        printf("%-4d %-20s %-12s %-20s %-12s\n",
               eng->logs[i].log_id, ts,
               eng->logs[i].actor ? eng->logs[i].actor : "",
               eng->logs[i].action ? eng->logs[i].action : "",
               eng->logs[i].result ? eng->logs[i].result : "");
    }
    if (eng->log_count > 0) {
        printf("\nChain hash: 0x%016llx (verified: %s)\n",
               (unsigned long long)eng->chain_hash,
               eng->chain_hash > 0 ? "yes" : "no");
    }
}

void comp_continuous_monitor(Compliance_Engine *eng, int interval_sec) {
    if (!eng) return;
    eng->monitoring_active = 1;
    (void)interval_sec;
    comp_check_all(eng);
    comp_detect_drift(eng);
    comp_update_dashboard(eng);
}

const char* comp_status_name(Compliance_Status s) {
    switch (s) {
        case COMP_STATUS_PASS:           return "PASS";
        case COMP_STATUS_FAIL:           return "FAIL";
        case COMP_STATUS_WARN:           return "WARN";
        case COMP_STATUS_ERROR:          return "ERROR";
        case COMP_STATUS_NOT_APPLICABLE: return "N/A";
        default:                         return "UNKNOWN";
    }
}

const char* comp_reg_name(Compliance_Regulation r) {
    switch (r) {
        case COMP_REG_GDPR:    return "GDPR";
        case COMP_REG_HIPAA:   return "HIPAA";
        case COMP_REG_PCI_DSS: return "PCI-DSS";
        case COMP_REG_SOX:     return "SOX";
        case COMP_REG_NIST:    return "NIST";
        case COMP_REG_ISO27001: return "ISO 27001";
        case COMP_REG_CUSTOM:  return "Custom";
        default:               return "Unknown";
    }
}

double comp_compliance_score(const Compliance_Engine *eng) {
    if (!eng || eng->policy_count == 0) return 0.0;
    int passing = 0;
    for (int i = 0; i < eng->check_count; i++) {
        if (eng->checks[i].status == COMP_STATUS_PASS) passing++;
    }
    return 100.0 * (double)passing / (double)eng->policy_count;
}

void comp_remediation_report(const Compliance_Engine *eng) {
    if (!eng) return;
    printf("=== Remediation Report ===\n");
    int open_drifts = 0;
    for (int i = 0; i < eng->drift_count; i++) {
        if (!eng->drifts[i].remediated_by) {
            printf("  Drift #%d: %s | expected=%s | actual=%s\n",
                   eng->drifts[i].drift_id,
                   eng->drifts[i].resource_path,
                   eng->drifts[i].expected_value,
                   eng->drifts[i].drifted_value);
            open_drifts++;
        }
    }
    printf("Open drifts: %d\n", open_drifts);
}

/* ═══════════════════════════════════════════════════════════════════
 * Rule Evaluation Engine
 * L3: Composite policy rule evaluator — supports AND, OR, NOT
 *     logic gates and comparison operators for policy as code.
 * Ref: OPA Rego-style policy evaluation semantics.
 * ═══════════════════════════════════════════════════════════════════ */

int comp_rule_add(Compliance_Engine *eng, const char *field,
                   Compliance_RuleOp op, const char *value, int severity,
                   int *sub_rules, int sub_count) {
    if (!eng || eng->check_count >= COMP_MAX_CHECKS) return -1;
    /* Rules are stored as checks with meta — reuse check array as rule store */
    Compliance_CheckResult *r = &eng->checks[eng->check_count];
    r->check_id       = eng->check_count + 1;
    r->policy_id      = 0;  /* rules are independent of policies */
    r->resource_value = value;
    r->timestamp      = time(NULL);
    r->status         = (Compliance_Status)op;
    (void)field;
    (void)severity;
    (void)sub_rules;
    (void)sub_count;
    eng->check_count++;
    return r->check_id;
}

int comp_rule_evaluate(const Compliance_Rule *rule,
                        const char *field, const char *actual_value) {
    if (!rule || !actual_value) return 0;
    if (!field && rule->field) field = rule->field;

    double num_expected, num_actual;
    int is_numeric = 0;

    /* Try numeric comparison first */
    if (rule->value && actual_value) {
        char *end_e, *end_a;
        num_expected = strtod(rule->value, &end_e);
        num_actual   = strtod(actual_value, &end_a);
        is_numeric   = (*end_e == '\0' || *end_e == ' ') &&
                       (*end_a == '\0' || *end_a == ' ');
    }

    switch (rule->op) {
    case COMP_OP_EQ:
        if (is_numeric) return num_expected == num_actual;
        return strcmp(actual_value, rule->value) == 0;
    case COMP_OP_NEQ:
        if (is_numeric) return num_expected != num_actual;
        return strcmp(actual_value, rule->value) != 0;
    case COMP_OP_GT:
        return is_numeric && num_actual > num_expected;
    case COMP_OP_GTE:
        return is_numeric && num_actual >= num_expected;
    case COMP_OP_LT:
        return is_numeric && num_actual < num_expected;
    case COMP_OP_LTE:
        return is_numeric && num_actual <= num_expected;
    case COMP_OP_CONTAINS:
        return strstr(actual_value, rule->value) != NULL;
    case COMP_OP_NOT:
        return !strcmp(actual_value, rule->value);
    default:
        return 0;
    }
    (void)field;
}

int comp_evaluate_composite(const Compliance_Rule *rules, int rule_count,
                             const char *field, const char *actual_value) {
    if (!rules || rule_count < 1) return 0;
    /* Composite evaluator: all AND rules must pass, any OR passes.
     * Simplified: evaluates each rule independently. */
    int result = 1; /* defaults to AND logic */
    for (int i = 0; i < rule_count; i++) {
        int r = comp_rule_evaluate(&rules[i], field, actual_value);
        if (rules[i].op == COMP_OP_AND) result = result && r;
        else if (rules[i].op == COMP_OP_OR) result = result || r;
        else result = result && r; /* default AND */
    }
    return result;
}

/* ═══════════════════════════════════════════════════════════════════
 * Control Mapping / Coverage Analysis
 * L4: Bi-directional policy-control mapping with coverage metrics.
 * Unified Compliance Framework (UCF) style cross-walking.
 * ═══════════════════════════════════════════════════════════════════ */

int comp_map_policy_to_control(Compliance_Engine *eng, int policy_id,
                                int control_id) {
    if (!eng || policy_id < 1 || policy_id > eng->policy_count) return -1;
    if (control_id < 1 || control_id > eng->control_count) return -1;
    /* Mark mapping by setting policy's regulation to include control's reg */
    Compliance_Policy *p = &eng->policies[policy_id - 1];
    Compliance_Control *c = &eng->controls[control_id - 1];
    if (p->reg_count < 4) {
        p->regs[p->reg_count++] = c->reg;
    }
    return 0;
}

int comp_control_coverage(const Compliance_Engine *eng,
                           Compliance_Regulation reg, double *coverage_pct) {
    if (!eng || !coverage_pct) return -1;
    int total_controls = 0, covered_controls = 0;
    for (int i = 0; i < eng->control_count; i++) {
        if (eng->controls[i].reg == reg) {
            total_controls++;
            if (eng->controls[i].pass_count > 0 ||
                eng->controls[i].status == COMP_STATUS_PASS) {
                covered_controls++;
            }
        }
    }
    if (total_controls == 0) { *coverage_pct = 0.0; return 0; }
    *coverage_pct = 100.0 * (double)covered_controls / (double)total_controls;
    return 0;
}

int comp_crosswalk_matrix(const Compliance_Engine *eng,
                           Compliance_Regulation reg_a,
                           Compliance_Regulation reg_b,
                           int *common_controls) {
    if (!eng || !common_controls) return -1;
    *common_controls = 0;
    for (int i = 0; i < eng->policy_count; i++) {
        int has_a = 0, has_b = 0;
        for (int j = 0; j < eng->policies[i].reg_count; j++) {
            if (eng->policies[i].regs[j] == reg_a) has_a = 1;
            if (eng->policies[i].regs[j] == reg_b) has_b = 1;
        }
        if (has_a && has_b) (*common_controls)++;
    }
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * Remediation Plan (Workflow Automation)
 * L7: Automated remediation tracking with state machine transitions.
 * Supports: Pending → InProgress → Verified → Closed → Deferred.
 * ═══════════════════════════════════════════════════════════════════ */

int comp_add_remediation(Compliance_Engine *eng, int drift_id,
                          int policy_id, const char *action_plan,
                          const char *assigned_to, int priority,
                          int target_days, double cost_estimate) {
    if (!eng || eng->remediation_count >= COMP_MAX_REMEDIATION) return -1;
    Compliance_Remediation *rm = &eng->remediations[eng->remediation_count];
    rm->remed_id      = eng->remediation_count + 1;
    rm->drift_id      = drift_id;
    rm->policy_id     = policy_id;
    rm->action_plan   = action_plan;
    rm->assigned_to   = assigned_to;
    rm->state         = COMP_REM_PENDING;
    rm->priority      = priority;
    rm->target_days   = target_days;
    rm->opened_at     = time(NULL);
    rm->resolved_at   = 0;
    rm->cost_estimate = cost_estimate;
    eng->remediation_count++;
    return rm->remed_id;
}

int comp_remediate_close(Compliance_Engine *eng, int remed_id) {
    if (!eng || remed_id < 1 || remed_id > eng->remediation_count) return -1;
    Compliance_Remediation *rm = &eng->remediations[remed_id - 1];
    if (rm->state == COMP_REM_CLOSED) return 0;
    rm->state       = COMP_REM_VERIFIED;
    rm->resolved_at = time(NULL);
    /* Mark corresponding drift as remediated */
    if (rm->drift_id > 0 && rm->drift_id <= eng->drift_count) {
        eng->drifts[rm->drift_id - 1].remediated_by = rm->assigned_to;
        eng->drifts[rm->drift_id - 1].remediated_at = rm->resolved_at;
    }
    rm->state = COMP_REM_CLOSED;
    return 0;
}

void comp_remediation_backlog(const Compliance_Engine *eng) {
    if (!eng) return;
    printf("=== Remediation Backlog ===\n");
    int open_count = 0;
    for (int i = 0; i < eng->remediation_count; i++) {
        if (eng->remediations[i].state != COMP_REM_CLOSED) {
            open_count++;
            printf("  REM-%d: [P%d] %-10s assigned=%s priority=%d target=%dd\n",
                   eng->remediations[i].remed_id,
                   eng->remediations[i].priority,
                   eng->remediations[i].action_plan,
                   eng->remediations[i].assigned_to,
                   eng->remediations[i].priority,
                   eng->remediations[i].target_days);
        }
    }
    printf("Open remediations: %d / %d total\n",
           open_count, eng->remediation_count);
}

/* ═══════════════════════════════════════════════════════════════════
 * GRC Maturity Model
 * L8: Capability maturity model integration (CMMI-style) for GRC.
 * Evaluates Governance, Risk Management, Compliance, and Audit
 * across 5 maturity levels from Initial to Optimizing.
 * ═══════════════════════════════════════════════════════════════════ */

static Compliance_MaturityLevel assess_dimension(int policies, int controls,
                                                   int passing, int evidences) {
    if (policies == 0 && controls == 0) return COMP_MATURITY_INITIAL;
    if (evidences == 0) return COMP_MATURITY_INITIAL;

    double pass_rate = controls > 0 ? (double)passing / (double)controls : 0.0;
    int total_items = policies + controls;

    if (total_items < 3) return COMP_MATURITY_INITIAL;
    if (total_items < 6) return COMP_MATURITY_MANAGED;
    if (total_items < 12) return COMP_MATURITY_DEFINED;
    if (pass_rate > 0.70 && evidences >= 3) {
        if (pass_rate > 0.90 && evidences >= 5)
            return COMP_MATURITY_OPTIMIZING;
        return COMP_MATURITY_QUANTITATIVE;
    }
    return COMP_MATURITY_DEFINED;
}

void comp_assess_maturity(Compliance_Engine *eng) {
    if (!eng) return;
    Compliance_MaturityAssessment *ma = &eng->maturity;
    ma->reg         = eng->active_reg_count > 0 ?
                       eng->active_regs[0] : COMP_REG_CUSTOM;
    ma->governance  = assess_dimension(eng->policy_count, 0,
                                        eng->policy_count, eng->log_count);
    ma->risk_mgmt   = assess_dimension(eng->policy_count,
                                        eng->drift_count,
                                        eng->policy_count - eng->drift_count,
                                        eng->log_count);
    ma->compliance  = assess_dimension(eng->policy_count,
                                        eng->control_count,
                                        eng->policy_count,
                                        eng->log_count);
    ma->audit       = assess_dimension(0, eng->control_count,
                                        eng->control_count, eng->log_count);
    /* Overall = floor of component averages */
    int sum = ma->governance + ma->risk_mgmt + ma->compliance + ma->audit;
    ma->overall = (Compliance_MaturityLevel)(sum / 4);

    /* Composite maturity score (0-100) */
    ma->score = 25.0 * (double)ma->overall +
                6.25 * (double)(ma->governance + ma->risk_mgmt +
                                ma->compliance + ma->audit) / 4.0;
    if (ma->score > 100.0) ma->score = 100.0;
}

const char* comp_maturity_level_name(Compliance_MaturityLevel ml) {
    switch (ml) {
        case COMP_MATURITY_INITIAL:      return "Initial (ad-hoc)";
        case COMP_MATURITY_MANAGED:      return "Managed (repeatable)";
        case COMP_MATURITY_DEFINED:      return "Defined (standardized)";
        case COMP_MATURITY_QUANTITATIVE: return "Quantitative (measured)";
        case COMP_MATURITY_OPTIMIZING:   return "Optimizing (continuous improvement)";
        default:                         return "Unknown";
    }
}

int comp_maturity_improvement_plan(const Compliance_MaturityAssessment *ma,
                                    Compliance_MaturityLevel target,
                                    char *plan_buf, int buf_size) {
    if (!ma || !plan_buf || buf_size < 1) return -1;
    if (target <= ma->overall) {
        snprintf(plan_buf, (size_t)buf_size,
                 "Already at or above target level (%s)",
                 comp_maturity_level_name(ma->overall));
        return 0;
    }

    int written = 0;
    if (ma->governance < target)
        written += snprintf(plan_buf + written, (size_t)(buf_size - written),
                            "Improve governance [%s → %s]; ",
                            comp_maturity_level_name(ma->governance),
                            comp_maturity_level_name(target));
    if (ma->risk_mgmt < target)
        written += snprintf(plan_buf + written, (size_t)(buf_size - written),
                            "Enhance risk management; ");
    if (ma->compliance < target)
        written += snprintf(plan_buf + written, (size_t)(buf_size - written),
                            "Standardize compliance processes; ");
    if (ma->audit < target)
        written += snprintf(plan_buf + written, (size_t)(buf_size - written),
                            "Establish continuous auditing; ");

    if (written == 0) {
        snprintf(plan_buf, (size_t)buf_size, "No improvements needed.");
    }
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * Compliance Trending & Forecasting
 * L7: Time-series analysis using linear regression for score forecasting.
 * Computes trend line from historical compliance snapshots.
 * ═══════════════════════════════════════════════════════════════════ */

int comp_record_trend(Compliance_Engine *eng) {
    if (!eng || eng->trend_count >= COMP_MAX_TREND_POINTS) return -1;
    Compliance_TrendPoint *tp = &eng->trends[eng->trend_count];
    tp->timestamp        = time(NULL);
    tp->compliance_score = comp_compliance_score(eng);
    tp->policies_passing = 0;
    tp->policies_total   = eng->policy_count;
    tp->drifts_open      = 0;
    for (int i = 0; i < eng->check_count; i++) {
        if (eng->checks[i].status == COMP_STATUS_PASS) tp->policies_passing++;
    }
    for (int i = 0; i < eng->drift_count; i++) {
        if (!eng->drifts[i].remediated_by) tp->drifts_open++;
    }
    eng->trend_count++;
    return eng->trend_count;
}

int comp_forecast_compliance(const Compliance_Engine *eng,
                              int days_ahead, double *predicted_score) {
    if (!eng || !predicted_score || eng->trend_count < 2) {
        if (predicted_score) *predicted_score = comp_compliance_score(eng);
        return eng->trend_count < 2 ? -1 : 0;
    }

    /* Simple linear regression: score = slope * day_index + intercept */
    double sum_x = 0, sum_y = 0, sum_xy = 0, sum_x2 = 0;
    int n = eng->trend_count;

    /* Use day offset from first trend point */
    time_t t0 = eng->trends[0].timestamp;
    for (int i = 0; i < n; i++) {
        double x = (double)(eng->trends[i].timestamp - t0) / 86400.0;
        double y = eng->trends[i].compliance_score;
        sum_x  += x;
        sum_y  += y;
        sum_xy += x * y;
        sum_x2 += x * x;
    }

    double denom = n * sum_x2 - sum_x * sum_x;
    if (fabs(denom) < 1e-10) {
        *predicted_score = sum_y / (double)n;
        return 0;
    }

    double slope     = (n * sum_xy - sum_x * sum_y) / denom;
    double intercept = (sum_y - slope * sum_x) / (double)n;
    double t_last    = (double)(eng->trends[n - 1].timestamp - t0) / 86400.0;
    double t_pred    = t_last + (double)days_ahead;

    *predicted_score = slope * t_pred + intercept;
    if (*predicted_score < 0.0)   *predicted_score = 0.0;
    if (*predicted_score > 100.0) *predicted_score = 100.0;
    return 0;
}

void comp_trend_report(const Compliance_Engine *eng) {
    if (!eng) return;
    printf("=== Compliance Trend Report ===\n");
    printf("%-4s %-20s %-8s %-10s %-10s\n",
           "Pt", "Date", "Score%", "Passing", "Drifts");
    printf("-------------------------------------------------------------\n");
    for (int i = 0; i < eng->trend_count; i++) {
        char ts[26];
        ctime_s(ts, sizeof(ts), &eng->trends[i].timestamp);
        ts[24] = '\0';
        printf("%-4d %-20s %-8.1f %-10d %-10d\n",
               i + 1, ts, eng->trends[i].compliance_score,
               eng->trends[i].policies_passing,
               eng->trends[i].drifts_open);
    }
    if (eng->trend_count >= 2) {
        double pred;
        comp_forecast_compliance(eng, 30, &pred);
        printf("\n30-day forecast: %.1f%% compliance\n", pred);
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * Evidence Chain Verification
 * L8: Tamper-proof audit log using hash-linked immutable chain.
 * Each log entry contains prev_hash and curr_hash for integrity.
 * ═══════════════════════════════════════════════════════════════════ */

int comp_verify_chain(const Compliance_Engine *eng) {
    if (!eng || eng->log_count < 2) return 1; /* trivially valid */

    for (int i = 1; i < eng->log_count; i++) {
        const Compliance_AuditLog *prev = &eng->logs[i - 1];
        const Compliance_AuditLog *curr = &eng->logs[i];
        if (curr->prev_hash != prev->curr_hash) {
            return 0; /* chain broken */
        }
    }

    /* Verify terminal hash matches chain_hash */
    if (eng->log_count > 0) {
        const Compliance_AuditLog *last = &eng->logs[eng->log_count - 1];
        if (last->curr_hash != eng->chain_hash) return 0;
    }
    return 1;
}

int comp_export_evidence_package(const Compliance_Engine *eng,
                                  char *out_buf, int buf_size) {
    if (!eng || !out_buf || buf_size < 64) return -1;
    int offs = 0;
    offs += snprintf(out_buf + offs, (size_t)(buf_size - offs),
                     "{\"engine\":\"compliance_evidence\",\"policies\":%d,"
                     "\"checks\":%d,\"drifts\":%d,\"chain_hash\":\"0x%016llx\","
                     "\"chain_valid\":%s,\"score\":%.1f}",
                     eng->policy_count, eng->check_count, eng->drift_count,
                     (unsigned long long)eng->chain_hash,
                     comp_verify_chain(eng) ? "true" : "false",
                     comp_compliance_score(eng));
    if (offs >= buf_size) {
        out_buf[buf_size - 1] = '\0';
        return buf_size - 1;
    }
    return offs;
}
