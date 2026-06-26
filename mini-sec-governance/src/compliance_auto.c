#include "compliance_auto.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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
