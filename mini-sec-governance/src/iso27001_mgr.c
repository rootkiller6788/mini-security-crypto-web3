#include "iso27001_mgr.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static const char *domain_names[ISO27001_ANNEX_A_DOMAINS] = {
    "A5 - Information Security Policies",
    "A6 - Organisation of Information Security",
    "A7 - Human Resource Security",
    "A8 - Asset Management",
    "A9 - Access Control",
    "A10 - Cryptography",
    "A11 - Physical & Environmental Security",
    "A12 - Operations Security",
    "A13 - Communications Security",
    "A14 - System Acquisition, Development & Maintenance",
    "A15 - Supplier Relationships",
    "A16 - Info Security Incident Management",
    "A17 - Info Security Aspects of Business Continuity",
    "A18 - Compliance"
};

static const char *status_names[] = {
    "Not Implemented", "Partial", "Full", "N/A"
};

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
