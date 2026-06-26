#include "nist_csf.h"
#include <stdio.h>
#include <string.h>

int nist_csf_init(NIST_CSF_Framework *fw) {
    if (!fw) return -1;
    memset(fw, 0, sizeof(*fw));
    fw->org_tier = NIST_TIER_1_PARTIAL;
    nist_csf_load_core(fw);
    return 0;
}

void nist_csf_load_core(NIST_CSF_Framework *fw) {
    static const struct {
        NIST_CSF_Function f; const char *name; const char *cat_id; const char *desc;
    } cats[] = {
        {NIST_CSF_IDENTIFY, "Asset Management",             "ID.AM", "Data, personnel, devices, systems, facilities"},
        {NIST_CSF_IDENTIFY, "Business Environment",          "ID.BE", "Mission, objectives, stakeholders, activities"},
        {NIST_CSF_IDENTIFY, "Governance",                    "ID.GV", "Policies, procedures, processes for security"},
        {NIST_CSF_IDENTIFY, "Risk Assessment",               "ID.RA", "Asset vulnerabilities, threats, impacts"},
        {NIST_CSF_IDENTIFY, "Risk Management Strategy",      "ID.RM", "Risk tolerance, prioritization"},
        {NIST_CSF_IDENTIFY, "Supply Chain Risk Management",  "ID.SC", "Cyber supply chain risk management"},
        {NIST_CSF_PROTECT,  "Identity Management & Access",  "PR.AC", "Access to physical and logical assets"},
        {NIST_CSF_PROTECT,  "Awareness & Training",          "PR.AT", "Personnel security awareness training"},
        {NIST_CSF_PROTECT,  "Data Security",                 "PR.DS", "Data-at-rest, in-transit, in-use protection"},
        {NIST_CSF_PROTECT,  "Info Protection Procedures",    "PR.IP", "Configuration, change, maintenance management"},
        {NIST_CSF_PROTECT,  "Maintenance",                   "PR.MA", "Remote and on-site maintenance"},
        {NIST_CSF_PROTECT,  "Protective Technology",         "PR.PT", "Technical security solutions"},
        {NIST_CSF_DETECT,   "Anomalies & Events",            "DE.AE", "Anomalous activity detection"},
        {NIST_CSF_DETECT,   "Security Continuous Monitoring","DE.CM", "Continuous monitoring"},
        {NIST_CSF_DETECT,   "Detection Processes",           "DE.DP", "Detection process testing"},
        {NIST_CSF_RESPOND,  "Response Planning",             "RS.RP", "Response plan execution"},
        {NIST_CSF_RESPOND,  "Communications",                "RS.CO", "Response communication"},
        {NIST_CSF_RESPOND,  "Analysis",                       "RS.AN", "Analysis to ensure adequate response"},
        {NIST_CSF_RESPOND,  "Mitigation",                     "RS.MI", "Incident mitigation and containment"},
        {NIST_CSF_RESPOND,  "Improvements",                   "RS.IM", "Response improvements from lessons learned"},
        {NIST_CSF_RECOVER,  "Recovery Planning",             "RC.RP", "Recovery plan execution"},
        {NIST_CSF_RECOVER,  "Improvements",                   "RC.IM", "Recovery improvements"},
        {NIST_CSF_RECOVER,  "Communications",                "RC.CO", "Recovery communication"},
    };
    int n = (int)(sizeof(cats) / sizeof(cats[0]));
    for (int i = 0; i < n && fw->category_count < NIST_CSF_MAX_CATEGORIES; i++) {
        NIST_CSF_Category *c = &fw->categories[fw->category_count++];
        c->function    = cats[i].f;
        c->name        = cats[i].name;
        c->category_id = cats[i].cat_id;
        c->description = cats[i].desc;
    }

    static const struct {
        NIST_CSF_Function f; const char *sid; const char *desc; int refs[2]; int rc;
    } subs[] = {
        {NIST_CSF_IDENTIFY, "ID.AM-1", "Physical devices and systems inventoried",  {0,1}, 2},
        {NIST_CSF_IDENTIFY, "ID.AM-2", "Software platforms and apps inventoried",   {1,2}, 2},
        {NIST_CSF_IDENTIFY, "ID.BE-1", "Organization's role in supply chain identified", {3,4}, 2},
        {NIST_CSF_IDENTIFY, "ID.RA-1", "Asset vulnerabilities identified",           {5,6}, 2},
        {NIST_CSF_PROTECT,  "PR.AC-1", "Identities and credentials managed",        {7,8}, 2},
        {NIST_CSF_PROTECT,  "PR.DS-1", "Data-at-rest protected",                     {9,10},2},
        {NIST_CSF_PROTECT,  "PR.DS-2", "Data-in-transit protected",                  {10,11},2},
        {NIST_CSF_DETECT,   "DE.CM-1", "Network monitored for security events",     {12,13},2},
        {NIST_CSF_DETECT,   "DE.CM-2", "Physical environment monitored",             {13,14},2},
        {NIST_CSF_RESPOND,  "RS.RP-1", "Response plan executed during incident",    {15,16},2},
        {NIST_CSF_RESPOND,  "RS.MI-1", "Incidents contained",                        {16,17},2},
        {NIST_CSF_RECOVER,  "RC.RP-1", "Recovery plan executed during event",        {17,18},2},
    };
    n = (int)(sizeof(subs) / sizeof(subs[0]));
    for (int i = 0; i < n && fw->subcategory_count < NIST_CSF_MAX_SUBCATEGORIES; i++) {
        NIST_CSF_Subcategory *s = &fw->subcategories[fw->subcategory_count++];
        s->function       = subs[i].f;
        s->subcategory_id = subs[i].sid;
        s->description    = subs[i].desc;
        s->nist_ref_count = subs[i].rc;
        for (int j = 0; j < subs[i].rc && j < 8; j++) {
            s->nist_refs[j] = subs[i].refs[j];
        }
    }
}

int nist_csf_set_org_tier(NIST_CSF_Framework *fw, NIST_CSF_Tier tier) {
    if (!fw || tier < NIST_TIER_1_PARTIAL || tier > NIST_TIER_4_ADAPTIVE) return -1;
    fw->org_tier = tier;
    return 0;
}

int nist_csf_add_profile_item(NIST_CSF_Framework *fw, const char *subcat_id,
                               NIST_CSF_Tier current, NIST_CSF_Tier target,
                               const char *remediation, int priority) {
    if (!fw || fw->profile_count >= NIST_CSF_MAX_PROFILE_ITEMS) return -1;
    NIST_CSF_ProfileItem *p = &fw->profile[fw->profile_count];
    p->item_id        = fw->profile_count + 1;
    p->subcategory_id = subcat_id;
    p->current_tier   = current;
    p->target_tier    = target;
    p->gap            = (int)target - (int)current;
    p->remediation    = remediation;
    p->priority       = priority;
    fw->profile_count++;
    return p->item_id;
}

int nist_csf_gap_analysis(const NIST_CSF_Framework *fw,
                           NIST_CSF_ProfileItem *gaps, int max_gaps) {
    if (!fw || !gaps) return 0;
    int count = 0;
    for (int i = 0; i < fw->profile_count && count < max_gaps; i++) {
        if (fw->profile[i].gap > 0) {
            gaps[count++] = fw->profile[i];
        }
    }
    return count;
}

void nist_csf_gap_report(const NIST_CSF_ProfileItem *gaps, int gap_count) {
    printf("=== NIST CSF Gap Analysis Report ===\n");
    printf("%-15s %-10s %-10s %-6s %-10s\n",
           "Subcategory", "Current", "Target", "Gap", "Priority");
    printf("-------------------------------------------------------------\n");
    for (int i = 0; i < gap_count; i++) {
        printf("%-15s %-10s %-10s %-6d %-10d\n",
               gaps[i].subcategory_id,
               nist_csf_tier_name(gaps[i].current_tier),
               nist_csf_tier_name(gaps[i].target_tier),
               gaps[i].gap,
               gaps[i].priority);
    }
}

int nist_csf_add_80053_control(NIST_CSF_Framework *fw, const char *id,
                                NIST_80053_Family family, const char *title,
                                const char *desc, int priority) {
    if (!fw || fw->control_count >= NIST_CSF_MAX_CONTROLS) return -1;
    NIST_80053_Control *c = &fw->controls[fw->control_count++];
    c->control_id  = id;
    c->family      = family;
    c->title       = title;
    c->description = desc;
    c->priority    = priority;
    return fw->control_count;
}

const char* nist_csf_function_name(NIST_CSF_Function f) {
    switch (f) {
        case NIST_CSF_IDENTIFY: return "Identify";
        case NIST_CSF_PROTECT:  return "Protect";
        case NIST_CSF_DETECT:   return "Detect";
        case NIST_CSF_RESPOND:  return "Respond";
        case NIST_CSF_RECOVER:  return "Recover";
        default:                return "Unknown";
    }
}

const char* nist_csf_tier_name(NIST_CSF_Tier t) {
    switch (t) {
        case NIST_TIER_1_PARTIAL:       return "Tier 1";
        case NIST_TIER_2_RISK_INFORMED: return "Tier 2";
        case NIST_TIER_3_REPEATABLE:    return "Tier 3";
        case NIST_TIER_4_ADAPTIVE:      return "Tier 4";
        default:                        return "Unknown";
    }
}

const char* nist_80053_family_name(NIST_80053_Family fam) {
    switch (fam) {
        case NIST_80053_FAM_AC: return "AC - Access Control";
        case NIST_80053_FAM_AT: return "AT - Awareness and Training";
        case NIST_80053_FAM_AU: return "AU - Audit and Accountability";
        case NIST_80053_FAM_CA: return "CA - Assessment & Authorization";
        case NIST_80053_FAM_CM: return "CM - Configuration Management";
        case NIST_80053_FAM_CP: return "CP - Contingency Planning";
        case NIST_80053_FAM_IA: return "IA - Identification & Authentication";
        case NIST_80053_FAM_IR: return "IR - Incident Response";
        case NIST_80053_FAM_MA: return "MA - Maintenance";
        case NIST_80053_FAM_MP: return "MP - Media Protection";
        case NIST_80053_FAM_PE: return "PE - Physical & Environmental";
        case NIST_80053_FAM_PL: return "PL - Planning";
        case NIST_80053_FAM_PS: return "PS - Personnel Security";
        case NIST_80053_FAM_RA: return "RA - Risk Assessment";
        case NIST_80053_FAM_SA: return "SA - System & Services Acquisition";
        case NIST_80053_FAM_SC: return "SC - System & Comms Protection";
        case NIST_80053_FAM_SI: return "SI - System & Information Integrity";
        case NIST_80053_FAM_SR: return "SR - Supply Chain Risk Management";
        default:                return "Unknown";
    }
}

int nist_fisma_assessment(const NIST_CSF_Framework *fw) {
    if (!fw) return 0;
    int score = 0;
    if (fw->org_tier >= NIST_TIER_3_REPEATABLE) score += 25;
    if (fw->control_count > 10) score += 25;
    if (fw->category_count >= 10) score += 25;
    if (fw->profile_count > 0) score += 25;
    return score;
}

/* ═══════════════════════════════════════════════════════════════════
 * NIST CSF Maturity Assessment
 * L5: Function-level maturity scoring using multi-dimensional metrics.
 * Evaluates Policy, Process, Technology, and People dimensions per
 * NIST CSF function (Identify/Protect/Detect/Respond/Recover).
 * ═══════════════════════════════════════════════════════════════════ */

int nist_csf_function_score(const NIST_CSF_Framework *fw,
                             NIST_CSF_Function func, double *score) {
    if (!fw || !score) return -1;
    int cat_count = 0, total_possible = 0;
    double achieved = 0.0;

    for (int i = 0; i < fw->category_count; i++) {
        if (fw->categories[i].function == func) {
            cat_count++;
            total_possible += 4; /* max tier level */
        }
    }

    /* Add profiled items for this function's subcategories */
    for (int i = 0; i < fw->profile_count; i++) {
        const NIST_CSF_ProfileItem *p = &fw->profile[i];
        /* Map subcategory prefix to function */
        if (p->subcategory_id) {
            char prefix[3] = {p->subcategory_id[0], p->subcategory_id[1], '\0'};
            int match = 0;
            if (strncmp(prefix, "ID", 2) == 0 && func == NIST_CSF_IDENTIFY) match = 1;
            if (strncmp(prefix, "PR", 2) == 0 && func == NIST_CSF_PROTECT)  match = 1;
            if (strncmp(prefix, "DE", 2) == 0 && func == NIST_CSF_DETECT)   match = 1;
            if (strncmp(prefix, "RS", 2) == 0 && func == NIST_CSF_RESPOND)  match = 1;
            if (strncmp(prefix, "RC", 2) == 0 && func == NIST_CSF_RECOVER)  match = 1;
            if (match) {
                achieved += (double)p->current_tier;
                total_possible += 4;
            }
        }
    }

    if (total_possible == 0) { *score = 0.0; return 0; }
    *score = 100.0 * achieved / (double)total_possible;
    return 0;
}

int nist_csf_assess_maturity(const NIST_CSF_Framework *fw,
                              NIST_CSF_MaturityAssessment *ma) {
    if (!fw || !ma) return -1;
    memset(ma, 0, sizeof(*ma));
    ma->function_count = NIST_CSF_MAX_FUNCTIONS;

    static const NIST_CSF_Function funcs[NIST_CSF_MAX_FUNCTIONS] = {
        NIST_CSF_IDENTIFY, NIST_CSF_PROTECT, NIST_CSF_DETECT,
        NIST_CSF_RESPOND, NIST_CSF_RECOVER
    };

    /* Dimensions: policy(20%), process(30%), technology(30%), people(20%) */
    static const double weights[4] = {0.20, 0.30, 0.30, 0.20};
    double total = 0.0;

    for (int i = 0; i < NIST_CSF_MAX_FUNCTIONS; i++) {
        NIST_CSF_FunctionMaturity *fm = &ma->functions[i];
        fm->function = funcs[i];

        /* Policy score: based on tier */
        fm->policy_score = (double)fw->org_tier * 25.0;

        /* Process score: based on subcategory coverage */
        int sub_count = 0;
        for (int j = 0; j < fw->subcategory_count; j++) {
            if (fw->subcategories[j].function == funcs[i]) sub_count++;
        }
        fm->process_score = sub_count > 0 ? 60.0 : 10.0;
        if (sub_count > 3) fm->process_score = 85.0;

        /* Technology score: based on 800-53 controls */
        int tech_controls = 0;
        for (int j = 0; j < fw->control_count; j++) {
            if (fw->controls[j].priority <= 3) tech_controls++;
        }
        fm->technology_score = tech_controls > 5 ? 75.0 :
                                tech_controls > 0 ? 40.0 : 15.0;

        /* People score: estimated from profile */
        fm->people_score = fw->profile_count > 0 ? 50.0 : 20.0;

        /* Weighted overall */
        fm->overall_score = fm->policy_score    * weights[0] +
                            fm->process_score   * weights[1] +
                            fm->technology_score * weights[2] +
                            fm->people_score    * weights[3];
        total += fm->overall_score;
    }

    ma->composite_score = total / (double)NIST_CSF_MAX_FUNCTIONS;
    /* Map composite score to tier */
    if (ma->composite_score >= 90.0)      ma->assessed_tier = NIST_TIER_4_ADAPTIVE;
    else if (ma->composite_score >= 65.0) ma->assessed_tier = NIST_TIER_3_REPEATABLE;
    else if (ma->composite_score >= 35.0) ma->assessed_tier = NIST_TIER_2_RISK_INFORMED;
    else                                  ma->assessed_tier = NIST_TIER_1_PARTIAL;

    return 0;
}

void nist_csf_maturity_report(const NIST_CSF_MaturityAssessment *ma) {
    if (!ma) return;
    printf("=== NIST CSF Maturity Assessment ===\n");
    printf("%-15s %-10s %-10s %-10s %-10s %-10s\n",
           "Function", "Policy", "Process", "Tech", "People", "Overall");
    printf("------------------------------------------------------------------\n");
    for (int i = 0; i < ma->function_count; i++) {
        const NIST_CSF_FunctionMaturity *fm = &ma->functions[i];
        printf("%-15s %-10.0f %-10.0f %-10.0f %-10.0f %-10.0f\n",
               nist_csf_function_name(fm->function),
               fm->policy_score, fm->process_score,
               fm->technology_score, fm->people_score,
               fm->overall_score);
    }
    printf("------------------------------------------------------------------\n");
    printf("Composite Score: %.0f/100 | Assessed Tier: %s\n",
           ma->composite_score, nist_csf_tier_name(ma->assessed_tier));
}

/* ═══════════════════════════════════════════════════════════════════
 * NIST CSF Profile Comparison Engine
 * L5: Compares Current vs Target profile, identifies gaps with
 *     quantitative implementation percentages.
 * ═══════════════════════════════════════════════════════════════════ */

int nist_csf_profile_diff(const NIST_CSF_Framework *fw,
                           NIST_CSF_ProfileGap *gaps, int max_gaps) {
    if (!fw || !gaps) return 0;
    int count = 0;
    for (int i = 0; i < fw->profile_count && count < max_gaps; i++) {
        const NIST_CSF_ProfileItem *p = &fw->profile[i];
        if (p->gap > 0) {
            NIST_CSF_ProfileGap *g = &gaps[count];
            g->subcategory_id      = p->subcategory_id;
            g->current             = p->current_tier;
            g->target              = p->target_tier;
            g->gap_levels          = p->gap;
            g->implementation_pct  = (double)p->current_tier * 25.0;
            g->recommendation      = p->remediation;
            count++;
        }
    }
    return count;
}

void nist_csf_profile_diff_report(const NIST_CSF_ProfileGap *gaps,
                                   int gap_count) {
    printf("=== NIST CSF Profile Comparison (Current vs Target) ===\n");
    printf("%-15s %-10s %-10s %-5s %-8s %s\n",
           "Subcategory", "Current", "Target", "Gap", "Impl%", "Recommendation");
    printf("------------------------------------------------------------------\n");
    for (int i = 0; i < gap_count; i++) {
        printf("%-15s %-10s %-10s %-5d %-8.0f %s\n",
               gaps[i].subcategory_id,
               nist_csf_tier_name(gaps[i].current),
               nist_csf_tier_name(gaps[i].target),
               gaps[i].gap_levels,
               gaps[i].implementation_pct,
               gaps[i].recommendation ? gaps[i].recommendation : "N/A");
    }
}

int nist_csf_implementation_pct(const NIST_CSF_Framework *fw,
                                 NIST_CSF_Function func) {
    if (!fw) return -1;
    double score;
    if (nist_csf_function_score(fw, func, &score) != 0) return -1;
    return (int)score;
}

/* ═══════════════════════════════════════════════════════════════════
 * Supply Chain Risk Management (NIST SP 800-161)
 * L8: Cyber Supply Chain Risk Management — tiered supplier
 *     assessment, criticality classification, and aggregate risk.
 * Ref: NIST SP 800-161 Rev 1 "C-SCRM Practices"
 * ═══════════════════════════════════════════════════════════════════ */

int nist_scrm_add_supplier(NIST_CSF_Framework *fw, const char *name,
                            NIST_SCRM_Tier tier, int is_critical,
                            double assessed_risk, int year,
                            int has_bcp, int has_ir) {
    if (!fw || fw->supplier_count >= 64) return -1;
    NIST_SCRM_Supplier *s = &fw->suppliers[fw->supplier_count];
    s->supplier_id          = fw->supplier_count + 1;
    s->name                 = name;
    s->tier                 = tier;
    s->is_critical          = is_critical;
    s->assessed_risk        = assessed_risk;
    s->last_assessment_year = year;
    s->has_bcp              = has_bcp;
    s->has_incident_response = has_ir;
    fw->supplier_count++;
    return s->supplier_id;
}

void nist_scrm_risk_heatmap(const NIST_CSF_Framework *fw) {
    if (!fw) return;
    printf("=== Supply Chain Risk Heatmap (NIST SP 800-161) ===\n");
    printf("%-4s %-25s %-12s %-8s %-10s %-8s\n",
           "ID", "Supplier", "Tier", "Critical", "Risk", "BCP+IR");
    printf("-------------------------------------------------------------\n");
    for (int i = 0; i < fw->supplier_count; i++) {
        const NIST_SCRM_Supplier *s = &fw->suppliers[i];
        const char *tier_name;
        switch (s->tier) {
            case NIST_SCRM_TIER1_DIRECT:      tier_name = "Tier-1"; break;
            case NIST_SCRM_TIER2_INDIRECT:    tier_name = "Tier-2"; break;
            case NIST_SCRM_TIER3_SUBCONTRACT: tier_name = "Tier-3"; break;
            case NIST_SCRM_TIER4_MATERIAL:    tier_name = "Tier-4"; break;
            default:                          tier_name = "?";      break;
        }
        printf("S%-3d %-25s %-12s %-8s %-10.1f %s\n",
               s->supplier_id, s->name, tier_name,
               s->is_critical ? "YES" : "no",
               s->assessed_risk,
               (s->has_bcp && s->has_incident_response) ? "Both" :
               s->has_bcp ? "BCP" : s->has_incident_response ? "IR" : "None");
    }
}

int nist_scrm_critical_suppliers(const NIST_CSF_Framework *fw,
                                  int *supplier_ids, int max_count) {
    if (!fw || !supplier_ids) return 0;
    int count = 0;
    for (int i = 0; i < fw->supplier_count && count < max_count; i++) {
        if (fw->suppliers[i].is_critical) {
            supplier_ids[count++] = fw->suppliers[i].supplier_id;
        }
    }
    return count;
}

double nist_scrm_aggregate_risk(const NIST_CSF_Framework *fw) {
    if (!fw || fw->supplier_count == 0) return 0.0;
    double total = 0.0;
    int weighted_count = 0;
    for (int i = 0; i < fw->supplier_count; i++) {
        double weight = fw->suppliers[i].is_critical ? 3.0 : 1.0;
        /* Higher tier = closer to org = higher weight */
        if (fw->suppliers[i].tier == NIST_SCRM_TIER1_DIRECT) weight *= 1.5;
        if (fw->suppliers[i].tier == NIST_SCRM_TIER2_INDIRECT) weight *= 1.2;
        total += fw->suppliers[i].assessed_risk * weight;
        weighted_count++;
    }
    return weighted_count > 0 ? total / (double)weighted_count : 0.0;
}
