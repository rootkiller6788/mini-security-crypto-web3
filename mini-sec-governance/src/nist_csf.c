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
        s->80053_ref_count = subs[i].rc;
        for (int j = 0; j < subs[i].rc && j < 8; j++) {
            s->80053_refs[j] = subs[i].refs[j];
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
