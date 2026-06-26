#include "nist_csf.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    NIST_CSF_Framework fw;
    nist_csf_init(&fw);

    printf("=== NIST Cybersecurity Framework Example ===\n");
    printf("Core Categories loaded:   %d\n", fw.category_count);
    printf("Core Subcategories loaded: %d\n\n", fw.subcategory_count);

    printf("NIST CSF Functions:\n");
    NIST_CSF_Function funcs[] = {
        NIST_CSF_IDENTIFY, NIST_CSF_PROTECT, NIST_CSF_DETECT,
        NIST_CSF_RESPOND, NIST_CSF_RECOVER
    };
    for (int i = 0; i < 5; i++) {
        int cnt = 0;
        for (int j = 0; j < fw.category_count; j++) {
            if (fw.categories[j].function == funcs[i]) cnt++;
        }
        printf("  %-10s: %d categories\n", nist_csf_function_name(funcs[i]), cnt);
    }

    printf("\n");

    nist_csf_set_org_tier(&fw, NIST_TIER_2_RISK_INFORMED);
    printf("Organization Tier: %s\n", nist_csf_tier_name(fw.org_tier));

    nist_csf_add_profile_item(&fw, "ID.AM-1", NIST_TIER_1_PARTIAL,       NIST_TIER_3_REPEATABLE, "Implement CMDB", 1);
    nist_csf_add_profile_item(&fw, "ID.AM-2", NIST_TIER_1_PARTIAL,       NIST_TIER_3_REPEATABLE, "Deploy inventory tool", 1);
    nist_csf_add_profile_item(&fw, "ID.RA-1", NIST_TIER_2_RISK_INFORMED, NIST_TIER_3_REPEATABLE, "Automate vulnerability scans", 2);
    nist_csf_add_profile_item(&fw, "PR.AC-1", NIST_TIER_2_RISK_INFORMED, NIST_TIER_3_REPEATABLE, "Deploy SSO solution", 1);
    nist_csf_add_profile_item(&fw, "PR.DS-1", NIST_TIER_2_RISK_INFORMED, NIST_TIER_4_ADAPTIVE,   "Implement data classification + DLP", 3);
    nist_csf_add_profile_item(&fw, "DE.CM-1", NIST_TIER_1_PARTIAL,       NIST_TIER_4_ADAPTIVE,   "Deploy SIEM + SOAR", 2);
    nist_csf_add_profile_item(&fw, "RS.RP-1", NIST_TIER_1_PARTIAL,       NIST_TIER_3_REPEATABLE, "Create IR playbooks", 2);
    nist_csf_add_profile_item(&fw, "RC.RP-1", NIST_TIER_1_PARTIAL,       NIST_TIER_2_RISK_INFORMED, "Test DR plan", 3);

    printf("Profile items: %d\n\n", fw.profile_count);

    NIST_CSF_ProfileItem gaps[NIST_CSF_MAX_GAP_ITEMS];
    int gap_count = nist_csf_gap_analysis(&fw, gaps, NIST_CSF_MAX_GAP_ITEMS);
    nist_csf_gap_report(gaps, gap_count);

    nist_csf_add_80053_control(&fw, "AC-1",  NIST_80053_FAM_AC, "Access Control Policy and Procedures",
        "Develop, document, and disseminate an access control policy", 1);
    nist_csf_add_80053_control(&fw, "AC-2",  NIST_80053_FAM_AC, "Account Management",
        "Manage information system accounts", 1);
    nist_csf_add_80053_control(&fw, "AU-2",  NIST_80053_FAM_AU, "Audit Events",
        "Determine auditable events", 2);
    nist_csf_add_80053_control(&fw, "CM-2",  NIST_80053_FAM_CM, "Baseline Configuration",
        "Develop and maintain a baseline configuration", 1);
    nist_csf_add_80053_control(&fw, "IA-2",  NIST_80053_FAM_IA, "Identification and Authentication",
        "Uniquely identify and authenticate users", 1);
    nist_csf_add_80053_control(&fw, "IR-4",  NIST_80053_FAM_IR, "Incident Handling",
        "Implement incident handling capability", 1);
    nist_csf_add_80053_control(&fw, "RA-3",  NIST_80053_FAM_RA, "Risk Assessment",
        "Conduct risk assessments", 2);
    nist_csf_add_80053_control(&fw, "SC-7",  NIST_80053_FAM_SC, "Boundary Protection",
        "Monitor and control communications at boundaries", 1);
    nist_csf_add_80053_control(&fw, "SC-13", NIST_80053_FAM_SC, "Cryptographic Protection",
        "Implement cryptographic mechanisms", 1);
    nist_csf_add_80053_control(&fw, "SI-4",  NIST_80053_FAM_SI, "Information System Monitoring",
        "Monitor the information system for attacks", 2);
    nist_csf_add_80053_control(&fw, "CP-2",  NIST_80053_FAM_CP, "Contingency Plan",
        "Develop a contingency plan", 2);
    nist_csf_add_80053_control(&fw, "MP-4",  NIST_80053_FAM_MP, "Media Storage",
        "Physically control and securely store media", 3);

    printf("\nNIST SP 800-53 Controls: %d\n", fw.control_count);
    for (int i = 0; i < fw.control_count; i++) {
        printf("  %-8s %-30s [Priority: %d]\n",
               fw.controls[i].control_id,
               nist_80053_family_name(fw.controls[i].family),
               fw.controls[i].priority);
    }

    int fisma = nist_fisma_assessment(&fw);
    printf("\nFISMA/FedRAMP Assessment Score: %d/100\n", fisma);
    printf("Compliance Level: %s\n",
           fisma >= 75 ? "High (FedRAMP High ready)" :
           fisma >= 50 ? "Moderate (FedRAMP Moderate ready)" :
           fisma >= 25 ? "Low (FedRAMP Low ready)" : "Not compliant");

    return 0;
}
