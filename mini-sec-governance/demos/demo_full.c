/*
 * mini-sec-governance — Full Demo: End-to-End Security GRC Platform
 */
#include "../include/iso27001_mgr.h"
#include "../include/soc2_audit.h"
#include "../include/nist_csf.h"
#include "../include/risk_assess.h"
#include "../include/compliance_auto.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    printf("=== mini-sec-governance: Full GRC Platform Demo ===\n\n");
    ISO27001_ISMS isms;
    iso27001_init(&isms, 2025);
    iso27001_load_annex_a(&isms);
    iso27001_init_clauses(&isms);
    iso27001_update_clause(&isms, 4, 6);
    iso27001_update_clause(&isms, 5, 5);
    iso27001_add_asset(&isms, "Customer PII DB", "DBA Team", "RESTRICTED", 2000000.0, 1);
    iso27001_add_threat(&isms, "Ransomware", "External", 0.9, 0.8);
    iso27001_add_risk(&isms, 1, 1, 4.5, 5);
    iso27001_generate_soa(&isms);
    iso27001_add_kpi(&isms, "Patch Compliance", "% hosts", 95.0, 85.0, 70.0, 5);
    iso27001_update_kpi(&isms, 1, 93.5);
    iso27001_set_risk_appetite(&isms, 500000.0, 12.0, 2, 5);
    iso27001_add_incident(&isms, "Phishing", "Spear", "SOC", 2025, 3, 2);
    iso27001_resolve_incident(&isms, 1, "Click link", "MFA deployed", 4.0, 8.0);
    iso27001_pdca_report(&isms);
    iso27001_kpi_scorecard(&isms);
    iso27001_incident_report(&isms);
    double mttr;
    iso27001_mean_time_to_resolve(&isms, &mttr);
    printf("MTTR: %.1f hours\n", mttr);

    printf("\n-- Step 2: SOC 2 Audit --\n");
    SOC2_Engagement eng;
    soc2_init_engagement(&eng);
    soc2_add_control(&eng, SOC2_TC_SECURITY, "CC6.1", "Access", "Check");
    soc2_add_control(&eng, SOC2_TC_AVAILABILITY, "CC7.1", "BC/DR", "Annual test");
    SOC2_AuditSample sample;
    soc2_attribute_sampling(&eng, SOC2_TC_SECURITY, &sample);
    soc2_evaluate_sample(&sample, 1);
    soc2_sample_report(&sample);
    SOC2_AuditReport report;
    soc2_generate_report(&eng, &report, SOC2_REPORT_TYPE_II, 2025,
        SOC2_TC_SECURITY | SOC2_TC_AVAILABILITY | SOC2_TC_CONFIDENTIAL, "E&Y", "Corp");
    soc2_summary(&report);

    printf("\n-- Step 3: NIST CSF --\n");
    NIST_CSF_Framework fw;
    nist_csf_init(&fw);
    nist_csf_set_org_tier(&fw, NIST_TIER_3_REPEATABLE);
    nist_csf_add_profile_item(&fw, "ID.AM-1", NIST_TIER_3_REPEATABLE, NIST_TIER_4_ADAPTIVE, "CMDB", 1);
    nist_csf_add_80053_control(&fw, "AC-2", NIST_80053_FAM_AC, "Account Mgmt", "Manage", 5);
    NIST_CSF_MaturityAssessment ma;
    nist_csf_assess_maturity(&fw, &ma);
    nist_csf_maturity_report(&ma);
    nist_scrm_add_supplier(&fw, "Cloud-X", NIST_SCRM_TIER1_DIRECT, 1, 65.0, 2024, 1, 1);
    nist_scrm_risk_heatmap(&fw);

    printf("\n-- Step 4: Risk Analysis --\n");
    Risk_Register reg;
    risk_init(&reg, 500000.0);
    risk_add_asset(&reg, "Customer DB", RISK_CLASS_RESTRICTED, "DB Team", 2000000.0, 1);
    risk_add_threat(&reg, RISK_STRIDE_SPOOFING, "Credential Theft", "Phishing", "External", RISK_PROB_MODERATE, 4.0, 2.5);
    risk_add_entry(&reg, 1, 1, RISK_PROB_MODERATE, RISK_IMPACT_CATASTROPHIC, 2000000.0);
    risk_set_treatment(&reg, 1, RISK_TREATMENT_MITIGATE, "MFA + EDR", 50000.0);
    risk_report(&reg);
    Risk_FAIR_Model fair;
    risk_fair_from_register(&reg, 1, &fair);
    risk_fair_compute(&fair);
    printf("FAIR ALE: $%.0f\n", fair.annualized_loss);
    Risk_MonteCarloResult mc;
    risk_monte_carlo_ale(&reg, 1, 10000, &mc);
    risk_mc_summary(&mc);

    printf("\n-- Step 5: Compliance Automation --\n");
    Compliance_Engine comp;
    comp_init(&comp);
    comp_add_regulation(&comp, COMP_REG_GDPR);
    Compliance_Regulation gdpr[] = {COMP_REG_GDPR};
    comp_add_policy(&comp, "Data-Enc", "AES-256", "rule", "config.enc", "AES256", 5, gdpr, 1);
    comp_check_policy(&comp, 1, "AES256");
    comp_add_log(&comp, "admin", "CREATE", "Data-Enc", "OK");
    comp_add_log(&comp, "auditor", "CHECK", "policy", "pass");
    comp_update_dashboard(&comp);
    comp_dashboard_display(&comp);
    comp_audit_trail(&comp);
    for (int i = 0; i < 3; i++) comp_record_trend(&comp);
    comp_trend_report(&comp);
    comp_assess_maturity(&comp);
    printf("Maturity: %s Chain: %s\n",
        comp_maturity_level_name(comp.maturity.overall),
        comp_verify_chain(&comp) ? "valid" : "broken");

    printf("\n=== Full GRC Demo Complete ===\n");
    return 0;
}
