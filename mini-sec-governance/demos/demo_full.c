/*
 * mini-sec-governance — Full Demo: Security Governance
 *
 * Demonstrates: ISO27001 ISMS, SOC2 audit, NIST CSF,
 *               risk assessment, compliance automation.
 */
#include "../include/iso27001_mgr.h"
#include "../include/soc2_audit.h"
#include "../include/nist_csf.h"
#include "../include/risk_assess.h"
#include "../include/compliance_auto.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    printf("╔══════════════════════════════════════════╗\n");
    printf("║   mini-sec-governance: Security GRC     ║\n");
    printf("╚══════════════════════════════════════════╝\n\n");

    /* Step 1: ISO27001 ISMS */
    printf("── Step 1: ISO 27001 ISMS ──\n");
    ISO27001_ISMS isms;
    iso27001_init(&isms, 2024);
    iso27001_add_asset(&isms, "Customer Database", "DBA Team", "confidential", 500000.0, 1);
    iso27001_add_asset(&isms, "Web Application", "DevOps", "public", 200000.0, 1);
    iso27001_add_asset(&isms, "HR System", "HR Dept", "internal", 300000.0, 1);
    printf("Assets registered: %d\n", isms.asset_count);

    iso27001_add_threat(&isms, "SQL Injection Attack", "external", 0.8, 0.7);
    iso27001_add_threat(&isms, "Insider Data Leak", "internal", 0.4, 0.9);
    iso27001_add_threat(&isms, "Ransomware", "external", 0.6, 0.8);
    printf("Threats registered: %d\n", isms.threat_count);

    int readiness = iso27001_certification_readiness(&isms);
    printf("Certification readiness score: %d/100\n", readiness);

    iso27001_add_control(&isms, "A.9.2.1", "User registration and de-registration");
    iso27001_add_control(&isms, "A.12.2.1", "Controls against malware");
    iso27001_add_control(&isms, "A.14.2.1", "Secure development policy");
    printf("Controls implemented: %d\n", isms.control_count);

    /* Step 2: SOC2 Audit */
    printf("\n── Step 2: SOC 2 Audit ──\n");
    SOC2_Engagement eng;
    soc2_init_engagement(&eng);

    soc2_add_control(&eng, SOC2_TC_SECURITY, "CC6.1", "Logical Access", "Review access logs quarterly");
    soc2_add_control(&eng, SOC2_TC_SECURITY, "CC6.6", "External Threats", "IDS/IPS monitoring");
    soc2_add_control(&eng, SOC2_TC_AVAILABILITY, "CC7.1", "BC/DR", "Annual DR test");
    soc2_add_control(&eng, SOC2_TC_CONFIDENTIALITY, "CC6.7", "Data Encryption", "AES-256 at rest");
    soc2_add_control(&eng, SOC2_TC_PRIVACY, "P1.1", "Privacy Notice", "Published privacy policy");
    printf("Controls added: %d (across %d TSCs)\n", eng.control_count, 4);

    SOC2_AuditReport report;
    soc2_generate_report(&eng, &report, SOC2_REPORT_TYPE_II, 2024,
                         SOC2_TC_SECURITY | SOC2_TC_AVAILABILITY | SOC2_TC_CONFIDENTIALITY,
                         "Big4 Auditor", "Example Corp");
    printf("Report: Type=%d, Year=%d\n", report.report_type, report.period_year);
    printf("  Auditor: %s\n", report.auditor_name);
    printf("  Organization: %s\n", report.organization_name);

    /* Step 3: NIST CSF */
    printf("\n── Step 3: NIST Cybersecurity Framework ──\n");
    NIST_CSF_Framework fw;
    nist_csf_init(&fw);
    nist_csf_load_core(&fw);

    printf("NIST CSF loaded: %d functions, %d categories\n",
           fw.function_count, fw.category_count);

    const char *functions[] = {"Identify", "Protect", "Detect", "Respond", "Recover"};
    for (int i = 0; i < 5; i++) {
        int score = nist_csf_function_score(&fw, functions[i]);
        printf("  %s: %d/100\n", functions[i], score);
    }

    int gaps = nist_csf_gap_analysis(&fw, NULL, 0);
    printf("Gap analysis: %d gaps identified\n", gaps);

    /* Step 4: Risk Assessment */
    printf("\n── Step 4: Risk Assessment ──\n");
    Risk_Register reg;
    risk_init(&reg, 15.0);

    risk_add_asset(&reg, "Payment Gateway", RISK_CLASS_CONFIDENT, "Finance", 1000000.0, 1);
    risk_add_asset(&reg, "Customer PII", RISK_CLASS_CONFIDENT, "Legal", 500000.0, 2);
    printf("Risk assets: %d\n", reg.asset_count);

    risk_add_threat(&reg, RISK_STRIDE_TAMPERING, "Payment Manipulation",
                    "Database tampering", "criminal", RISK_PROB_MODERATE, 0.7, 0.1);
    risk_add_threat(&reg, RISK_STRIDE_INFO_DISCLOSURE, "Data Breach",
                    "PII exposure via API", "criminal", RISK_PROB_LIKELY, 0.9, 0.05);
    printf("Threats: %d\n", reg.threat_count);

    risk_add_entry(&reg, 0, 0, RISK_PROB_MODERATE, RISK_IMPACT_MAJOR, 500000.0);
    risk_add_entry(&reg, 1, 1, RISK_PROB_LIKELY, RISK_IMPACT_MAJOR, 750000.0);
    printf("Risk entries: %d\n", reg.entry_count);

    risk_recalculate(&reg);
    double total_risk = risk_total_exposure(&reg);
    printf("Total risk exposure: $%.0f\n", total_risk);

    for (int i = 0; i < reg.entry_count; i++) {
        printf("  Risk[%d]: inherent=%.0f, residual=%.0f, level=%d\n",
               i, reg.entries[i].inherent_risk, reg.entries[i].residual_risk, reg.entries[i].risk_level);
    }

    /* Step 5: Compliance Automation */
    printf("\n── Step 5: Compliance Automation ──\n");
    Compliance_Engine comp_eng;
    comp_init(&comp_eng);

    Compliance_Regulation gdpr[] = {COMP_REG_GDPR};
    Compliance_Regulation pcidss[] = {COMP_REG_PCI_DSS};

    comp_add_policy(&comp_eng, "data-encryption", "Encrypt all personal data at rest",
                    "config.encryption == 'on'", "config.encryption", "on", 5, gdpr, 1);
    comp_add_policy(&comp_eng, "access-logging", "Log all access to PII",
                    "config.access_log == 'enabled'", "config.access_log", "enabled", 4, gdpr, 1);
    comp_add_policy(&comp_eng, "card-data-protection", "Never store full card numbers",
                    "config.store_card == 'never'", "config.store_card", "never", 5, pcidss, 1);
    printf("Compliance policies: %d\n", comp_eng.policy_count);

    bool enc_ok = comp_check_policy(&comp_eng, 0, "on");
    bool log_ok = comp_check_policy(&comp_eng, 1, "enabled");
    bool card_ok = comp_check_policy(&comp_eng, 2, "never");
    printf("Policy 'data-encryption': %s\n", enc_ok ? "COMPLIANT" : "NON-COMPLIANT");
    printf("Policy 'access-logging': %s\n", log_ok ? "COMPLIANT" : "NON-COMPLIANT");
    printf("Policy 'card-data-protection': %s\n", card_ok ? "COMPLIANT" : "NON-COMPLIANT");

    int compliant = comp_count_compliant(&comp_eng, "on", "enabled", "never");
    printf("Compliance score: %d/%d\n", compliant, comp_eng.policy_count);

    printf("\n✓ Full security governance demo complete!\n");
    return 0;
}
