#include "risk_assess.h"
#include <stdio.h>

int main(void) {
    Risk_Register reg;
    risk_init(&reg, 500000.0);

    printf("=== Risk Assessment Demo (Quantitative & Qualitative) ===\n\n");

    risk_add_asset(&reg, "Customer PII Database",    RISK_CLASS_RESTRICTED, "DB Team",     2000000.0, 1);
    risk_add_asset(&reg, "Payment Processing System", RISK_CLASS_RESTRICTED, "Payments",    1500000.0, 1);
    risk_add_asset(&reg, "Internal Wiki",             RISK_CLASS_INTERNAL,   "IT",           50000.0, 0);
    risk_add_asset(&reg, "Cloud Infrastructure",      RISK_CLASS_CONFIDENT,  "Platform",   3000000.0, 1);
    risk_add_asset(&reg, "Employee HR System",        RISK_CLASS_INTERNAL,   "HR",          200000.0, 0);
    risk_add_asset(&reg, "Public Marketing Site",     RISK_CLASS_PUBLIC,     "Marketing",    25000.0, 0);

    printf("Assets Registered:\n");
    for (int i = 0; i < reg.asset_count; i++) {
        printf("  [%d] %-30s Class: %-12s Value: $%.0f %s\n",
               reg.assets[i].asset_id, reg.assets[i].name,
               risk_class_name(reg.assets[i].data_class),
               reg.assets[i].monetary_value,
               reg.assets[i].is_critical ? "[CRITICAL]" : "");
    }

    printf("\n");

    risk_add_threat(&reg, RISK_STRIDE_SPOOFING,    "Credential Theft",
        "Attacker steals user credentials via phishing",         "External Attacker",  RISK_PROB_MODERATE,  4.0, 2.5);
    risk_add_threat(&reg, RISK_STRIDE_TAMPERING,   "Data Manipulation",
        "Unauthorized modification of database records",        "Malicious Insider",  RISK_PROB_LOW,       3.0, 0.5);
    risk_add_threat(&reg, RISK_STRIDE_REPUDIATION, "Transaction Denial",
        "User denies performing a financial transaction",       "User",               RISK_PROB_MODERATE,  2.0, 3.0);
    risk_add_threat(&reg, RISK_STRIDE_INFO_DISCL,  "Data Exfiltration",
        "Sensitive data exfiltrated via compromised endpoint",   "APT Group",          RISK_PROB_LOW,       5.0, 0.8);
    risk_add_threat(&reg, RISK_STRIDE_DOS,         "DDoS Attack",
        "Volumetric attack overwhelming network capacity",      "Botnet Operator",    RISK_PROB_HIGH,      4.5, 4.0);
    risk_add_threat(&reg, RISK_STRIDE_ELEVATION,   "Privilege Escalation",
        "Attacker gains admin privileges after initial access",  "External Attacker",  RISK_PROB_MODERATE,  4.0, 1.5);

    printf("Threats Registered:\n");
    for (int i = 0; i < reg.threat_count; i++) {
        printf("  [%d] %-20s STRIDE: %-18s Prob: %d Cap: %.1f ARO: %.1f\n",
               reg.threats[i].threat_id, reg.threats[i].name,
               risk_stride_name(reg.threats[i].stride_cat),
               (int)reg.threats[i].prob,
               reg.threats[i].capability,
               reg.threats[i].annual_rate);
    }

    printf("\n");

    risk_add_entry(&reg, 1, 1, RISK_PROB_MODERATE, RISK_IMPACT_CATASTROPHIC, 2000000.0);
    risk_add_entry(&reg, 1, 4, RISK_PROB_LOW,      RISK_IMPACT_CATASTROPHIC, 2000000.0);
    risk_add_entry(&reg, 2, 2, RISK_PROB_LOW,      RISK_IMPACT_MAJOR,         500000.0);
    risk_add_entry(&reg, 2, 3, RISK_PROB_MODERATE, RISK_IMPACT_MODERATE,      100000.0);
    risk_add_entry(&reg, 4, 5, RISK_PROB_HIGH,     RISK_IMPACT_MAJOR,        1000000.0);
    risk_add_entry(&reg, 4, 6, RISK_PROB_MODERATE, RISK_IMPACT_MAJOR,        1000000.0);
    risk_add_entry(&reg, 3, 1, RISK_PROB_HIGH,     RISK_IMPACT_NEGLIGIBLE,     10000.0);
    risk_add_entry(&reg, 5, 3, RISK_PROB_MODERATE, RISK_IMPACT_MINOR,          50000.0);
    risk_add_entry(&reg, 6, 5, RISK_PROB_LOW,      RISK_IMPACT_NEGLIGIBLE,      5000.0);

    printf("Risk Entries Created: %d\n\n", reg.risk_count);

    risk_set_treatment(&reg, 1, RISK_TREATMENT_MITIGATE, "Deploy MFA + Advanced Threat Protection", 50000.0);
    risk_set_treatment(&reg, 2, RISK_TREATMENT_MITIGATE, "Implement DLP + EDR solution", 75000.0);
    risk_set_treatment(&reg, 3, RISK_TREATMENT_MITIGATE, "Deploy integrity monitoring", 30000.0);
    risk_set_treatment(&reg, 4, RISK_TREATMENT_ACCEPT,    "Business decision - low impact", 0.0);
    risk_set_treatment(&reg, 5, RISK_TREATMENT_TRANSFER,  "Transfer risk via cyber insurance", 25000.0);
    risk_set_treatment(&reg, 6, RISK_TREATMENT_AVOID,     "Migrate to zero-trust architecture", 150000.0);
    risk_set_treatment(&reg, 7, RISK_TREATMENT_ACCEPT,    "Risk within tolerance", 0.0);
    risk_set_treatment(&reg, 8, RISK_TREATMENT_ACCEPT,    "Low risk - accepted", 0.0);
    risk_set_treatment(&reg, 9, RISK_TREATMENT_ACCEPT,    "Negligible - accepted", 0.0);

    risk_report(&reg);

    int matrix[5][5];
    risk_heatmap(&reg, matrix);
    risk_matrix_display(matrix);

    int high_ids[16];
    int high_count = risk_high_priority(&reg, high_ids, 16);
    printf("\nHigh-priority risks (score >= 12): %d\n", high_count);

    printf("\nRisk Treatment Summary:\n");
    for (int i = 0; i < reg.risk_count; i++) {
        Risk_Entry *e = &reg.risks[i];
        double cba = risk_cost_benefit(&reg, e->risk_id);
        printf("  R-%d | Score: %2d -> %2d | ALE: $%8.0f -> $%8.0f | %-10s | CBA: $%.0f\n",
               e->risk_id, e->risk_score, e->residual_score,
               e->ale, e->residual_ale,
               risk_treatment_name(e->treatment), cba);
    }

    risk_add_stride(&reg, RISK_STRIDE_SPOOFING,    "Customer DB", "Credential theft via phishing", "MFA + FIDO2");
    risk_add_stride(&reg, RISK_STRIDE_TAMPERING,   "Payment DB", "Transaction tampering", "Blockchain audit trail");
    risk_add_stride(&reg, RISK_STRIDE_INFO_DISCL,  "Customer DB", "Data exfiltration", "DLP + Encryption");
    risk_add_stride(&reg, RISK_STRIDE_DOS,         "API Gateway", "Volumetric DDoS", "CDN + WAF + Rate Limiting");
    risk_add_stride(&reg, RISK_STRIDE_ELEVATION,   "K8s Cluster", "Container breakout", "Pod Security Policy + Sandbox");
    risk_add_stride(&reg, RISK_STRIDE_REPUDIATION, "Payment DB", "Transaction denial", "Digital signatures + Audit log");

    printf("\nSTRIDE Threat Models: %d\n", reg.stride_count);
    for (int i = 0; i < reg.stride_count; i++) {
        printf("  [%s] %-15s -> %-30s | Mitigation: %s\n",
               risk_stride_name(reg.stride_models[i].category),
               reg.stride_models[i].asset_name,
               reg.stride_models[i].threat_desc,
               reg.stride_models[i].mitigation);
    }

    return 0;
}
