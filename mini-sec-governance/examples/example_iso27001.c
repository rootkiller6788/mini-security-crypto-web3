#include "iso27001_mgr.h"
#include <stdio.h>

int main(void) {
    ISO27001_ISMS isms;
    iso27001_init(&isms, 2025);

    printf("=== ISO 27001 ISMS Example ===\n");
    printf("Certification year: %d\n", isms.cert_year);
    printf("Annex A controls loaded: %d\n\n", isms.control_count);

    iso27001_add_asset(&isms, "Customer Database", "DB Team", "Confidential", 500000.0, 1);
    iso27001_add_asset(&isms, "Employee Portal", "HR", "Internal", 100000.0, 0);
    iso27001_add_asset(&isms, "API Gateway", "Platform", "Restricted", 750000.0, 1);
    iso27001_add_asset(&isms, "Public Website", "Marketing", "Public", 50000.0, 0);

    iso27001_add_threat(&isms, "Unauthorized Access", "External attacker", 4.0, 3.0);
    iso27001_add_threat(&isms, "Data Leakage", "Insider", 3.0, 4.0);
    iso27001_add_threat(&isms, "DDoS Attack", "Botnet", 5.0, 4.5);
    iso27001_add_threat(&isms, "Ransomware", "Criminal group", 4.5, 5.0);

    iso27001_add_risk(&isms, 1, 1, 4.0, 5);   /* Customer DB + Unauthorized Access, with control */
    iso27001_add_risk(&isms, 1, 2, 4.5, 15);  /* Customer DB + Data Leakage, with control */
    iso27001_add_risk(&isms, 3, 3, 3.5, 22);  /* API Gateway + DDoS, with control */
    iso27001_add_risk(&isms, 3, 4, 5.0, 0);   /* API Gateway + Ransomware, no control */
    iso27001_add_risk(&isms, 2, 1, 2.5, 9);   /* Employee Portal + Unauthorized Access */

    printf("Assets:  %d\n", isms.asset_count);
    printf("Threats: %d\n", isms.threat_count);
    printf("Risks:   %d\n", isms.risk_count);

    iso27001_generate_soa(&isms);
    printf("SoA entries: %d\n", isms.soa_count);

    iso27001_schedule_audit(&isms, "Full ISMS internal audit", "Internal Audit Team", 3);
    iso27001_schedule_audit(&isms, "Annex A compliance review", "External Auditor", 9);

    iso27001_add_review(&isms, "Management Review Q1",
        "Audit results, incident reports, risk register updates",
        "Corrective actions, resource allocation",
        "Approve SoA updates, authorize additional controls", 2025);
    iso27001_add_review(&isms, "Management Review Q3",
        "Internal audit findings, compliance status",
        "Policy updates, training requirements",
        "Accept residual risks R-004, increase security budget", 2025);

    iso27001_pdca_report(&isms);

    int risk_ids[16], risk_count;
    iso27001_risks_by_asset(&isms, 1, risk_ids, &risk_count, 16);
    printf("\nRisks for Asset #1 (Customer DB): %d\n", risk_count);

    int readiness = iso27001_certification_readiness(&isms);
    printf("Certification readiness score: %d/100\n", readiness);
    printf("Readiness: %s\n", readiness >= 60 ? "READY for Stage 1 Audit" :
           readiness >= 40 ? "Approaching readiness" : "Significant work needed");

    return 0;
}
