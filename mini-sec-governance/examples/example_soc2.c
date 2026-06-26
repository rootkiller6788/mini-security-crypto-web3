#include "soc2_audit.h"
#include <stdio.h>

int main(void) {
    SOC2_Engagement eng;
    soc2_init_engagement(&eng);

    printf("=== SOC 2 Audit Engagement Example ===\n\n");

    soc2_add_control(&eng, SOC2_TC_SECURITY,
        "Access Control Review",
        "Quarterly access reviews for all production systems",
        "1. Obtain user access list. 2. Verify approver. 3. Test segregation.");

    soc2_add_control(&eng, SOC2_TC_SECURITY,
        "MFA Enforcement",
        "Multi-factor authentication enforced for all admin accounts",
        "1. Review IdP configuration. 2. Test login flow. 3. Verify bypass controls.");

    soc2_add_control(&eng, SOC2_TC_AVAILABILITY,
        "Backup and Recovery",
        "Daily automated backups with quarterly restore tests",
        "1. Review backup schedule. 2. Examine restore test results. 3. Verify RPO/RTO.");

    soc2_add_control(&eng, SOC2_TC_CONFIDENTIAL,
        "Data Encryption at Rest",
        "AES-256 encryption for all data stores containing PII",
        "1. Review KMS configuration. 2. Verify encryption status. 3. Test key rotation.");

    soc2_add_control(&eng, SOC2_TC_INTEGRITY,
        "Change Management",
        "Formal change management process with CAB approval",
        "1. Sample change tickets. 2. Verify testing sign-off. 3. Review CAB minutes.");

    soc2_add_control(&eng, SOC2_TC_PRIVACY,
        "Privacy Notice and Consent",
        "Privacy notice displayed and consent recorded for all data subjects",
        "1. Review privacy notice. 2. Test consent flow. 3. Verify data subject access.");

    soc2_collect_evidence(&eng, 1, SOC2_TC_SECURITY,
        "Q1 Access Review Log", "IAM System", "API Export", 2025, 3);
    soc2_collect_evidence(&eng, 1, SOC2_TC_SECURITY,
        "Q2 Access Review Log", "IAM System", "API Export", 2025, 6);
    soc2_collect_evidence(&eng, 2, SOC2_TC_SECURITY,
        "MFA Configuration Screenshot", "IdP Admin Console", "Screenshot", 2025, 6);
    soc2_collect_evidence(&eng, 3, SOC2_TC_AVAILABILITY,
        "Backup Job History", "Backup Dashboard", "CSV Export", 2025, 6);
    soc2_collect_evidence(&eng, 4, SOC2_TC_CONFIDENTIAL,
        "KMS Key Policy", "AWS KMS Console", "JSON Export", 2025, 6);
    soc2_collect_evidence(&eng, 5, SOC2_TC_INTEGRITY,
        "Change Tickets Sample", "JIRA", "Screenshot", 2025, 6);
    soc2_collect_evidence(&eng, 6, SOC2_TC_PRIVACY,
        "Privacy Consent Log", "Backend DB", "SQL Query Output", 2025, 3);
    soc2_collect_evidence(&eng, 6, SOC2_TC_PRIVACY,
        "Data Subject Access Test", "Privacy Portal", "Browser Recording", 2025, 6);

    soc2_evaluate_control(&eng, 1, SOC2_EVAL_OPERATING_EFFECTIVE);
    soc2_evaluate_control(&eng, 2, SOC2_EVAL_OPERATING_EFFECTIVE);
    soc2_evaluate_control(&eng, 3, SOC2_EVAL_DEFICIENCY);
    soc2_evaluate_control(&eng, 4, SOC2_EVAL_OPERATING_EFFECTIVE);
    soc2_evaluate_control(&eng, 5, SOC2_EVAL_OPERATING_EFFECTIVE);
    soc2_evaluate_control(&eng, 6, SOC2_EVAL_SIGNIFICANT_DEFICIENCY);

    printf("Controls defined:    %d\n", eng.activity_count);
    printf("Evidence collected:  %d\n\n", eng.evidence_count);

    printf("Control Evaluations:\n");
    for (int i = 0; i < eng.activity_count; i++) {
        printf("  [%d] %s: %s\n", eng.activities[i].control_id,
               eng.activities[i].name,
               soc2_eval_result_name(eng.activities[i].evaluation));
    }

    SOC2_AuditReport report;
    soc2_generate_report(&eng, &report, SOC2_REPORT_TYPE_II, 2025,
        SOC2_TC_SECURITY | SOC2_TC_AVAILABILITY | SOC2_TC_CONFIDENTIAL |
        SOC2_TC_INTEGRITY | SOC2_TC_PRIVACY,
        "Deloitte", "Acme Cloud Services, Inc.");

    printf("\n");
    soc2_summary(&report);

    printf("\nTrust Criteria Summary:\n");
    SOC2_TrustCriteria all[] = {
        SOC2_TC_SECURITY, SOC2_TC_AVAILABILITY, SOC2_TC_CONFIDENTIAL,
        SOC2_TC_INTEGRITY, SOC2_TC_PRIVACY
    };
    for (int i = 0; i < 5; i++) {
        printf("  %-20s: %s\n", soc2_trust_criteria_name(all[i]),
               (report.scope & all[i]) ? "In Scope" : "Not in Scope");
    }

    return 0;
}
