#include "compliance_auto.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    Compliance_Engine eng;
    comp_init(&eng);

    printf("=== Compliance Automation Demo ===\n\n");

    comp_add_regulation(&eng, COMP_REG_GDPR);
    comp_add_regulation(&eng, COMP_REG_HIPAA);
    comp_add_regulation(&eng, COMP_REG_PCI_DSS);
    comp_add_regulation(&eng, COMP_REG_ISO27001);
    comp_add_regulation(&eng, COMP_REG_NIST);
    comp_add_regulation(&eng, COMP_REG_SOX);

    printf("Active Regulations: ");
    for (int i = 0; i < eng.active_reg_count; i++) {
        printf("%s ", comp_reg_name(eng.active_regs[i]));
    }
    printf("\n\n");

    Compliance_Regulation gdpr[]  = {COMP_REG_GDPR, COMP_REG_ISO27001};
    Compliance_Regulation hipaa[] = {COMP_REG_HIPAA};
    Compliance_Regulation pci[]   = {COMP_REG_PCI_DSS};
    Compliance_Regulation sox[]   = {COMP_REG_SOX};
    Compliance_Regulation multi[] = {COMP_REG_GDPR, COMP_REG_HIPAA, COMP_REG_PCI_DSS, COMP_REG_NIST};

    comp_add_policy(&eng, "Data Encryption at Rest",
        "All data stores containing PII must use AES-256 encryption",
        "config.db.encryption == AES256", "config.db.encryption", "AES256", 5, gdpr, 2);
    comp_add_policy(&eng, "Access Control Review Period",
        "Access reviews must be conducted at least quarterly",
        "config.access.review_period <= 90", "config.access.review_period", "90", 4, multi, 4);
    comp_add_policy(&eng, "Audit Log Retention",
        "Audit logs must be retained for a minimum of 365 days",
        "config.audit.retention_days >= 365", "config.audit.retention_days", "365", 5, sox, 1);
    comp_add_policy(&eng, "MFA Enforcement",
        "Multi-factor authentication required for all admin accounts",
        "config.auth.mfa_enabled == true", "config.auth.mfa_enabled", "true", 5, pci, 1);
    comp_add_policy(&eng, "Database Backup Frequency",
        "Database backups must run at least daily",
        "config.backup.frequency_hours <= 24", "config.backup.frequency_hours", "24", 4, hipaa, 1);
    comp_add_policy(&eng, "Password Minimum Length",
        "Passwords must be at least 12 characters",
        "config.auth.password_min_length >= 12", "config.auth.password_min_length", "12", 3, pci, 1);
    comp_add_policy(&eng, "Session Timeout",
        "User sessions must timeout after 15 minutes of inactivity",
        "config.auth.session_timeout_minutes <= 15", "config.auth.session_timeout_minutes", "15", 3, gdpr, 2);
    comp_add_policy(&eng, "TLS Version Minimum",
        "TLS 1.2 or higher required for all connections",
        "config.network.tls_version >= 1.2", "config.network.tls_version", "1.2", 5, pci, 1);

    printf("Policies defined: %d\n\n", eng.policy_count);

    comp_check_policy(&eng, 1, "AES256");
    comp_check_policy(&eng, 2, "90");
    comp_check_policy(&eng, 3, "365");
    comp_check_policy(&eng, 4, "true");
    comp_check_policy(&eng, 5, "24");
    comp_check_policy(&eng, 6, "8");    // FAIL
    comp_check_policy(&eng, 7, "30");   // FAIL
    comp_check_policy(&eng, 8, "1.0");  // FAIL

    printf("Policy Check Results:\n");
    for (int i = 0; i < eng.check_count; i++) {
        printf("  Check #%d: Policy #%d => %-6s | %s (%s)\n",
               eng.checks[i].check_id, eng.checks[i].policy_id,
               comp_status_name(eng.checks[i].status),
               eng.checks[i].message,
               eng.checks[i].resource_value ? eng.checks[i].resource_value : "null");
    }

    int new_drifts = comp_detect_drift(&eng);
    printf("\nDrifts detected: %d\n\n", new_drifts);

    comp_add_control(&eng, "CTRL-001", COMP_REG_GDPR,  "Data encryption at rest");
    comp_add_control(&eng, "CTRL-002", COMP_REG_GDPR,  "Right of access by data subject");
    comp_add_control(&eng, "CTRL-003", COMP_REG_HIPAA, "Administrative safeguards");
    comp_add_control(&eng, "CTRL-004", COMP_REG_HIPAA, "Technical safeguards");
    comp_add_control(&eng, "CTRL-005", COMP_REG_PCI_DSS, "Firewall configuration");
    comp_add_control(&eng, "CTRL-006", COMP_REG_PCI_DSS, "Encrypt cardholder data");
    comp_add_control(&eng, "CTRL-007", COMP_REG_SOX,   "IT general controls");
    comp_add_control(&eng, "CTRL-008", COMP_REG_ISO27001, "Annex A.5 policies");

    for (int i = 0; i < eng.control_count; i++) {
        eng.controls[i].pass_count = 5 + (i * 3) % 5;
        eng.controls[i].fail_count = i % 3;
        comp_generate_evidence(&eng, i + 1);
    }

    comp_add_log(&eng, "admin", "POLICY_CREATE", "Data Encryption at Rest", "SUCCESS");
    comp_add_log(&eng, "auditor", "CHECK_EXECUTED", "8 policies", "5 passed");
    comp_add_log(&eng, "system", "DRIFT_DETECTED", "config.auth.password_min_length", "8 != 12");
    comp_add_log(&eng, "admin", "REMEDIATION", "config.auth.password_min_length", "CHANGED to 12");
    comp_add_log(&eng, "auditor", "REPORT_GENERATED", "Compliance Dashboard", "SUCCESS");
    comp_add_log(&eng, "system", "DRIFT_DETECTED", "config.auth.session_timeout_minutes", "30 != 15");
    comp_add_log(&eng, "admin", "REMEDIATION", "config.auth.session_timeout_minutes", "CHANGED to 15");
    comp_add_log(&eng, "system", "DRIFT_DETECTED", "config.network.tls_version", "1.0 != 1.2");
    comp_add_log(&eng, "security", "INCIDENT_RESPONSE", "TLS downgrade attack mitigated", "RESOLVED");

    comp_update_dashboard(&eng);
    comp_dashboard_display(&eng);

    printf("\n");
    comp_audit_trail(&eng);

    printf("\n");
    comp_remediation_report(&eng);

    printf("\nContinuous Monitoring Simulation:\n");
    comp_continuous_monitor(&eng, 60);
    printf("  Monitoring active: %s\n", eng.monitoring_active ? "Yes" : "No");
    printf("  Total checks: %d\n", eng.check_count);
    printf("  Compliance Score: %.1f%%\n", comp_compliance_score(&eng));

    printf("\nPolicy-to-Regulation Mapping:\n");
    for (int i = 0; i < eng.policy_count; i++) {
        printf("  P-%d: %-30s -> ", eng.policies[i].policy_id, eng.policies[i].name);
        for (int j = 0; j < eng.policies[i].reg_count; j++) {
            printf("%s ", comp_reg_name(eng.policies[i].regs[j]));
        }
        printf("\n");
    }

    return 0;
}
