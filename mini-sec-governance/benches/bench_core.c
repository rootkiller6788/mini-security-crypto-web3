/*
 * mini-sec-governance — Benchmark: ISO27001, SOC2, NIST CSF, risk, compliance
 *
 * Usage: bench_core [iterations]
 */
#include "../include/iso27001_mgr.h"
#include "../include/soc2_audit.h"
#include "../include/nist_csf.h"
#include "../include/risk_assess.h"
#include "../include/compliance_auto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now_ms(void) {
    return (double)clock() / (double)(CLOCKS_PER_SEC / 1000);
}

int main(int argc, char **argv) {
    int N = (argc > 1) ? atoi(argv[1]) : 5000;
    printf("=== mini-sec-governance Benchmarks (iterations=%d) ===\n\n", N);

    /* ISO27001 risk calculation */
    {
        ISO27001_ISMS isms;
        iso27001_init(&isms, 2024);
        iso27001_add_asset(&isms, "DB", "dba", "confidential", 50000.0, 1);
        iso27001_add_threat(&isms, "hack", "external", 0.8, 0.7);
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            iso27001_certification_readiness(&isms);
        }
        double dt = now_ms() - t0;
        printf("  iso27001_certification_readiness:     %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    /* SOC2 control evaluation */
    {
        SOC2_Engagement eng;
        soc2_init_engagement(&eng);
        soc2_add_control(&eng, SOC2_TC_SECURITY, "AC-1", "Access Control", "Review logs");
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            SOC2_AuditReport report;
            soc2_generate_report(&eng, &report, SOC2_REPORT_TYPE_II, 2024,
                                 SOC2_TC_SECURITY, "auditor", "org");
        }
        double dt = now_ms() - t0;
        printf("  soc2_generate_report:                 %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    /* NIST CSF gap analysis */
    {
        NIST_CSF_Framework fw;
        nist_csf_init(&fw);
        nist_csf_load_core(&fw);
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            nist_csf_gap_analysis(&fw, NULL, 0);
        }
        double dt = now_ms() - t0;
        printf("  nist_csf_gap_analysis:                %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    /* Risk register recalculation */
    {
        Risk_Register reg;
        risk_init(&reg, 15.0);
        risk_add_asset(&reg, "server", RISK_CLASS_CONFIDENT, "ops", 100000.0, 1);
        risk_add_threat(&reg, RISK_STRIDE_TAMPERING, "malware", "ransomware", "criminal",
                         RISK_PROB_MODERATE, 0.7, 0.1);
        risk_add_entry(&reg, 0, 0, RISK_PROB_MODERATE, RISK_IMPACT_MAJOR, 50000.0);
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            risk_recalculate(&reg);
        }
        double dt = now_ms() - t0;
        printf("  risk_recalculate:                     %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    /* Compliance check */
    {
        Compliance_Engine eng;
        comp_init(&eng);
        Compliance_Regulation regs[] = {COMP_REG_GDPR};
        comp_add_policy(&eng, "encrypt", "data at rest encrypted",
                        "config.db.encryption == 'on'", "config.db.encryption",
                        "on", 5, regs, 1);
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            comp_check_policy(&eng, 0, "on");
        }
        double dt = now_ms() - t0;
        printf("  comp_check_policy:                    %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    printf("\n=== Benchmarks complete ===\n");
    return 0;
}
