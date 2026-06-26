#include "pet_tools.h"
#include "differential_privacy.h"
#include "federated_learn.h"
#include "secure_mpc_comp.h"
#include "anonymization.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

/* ---- helper: simple on-device compute function ---- */
static void sample_compute(uint8_t *memory, size_t size, void *ctx) {
    double *data = (double *)memory;
    int *result = (int *)ctx;
    double sum = 0.0;
    size_t count = size / sizeof(double);
    for (size_t i = 0; i < count && i < 128; i++) {
        sum += data[i];
    }
    *result = (int)(sum * 100.0);
    printf("    [Enclave compute: sum=%.2f, size=%zu]\n", sum, size);
}

int main(void) {
    uint64_t seed = 77777ULL;
    srand((unsigned int)time(NULL));
    printf("=== Privacy-Enhancing Technologies (PETs) Demo ===\n\n");

    /* ============================================ */
    /* 1. PET LANDSCAPE OVERVIEW                     */
    /* ============================================ */
    {
        printf("--- PET Landscape ---\n");
        pet_print_landscape();

        printf("\nIndividual PET details:\n");
        for (int cat = PET_ON_DEVICE; cat < PET_COUNT; cat++) {
            const PETDescriptor *desc = pet_get_descriptor((PETCategory)cat);
            if (desc) {
                printf("  %-24s [maturity=%d/5 overhead=%d/5 privacy=%d/5]\n",
                       desc->name, desc->maturity, desc->overhead, desc->privacy_strength);
            }
        }
        printf("\n");
    }

    /* ============================================ */
    /* 2. ON-DEVICE PROCESSING                       */
    /* ============================================ */
    {
        printf("--- On-Device Processing ---\n");

        OnDeviceProcessor odp;
        odproc_init(&odp, 4, 100);
        printf("Initialized: %zu features x %zu samples = %zu total values\n",
               odp.num_features, odp.num_samples,
               odp.num_features * odp.num_samples);

        /* Fill with sample data */
        for (size_t i = 0; i < odp.num_samples * odp.num_features; i++) {
            odp.local_data[i] = (double)((i * 13 + 7) % 1000) / 100.0;
        }

        /* Compute locally */
        double result[16];
        odproc_compute_local(&odp, result, 16);
        printf("Local compute result[0..3]: [%.2f, %.2f, %.2f, %.2f]\n",
               result[0], result[1], result[2], result[3]);

        /* Minimize upload: only send essentials */
        double essential[64];
        size_t essential_len = 0;
        int minimized = odproc_minimize_upload(&odp, essential, &essential_len, 256.0);
        printf("Minimized upload: %s, sent %zu values (%d bytes)\n",
               minimized ? "YES" : "NO", essential_len, odp.data_sent_to_server);

        odproc_free(&odp);
        printf("\n");
    }

    /* ============================================ */
    /* 3. DIFFERENTIAL PRIVACY REPORTS               */
    /* ============================================ */
    {
        printf("--- Differential Privacy Reports ---\n");

        DPReport report;
        dprep_init(&report);

        double true_counts[] = {1500.0, 2300.0, 1800.0};
        double sensitivity = 1.0;
        double epsilon = 0.5;

        for (int i = 0; i < 3; i++) {
            dprep_generate(&report, true_counts[i], sensitivity, epsilon, 0, seed + (uint64_t)i);
            int verified = dprep_verify(&report, epsilon);
            printf("  Report %d: true=%.0f dp=%.1f CI=[%.0f, %.0f] eps_used=%.2f verified=%s\n",
                   i, report.true_value, report.perturbed_value,
                   report.confidence_interval[0], report.confidence_interval[1],
                   report.epsilon_used, verified ? "YES" : "NO");
        }

        /* Serialize / deserialize */
        uint8_t buf[512];
        size_t buf_len = 0;
        dprep_serialize(&report, buf, &buf_len);
        printf("  Serialized report: %zu bytes\n", buf_len);

        DPReport report2;
        dprep_deserialize(&report2, buf, buf_len);
        printf("  Deserialized: true=%.0f dp=%.1f\n",
               report2.true_value, report2.perturbed_value);

        dprep_free(&report);
        dprep_free(&report2);
        printf("\n");
    }

    /* ============================================ */
    /* 4. SECURE ENCLAVE (TEE)                       */
    /* ============================================ */
    {
        printf("--- Secure Enclave (TEE Abstraction) ---\n");

        SecureEnclave se;
        enclave_init(&se, 4096);

        /* Set up expected measurement */
        uint8_t expected_measurement[32];
        for (int i = 0; i < 32; i++) {
            expected_measurement[i] = (uint8_t)((i * 7 + 3) & 0xFF);
        }
        memcpy(se.measurement, expected_measurement, 32);

        /* Perform attestation */
        int attest_ok = enclave_attest(&se, expected_measurement);
        printf("  Attestation: %s\n", attest_ok ? "VERIFIED" : "FAILED");

        /* Load data into enclave */
        double encl_data[50];
        for (int i = 0; i < 50; i++) encl_data[i] = (double)(i + 1);
        enclave_load_data(&se, (const uint8_t *)encl_data, 50 * sizeof(double));

        /* Compute inside enclave */
        int compute_result = 0;
        enclave_compute(&se, sample_compute, &compute_result);

        /* Seal data */
        uint8_t sealed[8192];
        size_t sealed_len = 0;
        enclave_seal(&se, sealed, &sealed_len);
        printf("  Sealed output: %zu bytes\n", sealed_len);

        /* Verify sealing */
        int seal_ok = enclave_verify_sealing(&se, sealed, sealed_len);
        printf("  Sealing verification: %s\n", seal_ok ? "VALID" : "TAMPERED");

        enclave_free(&se);
        printf("\n");
    }

    /* ============================================ */
    /* 5. ANONYMOUS CREDENTIALS                      */
    /* ============================================ */
    {
        printf("--- Anonymous Credentials ---\n");

        uint8_t issuer_pubkey[32];
        uint8_t issuer_secret[32];
        for (int i = 0; i < 32; i++) {
            issuer_pubkey[i] = (uint8_t)((i * 13 + 29) & 0xFF);
            issuer_secret[i] = (uint8_t)((i * 7 + 11) & 0xFF);
        }

        AnonCredential ac;
        anoncred_init(&ac, issuer_pubkey, 32);

        /* User requests credential with attributes: {"name":"Alice","age":"30","nationality":"US"} */
        const uint8_t attrs[] = "Alice\0\0\0""30\0\0\0\0\0\0""US\0\0\0\0\0\0\0";
        anoncred_request(&ac, attrs, 3, 10);

        /* Issuer signs */
        anoncred_issue(&ac, issuer_secret, 32);
        printf("  Credential issued (len=%zu)\n", ac.cred_len);

        /* User presents credential, revealing only nationality */
        int to_reveal[] = {2};
        uint8_t proof[4096];
        size_t proof_len = 0;
        int present_ok = anoncred_present(&ac, to_reveal, 1, proof, &proof_len);
        printf("  Presentation: %s (proof_len=%zu, revealed_attr=%d)\n",
               present_ok ? "OK" : "FAIL", proof_len, ac.revealed_attrs[0]);

        /* Verifier checks */
        int verify_ok = anoncred_verify_presentation(proof, proof_len, issuer_pubkey, 32);
        printf("  Verification: %s\n", verify_ok ? "ACCEPTED" : "REJECTED");

        anoncred_free(&ac);
        printf("\n");
    }

    /* ============================================ */
    /* 6. ZERO-KNOWLEDGE IDENTITY PROOFS             */
    /* ============================================ */
    {
        printf("--- Zero-Knowledge Identity Proofs ---\n");

        ZKIdentityProof zkp;
        zkidp_init(&zkp, 0);  /* Schnorr-style */

        const uint8_t stmt[] = "I_am_over_18_years_old";
        const uint8_t wit[]  = "birth_date=2000-05-15_secret_evidence";

        zkidp_set_statement(&zkp, stmt, strlen((const char *)stmt));
        zkidp_set_witness(&zkp, wit, strlen((const char *)wit));

        int proved = zkidp_prove(&zkp);
        printf("  Proof generated: %s\n", proved ? "YES" : "NO");

        int verified = zkidp_verify(&zkp);
        printf("  Proof verified: %s\n", verified ? "VALID" : "INVALID");

        /* Range proof: prove age is in [18, 120] */
        uint8_t range_pf[32];
        size_t range_len = 0;
        int in_range = zkidp_range_proof(&zkp, 25, 18, 120, range_pf, &range_len);
        printf("  Range proof (25 in [18,120]): %s\n", in_range ? "IN RANGE" : "OUT OF RANGE");

        in_range = zkidp_range_proof(&zkp, 15, 18, 120, range_pf, &range_len);
        printf("  Range proof (15 in [18,120]): %s\n", in_range ? "IN RANGE" : "OUT OF RANGE");

        zkidp_free(&zkp);
        printf("\n");
    }

    /* ============================================ */
    /* 7. VERIFIABLE CREDENTIALS (W3C)               */
    /* ============================================ */
    {
        printf("--- Verifiable Credentials (W3C-style) ---\n");

        VerifiableCredential vc;
        const char *claims[] = {"name", "role", "clearance"};
        const char *values[] = {"Bob_Smith", "engineer", "level_3"};
        vc_create(&vc, "did:example:issuer123", claims, values, 3);
        printf("  VC created: len=%zu\n", vc.vc_len);

        uint8_t issuer_key[32];
        for (int i = 0; i < 32; i++) issuer_key[i] = (uint8_t)((i * 19 + 3) & 0xFF);

        int issued = vc_issue(&vc, issuer_key, 32);
        printf("  VC issued: %s\n", issued ? "YES" : "NO");

        uint8_t issuer_pub[32];
        for (int i = 0; i < 32; i++) issuer_pub[i] = (uint8_t)((i * 23 + 7) & 0xFF);

        int vc_ok = vc_verify(&vc, issuer_pub);
        printf("  VC verified: %s\n", vc_ok ? "VALID" : "INVALID");

        uint8_t revoke_registry[16] = {0};
        int not_revoked = vc_check_revocation(&vc, revoke_registry);
        printf("  Revocation check: %s\n", not_revoked ? "NOT REVOKED" : "REVOKED");

        vc_free(&vc);
        printf("\n");
    }

    /* ============================================ */
    /* 8. DATA MINIMIZATION                         */
    /* ============================================ */
    {
        printf("--- Data Minimization ---\n");

        DataMinimizer dm;
        datamin_init(&dm, 10);

        /* Feature importance scores */
        double importance[] = {0.9, 0.85, 0.7, 0.3, 0.15, 0.05, 0.02, 0.8, 0.6, 0.1};
        datamin_collect_purpose(importance, 10, 0.5, &dm);
        printf("  Threshold=0.5: %zu/%zu features retained, info_loss=%.2f%%\n",
               dm.minimized_features, dm.total_features, dm.information_loss * 100.0);

        /* Apply minimization */
        double input[10] = {1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0};
        double minimized[10] = {0};
        datamin_apply(&dm, input, minimized);
        printf("  Minimized data: [");
        for (size_t i = 0; i < dm.minimized_features; i++) {
            printf("%.1f%s", minimized[i], i < dm.minimized_features - 1 ? ", " : "");
        }
        printf("]\n");

        /* Audit */
        char audit[256];
        datamin_audit(&dm, audit, sizeof(audit));
        printf("  Audit: %s\n", audit);

        datamin_free(&dm);
        printf("\n");
    }

    /* ============================================ */
    /* 9. PRIVACY BY DESIGN                          */
    /* ============================================ */
    {
        printf("--- Privacy by Design ---\n");

        PbDDesign pbd;
        pbd_init(&pbd);

        /* Add GDPR requirements */
        pbd_add_requirement(&pbd, 1);  /* Purpose limitation */
        pbd_add_requirement(&pbd, 2);  /* Data minimization */
        pbd_add_requirement(&pbd, 3);  /* Storage limitation */
        pbd_add_requirement(&pbd, 4);  /* Integrity and confidentiality */
        pbd_add_requirement(&pbd, 5);  /* Accountability */
        printf("  Added %d privacy requirements\n", pbd.num_requirements);

        /* Map data flows: 4 nodes (user, app, analytics, storage) */
        pbd_map_dataflow(&pbd, 0, 1, 1);  /* user -> app: allowed */
        pbd_map_dataflow(&pbd, 1, 2, 1);  /* app -> analytics: allowed */
        pbd_map_dataflow(&pbd, 1, 3, 1);  /* app -> storage: allowed */
        pbd_map_dataflow(&pbd, 2, 3, 0);  /* analytics -> storage: blocked */
        pbd_map_dataflow(&pbd, 3, 1, 0);  /* storage -> app (direct): blocked */
        printf("  Mapped %d data flow nodes\n", pbd.num_data_nodes);

        /* Risk assessment */
        pbd_assess_risk(&pbd);
        printf("  Risk scores: [");
        for (int i = 0; i < pbd.num_data_nodes; i++) {
            printf("%.2f%s", pbd.risk_scores[i],
                   i < pbd.num_data_nodes - 1 ? ", " : "");
        }
        printf("]\n");

        /* Validate design */
        char design_report[256];
        int valid = pbd_validate_design(&pbd, design_report, sizeof(design_report));
        printf("  Design validation: %s\n  %s\n", valid ? "PASS" : "FAIL", design_report);

        /* GDPR check */
        int gdpr = pbd_check_gdpr(&pbd);
        printf("  GDPR compliance: %s\n", gdpr ? "COMPLIANT" : "NON-COMPLIANT");

        printf("\n");
    }

    /* ============================================ */
    /* 10. PET ORCHESTRATOR                          */
    /* ============================================ */
    {
        printf("--- PET Orchestrator ---\n");

        PETOrchestrator orch;
        petorch_init(&orch);

        /* Enable multiple PETs */
        petorch_enable(&orch, PET_DP);
        petorch_enable(&orch, PET_FEDERATED);
        petorch_enable(&orch, PET_ON_DEVICE);
        petorch_enable(&orch, PET_DATAMIN);
        petorch_enable(&orch, PET_PRIVACY_BY_DESIGN);

        printf("  Enabled %d PETs:\n", orch.num_enabled);
        for (int i = 0; i < orch.num_enabled; i++) {
            if (orch.enabled_pets[i].category >= 0) {
                printf("    - %s (privacy=%d/5)\n",
                       orch.enabled_pets[i].name,
                       orch.enabled_pets[i].privacy_strength);
            }
        }

        /* Assess overall privacy score */
        double privacy_score = 0.0;
        petorch_assess_privacy(&orch, &privacy_score);
        printf("  Overall privacy score: %.2f / 1.0\n", privacy_score);

        /* Audit logging */
        petorch_audit_log_event(&orch, "DP_module_activated:eps=1.0");
        petorch_audit_log_event(&orch, "FL_round_1:5_clients_selected");
        petorch_audit_log_event(&orch, "OnDevice:computed_locally_no_data_sent");
        petorch_audit_log_event(&orch, "DataMin:reduced_features_from_10_to_5");
        printf("  Audit log:\n%s\n", orch.audit_log);

        /* Disable a PET and re-assess */
        petorch_disable(&orch, PET_DP);
        petorch_assess_privacy(&orch, &privacy_score);
        printf("  After disabling DP: score=%.2f\n", privacy_score);

        printf("\n");
    }

    /* ============================================ */
    /* 11. CROSS-PET INTEGRATION DEMONSTRATION       */
    /* ============================================ */
    {
        printf("--- Cross-PET Integration ---\n");
        printf("Scenario: Privacy-preserving health analytics pipeline\n\n");

        /* Step 1: Data minimization on device */
        printf("[1/5] Data minimization on device...\n");
        DataMinimizer dm;
        datamin_init(&dm, 8);
        double health_importance[] = {0.95, 0.05, 0.90, 0.15, 0.80, 0.02, 0.70, 0.01};
        datamin_collect_purpose(health_importance, 8, 0.5, &dm);
        printf("      Retained %zu/%zu features on device\n",
               dm.minimized_features, dm.total_features);
        datamin_free(&dm);

        /* Step 2: Differential privacy noise */
        printf("[2/5] Applying differential privacy...\n");
        DPBudget budget;
        dp_budget_init(&budget, 1.0, 1e-5);
        dp_budget_consume(&budget, 0.3, 0.0);
        printf("      DP budget consumed: epsilon=%.2f\n", budget.epsilon_spent);

        /* Step 3: Federated learning with DP */
        printf("[3/5] Federated learning with DP protection...\n");
        FLServer fl_server;
        fl_server_init(&fl_server, 4, 5, 2, 1, 0.01);
        printf("      FL: %d clients, %d selected, epsilon=%.1f\n",
               fl_server.num_clients, fl_server.num_selected, fl_server.epsilon);
        fl_server_free(&fl_server);

        /* Step 4: Secure aggregation of results */
        printf("[4/5] Secure aggregation of encrypted updates...\n");
        SecureAggState sa;
        secagg_init(&sa, 4, 3);
        printf("      %zu parties in secure aggregation\n", sa.num_participants);
        secagg_free(&sa);

        /* Step 5: K-anonymity check on output */
        printf("[5/5] K-anonymity verification on output...\n");
        AnonDataset out_ds;
        kanon_init_dataset(&out_ds, 100, 3, (char *[]){"metric","value","category"});
        KAnonymityResult kr;
        kanon_check(&out_ds, 5, &kr);
        printf("      k=5 on output: %s\n", kr.satisfied ? "SATISFIED" : "NOT SATISFIED");
        free(kr.group_ids);
        kanon_free_dataset(&out_ds);

        printf("\nPipeline complete: Data minimized -> DP protected -> FL trained\n");
        printf("                 -> Securely aggregated -> K-anonymity verified\n");
    }

    printf("\n=== PET Demo Complete ===\n");
    return 0;
}
