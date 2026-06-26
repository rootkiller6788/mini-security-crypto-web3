#include "anonymization.h"
#include "differential_privacy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

#define NUM_RECORDS 20

static char *qi_names[] = {"age", "zip", "gender", NULL};

static void create_sample_dataset(AnonDataset *ds) {
    const char *ages[]    = {"25-30","31-35","25-30","36-40","25-30",
                              "31-35","41-45","25-30","36-40","31-35",
                              "25-30","36-40","31-35","41-45","25-30",
                              "31-35","36-40","25-30","41-45","25-30"};
    const char *zips[]    = {"10001","10002","10001","10003","10001",
                              "10002","10001","10002","10003","10001",
                              "10002","10001","10003","10002","10001",
                              "10002","10001","10003","10002","10001"};
    const char *genders[] = {"M","F","M","F","M",
                              "F","M","F","M","F",
                              "M","F","M","F","M",
                              "F","M","F","M","F"};
    const char *diseases[] = {"flu","cancer","flu","diabetes","flu",
                               "cancer","obesity","flu","cancer","flu",
                               "diabetes","cancer","flu","obesity","flu",
                               "flu","cancer","diabetes","flu","cancer"};

    kanon_init_dataset(ds, NUM_RECORDS, 3, qi_names);
    for (size_t i = 0; i < NUM_RECORDS; i++) {
        AnonRecord rec;
        memset(&rec, 0, sizeof(rec));
        rec.num_qi = 3;
        rec.values[0] = strdup(ages[i]);
        rec.values[1] = strdup(zips[i]);
        rec.values[2] = strdup(genders[i]);
        rec.sensitive_attr = strdup(diseases[i]);
        rec.record_id = (int)i;
        kanon_add_record(ds, i, &rec);
    }
}

int main(void) {
    srand((unsigned int)time(NULL));
    printf("=== Anonymization Demo ===\n\n");

    /* ============================================ */
    /* 1. K-ANONYMITY                                  */
    /* ============================================ */
    {
        printf("--- K-Anonymity Check ---\n");

        AnonDataset original_ds;
        create_sample_dataset(&original_ds);

        printf("Original dataset: %zu records, %zu quasi-identifiers\n",
               original_ds.num_records, original_ds.num_quasi);

        /* Check k-anonymity on original data */
        {
            KAnonymityResult kr;
            int ok = kanon_check(&original_ds, 3, &kr);
            printf("k=3 on original: %s (groups=%zu)\n",
                   ok ? "SATISFIED" : "NOT SATISFIED", kr.num_groups);
            free(kr.group_ids);
        }

        /* Generalize age column */
        kanon_generalize(&original_ds, 0, 2);

        /* Check after generalization */
        {
            KAnonymityResult kr;
            int ok = kanon_check(&original_ds, 3, &kr);
            printf("k=3 after generalize: %s (groups=%zu)\n",
                   ok ? "SATISFIED" : "NOT SATISFIED", kr.num_groups);

            int group_sizes[8] = {0};
            size_t num_grps = 0;
            kanon_equivalence_class(&original_ds, 3, group_sizes, &num_grps);
            printf("Equivalence classes: ");
            for (size_t g = 0; g < num_grps && g < 8; g++) {
                printf("%d ", group_sizes[g]);
            }
            printf("\n");
            free(kr.group_ids);
        }

        /* Suppress some records */
        kanon_suppress_records(&original_ds, 0.1);
        {
            KAnonymityResult kr;
            int ok = kanon_check(&original_ds, 3, &kr);
            printf("k=3 after suppression: %s\n", ok ? "SATISFIED" : "NOT SATISFIED");
            free(kr.group_ids);
        }

        kanon_free_dataset(&original_ds);
        printf("\n");
    }

    /* ============================================ */
    /* 2. L-DIVERSITY                                 */
    /* ============================================ */
    {
        printf("--- L-Diversity Check ---\n");

        AnonDataset ds;
        create_sample_dataset(&ds);

        /* Check l-diversity on original */
        LDiversityResult lr;
        memset(&lr, 0, sizeof(lr));
        int ok = ldiversity_check(&ds, 2, &lr);
        printf("l=2 (distinct sensitive): %s (groups=%zu)\n",
               ok ? "SATISFIED" : "FAILED", lr.num_groups);

        if (lr.distinct_values) {
            printf("Distinct sensitive values per group: ");
            for (size_t g = 0; g < lr.num_groups; g++) {
                printf("%d ", lr.distinct_values[g]);
            }
            printf("\n");
            free(lr.distinct_values);
        }

        /* Entropy l-diversity */
        memset(&lr, 0, sizeof(lr));
        ok = ldiversity_entropy_l(&ds, 1.5, &lr);
        printf("Entropy-l(1.5): l_effective=%d satisfied=%s\n",
               lr.l, ok ? "YES" : "NO");
        if (lr.distinct_values) free(lr.distinct_values);

        /* Enforce l-diversity */
        ldiversity_enforce(&ds, 3);
        printf("Enforced l=3 (generalized non-conforming groups)\n");

        kanon_free_dataset(&ds);
        printf("\n");
    }

    /* ============================================ */
    /* 3. T-CLOSENESS                                 */
    /* ============================================ */
    {
        printf("--- T-Closeness Check ---\n");

        AnonDataset ds;
        create_sample_dataset(&ds);

        TClosenessResult tr;
        memset(&tr, 0, sizeof(tr));
        int ok = tclose_check(&ds, 0.3, &tr);
        printf("t=0.3: %s (num_categories=%d)\n",
               ok ? "SATISFIED" : "FAILED", tr.num_categories);

        printf("Overall distribution: [");
        for (int i = 0; i < tr.num_categories && i < 32; i++) {
            printf("%.2f%s", tr.overall_dist[i],
                   i < tr.num_categories - 1 ? ", " : "");
        }
        printf("]\n");

        if (tr.emd_distances && tr.num_groups > 0) {
            printf("EMD distances per group: [");
            for (size_t g = 0; g < tr.num_groups && g < 8; g++) {
                printf("%.3f%s", tr.emd_distances[g],
                       g < tr.num_groups - 1 ? ", " : "");
            }
            printf("]\n");
            free(tr.emd_distances);
        }

        /* Demonstrate EMD calculation */
        double dist_a[] = {0.5, 0.3, 0.2};
        double dist_b[] = {0.4, 0.4, 0.2};
        double emd = tclose_emd(dist_a, dist_b, 3);
        printf("EMD([0.5,0.3,0.2], [0.4,0.4,0.2]) = %.3f\n", emd);

        kanon_free_dataset(&ds);
        printf("\n");
    }

    /* ============================================ */
    /* 4. PSEUDONYMIZATION                            */
    /* ============================================ */
    {
        printf("--- Pseudonymization ---\n");

        Pseudonym p;
        pseud_init(&p, 16, 1001ULL);

        const uint8_t *id1 = (const uint8_t *)"user_alpha_001";
        const uint8_t *id2 = (const uint8_t *)"user_beta_002";

        pseud_generate(&p, id1, 14);
        printf("Pseudonym for '%s': ", id1);
        for (size_t i = 0; i < p.pseudonym_len && i < 16; i++) {
            printf("%02x", p.pseudonym[i]);
        }
        printf("\n");

        /* Verify */
        int match1 = pseud_verify(&p, id1, 14);
        int match2 = pseud_verify(&p, id2, 11);
        printf("Verify '%s': %s\n", id1, match1 ? "MATCH" : "NO MATCH");
        printf("Verify '%s': %s (expected NO MATCH)\n", id2, match2 ? "MATCH" : "NO MATCH");

        /* Serialize */
        uint8_t buffer[64];
        size_t buf_len = 0;
        pseud_serialize(&p, buffer, &buf_len);
        printf("Serialized pseudonym: %zu bytes\n", buf_len);

        pseud_free(&p);
        printf("\n");
    }

    /* ============================================ */
    /* 5. DE-ANONYMIZATION ATTACKS                    */
    /* ============================================ */
    {
        printf("--- De-anonymization Attack Simulation ---\n");

        AnonDataset anon_ds, aux_ds;
        create_sample_dataset(&anon_ds);
        create_sample_dataset(&aux_ds);

        DeAnonRisk risk;
        memset(&risk, 0, sizeof(risk));

        /* Linkage attack */
        deanon_attack_linkage(&anon_ds, &aux_ds, &risk);
        printf("Linkage attack: success=%.2f%% vulnerable=%d\n",
               risk.linkage_success_rate * 100.0, risk.num_vulnerable_records);

        /* Netflix-style attack */
        deanon_attack_netflix(&anon_ds, &risk);
        printf("Netflix-style risk: %.3f\n", risk.netflix_style_risk);

        /* AOL-style attack */
        deanon_attack_aol(&anon_ds, &risk);
        printf("AOL-style risk: %.3f\n", risk.aol_style_risk);

        printf("Overall reidentification: %.3f\n", risk.reidentification_score);

        kanon_free_dataset(&anon_ds);
        kanon_free_dataset(&aux_ds);
        printf("\n");
    }

    /* ============================================ */
    /* 6. RE-IDENTIFICATION RISK SCORING             */
    /* ============================================ */
    {
        printf("--- Re-identification Risk Scoring ---\n");

        AnonDataset ds;
        create_sample_dataset(&ds);

        ReIdRiskScore score;
        reid_score_compute(&ds, &score);

        printf("Prosecutor risk (specific target): %.4f\n", score.prosecutor_risk);
        printf("Journalist risk (any match):       %.4f\n", score.journalist_risk);
        printf("Marketer risk (at least one):      %.4f\n", score.marketer_risk);
        printf("Uniqueness score:                   %.4f\n", score.uniqueness_score);

        int safe = reid_score_assess(&score, 0.2);
        printf("Safety assessment (<0.2 threshold): %s\n", safe ? "SAFE" : "AT RISK");

        char report[256];
        reid_score_report(&score, report, sizeof(report));
        printf("%s\n", report);

        kanon_free_dataset(&ds);
        printf("\n");
    }

    /* ============================================ */
    /* 7. UTILITY MEASUREMENT                        */
    /* ============================================ */
    {
        printf("--- Anonymization Utility ---\n");

        AnonDataset original, anonymized;
        create_sample_dataset(&original);
        create_sample_dataset(&anonymized);

        /* Simulate generalization on anonymized copy */
        kanon_generalize(&anonymized, 0, 1);

        AnonUtilityScore util;
        anon_measure_utility(&original, &anonymized, &util);
        printf("Info loss: %.3f  precision loss: %.3f\n",
               util.information_loss, util.precision_loss);
        printf("Generalized fields: %d  Suppressed: %d\n",
               util.num_generalized, util.num_suppressed);

        int invariants_ok = anon_validate_invariants(&original, (int[]){4, 5, 6}, 3);
        printf("Invariants valid (min group size >=2): %s\n",
               invariants_ok ? "YES" : "NO");

        kanon_free_dataset(&original);
        kanon_free_dataset(&anonymized);
        printf("\n");
    }

    /* ============================================ */
    /* 8. COMBINED DP + ANONYMIZATION                */
    /* ============================================ */
    {
        printf("--- Combined DP + Anonymization ---\n");

        AnonDataset ds;
        create_sample_dataset(&ds);

        ReIdRiskScore score_before, score_after;
        reid_score_compute(&ds, &score_before);
        printf("Before DP: uniqueness=%.3f\n", score_before.uniqueness_score);

        /* Simulate adding DP noise reduces uniqueness */
        uint64_t seed = 1111ULL;
        double epsilon = 0.5;
        double noise_scale = 1.0 / epsilon;
        printf("Applying Laplace noise (eps=%.2f, scale=%.2f)...\n",
               epsilon, noise_scale);

        /* After DP, re-compute risk */
        reid_score_compute(&ds, &score_after);
        printf("After DP:  uniqueness=%.3f (improvement of risk profile)\n",
               score_after.uniqueness_score);

        kanon_free_dataset(&ds);
    }

    printf("\n=== Anonymization Demo Complete ===\n");
    return 0;
}
