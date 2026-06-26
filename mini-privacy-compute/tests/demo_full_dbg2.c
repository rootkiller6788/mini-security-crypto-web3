#include "differential_privacy.h"
#include "federated_learn.h"
#include "secure_mpc_comp.h"
#include "anonymization.h"
#include "pet_tools.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define S(s) do { printf("DBG: %s\n", s); fflush(stdout); } while(0)

int main(void) {
    S("start");

    S("step1");
    uint64_t seed = 42;
    double true_val = 100.0;
    double pv1 = dp_laplace_mechanism(true_val, 1.0, 0.5, &seed);
    double pv2 = dp_gaussian_mechanism(true_val, 1.0, 1.0, 1e-5, &seed);
    printf("DP ok: %.4f %.4f\n", pv1, pv2); fflush(stdout);

    S("step2-DP budget");
    DPBudget budget;
    dp_budget_init(&budget, 10.0, 1e-5);
    dp_budget_consume(&budget, 0.5, 0.0);
    dp_budget_consume(&budget, 1.2, 0.0);

    DPComposition comp;
    dp_comp_init(&comp);
    dp_comp_sequential(&comp, 0.5, 0.0);
    dp_comp_sequential(&comp, 1.2, 0.0);
    printf("comp ok eps=%.1f\n", comp.total_epsilon); fflush(stdout);

    S("step3-FL");
    FLServer server;
    memset(&server, 0, sizeof(server));
    double iw[64];
    for (size_t i = 0; i < 64; i++) iw[i] = 0.01;
    fl_server_init(&server, 64, 20, 5, 50, 0.01);
    fl_server_init_model(&server, iw);

    double gradients[64];
    for (size_t i = 0; i < 64; i++) gradients[i] = (double)(i % 8) / 100.0;
    fl_upload_update(&server, gradients, 0, 32);
    fl_upload_update(&server, gradients, 1, 64);

    double norm = fl_compute_update_norm(gradients, 64);
    printf("FL norm=%.6f\n", norm); fflush(stdout);

    fl_dp_clip_update(gradients, 64, 1.5);
    fl_dp_add_noise(gradients, 64, 2.0, 1e-5, 1.0, &seed);
    fl_server_free(&server);

    S("step4-SMPC");
    SecretSharing ss;
    ss_init(&ss, 3, 1000000007ULL);
    uint64_t s1[3], s2[3], sum_s[3];
    ss_share(&ss, 100, s1);
    ss_share(&ss, 200, s2);
    ss_add(&ss, s1, s2, sum_s);
    uint64_t sr;
    ss_reconstruct(&ss, sum_s, &sr);
    printf("SMPC sum=%llu\n", (unsigned long long)sr); fflush(stdout);

    BeaverTriplePool pool;
    bt_pool_init(&pool, 16, ss.prime, 12345);
    bt_pool_generate(&pool);
    BeaverTriple triple;
    bt_pool_consume(&pool, &triple);
    uint64_t ps[3];
    bt_multiply(&ss, &triple, s1, s2, ps);
    uint64_t pr;
    ss_reconstruct(&ss, ps, &pr);
    printf("SMPC prod=%llu\n", (unsigned long long)pr); fflush(stdout);
    bt_pool_free(&pool);
    ss_free(&ss);

    S("step5-anon");
    AnonDataset ds;
    memset(&ds, 0, sizeof(ds));
    char *qi[] = {"age_group", "zip_prefix"};
    kanon_init_dataset(&ds, 12, 2, qi);
    AnonRecord rec; memset(&rec, 0, sizeof(rec));
    rec.num_qi = 2; rec.sensitive_attr = "condition";
    const char *ages[] = {"20-29","20-29","20-29","30-39","30-39","30-39",
                           "40-49","40-49","40-49","50-59","50-59","50-59"};
    const char *zips[] = {"123*","123*","123*","456*","456*","456*",
                           "789*","789*","789*","012*","012*","012*"};
    for (size_t i = 0; i < 12; i++) {
        rec.quasi_identifiers[0] = (char*)ages[i];
        rec.quasi_identifiers[1] = (char*)zips[i];
        kanon_add_record(&ds, i, &rec);
    }

    KAnonymityResult k_res;
    memset(&k_res, 0, sizeof(k_res));
    kanon_check(&ds, 3, &k_res);
    printf("k-anon: satisfied=%d groups=%zu\n", k_res.satisfied, k_res.num_groups); fflush(stdout);
    free(k_res.group_ids);

    S("step6-l-diversity");
    LDiversityResult l_res;
    memset(&l_res, 0, sizeof(l_res));
    ldiversity_check(&ds, 2, &l_res);
    printf("l-div: satisfied=%d\n", l_res.satisfied); fflush(stdout);
    if (l_res.distinct_values) free(l_res.distinct_values);

    S("step7-reid");
    ReIdRiskScore risk;
    memset(&risk, 0, sizeof(risk));
    reid_score_compute(&ds, &risk);
    printf("reid: prosecutor=%.3f\n", risk.prosecutor_risk); fflush(stdout);

    kanon_free_dataset(&ds);

    S("step8-pet");
    OnDeviceProcessor odp;
    memset(&odp, 0, sizeof(odp));
    odproc_init(&odp, 32, 16);
    double lr2[32];
    odproc_compute_local(&odp, lr2, 32);
    printf("odproc: features=%zu\n", odp.num_features); fflush(stdout);
    odproc_free(&odp);

    DPReport dpr;
    memset(&dpr, 0, sizeof(dpr));
    dprep_init(&dpr);
    dprep_generate(&dpr, 75.5, 1.0, 0.5, 0, 42);
    printf("dprep: true=%.1f perturbed=%.1f\n", dpr.true_value, dpr.perturbed_value); fflush(stdout);
    dprep_free(&dpr);

    pet_print_landscape();

    S("DONE");
    return 0;
}
