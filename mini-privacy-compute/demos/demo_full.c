/*
 * mini-privacy-compute — Full Demo: Privacy Computing
 *
 * Demonstrates: differential privacy, federated learning, secure MPC,
 *               anonymization (k-anonymity/l-diversity), PET tools (VC, ZKP, on-device).
 */
#include "../include/differential_privacy.h"
#include "../include/federated_learn.h"
#include "../include/secure_mpc_comp.h"
#include "../include/anonymization.h"
#include "../include/pet_tools.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    printf("=== mini-privacy-compute: Privacy Computing Demo ===\n\n");

    /* Step 1: Differential Privacy */
    printf("-- Step 1: Differential Privacy --\n");
    uint64_t seed = 42;
    double true_val = 100.0;
    double private_val1 = dp_laplace_mechanism(true_val, 1.0, 0.5, &seed);
    double private_val2 = dp_gaussian_mechanism(true_val, 1.0, 1.0, 1e-5, &seed);
    printf("True value: %.2f\n", true_val);
    printf("  Laplace (eps=0.5):  %.4f\n", private_val1);
    printf("  Gaussian (eps=1.0): %.4f\n", private_val2);

    DPBudget budget;
    dp_budget_init(&budget, 10.0, 1e-5);
    printf("Privacy budget: epsilon=%.1f, delta=%.1e\n", budget.epsilon_limit, budget.delta_limit);

    dp_budget_consume(&budget, 0.5, 0.0);
    dp_budget_consume(&budget, 1.2, 0.0);
    printf("After 2 queries: spent=%.1f, remaining=%.1f\n",
           budget.epsilon_spent, dp_budget_remaining_eps(&budget));

    DPComposition comp;
    dp_comp_init(&comp);
    dp_comp_sequential(&comp, 0.5, 0.0);
    dp_comp_sequential(&comp, 1.2, 0.0);
    printf("Sequential composition: total_eps=%.1f\n", comp.total_epsilon);

    /* Step 2: Federated Learning */
    printf("\n-- Step 2: Federated Learning --\n");
    FLServer server;
    double init_weights[64];
    for (size_t i = 0; i < 64; i++) init_weights[i] = 0.01;
    fl_server_init(&server, 64, 20, 5, 50, 0.01);
    fl_server_init_model(&server, init_weights);
    printf("FL server: %d clients, %d selected/round, %d rounds, lr=%.3f\n",
           server.num_clients, server.num_selected, server.total_rounds, server.learning_rate);

    double gradients[64];
    for (size_t i = 0; i < 64; i++) gradients[i] = (double)(i % 8) / 100.0;
    fl_upload_update(&server, gradients, 0, 32);
    fl_upload_update(&server, gradients, 1, 64);
    printf("Clients uploaded updates: 0 (32 samples), 1 (64 samples)\n");

    double norm = fl_compute_update_norm(gradients, 64);
    printf("Update norm: %.6f\n", norm);

    fl_dp_clip_update(gradients, 64, 1.5);
    fl_dp_add_noise(gradients, 64, 2.0, 1e-5, 1.0, &seed);
    printf("DP protection applied: clipped+noised 64 parameters\n");
    fl_server_free(&server);

    /* Step 3: Secure MPC */
    printf("\n-- Step 3: Secure Multi-Party Computation --\n");
    SecretSharing ss;
    ss_init(&ss, 3, 1000000007ULL);
    printf("Secret sharing: %zu parties, prime=%llu\n", ss.num_parties, (unsigned long long)ss.prime);

    uint64_t shares1[3], shares2[3], sum_shares[3];
    ss_share(&ss, 100, shares1);
    ss_share(&ss, 200, shares2);
    ss_add(&ss, shares1, shares2, sum_shares);
    uint64_t sum_result;
    ss_reconstruct(&ss, sum_shares, &sum_result);
    printf("[100] + [200] = [%llu] (in shares) reconstructed to %llu\n",
           (unsigned long long)sum_shares[0], (unsigned long long)sum_result);

    BeaverTriplePool pool;
    bt_pool_init(&pool, 16, ss.prime, 12345);
    bt_pool_generate(&pool);
    BeaverTriple triple;
    bt_pool_consume(&pool, &triple);
    printf("Beaver triple pool: %zu triples generated\n", pool.num_triples);

    uint64_t prod_shares[3];
    bt_multiply(&ss, &triple, shares1, shares2, prod_shares);
    uint64_t prod_res;
    ss_reconstruct(&ss, prod_shares, &prod_res);
    printf("[100] * [200] = [20000] reconstructed to %llu\n", (unsigned long long)prod_res);
    bt_pool_free(&pool);
    ss_free(&ss);

    /* Step 4: Anonymization */
    printf("\n-- Step 4: Data Anonymization --\n");
    AnonDataset ds;
    char *qi_names[] = {"age_group", "zip_prefix"};
    kanon_init_dataset(&ds, 12, 2, qi_names);
    AnonRecord rec; memset(&rec, 0, sizeof(rec));
    rec.num_qi = 2; rec.sensitive_attr = "condition";
    const char *ages[] = {"20-29", "20-29", "20-29", "30-39", "30-39", "30-39",
                           "40-49", "40-49", "40-49", "50-59", "50-59", "50-59"};
    const char *zips[] = {"123*", "123*", "123*", "456*", "456*", "456*",
                           "789*", "789*", "789*", "012*", "012*", "012*"};
    for (size_t i = 0; i < 12; i++) {
        rec.quasi_identifiers[0] = (char*)ages[i];
        rec.quasi_identifiers[1] = (char*)zips[i];
        kanon_add_record(&ds, i, &rec);
    }

    KAnonymityResult k_res;
    kanon_check(&ds, 3, &k_res);
    printf("k-anonymity (k=3): %s (%zu groups)\n",
           k_res.satisfied ? "SATISFIED" : "NOT SATISFIED", k_res.num_groups);

    LDiversityResult l_res;
    ldiversity_check(&ds, 2, &l_res);
    printf("l-diversity (l=2): %s\n", l_res.satisfied ? "SATISFIED" : "NOT SATISFIED");

    ReIdRiskScore risk;
    reid_score_compute(&ds, &risk);
    printf("Re-identification risk: prosecutor=%.3f, journalist=%.3f, uniqueness=%.3f\n",
           risk.prosecutor_risk, risk.journalist_risk, risk.uniqueness_score);
    kanon_free_dataset(&ds);

    /* Step 5: PET Tools */
    printf("\n-- Step 5: Privacy-Enhancing Technology Tools --\n");
    OnDeviceProcessor odp;
    odproc_init(&odp, 32, 16);
    double local_result[32];
    odproc_compute_local(&odp, local_result, 32);
    printf("On-device processing: %zu features, %zu samples processed locally\n",
           odp.num_features, odp.num_samples);

    DPReport dp_rep;
    dprep_init(&dp_rep);
    dprep_generate(&dp_rep, 75.5, 1.0, 0.5, 0, 42);
    printf("DP report: true=%.1f, perturbed=%.1f, epsilon=%.2f\n",
           dp_rep.true_value, dp_rep.perturbed_value, dp_rep.epsilon_used);
    dprep_free(&dp_rep);

    pet_print_landscape();
    odproc_free(&odp);

    printf("\nPrivacy computing demo complete!\n");
    return 0;
}
