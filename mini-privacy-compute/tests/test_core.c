/*
 * mini-privacy-compute — Core Tests
 *
 * Unit tests for differential privacy, federated learning, secure MPC, anonymization, PET.
 */
#include "../include/differential_privacy.h"
#include "../include/federated_learn.h"
#include "../include/secure_mpc_comp.h"
#include "../include/anonymization.h"
#include "../include/pet_tools.h"
#include <stdio.h>
#include <string.h>

static int tests_run = 0, tests_passed = 0;

#define TEST(name) do { tests_run++; printf("  TEST %s ... ", name); } while(0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); return 1; } while(0)
#define CHECK(cond, msg) if (!(cond)) FAIL(msg)

/* ── Differential Privacy Tests ── */
static int test_dp_laplace_mechanism(void) {
    TEST("dp_laplace_mechanism");
    uint64_t seed = 42;
    double result = dp_laplace_mechanism(100.0, 1.0, 0.5, &seed);
    CHECK(result != 100.0, "laplace should add noise");
    CHECK(result > 0.0, "result should be positive");
    PASS();
    return 0;
}

static int test_dp_gaussian_mechanism(void) {
    TEST("dp_gaussian_mechanism");
    uint64_t seed = 42;
    double result = dp_gaussian_mechanism(100.0, 1.0, 1.0, 1e-5, &seed);
    CHECK(result != 100.0, "gaussian should add noise");
    PASS();
    return 0;
}

static int test_dp_budget(void) {
    TEST("dp_budget");
    DPBudget budget;
    dp_budget_init(&budget, 10.0, 1e-5);
    CHECK(budget.epsilon_limit == 10.0, "epsilon limit wrong");
    CHECK(dp_budget_remaining_eps(&budget) > 0.0, "remaining should be > 0");
    dp_budget_consume(&budget, 0.5, 0.0);
    dp_budget_consume(&budget, 1.2, 0.0);
    double remaining = dp_budget_remaining_eps(&budget);
    CHECK(remaining < 9.0, "budget not consumed");
    CHECK(remaining > 0.0, "budget exhausted");
    PASS();
    return 0;
}

static int test_dp_sequential_composition(void) {
    TEST("dp_sequential_composition");
    DPComposition comp;
    dp_comp_init(&comp);
    dp_comp_sequential(&comp, 0.5, 0.0);
    dp_comp_sequential(&comp, 1.2, 0.0);
    CHECK(comp.total_epsilon == 1.7, "sequential composition wrong");
    PASS();
    return 0;
}

/* ── Federated Learning Tests ── */
static int test_fl_server_init(void) {
    TEST("fl_server_init");
    FLServer server;
    double weights[64];
    for (int i = 0; i < 64; i++) weights[i] = 0.01;
    fl_server_init(&server, 64, 20, 5, 50, 0.01);
    fl_server_init_model(&server, weights);
    CHECK(server.num_clients == 20, "num_clients wrong");
    CHECK(server.total_rounds == 50, "total_rounds wrong");
    fl_server_free(&server);
    PASS();
    return 0;
}

static int test_fl_update_norm(void) {
    TEST("fl_update_norm");
    double gradients[64];
    for (int i = 0; i < 64; i++) gradients[i] = (double)(i % 8) / 100.0;
    double norm = fl_compute_update_norm(gradients, 64);
    CHECK(norm > 0.0, "norm should be > 0");
    CHECK(norm < 10.0, "norm unreasonably large");
    PASS();
    return 0;
}

/* ── Secure MPC Tests ── */
static int test_secret_sharing(void) {
    TEST("secret_sharing");
    SecretSharing ss;
    ss_init(&ss, 3, 1000000007ULL);
    uint64_t shares1[3], shares2[3], sum_shares[3];
    ss_share(&ss, 100, shares1);
    ss_share(&ss, 200, shares2);
    ss_add(&ss, shares1, shares2, sum_shares);
    uint64_t result;
    ss_reconstruct(&ss, sum_shares, &result);
    CHECK(result == 300, "100 + 200 != 300");
    ss_free(&ss);
    PASS();
    return 0;
}

static int test_beaver_multiply(void) {
    TEST("beaver_multiply");
    SecretSharing ss;
    ss_init(&ss, 3, 1000000007ULL);
    BeaverTriplePool pool;
    bt_pool_init(&pool, 8, ss.prime, 12345);
    bt_pool_generate(&pool);
    CHECK(pool.num_triples > 0, "no triples generated");
    BeaverTriple triple;
    bt_pool_consume(&pool, &triple);
    uint64_t shares1[3], shares2[3], prod_shares[3];
    ss_share(&ss, 5, shares1);
    ss_share(&ss, 7, shares2);
    bt_multiply(&ss, &triple, shares1, shares2, prod_shares);
    uint64_t result;
    ss_reconstruct(&ss, prod_shares, &result);
    CHECK(result == 35, "5 * 7 != 35");
    bt_pool_free(&pool);
    ss_free(&ss);
    PASS();
    return 0;
}

/* ── Anonymization Tests ── */
static int test_k_anonymity(void) {
    TEST("k_anonymity");
    AnonDataset ds;
    char *qi[] = {"age", "zip"};
    kanon_init_dataset(&ds, 6, 2, qi);
    AnonRecord rec; memset(&rec, 0, sizeof(rec));
    rec.num_qi = 2; rec.sensitive_attr = "disease";
    const char *ages[] = {"20-29","20-29","20-29","30-39","30-39","30-39"};
    const char *zips[] = {"123*","123*","123*","456*","456*","456*"};
    for (int i = 0; i < 6; i++) {
        rec.quasi_identifiers[0] = (char*)ages[i];
        rec.quasi_identifiers[1] = (char*)zips[i];
        kanon_add_record(&ds, i, &rec);
    }
    KAnonymityResult k_res;
    kanon_check(&ds, 3, &k_res);
    CHECK(k_res.satisfied, "k-anonymity should be satisfied (k=3)");
    kanon_free_dataset(&ds);
    PASS();
    return 0;
}

static int test_reid_risk(void) {
    TEST("reid_risk");
    AnonDataset ds;
    char *qi[] = {"age"};
    kanon_init_dataset(&ds, 3, 1, qi);
    AnonRecord rec; memset(&rec, 0, sizeof(rec));
    rec.num_qi = 1; rec.sensitive_attr = "condition";
    rec.quasi_identifiers[0] = "20-29"; kanon_add_record(&ds, 0, &rec);
    rec.quasi_identifiers[0] = "20-29"; kanon_add_record(&ds, 1, &rec);
    rec.quasi_identifiers[0] = "30-39"; kanon_add_record(&ds, 2, &rec);
    ReIdRiskScore risk;
    reid_score_compute(&ds, &risk);
    CHECK(risk.prosecutor_risk >= 0.0 && risk.prosecutor_risk <= 1.0, "risk out of range");
    kanon_free_dataset(&ds);
    PASS();
    return 0;
}

/* ── PET Tools Tests ── */
static int test_on_device_processing(void) {
    TEST("on_device_processing");
    OnDeviceProcessor odp;
    odproc_init(&odp, 32, 16);
    double result[32];
    odproc_compute_local(&odp, result, 32);
    CHECK(odp.num_features == 32, "num_features wrong");
    CHECK(odp.num_samples == 16, "num_samples wrong");
    odproc_free(&odp);
    PASS();
    return 0;
}

int main(void) {
    printf("=== mini-privacy-compute Unit Tests ===\n\n");

    int failed = 0;
    failed += test_dp_laplace_mechanism();
    failed += test_dp_gaussian_mechanism();
    failed += test_dp_budget();
    failed += test_dp_sequential_composition();
    failed += test_fl_server_init();
    failed += test_fl_update_norm();
    failed += test_secret_sharing();
    failed += test_beaver_multiply();
    failed += test_k_anonymity();
    failed += test_reid_risk();
    failed += test_on_device_processing();

    printf("\n=== Results: %d/%d passed, %d failed ===\n",
           tests_passed, tests_run, failed);
    return failed > 0 ? 1 : 0;
}
