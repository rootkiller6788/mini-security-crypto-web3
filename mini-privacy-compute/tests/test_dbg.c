#include "../include/differential_privacy.h"
#include "../include/federated_learn.h"
#include "../include/secure_mpc_comp.h"
#include "../include/anonymization.h"
#include "../include/pet_tools.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run = 0, tests_passed = 0;
#define TEST(name) do { printf("  TEST %s ... ", name); fflush(stdout); tests_run++; } while(0)
#define PASS() do { printf("PASS\n"); fflush(stdout); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); fflush(stdout); return 1; } while(0)
#define CHECK(cond, msg) if (!(cond)) FAIL(msg)

static int test_dp_laplace_mechanism(void) {
    TEST("dp_laplace_mechanism");
    uint64_t seed = 42;
    double result = dp_laplace_mechanism(100.0, 1.0, 0.5, &seed);
    CHECK(result != 100.0, "noise");
    CHECK(result > 0.0, "positive");
    PASS(); return 0;
}
static int test_dp_budget(void) {
    TEST("dp_budget");
    DPBudget budget;
    dp_budget_init(&budget, 10.0, 1e-5);
    dp_budget_consume(&budget, 0.5, 0.0);
    CHECK(dp_budget_remaining_eps(&budget) < 10.0, "not consumed");
    PASS(); return 0;
}
static int test_fl_server_init(void) {
    TEST("fl_server_init");
    FLServer server;
    double weights[64];
    for (int i = 0; i < 64; i++) weights[i] = 0.01;
    fl_server_init(&server, 64, 20, 5, 50, 0.01);
    fl_server_init_model(&server, weights);
    fl_server_free(&server);
    PASS(); return 0;
}
static int test_secret_sharing(void) {
    TEST("secret_sharing");
    SecretSharing ss;
    ss_init(&ss, 3, 1000000007ULL);
    uint64_t s1[3], s2[3], sum_s[3];
    ss_share(&ss, 100, s1);
    ss_share(&ss, 200, s2);
    ss_add(&ss, s1, s2, sum_s);
    uint64_t result;
    ss_reconstruct(&ss, sum_s, &result);
    CHECK(result == 300, "100+200!=300");
    ss_free(&ss);
    PASS(); return 0;
}
static int test_beaver_multiply(void) {
    TEST("beaver_multiply");
    SecretSharing ss;
    ss_init(&ss, 3, 1000000007ULL);
    BeaverTriplePool pool;
    bt_pool_init(&pool, 8, ss.prime, 12345);
    bt_pool_generate(&pool);
    BeaverTriple triple;
    bt_pool_consume(&pool, &triple);
    uint64_t s1[3], s2[3], ps[3];
    ss_share(&ss, 5, s1);
    ss_share(&ss, 7, s2);
    bt_multiply(&ss, &triple, s1, s2, ps);
    uint64_t result;
    ss_reconstruct(&ss, ps, &result);
    CHECK(result == 35, "5*7!=35");
    bt_pool_free(&pool);
    ss_free(&ss);
    PASS(); return 0;
}
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
    CHECK(k_res.satisfied, "k=3");
    free(k_res.group_ids);
    kanon_free_dataset(&ds);
    PASS(); return 0;
}
static int test_shamir(void) {
    TEST("shamir");
    ShamirSS sss;
    shamir_ss_init(&sss, 3, 5, 1000000007ULL);
    uint64_t shares[5];
    uint64_t seed = 999;
    shamir_ss_share(&sss, 12345, shares, &seed);
    uint64_t xi[3] = {0,2,4};
    uint64_t sv[3] = {shares[0],shares[2],shares[4]};
    uint64_t rec;
    int ok = shamir_ss_reconstruct(&sss, xi, sv, 3, &rec);
    CHECK(ok && rec == 12345, "shamir");
    shamir_ss_free(&sss);
    PASS(); return 0;
}
static int test_paillier(void) {
    TEST("paillier");
    PaillierPubKey pub; PaillierPrivKey priv;
    int ok = paillier_keygen(&pub, &priv, 12);
    CHECK(ok, "keygen");
    uint64_t ct;
    uint64_t seed = 77777;
    paillier_encrypt(&pub, 42, &ct, &seed);
    uint64_t dec = paillier_decrypt(&pub, &priv, ct);
    CHECK(dec == 42, "decrypt");
    PASS(); return 0;
}
static int test_paillier_add(void) {
    TEST("paillier_add");
    PaillierPubKey pub; PaillierPrivKey priv;
    paillier_keygen(&pub, &priv, 12);
    uint64_t ct1, ct2;
    uint64_t seed = 11111;
    paillier_encrypt(&pub, 25, &ct1, &seed);
    paillier_encrypt(&pub, 17, &ct2, &seed);
    uint64_t ct_sum = paillier_add(&pub, ct1, ct2);
    uint64_t dec_sum = paillier_decrypt(&pub, &priv, ct_sum);
    CHECK(dec_sum == 42, "hom_add");
    PASS(); return 0;
}
static int test_dp_composition(void) {
    TEST("dp_composition");
    dp_print_composition_theorems();
    double eps = dp_advanced_composition(0.1, 1e-6, 100, 1e-5);
    CHECK(eps > 0.0 && eps < 100.0, "advanced");
    PASS(); return 0;
}

int main(void) {
    printf("=== test suite ===\n\n"); fflush(stdout);
    int failed = 0;
    failed += test_dp_laplace_mechanism();
    failed += test_dp_budget();
    failed += test_fl_server_init();
    failed += test_secret_sharing();
    failed += test_beaver_multiply();
    failed += test_k_anonymity();
    failed += test_shamir();
    failed += test_paillier();
    failed += test_paillier_add();
    failed += test_dp_composition();
    printf("\n=== %d/%d passed, %d failed ===\n", tests_passed, tests_run, failed);
    fflush(stdout);
    return failed > 0 ? 1 : 0;
}
