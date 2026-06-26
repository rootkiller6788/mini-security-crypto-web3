/*
 * mini-adv-crypto — Core Tests
 *
 * Unit tests for ZK proofs, homomorphic encryption, MPC, post-quantum, threshold sigs.
 */
#include "../include/zk_proof.h"
#include "../include/homomorphic_enc.h"
#include "../include/mpc_proto.h"
#include "../include/post_quantum.h"
#include "../include/threshold_sig.h"
#include <stdio.h>
#include <string.h>

static int tests_run = 0, tests_passed = 0;

#define TEST(name) do { tests_run++; printf("  TEST %s ... ", name); } while(0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); return 1; } while(0)
#define CHECK(cond, msg) if (!(cond)) FAIL(msg)

/* ── ZK Proof Tests ── */
static int test_zk_field_arithmetic(void) {
    TEST("zk_field_arithmetic");
    zk_field_t a, b, r;
    zk_field_from_u64(&a, 5);
    zk_field_from_u64(&b, 3);
    zk_field_add(&r, &a, &b);
    zk_field_t exp; zk_field_from_u64(&exp, 8);
    CHECK(zk_field_eq(&r, &exp), "5+3 != 8");
    zk_field_mul(&r, &a, &b);
    zk_field_from_u64(&exp, 15);
    CHECK(zk_field_eq(&r, &exp), "5*3 != 15");
    PASS();
    return 0;
}

static int test_zk_r1cs_basic(void) {
    TEST("zk_r1cs_init_and_constraint");
    zk_r1cs_t r1cs;
    CHECK(zk_r1cs_init(&r1cs, 4, 3) == 0, "r1cs init failed");
    CHECK(r1cs.num_vars == 4, "num_vars wrong");
    CHECK(r1cs.num_constraints == 3, "num_constraints wrong");
    PASS();
    return 0;
}

static int test_zk_groth16_prove_verify(void) {
    TEST("zk_groth16_prove_verify");
    zk_r1cs_t r1cs;
    zk_r1cs_init(&r1cs, 3, 2);
    zk_proving_key_t pk;
    zk_verification_key_t vk;
    zk_setup_info_t info; info.num_vars = 3; info.num_inputs = 1;
    zk_field_from_u64(&info.toxic_waste, 7);
    CHECK(zk_trusted_setup(&pk, &vk, &r1cs, &info) == 0, "setup failed");
    int32_t witness[] = {1, 2, 3};
    zk_groth16_proof_t proof;
    CHECK(zk_groth16_prove(&proof, &pk, witness, 1) == 0, "prove failed");
    int32_t pub_inputs[] = {1};
    CHECK(zk_groth16_verify(&proof, &vk, pub_inputs, 1) == 1, "verify failed");
    zk_proving_key_free(&pk);
    zk_verification_key_free(&vk);
    PASS();
    return 0;
}

/* ── Homomorphic Encryption Tests ── */
static int test_paillier_encrypt_decrypt(void) {
    TEST("paillier_encrypt_decrypt");
    he_paillier_pub_t pub;
    he_paillier_prv_t prv;
    CHECK(he_paillier_keygen(&pub, &prv, 512) == 0, "keygen failed");
    he_bigint_t msg;
    he_bigint_set_u64(&msg, 42);
    he_paillier_ct_t ct;
    CHECK(he_paillier_encrypt(&ct, &msg, &pub) == 0, "encrypt failed");
    he_bigint_t dec;
    CHECK(he_paillier_decrypt(&dec, &ct, &prv) == 0, "decrypt failed");
    CHECK(he_bigint_cmp(&dec, &msg) == 0, "decrypt != msg");
    PASS();
    return 0;
}

static int test_paillier_homomorphic_add(void) {
    TEST("paillier_homomorphic_add");
    he_paillier_pub_t pub;
    he_paillier_prv_t prv;
    he_paillier_keygen(&pub, &prv, 512);
    he_bigint_t m1, m2;
    he_bigint_set_u64(&m1, 10);
    he_bigint_set_u64(&m2, 20);
    he_paillier_ct_t c1, c2, csum;
    he_paillier_encrypt(&c1, &m1, &pub);
    he_paillier_encrypt(&c2, &m2, &pub);
    CHECK(he_paillier_add(&csum, &c1, &c2, &pub) == 0, "homomorphic add failed");
    he_bigint_t dec;
    he_paillier_decrypt(&dec, &csum, &prv);
    he_bigint_t exp; he_bigint_set_u64(&exp, 30);
    CHECK(he_bigint_cmp(&dec, &exp) == 0, "10+20 != 30");
    PASS();
    return 0;
}

/* ── Secure MPC Tests ── */
static int test_shamir_split_reconstruct(void) {
    TEST("shamir_split_reconstruct");
    mpc_shamir_ctx_t ctx;
    CHECK(mpc_shamir_split(&ctx, 12345, 3, 5) == 0, "split failed");
    CHECK(ctx.threshold == 3, "threshold wrong");
    CHECK(ctx.total == 5, "total wrong");
    uint32_t indices[] = {0, 1, 2};
    int64_t secret;
    CHECK(mpc_shamir_reconstruct(&secret, &ctx, indices, 3) == 0, "reconstruct failed");
    CHECK(secret == 12345, "secret mismatch");
    PASS();
    return 0;
}

static int test_mpc_multi_party_sum(void) {
    TEST("mpc_multi_party_sum");
    int64_t inputs[] = {100, 200, 300, 400};
    int64_t result;
    CHECK(mpc_multi_party_sum(&result, inputs, 4) == 0, "multi party sum failed");
    CHECK(result == 1000, "sum wrong");
    PASS();
    return 0;
}

/* ── Post-Quantum Tests ── */
static int test_kyber_keygen_encaps(void) {
    TEST("kyber_keygen_encaps_decaps");
    pq_kyber_pk_t pk;
    pq_kyber_sk_t sk;
    CHECK(pq_kyber_keygen(&pk, &sk) == 0, "kyber keygen failed");
    pq_kyber_ct_t ct;
    uint8_t ss1[PQ_KYBER_SS_BYTES], ss2[PQ_KYBER_SS_BYTES];
    CHECK(pq_kyber_encaps(&ct, ss1, &pk) == 0, "encaps failed");
    CHECK(pq_kyber_decaps(ss2, &ct, &sk) == 0, "decaps failed");
    CHECK(memcmp(ss1, ss2, PQ_KYBER_SS_BYTES) == 0, "shared secrets differ");
    PASS();
    return 0;
}

static int test_dilithium_sign_verify(void) {
    TEST("dilithium_sign_verify");
    pq_dilithium_pk_t pk;
    pq_dilithium_sk_t sk;
    CHECK(pq_dilithium_keygen(&pk, &sk) == 0, "dilithium keygen failed");
    const char *msg = "post-quantum signature test";
    pq_dilithium_sig_t sig;
    uint32_t siglen;
    CHECK(pq_dilithium_sign(&sig, &siglen, (const uint8_t *)msg, (uint32_t)strlen(msg), &sk) == 0, "sign failed");
    CHECK(pq_dilithium_verify(&sig, (const uint8_t *)msg, (uint32_t)strlen(msg), &pk) == 0, "verify failed");
    PASS();
    return 0;
}

/* ── Threshold Signature Tests ── */
static int test_sss_split_reconstruct(void) {
    TEST("sss_split_reconstruct");
    ts_sss_ctx_t ctx;
    CHECK(ts_sss_split(&ctx, 9999, 3, 5) == 0, "sss split failed");
    ts_share_t subset[3];
    subset[0] = ctx.shares[0];
    subset[1] = ctx.shares[1];
    subset[2] = ctx.shares[2];
    int64_t secret;
    CHECK(ts_sss_reconstruct(&secret, subset, 3, 3) == 0, "reconstruct failed");
    CHECK(secret == 9999, "sss secret mismatch");
    PASS();
    return 0;
}

static int test_frost_round1(void) {
    TEST("frost_keygen_round1");
    ts_frost_party_t party;
    CHECK(ts_frost_keygen_round1(&party, 1, 3, 5) == 0, "frost round1 failed");
    CHECK(party.party_id == 1, "party_id wrong");
    CHECK(party.threshold == 3, "threshold wrong");
    CHECK(party.num_signers == 5, "num_signers wrong");
    PASS();
    return 0;
}

int main(void) {
    printf("=== mini-adv-crypto Unit Tests ===\n\n");

    int failed = 0;
    failed += test_zk_field_arithmetic();
    failed += test_zk_r1cs_basic();
    failed += test_zk_groth16_prove_verify();
    failed += test_paillier_encrypt_decrypt();
    failed += test_paillier_homomorphic_add();
    failed += test_shamir_split_reconstruct();
    failed += test_mpc_multi_party_sum();
    failed += test_kyber_keygen_encaps();
    failed += test_dilithium_sign_verify();
    failed += test_sss_split_reconstruct();
    failed += test_frost_round1();

    printf("\n=== Results: %d/%d passed, %d failed ===\n",
           tests_passed, tests_run, failed);
    return failed > 0 ? 1 : 0;
}
