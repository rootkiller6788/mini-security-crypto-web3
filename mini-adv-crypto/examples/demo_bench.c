#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include "zk_proof.h"
#include "homomorphic_enc.h"
#include "mpc_proto.h"
#include "post_quantum.h"
#include "threshold_sig.h"

#ifdef _WIN32
#include <windows.h>
static double bench_tick(void) {
    LARGE_INTEGER f, c;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&c);
    return (double)c.QuadPart / (double)f.QuadPart;
}
#else
#include <sys/time.h>
static double bench_tick(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec * 1e-6;
}
#endif

#define BENCH_ITER_SMALL  100
#define BENCH_ITER_MEDIUM 1000
#define BENCH_ITER_LARGE  5000

typedef struct {
    const char *name;
    double      elapsed;
    int         iterations;
} bench_result_t;

static bench_result_t bench_results[64];
static int bench_count = 0;

static void bench_record(const char *name, double elapsed, int iterations) {
    bench_results[bench_count].name       = name;
    bench_results[bench_count].elapsed    = elapsed;
    bench_results[bench_count].iterations = iterations;
    bench_count++;
}

static void bench_header(const char *section) {
    printf("\n=== %s ===\n", section);
}

#define BENCH_RUN(name, iterations, block) do { \
    double __bt0 = bench_tick(); \
    for (int __bi = 0; __bi < (iterations); __bi++) { block; } \
    double __bt1 = bench_tick(); \
    double __belapsed = __bt1 - __bt0; \
    printf("  %-40s %8.4f ms  (%d iters, %.2f us/op)\n", \
           name, __belapsed * 1000.0, iterations, \
           (__belapsed * 1e6) / (double)(iterations)); \
    bench_record(name, __belapsed, iterations); \
} while(0)

static void bench_print_summary(void) {
    printf("\n========================================\n");
    printf("  BENCHMARK SUMMARY\n");
    printf("========================================\n");
    printf("%-40s %8s %8s %10s\n", "Operation", "Time(ms)", "Iters", "us/op");
    printf("----------------------------------------\n");
    for (int i = 0; i < bench_count; i++) {
        double ms = bench_results[i].elapsed * 1000.0;
        double us_per_op = (bench_results[i].elapsed * 1e6) / (double)bench_results[i].iterations;
        printf("%-40s %8.4f %8d %10.2f\n",
               bench_results[i].name, ms,
               bench_results[i].iterations, us_per_op);
    }
    printf("========================================\n");
}

static void bench_zk_proofs(void) {
    bench_header("ZERO-KNOWLEDGE PROOFS");

    zk_field_t a, b, r;
    zk_field_from_u64(&a, 0xDEADBEEF);
    zk_field_from_u64(&b, 0xCAFEBABE);

    BENCH_RUN("zk_field_add", BENCH_ITER_LARGE, zk_field_add(&r, &a, &b));
    BENCH_RUN("zk_field_mul", BENCH_ITER_LARGE, zk_field_mul(&r, &a, &b));
    BENCH_RUN("zk_field_neg", BENCH_ITER_LARGE, zk_field_neg(&r, &a));
    BENCH_RUN("zk_field_inv", BENCH_ITER_SMALL, zk_field_inv(&r, &a));
    BENCH_RUN("zk_field_eq", BENCH_ITER_LARGE, zk_field_eq(&a, &b));

    zk_r1cs_t r1cs;
    zk_r1cs_init(&r1cs, 8, 16);

    BENCH_RUN("zk_r1cs_init(8,16)", BENCH_ITER_LARGE, zk_r1cs_init(&r1cs, 8, 16));

    int32_t a1[] = {0, 1, 0, 0, 0, 0, 0, 0, 0};
    int32_t b1[] = {0, 0, 1, 0, 0, 0, 0, 0, 0};
    int32_t c1[] = {0, 0, 0, 1, 0, 0, 0, 0, 0};
    BENCH_RUN("zk_r1cs_add_constraint", BENCH_ITER_LARGE,
              zk_r1cs_add_constraint(&r1cs, 0, a1, b1, c1));

    zk_proving_key_t pk;
    zk_verification_key_t vk;
    zk_setup_info_t info = {8, 1, {{0}}};

    BENCH_RUN("zk_trusted_setup", BENCH_ITER_SMALL,
              zk_trusted_setup(&pk, &vk, &r1cs, &info));

    int32_t witness[] = {1, 3, 4, 12, 7, 2, 5, 8, 0};
    zk_groth16_proof_t proof;

    BENCH_RUN("zk_groth16_prove", BENCH_ITER_MEDIUM,
              zk_groth16_prove(&proof, &pk, witness, 1));

    int32_t pub[] = {84};
    BENCH_RUN("zk_groth16_verify", BENCH_ITER_MEDIUM,
              zk_groth16_verify(&proof, &vk, pub, 1));

    zk_qap_t qap;
    zk_qap_from_r1cs(&qap, &r1cs);
    int32_t ea, eb, ec, et;
    BENCH_RUN("zk_qap_evaluate", BENCH_ITER_LARGE,
              zk_qap_evaluate(&qap, 2, &ea, &eb, &ec, &et));
}

static void bench_homomorphic(void) {
    bench_header("HOMOMORPHIC ENCRYPTION");

    he_paillier_pub_t pub;
    he_paillier_prv_t prv;

    BENCH_RUN("he_paillier_keygen(512)", BENCH_ITER_SMALL,
              he_paillier_keygen(&pub, &prv, 512));

    he_bigint_t m;
    he_bigint_set_u64(&m, 42);
    he_paillier_ct_t ct;

    BENCH_RUN("he_paillier_encrypt", BENCH_ITER_SMALL,
              he_paillier_encrypt(&ct, &m, &pub));

    he_bigint_t dec;
    BENCH_RUN("he_paillier_decrypt", BENCH_ITER_SMALL,
              he_paillier_decrypt(&dec, &ct, &prv));

    he_paillier_ct_t ct2;
    he_bigint_t m2;
    he_bigint_set_u64(&m2, 7);
    he_paillier_encrypt(&ct2, &m2, &pub);

    BENCH_RUN("he_paillier_add (homomorphic)", BENCH_ITER_SMALL,
              he_paillier_add(&ct2, &ct, &ct2, &pub));

    he_bigint_t scalar;
    he_bigint_set_u64(&scalar, 3);
    BENCH_RUN("he_paillier_scalar_mul", BENCH_ITER_SMALL,
              he_paillier_scalar_mul(&ct2, &ct, &scalar, &pub));

    he_bigint_t ba, bb, bg;
    he_bigint_set_u64(&ba, 48);
    he_bigint_set_u64(&bb, 180);

    BENCH_RUN("he_bigint_add", BENCH_ITER_LARGE,
              he_bigint_add(&bg, &ba, &bb));
    BENCH_RUN("he_bigint_mul", BENCH_ITER_LARGE,
              he_bigint_mul(&bg, &ba, &bb));
    BENCH_RUN("he_bigint_gcd", BENCH_ITER_MEDIUM,
              he_bigint_gcd(&bg, &ba, &bb));

    he_bfv_params_t bparams;
    he_bfv_params_init(&bparams, 16, 65537);
    he_bfv_secret_t bsk;
    he_bfv_keygen(&bsk, &bparams);

    he_bfv_plain_t bpt;
    memset(&bpt, 0, sizeof(bpt));
    bpt.coeff[0] = 5;
    bpt.noise_budget = 100;

    he_bfv_cipher_t bct;
    BENCH_RUN("he_bfv_encrypt", BENCH_ITER_MEDIUM,
              he_bfv_encrypt(&bct, &bpt, &bsk, &bparams));

    he_bfv_plain_t bdec;
    BENCH_RUN("he_bfv_decrypt", BENCH_ITER_MEDIUM,
              he_bfv_decrypt(&bdec, &bct, &bsk, &bparams));

    he_bfv_cipher_t bct2;
    he_bfv_encrypt(&bct2, &bpt, &bsk, &bparams);
    BENCH_RUN("he_bfv_add", BENCH_ITER_MEDIUM,
              he_bfv_add(&bct, &bct, &bct2, &bparams));
    BENCH_RUN("he_bfv_mul", BENCH_ITER_SMALL,
              he_bfv_mul(&bct, &bct, &bct2, &bparams));
}

static void bench_mpc(void) {
    bench_header("SECURE MULTI-PARTY COMPUTATION");

    mpc_shamir_ctx_t ctx;

    BENCH_RUN("mpc_shamir_split(t=3,n=7)", BENCH_ITER_MEDIUM,
              mpc_shamir_split(&ctx, 12345, 3, 7));

    uint32_t indices[] = {0, 2, 4};
    int64_t secret;
    BENCH_RUN("mpc_shamir_reconstruct(3)", BENCH_ITER_LARGE,
              mpc_shamir_reconstruct(&secret, &ctx, indices, 3));

    mpc_shamir_share_t sr;
    BENCH_RUN("mpc_shamir_add_share", BENCH_ITER_LARGE,
              mpc_shamir_add_share(&sr, &ctx.shares[0], &ctx.shares[1]));

    mpc_garbled_circuit_t gc;
    BENCH_RUN("mpc_garble_circuit_init", BENCH_ITER_LARGE,
              mpc_garble_circuit_init(&gc, 16, 8, 4));

    mpc_garbled_gate_t gate;
    BENCH_RUN("mpc_garble_and_gate", BENCH_ITER_LARGE,
              mpc_garble_and_gate(&gate, 0, 1, 2));

    mpc_garbled_key_t keys[2];
    mpc_garble_encode_input(&keys[0], 1, 0);
    mpc_garble_encode_input(&keys[1], 0, 1);
    uint64_t out;
    BENCH_RUN("mpc_garble_evaluate_circuit", BENCH_ITER_MEDIUM,
              mpc_garble_evaluate_circuit(&out, &gc, keys, 2));

    mpc_ot_sender_t ots;
    mpc_ot_sender_init(&ots);
    mpc_ot_message_t m0, m1;
    m0.limbs[0] = 0xAAA; m1.limbs[0] = 0xBBB;
    uint64_t ot_res;
    BENCH_RUN("mpc_ot_1_of_2", BENCH_ITER_LARGE,
              mpc_ot_1_of_2(&ot_res, &m0.limbs[0], &m1.limbs[0], 0));

    mpc_spdz_ctx_t spdz;
    mpc_spdz_init(&spdz, 4, 12345);
    BENCH_RUN("mpc_spdz_share", BENCH_ITER_LARGE,
              mpc_spdz_share(&spdz, 0, 100));

    mpc_spdz_share_t s1 = spdz.shares[0], s2 = spdz.shares[1];
    mpc_spdz_share_t sr2;
    BENCH_RUN("mpc_spdz_add", BENCH_ITER_LARGE,
              mpc_spdz_add(&sr2, &s1, &s2));

    BENCH_RUN("mpc_spdz_verify", BENCH_ITER_LARGE,
              mpc_spdz_verify(&spdz));

    int64_t mpc_sum;
    int64_t inputs[] = {10, 20, 30, 40, 50};
    BENCH_RUN("mpc_multi_party_sum(5)", BENCH_ITER_LARGE,
              mpc_multi_party_sum(&mpc_sum, inputs, 5));
}

static void bench_post_quantum(void) {
    bench_header("POST-QUANTUM CRYPTOGRAPHY");

    BENCH_RUN("pq_kyber_keygen", BENCH_ITER_SMALL, {
        pq_kyber_pk_t pk;
        pq_kyber_sk_t sk;
        pq_kyber_keygen(&pk, &sk);
    });

    pq_kyber_pk_t kpk;
    pq_kyber_sk_t ksk;
    pq_kyber_keygen(&kpk, &ksk);

    uint8_t ss[PQ_KYBER_SS_BYTES];
    pq_kyber_ct_t kct;

    BENCH_RUN("pq_kyber_encaps", BENCH_ITER_SMALL,
              pq_kyber_encaps(&kct, ss, &kpk));

    BENCH_RUN("pq_kyber_decaps", BENCH_ITER_SMALL,
              pq_kyber_decaps(ss, &kct, &ksk));

    BENCH_RUN("pq_dilithium_keygen", BENCH_ITER_SMALL, {
        pq_dilithium_pk_t dpk;
        pq_dilithium_sk_t dsk;
        pq_dilithium_keygen(&dpk, &dsk);
    });

    pq_dilithium_pk_t dpk;
    pq_dilithium_sk_t dsk;
    pq_dilithium_keygen(&dpk, &dsk);

    const uint8_t msg[] = "Benchmark message for Dilithium";
    pq_dilithium_sig_t dsig;
    uint32_t slen;

    BENCH_RUN("pq_dilithium_sign", BENCH_ITER_SMALL,
              pq_dilithium_sign(&dsig, &slen, msg, (uint32_t)sizeof(msg), &dsk));

    BENCH_RUN("pq_dilithium_verify", BENCH_ITER_SMALL,
              pq_dilithium_verify(&dsig, msg, (uint32_t)sizeof(msg), &dpk));

    BENCH_RUN("pq_sphincs_keygen", BENCH_ITER_SMALL, {
        pq_sphincs_pk_t spk;
        pq_sphincs_sk_t ssk;
        pq_sphincs_keygen(&spk, &ssk);
    });

    pq_sphincs_pk_t spk;
    pq_sphincs_sk_t ssk;
    pq_sphincs_keygen(&spk, &ssk);

    pq_sphincs_sig_t ssig;
    BENCH_RUN("pq_sphincs_sign", BENCH_ITER_SMALL,
              pq_sphincs_sign(&ssig, msg, (uint32_t)sizeof(msg), &ssk));

    BENCH_RUN("pq_sphincs_verify", BENCH_ITER_SMALL,
              pq_sphincs_verify(&ssig, msg, (uint32_t)sizeof(msg), &spk));

    pq_poly_t pa, pb, pr;
    pq_poly_init(&pa);
    pq_poly_init(&pb);
    for (int i = 0; i < PQ_KYBER_N; i++) {
        pa.coeffs[i] = (int16_t)(i * 3 % PQ_KYBER_Q);
        pb.coeffs[i] = (int16_t)(i * 5 % PQ_KYBER_Q);
    }

    BENCH_RUN("pq_poly_add(256)", BENCH_ITER_LARGE,
              pq_poly_add(&pr, &pa, &pb));
    BENCH_RUN("pq_poly_mul(256)", BENCH_ITER_SMALL,
              pq_poly_mul(&pr, &pa, &pb));
    BENCH_RUN("pq_poly_ntt(256)", BENCH_ITER_SMALL,
              pq_poly_ntt(&pa));

    uint8_t seed[PQ_KYBER_SYMBYTES];
    memset(seed, 0x42, sizeof(seed));
    pq_poly_t sampled;
    BENCH_RUN("pq_mlwe_sample", BENCH_ITER_MEDIUM,
              pq_mlwe_sample(&sampled, seed));
}

static void bench_threshold(void) {
    bench_header("THRESHOLD SIGNATURES");

    ts_sss_ctx_t tsctx;

    BENCH_RUN("ts_sss_split(t=3,n=7)", BENCH_ITER_MEDIUM,
              ts_sss_split(&tsctx, 12345, 3, 7));

    ts_share_t ts_shares[5];
    for (int i = 0; i < 5; i++) ts_shares[i] = tsctx.shares[i];
    int64_t ts_secret;

    BENCH_RUN("ts_sss_reconstruct(3)", BENCH_ITER_LARGE,
              ts_sss_reconstruct(&ts_secret, ts_shares, 3, 3));

    BENCH_RUN("ts_sss_lagrange_coeff", BENCH_ITER_LARGE, {
        int64_t coeff;
        uint32_t indices[] = {0, 2, 4};
        ts_sss_lagrange_coeff(&coeff, indices, 3, 1, TS_SSS_PRIME);
    });

    ts_frost_party_t party;
    BENCH_RUN("ts_frost_keygen_round1", BENCH_ITER_MEDIUM,
              ts_frost_keygen_round1(&party, 1, 2, 3));

    ts_frost_nonce_t nonce;
    ts_frost_commit_t commit;
    BENCH_RUN("ts_frost_sign_round1", BENCH_ITER_MEDIUM,
              ts_frost_sign_round1(&nonce, &commit, &party));

    uint8_t agg_r[TS_FROST_R_BYTES];
    ts_frost_commit_t commits_b[1];
    memcpy(&commits_b[0], &commit, sizeof(commit));
    BENCH_RUN("ts_frost_aggregate_nonces", BENCH_ITER_MEDIUM,
              ts_frost_aggregate_nonces(agg_r, commits_b, 1));

    uint8_t sig_z[TS_FROST_Z_BYTES];
    uint8_t challenge[TS_FROST_C_BYTES] = {0};
    const uint8_t fmsg[] = "bench";
    BENCH_RUN("ts_frost_sign_round2", BENCH_ITER_MEDIUM,
              ts_frost_sign_round2(sig_z, &party, &nonce, agg_r, challenge, fmsg, 5));

    uint8_t sig_shares[1][TS_FROST_Z_BYTES];
    memcpy(sig_shares[0], sig_z, TS_FROST_Z_BYTES);
    ts_frost_signature_t fsig;
    BENCH_RUN("ts_frost_aggregate_sigs", BENCH_ITER_MEDIUM,
              ts_frost_aggregate_sigs(&fsig, sig_shares, &party, 1));

    ts_dkg_ctx_t dkg;
    BENCH_RUN("ts_dkg_init", BENCH_ITER_MEDIUM,
              ts_dkg_init(&dkg, 3, 5));

    BENCH_RUN("ts_dkg_round1(5 parties)", BENCH_ITER_SMALL, {
        for (uint32_t p = 0; p < 5; p++) ts_dkg_round1(&dkg, p);
    });

    BENCH_RUN("ts_dkg_round2(5 parties)", BENCH_ITER_SMALL, {
        for (uint32_t p = 0; p < 5; p++) ts_dkg_round2(&dkg, p);
    });

    ts_sss_ctx_t rold, rnew;
    ts_sss_split(&rold, 55555, 2, 4);
    memcpy(&rnew, &rold, sizeof(ts_sss_ctx_t));
    BENCH_RUN("ts_refresh_proactive", BENCH_ITER_LARGE,
              ts_refresh_proactive(&rnew, 1));
}

int main(void) {
    double total_start = bench_tick();

    printf("===============================================\n");
    printf("  mini-adv-crypto  -  Performance Benchmarks\n");
    printf("  Advanced Cryptography Primitives (C99)\n");
    printf("===============================================\n");
    printf("  Iterations: SMALL=%d MEDIUM=%d LARGE=%d\n",
           BENCH_ITER_SMALL, BENCH_ITER_MEDIUM, BENCH_ITER_LARGE);

    zk_module_version();
    he_module_version();
    mpc_module_version();
    pq_module_version();
    ts_module_version();

    bench_zk_proofs();
    bench_homomorphic();
    bench_mpc();
    bench_post_quantum();
    bench_threshold();

    double total_end = bench_tick();

    bench_print_summary();

    printf("\nTotal benchmark time: %.3f seconds\n", total_end - total_start);

    return 0;
}
