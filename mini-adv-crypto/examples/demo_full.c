#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "zk_proof.h"
#include "homomorphic_enc.h"
#include "mpc_proto.h"
#include "post_quantum.h"
#include "threshold_sig.h"

#ifdef _WIN32
#include <windows.h>
static double demo_now(void) {
    LARGE_INTEGER f, c;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&c);
    return (double)c.QuadPart / (double)f.QuadPart;
}
#else
#include <sys/time.h>
static double demo_now(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec * 1e-6;
}
#endif

static const char *demo_passfail(int ok) { return ok == 0 ? "PASS" : "FAIL"; }

static void demo_section_header(const char *title) {
    printf("\n%s\n", title);
    for (size_t i = 0; i < strlen(title); i++) printf("=");
    printf("\n\n");
}

static void demo_full_zk(void) {
    demo_section_header("ZERO-KNOWLEDGE PROOFS (Full Demo)");

    printf("[1] R1CS Constraint System\n");
    zk_r1cs_t r1cs;
    zk_r1cs_init(&r1cs, 4, 3);

    int32_t a1[] = {0, 1, 0, 0, 0};
    int32_t b1[] = {0, 0, 1, 0, 0};
    int32_t c1[] = {0, 0, 0, 1, 0};
    zk_r1cs_add_constraint(&r1cs, 0, a1, b1, c1);

    int32_t a2[] = {0, 0, 0, 1, 0};
    int32_t b2[] = {0, 0, 0, 0, 1};
    int32_t c2[] = {0, 1, 0, 0, 0};
    zk_r1cs_add_constraint(&r1cs, 1, a2, b2, c2);

    int32_t a3[] = {0, 0, 1, 0, 0};
    int32_t b3[] = {0, 0, 0, 0, 1};
    int32_t c3[] = {0, 0, 0, 1, 0};
    zk_r1cs_add_constraint(&r1cs, 2, a3, b3, c3);

    zk_r1cs_print(&r1cs);

    int32_t witness[] = {1, 3, 4, 12, 7};
    int ok = zk_r1cs_verify_witness(&r1cs, witness);
    printf("  Witness verify: %s\n", demo_passfail(ok));

    printf("\n[2] Groth16 Trusted Setup\n");
    zk_proving_key_t pk;
    zk_verification_key_t vk;
    zk_setup_info_t info = {4, 1, {{0}}};
    zk_trusted_setup(&pk, &vk, &r1cs, &info);
    printf("  PK: num_vars=%u num_inputs=%u\n", pk.num_vars, pk.num_inputs);

    zk_setup_toxic_mpc(&pk, 7);
    printf("  MPC ceremony complete (7 participants)\n");

    printf("\n[3] Groth16 Proof Generation & Verification\n");
    zk_groth16_proof_t proof;
    zk_groth16_prove(&proof, &pk, witness, 1);
    zk_groth16_print(&proof);

    int32_t pub[] = {84};
    ok = zk_groth16_verify(&proof, &vk, pub, 1);
    printf("  Groth16 verify: %s\n", demo_passfail(ok));

    printf("\n[4] QAP Conversion\n");
    zk_qap_t qap;
    zk_qap_from_r1cs(&qap, &r1cs);
    printf("  QAP degree: %u\n", qap.degree);

    printf("\n[5] Pinocchio Protocol\n");
    int32_t io[] = {84, 3};
    ok = zk_pinocchio_verify(&proof, &qap, io, 2);
    printf("  Pinocchio verify: %s\n", demo_passfail(ok));

    printf("\n[6] STARK Trace & FRI\n");
    int32_t trace_data[] = {1,0,2, 2,1,0, 3,2,1, 4,3,2, 5,4,3, 6,5,4, 7,6,5, 8,7,6};
    zk_stark_trace_t stark;
    zk_stark_trace_commit(&stark, trace_data, 8, 3);
    printf("  Trace: %u x %u\n", stark.width, stark.height);
    ok = zk_stark_fri_verify(&stark, 4);
    printf("  FRI verify: %s\n", demo_passfail(ok));

    zk_proving_key_free(&pk);
    zk_verification_key_free(&vk);
}

static void demo_full_he(void) {
    demo_section_header("HOMOMORPHIC ENCRYPTION (Full Demo)");

    printf("[1] Paillier Key Generation\n");
    he_paillier_pub_t pub;
    he_paillier_prv_t prv;
    he_paillier_keygen(&pub, &prv, 512);
    printf("  Key generated (%u bits)\n", pub.bits);

    printf("\n[2] Paillier Encrypt/Decrypt Round-trip\n");
    he_bigint_t m, m_dec;
    he_bigint_set_u64(&m, 31337);
    he_paillier_ct_t ct;
    he_paillier_encrypt(&ct, &m, &pub);
    he_paillier_decrypt(&m_dec, &ct, &prv);
    he_bigint_print("  Original: ", &m);
    he_bigint_print("  Decrypted: ", &m_dec);
    printf("  %s\n", m_dec.limbs[0] == 31337 ? "OK" : "FAIL");

    printf("\n[3] Homomorphic Addition (Enc(a) + Enc(b) = Enc(a+b))\n");
    he_bigint_t a, b;
    he_bigint_set_u64(&a, 100);
    he_bigint_set_u64(&b, 200);
    he_paillier_ct_t ca, cb, csum;
    he_paillier_encrypt(&ca, &a, &pub);
    he_paillier_encrypt(&cb, &b, &pub);
    he_paillier_add(&csum, &ca, &cb, &pub);
    he_bigint_t sum_dec;
    he_paillier_decrypt(&sum_dec, &csum, &prv);
    he_bigint_print("  100 + 200 = ", &sum_dec);
    printf("  %s\n", sum_dec.limbs[0] == 300 ? "OK" : "FAIL");

    printf("\n[4] Homomorphic Scalar Multiplication\n");
    he_bigint_t scalar;
    he_bigint_set_u64(&scalar, 5);
    he_paillier_ct_t cscaled;
    he_paillier_scalar_mul(&cscaled, &ca, &scalar, &pub);
    he_bigint_t scaled_dec;
    he_paillier_decrypt(&scaled_dec, &cscaled, &prv);
    he_bigint_print("  100 * 5 = ", &scaled_dec);
    printf("  %s\n", scaled_dec.limbs[0] == 500 ? "OK" : "FAIL");

    printf("\n[5] Encrypted Polynomial Evaluation: f(x)=3x^2+2x+1 at x=5\n");
    he_bigint_t x, three, two, one;
    he_bigint_set_u64(&x, 5);
    he_bigint_set_u64(&three, 3);
    he_bigint_set_u64(&two, 2);
    he_bigint_set_u64(&one, 1);

    he_paillier_ct_t cx, cresult, c3x2, c2x;
    he_paillier_encrypt(&cx, &x, &pub);

    he_paillier_ct_t cx_squared;
    he_paillier_scalar_mul(&cx_squared, &cx, &x, &pub);

    he_paillier_scalar_mul(&c3x2, &cx_squared, &three, &pub);
    he_paillier_scalar_mul(&c2x, &cx, &two, &pub);
    he_paillier_add(&cresult, &c3x2, &c2x, &pub);

    he_paillier_ct_t cone;
    he_paillier_encrypt(&cone, &one, &pub);
    he_paillier_ct_t final;
    he_paillier_add(&final, &cresult, &cone, &pub);

    he_bigint_t f5;
    he_paillier_decrypt(&f5, &final, &prv);
    he_bigint_print("  f(5) = 3*25 + 2*5 + 1 = ", &f5);
    printf("  %s (expect 86)\n", f5.limbs[0] == 86 ? "OK" : "FAIL");

    printf("\n[6] BFV Scheme Demo\n");
    he_bfv_params_t bfv_params;
    he_bfv_params_init(&bfv_params, 16, 65537);
    he_bfv_secret_t sk;
    he_bfv_keygen(&sk, &bfv_params);
    printf("  BFV init: modulus=%llu degree=%u\n",
           (unsigned long long)bfv_params.modulus, bfv_params.poly_degree);

    he_bfv_plain_t pt;
    memset(&pt, 0, sizeof(pt));
    pt.coeff[0] = 42;
    pt.noise_budget = 100;

    he_bfv_cipher_t bfv_ct;
    he_bfv_encrypt(&bfv_ct, &pt, &sk, &bfv_params);
    he_bfv_plain_t bfv_dec;
    he_bfv_decrypt(&bfv_dec, &bfv_ct, &sk, &bfv_params);
    printf("  Encrypt/Decrypt: %llu %s\n",
           (unsigned long long)bfv_dec.coeff[0],
           bfv_dec.coeff[0] == 42 ? "OK" : "FAIL");
    printf("  Noise budget: %d\n", he_bfv_noise_budget(&bfv_ct));
}

static void demo_full_mpc(void) {
    demo_section_header("SECURE MULTI-PARTY COMPUTATION (Full Demo)");

    printf("[1] Shamir Secret Sharing: t=3, n=7\n");
    mpc_shamir_ctx_t sss;
    mpc_shamir_split(&sss, 999888777LL, 3, 7);
    mpc_shamir_print(&sss);

    printf("  Reconstruction tests:\n");
    uint32_t indices[7] = {0,1,2,3,4,5,6};
    for (uint32_t k = 3; k <= 7; k++) {
        int64_t secret;
        int ok = mpc_shamir_reconstruct(&secret, &sss, indices, k);
        printf("    %u shares => %lld %s\n", k, (long long)secret, demo_passfail(ok));
    }

    printf("\n[2] Yao Garbled Circuit: Full Adder\n");
    mpc_garbled_circuit_t gc;
    mpc_garble_circuit_init(&gc, 5, 3, 2);
    for (uint32_t g = 0; g < gc.num_gates; g++) {
        mpc_garble_and_gate(&gc.gates[g], g * 3, g * 3 + 1, g + 20);
    }
    mpc_garble_print_circuit(&gc);

    mpc_garbled_key_t in_keys[3];
    mpc_garble_encode_input(&in_keys[0], 1, 0);
    mpc_garble_encode_input(&in_keys[1], 0, 1);
    mpc_garble_encode_input(&in_keys[2], 1, 2);

    uint64_t out;
    mpc_garble_evaluate_circuit(&out, &gc, in_keys, 3);
    printf("  Circuit output: %016llx\n", (unsigned long long)out);

    printf("\n[3] Oblivious Transfer: 1-of-2\n");
    mpc_ot_sender_t ot_s;
    mpc_ot_sender_init(&ot_s);
    mpc_ot_message_t om0, om1;
    om0.limbs[0] = 0x11111111ULL; om0.limbs[1] = 0x22222222ULL;
    om1.limbs[0] = 0xAAAAAAAAULL; om1.limbs[1] = 0xBBBBBBBBULL;
    mpc_ot_send_messages(&ot_s, &om0, &om1);
    mpc_ot_print_messages(&ot_s);

    for (int ch = 0; ch < 2; ch++) {
        uint64_t res;
        mpc_ot_1_of_2(&res, &om0.limbs[0], &om1.limbs[0], (uint64_t)ch);
        printf("  Choice=%d => 0x%016llx\n", ch, (unsigned long long)res);
    }

    printf("\n[4] SPDZ Multi-party Computation\n");
    mpc_spdz_ctx_t spdz;
    mpc_spdz_init(&spdz, 5, 98765);
    int64_t values[] = {10, 20, 30, 40, 50};
    for (uint32_t i = 0; i < 5; i++) mpc_spdz_share(&spdz, i, values[i]);
    int64_t spdz_sum;
    int ok = mpc_spdz_reconstruct(&spdz_sum, &spdz);
    printf("  Sum: %lld MAC: %s\n", (long long)spdz_sum, demo_passfail(ok));

    int verify = mpc_spdz_verify(&spdz);
    printf("  SPDZ verify: %s\n", demo_passfail(verify));

    printf("\n[5] Privacy-preserving Multi-party Sum\n");
    int64_t inputs[] = {512, 256, 128, 64, 32, 16, 8, 4, 2, 1};
    int64_t mpc_sum;
    mpc_multi_party_sum(&mpc_sum, inputs, 10);
    printf("  Sum of 10 values = %lld (expect 1023)\n", (long long)mpc_sum);
}

static void demo_full_pq(void) {
    demo_section_header("POST-QUANTUM CRYPTOGRAPHY (Full Demo)");

    printf("[1] Kyber KEM (Lattice-based)\n");
    pq_kyber_pk_t kpk;
    pq_kyber_sk_t ksk;
    pq_kyber_keygen(&kpk, &ksk);
    printf("  Keygen: OK\n");

    uint8_t ss_enc[PQ_KYBER_SS_BYTES];
    uint8_t ss_dec[PQ_KYBER_SS_BYTES];
    pq_kyber_ct_t kct;
    pq_kyber_encaps(&kct, ss_enc, &kpk);
    pq_kyber_decaps(ss_dec, &kct, &ksk);

    printf("  Encaps SS: ");
    for (int i = 0; i < 8; i++) printf("%02x", ss_enc[i]);
    printf("\n  Decaps SS: ");
    for (int i = 0; i < 8; i++) printf("%02x", ss_dec[i]);
    printf("\n  Match: %s\n", memcmp(ss_enc, ss_dec, PQ_KYBER_SS_BYTES) == 0 ? "YES" : "NO");

    printf("\n[2] Dilithium Signature (Lattice-based)\n");
    pq_dilithium_pk_t dpk;
    pq_dilithium_sk_t dsk;
    pq_dilithium_keygen(&dpk, &dsk);
    printf("  Keygen: OK\n");

    const char *dmsg = "Dilithium signature demo message";
    pq_dilithium_sig_t dsig;
    uint32_t siglen;
    pq_dilithium_sign(&dsig, &siglen, (const uint8_t *)dmsg, (uint32_t)strlen(dmsg), &dsk);
    printf("  Signature: %u bytes\n", siglen);

    int dok = pq_dilithium_verify(&dsig, (const uint8_t *)dmsg, (uint32_t)strlen(dmsg), &dpk);
    printf("  Verify: %s\n", demo_passfail(dok));

    printf("\n[3] SPHINCS+ Hash-based Signature\n");
    pq_sphincs_pk_t spk;
    pq_sphincs_sk_t ssk;
    pq_sphincs_keygen(&spk, &ssk);
    printf("  Keygen: leaves=%u paths=%u\n", ssk.num_leaves, ssk.num_paths);

    const char *smsg = "SPHINCS+ stateless hash-based signature";
    pq_sphincs_sig_t ssig;
    pq_sphincs_sign(&ssig, (const uint8_t *)smsg, (uint32_t)strlen(smsg), &ssk);
    printf("  Signature: %u bytes\n", ssig.sig_len);

    int sok = pq_sphincs_verify(&ssig, (const uint8_t *)smsg, (uint32_t)strlen(smsg), &spk);
    printf("  Verify: %s\n", demo_passfail(sok));

    printf("\n[4] Module-LWE Problem\n");
    pq_poly_t s, e, a, b;
    pq_poly_init(&s);
    pq_poly_init(&e);
    pq_poly_init(&a);

    uint8_t seed[PQ_KYBER_SYMBYTES];
    for (int i = 0; i < PQ_KYBER_SYMBYTES; i++) seed[i] = (uint8_t)(i * 23 + 11);
    pq_mlwe_sample(&s, seed);
    pq_poly_cbd(&e, seed, PQ_KYBER_ETA);

    for (int i = 0; i < PQ_KYBER_N; i++) a.coeffs[i] = (int16_t)((i * 7919) % PQ_KYBER_Q);
    pq_poly_mul(&b, &a, &s);
    pq_poly_add(&b, &b, &e);
    pq_poly_reduce(&b);

    printf("  MLWE sample: b = a * s + e, ||s|| ~ eta, ||e|| ~ eta\n");
    printf("  Check: a[0]=%d, s[0]=%d, b[0]=%d\n", a.coeffs[0], s.coeffs[0], b.coeffs[0]);
}

static void demo_full_threshold(void) {
    demo_section_header("THRESHOLD SIGNATURES (Full Demo)");

    printf("[1] Threshold Secret Sharing (t=3,n=5)\n");
    ts_sss_ctx_t tctx;
    ts_sss_split(&tctx, 7777777LL, 3, 5);
    printf("  Secret: %lld, t=%u n=%u\n",
           (long long)tctx.secret, tctx.threshold, tctx.total);

    for (uint32_t i = 0; i < tctx.total; i++) {
        printf("  Share[%u]: id=%u x=%lld y=%lld\n",
               i, tctx.shares[i].id,
               (long long)tctx.shares[i].x, (long long)tctx.shares[i].y);
    }

    ts_share_t subset[5];
    for (uint32_t i = 0; i < 3; i++) subset[i] = tctx.shares[i * 2 % 5];
    int64_t recovered;
    ts_sss_reconstruct(&recovered, subset, 3, 3);
    printf("  Recovered (3 shares): %lld %s\n",
           (long long)recovered, recovered == 7777777LL ? "OK" : "FAIL");

    printf("\n[2] FROST Threshold Schnorr (Round-optimized)\n");
    ts_frost_party_t party;
    ts_frost_keygen_round1(&party, 1, 2, 3);
    printf("  Party %u: threshold=%u/%u\n", party.party_id, party.threshold, party.num_signers);
    printf("  Secret key share: ");
    for (int i = 0; i < 8; i++) printf("%02x", party.secret_key_share[i]);
    printf("...\n");

    ts_frost_nonce_t nonce;
    ts_frost_commit_t commit;
    ts_frost_sign_round1(&nonce, &commit, &party);
    printf("  Round 1: nonce committed\n");

    ts_frost_commit_t commits[1] = {commit};
    uint8_t agg_r[TS_FROST_R_BYTES];
    ts_frost_aggregate_nonces(agg_r, commits, 1);

    uint8_t challenge[TS_FROST_C_BYTES] = {0};
    const char *fmsg = "FROST demo message";
    uint8_t sig_z[TS_FROST_Z_BYTES];
    ts_frost_sign_round2(sig_z, &party, &nonce, agg_r, challenge,
                         (const uint8_t *)fmsg, (uint32_t)strlen(fmsg));
    printf("  Round 2: signature share generated\n");

    uint8_t sig_shares[1][TS_FROST_Z_BYTES];
    memcpy(sig_shares[0], sig_z, TS_FROST_Z_BYTES);

    ts_frost_signature_t frost_sig;
    ts_frost_aggregate_sigs(&frost_sig, sig_shares, &party, 1);
    printf("  Aggregated signature: %u signers\n", frost_sig.used_count);

    int fok = ts_frost_verify(&frost_sig, (const uint8_t *)fmsg,
                              (uint32_t)strlen(fmsg), party.group_pubkey);
    printf("  Verify: %s\n", demo_passfail(fok));

    printf("\n[3] Distributed Key Generation (DKG)\n");
    ts_dkg_ctx_t dkg;
    ts_dkg_init(&dkg, 3, 5);
    printf("  DKG init: t=%u n=%u\n", dkg.threshold, dkg.total);

    for (uint32_t p = 0; p < dkg.total; p++) {
        ts_dkg_round1(&dkg, p);
    }
    printf("  Round 1: %u parties committed coefficients\n", dkg.total);

    for (uint32_t p = 0; p < dkg.total; p++) {
        ts_dkg_round2(&dkg, p);
    }
    printf("  Round 2: %u parties distributed shares\n", dkg.total);

    ts_dkg_round3(&dkg, 0);
    printf("  Round 3: group public key computed\n");

    uint8_t group_pk[TS_FROST_R_BYTES];
    uint8_t sec_shares[TS_MAX_PARTIES][TS_FROST_R_BYTES];
    ts_dkg_finalize(group_pk, sec_shares, &dkg);
    printf("  DKG finalized: group_pk=");
    for (int i = 0; i < 8; i++) printf("%02x", group_pk[i]);
    printf("...\n");

    printf("\n[4] Proactive Share Refresh\n");
    ts_sss_ctx_t old_ctx, new_ctx;
    ts_sss_split(&old_ctx, 123456LL, 2, 4);
    memcpy(&new_ctx, &old_ctx, sizeof(ts_sss_ctx_t));

    printf("  Before: shares[0].y=%lld shares[1].y=%lld\n",
           (long long)old_ctx.shares[0].y, (long long)old_ctx.shares[1].y);

    ts_refresh_proactive(&new_ctx, 42);

    printf("  After:  shares[0].y=%lld shares[1].y=%lld\n",
           (long long)new_ctx.shares[0].y, (long long)new_ctx.shares[1].y);

    int rok = ts_refresh_verify(&old_ctx, &new_ctx, 2);
    printf("  Refresh verify: %s\n", demo_passfail(rok));
}

int main(void) {
    double t0 = demo_now();

    printf("===============================================\n");
    printf("  mini-adv-crypto  -  Full Demonstration\n");
    printf("  Advanced Cryptography Primitives (C99)\n");
    printf("===============================================\n");

    zk_module_version();
    he_module_version();
    mpc_module_version();
    pq_module_version();
    ts_module_version();

    demo_full_zk();
    demo_full_he();
    demo_full_mpc();
    demo_full_pq();
    demo_full_threshold();

    double t1 = demo_now();
    printf("\n===============================================\n");
    printf("  All demos completed in %.3f seconds\n", t1 - t0);
    printf("===============================================\n");

    return 0;
}
