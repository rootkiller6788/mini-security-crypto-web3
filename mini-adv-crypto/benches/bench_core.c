/*
 * mini-adv-crypto — Benchmark: ZK, HE, MPC, PQ, threshold sigs
 *
 * Usage: bench_core [iterations]
 */
#include "../include/zk_proof.h"
#include "../include/homomorphic_enc.h"
#include "../include/mpc_proto.h"
#include "../include/post_quantum.h"
#include "../include/threshold_sig.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now_ms(void) {
    return (double)clock() / (double)(CLOCKS_PER_SEC / 1000);
}

int main(int argc, char **argv) {
    int N = (argc > 1) ? atoi(argv[1]) : 1000;
    printf("=== mini-adv-crypto Benchmarks (iterations=%d) ===\n\n", N);

    /* ZK field arithmetic */
    {
        zk_field_t a, b, r;
        zk_field_from_u64(&a, 12345);
        zk_field_from_u64(&b, 67890);
        double t0 = now_ms();
        for (int i = 0; i < N * 10; i++) {
            zk_field_mul(&r, &a, &b);
        }
        double dt = now_ms() - t0;
        printf("  zk_field_mul:                        %d ops in %.1f ms  (%.1f µs/op)\n",
               N * 10, dt, dt * 1000.0 / (double)(N * 10));
    }

    /* R1CS init + constraint */
    {
        zk_r1cs_t r1cs;
        int32_t a[5] = {1,0,0,0,0}, b[5] = {0,1,0,0,0}, c[5] = {0,0,1,0,0};
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            zk_r1cs_init(&r1cs, 4, 1);
            zk_r1cs_add_constraint(&r1cs, 0, a, b, c);
        }
        double dt = now_ms() - t0;
        printf("  zk_r1cs_init+constraint:             %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    /* Paillier encrypt/decrypt */
    {
        he_paillier_pub_t pub; he_paillier_prv_t prv;
        he_paillier_keygen(&pub, &prv, 512);
        he_bigint_t msg; he_bigint_set_u64(&msg, 42);
        he_paillier_ct_t ct;
        he_bigint_t dec;
        int k = N / 10 > 0 ? N / 10 : 1;
        double t0 = now_ms();
        for (int i = 0; i < k; i++) {
            he_paillier_encrypt(&ct, &msg, &pub);
            he_paillier_decrypt(&dec, &ct, &prv);
        }
        double dt = now_ms() - t0;
        printf("  paillier encrypt+decrypt (512-bit):   %d ops in %.1f ms  (%.1f µs/op)\n",
               k, dt, dt * 1000.0 / (double)k);
    }

    /* Shamir secret sharing */
    {
        mpc_shamir_ctx_t ctx;
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            mpc_shamir_split(&ctx, 123456789, 3, 5);
            int64_t secret;
            uint32_t indices[] = {0, 1, 2};
            mpc_shamir_reconstruct(&secret, &ctx, indices, 3);
        }
        double dt = now_ms() - t0;
        printf("  shamir split+reconstruct (3-of-5):    %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    /* Kyber keygen */
    {
        pq_kyber_pk_t pk; pq_kyber_sk_t sk;
        int k = N / 5 > 0 ? N / 5 : 1;
        double t0 = now_ms();
        for (int i = 0; i < k; i++) {
            pq_kyber_keygen(&pk, &sk);
        }
        double dt = now_ms() - t0;
        printf("  kyber_keygen:                         %d ops in %.1f ms  (%.1f µs/op)\n",
               k, dt, dt * 1000.0 / (double)k);
    }

    /* Dilithium sign+verify */
    {
        pq_dilithium_pk_t pk; pq_dilithium_sk_t sk;
        pq_dilithium_keygen(&pk, &sk);
        uint8_t msg[] = "benchmark dilithium signature";
        pq_dilithium_sig_t sig; uint32_t siglen;
        int k = N / 5 > 0 ? N / 5 : 1;
        double t0 = now_ms();
        for (int i = 0; i < k; i++) {
            pq_dilithium_sign(&sig, &siglen, msg, sizeof(msg), &sk);
            pq_dilithium_verify(&sig, msg, sizeof(msg), &pk);
        }
        double dt = now_ms() - t0;
        printf("  dilithium sign+verify:                %d ops in %.1f ms  (%.1f µs/op)\n",
               k, dt, dt * 1000.0 / (double)k);
    }

    /* FROST threshold sig (sign round) */
    {
        ts_frost_party_t party;
        ts_frost_keygen_round1(&party, 1, 3, 5);
        ts_frost_nonce_t nonce; ts_frost_commit_t commit;
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            ts_frost_sign_round1(&nonce, &commit, &party);
        }
        double dt = now_ms() - t0;
        printf("  frost_sign_round1:                    %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    printf("\n=== Benchmarks complete ===\n");
    return 0;
}
