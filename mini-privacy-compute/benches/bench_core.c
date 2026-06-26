/*
 * mini-privacy-compute — Benchmark: differential privacy, federated learning, secure MPC, anonymization, PET tools
 *
 * Usage: bench_core [iterations]
 */
#include "../include/differential_privacy.h"
#include "../include/federated_learn.h"
#include "../include/secure_mpc_comp.h"
#include "../include/anonymization.h"
#include "../include/pet_tools.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now_ms(void) {
    return (double)clock() / (double)(CLOCKS_PER_SEC / 1000);
}

int main(int argc, char **argv) {
    int N = (argc > 1) ? atoi(argv[1]) : 5000;
    printf("=== mini-privacy-compute Benchmarks (iterations=%d) ===\n\n", N);

    /* Differential privacy: Laplace mechanism */
    {
        uint64_t seed = 42;
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            dp_laplace_mechanism(100.0, 1.0, 0.5, &seed);
        }
        double dt = now_ms() - t0;
        printf("  dp_laplace_mechanism:                 %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    /* Differential privacy: Gaussian mechanism */
    {
        uint64_t seed = 123;
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            dp_gaussian_mechanism(100.0, 1.0, 1.0, 1e-5, &seed);
        }
        double dt = now_ms() - t0;
        printf("  dp_gaussian_mechanism:                %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    /* DP budget tracking */
    {
        DPBudget budget;
        dp_budget_init(&budget, 10.0, 1e-5);
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            dp_budget_consume(&budget, 0.001, 0.0);
        }
        double dt = now_ms() - t0;
        printf("  dp_budget_consume:                    %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    /* Federated learning: FedAvg */
    {
        FLServer server;
        fl_server_init(&server, 128, 10, 5, 100, 0.01);
        double *gradients = calloc(128, sizeof(double));
        for (size_t i = 0; i < 128; i++) gradients[i] = (double)i / 1000.0;
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            fl_upload_update(&server, gradients, i % 10, 100);
        }
        double dt = now_ms() - t0;
        printf("  fl_upload_update:                     %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
        free(gradients);
        fl_server_free(&server);
    }

    /* Secure MPC: secret sharing */
    {
        SecretSharing ss;
        ss_init(&ss, 3, 1000000007ULL);
        uint64_t shares[3];
        uint64_t secret;
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            ss_share(&ss, 12345 + i, shares);
            ss_reconstruct(&ss, shares, &secret);
        }
        double dt = now_ms() - t0;
        printf("  ss_share+reconstruct (3 parties):     %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
        ss_free(&ss);
    }

    /* Beaver triple multiplication */
    {
        SecretSharing ss;
        ss_init(&ss, 3, 1000000007ULL);
        BeaverTriplePool pool;
        bt_pool_init(&pool, 64, 1000000007ULL, 42);
        bt_pool_generate(&pool);
        BeaverTriple triple;
        bt_pool_consume(&pool, &triple);
        uint64_t xs[3], ys[3], ps[3];
        ss_share(&ss, 100, xs);
        ss_share(&ss, 200, ys);
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            bt_multiply(&ss, &triple, xs, ys, ps);
        }
        double dt = now_ms() - t0;
        printf("  bt_multiply (Beaver triple):          %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
        bt_pool_free(&pool);
        ss_free(&ss);
    }

    /* K-anonymity check */
    {
        AnonDataset ds;
        char *qi_names[] = {"age", "zip"};
        kanon_init_dataset(&ds, 16, 2, qi_names);
        AnonRecord rec; memset(&rec, 0, sizeof(rec));
        rec.quasi_identifiers[0] = "30-39"; rec.quasi_identifiers[1] = "12345";
        rec.num_qi = 2; rec.sensitive_attr = "flu"; rec.num_values = 1;
        for (size_t i = 0; i < 16; i++) { rec.record_id = i; kanon_add_record(&ds, i, &rec); }
        KAnonymityResult result;
        double t0 = now_ms();
        for (int i = 0; i < N / 10; i++) {
            kanon_check(&ds, 4, &result);
        }
        double dt = now_ms() - t0;
        int k = N / 10 > 0 ? N / 10 : 1;
        printf("  kanon_check (k=4, 16 records):        %d ops in %.1f ms  (%.1f µs/op)\n",
               k, dt, dt * 1000.0 / (double)k);
        kanon_free_dataset(&ds);
    }

    /* PET on-device processing */
    {
        OnDeviceProcessor odp;
        odproc_init(&odp, 64, 8);
        double result[64]; size_t essential_len;
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            odproc_compute_local(&odp, result, 64);
        }
        double dt = now_ms() - t0;
        printf("  odproc_compute_local (64 features):   %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
        odproc_free(&odp);
    }

    printf("\n=== Benchmarks complete ===\n");
    return 0;
}
