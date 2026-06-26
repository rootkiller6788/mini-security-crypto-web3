#include "federated_learn.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

#define NUM_CLIENTS       10
#define NUM_SELECTED      4
#define NUM_PARAMS        8
#define TOTAL_ROUNDS      5
#define NUM_SAMPLES        50
#define NUM_FEATURES       NUM_PARAMS
#define LEARNING_RATE     0.01

static void generate_synthetic_data(double *data, double *labels, size_t n, uint64_t seed) {
    for (size_t i = 0; i < n; i++) {
        labels[i] = 0.0;
        for (size_t f = 0; f < NUM_FEATURES; f++) {
            seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
            data[i * NUM_FEATURES + f] = (double)((seed >> 33) & 0xFF) / 255.0;
            labels[i] += data[i * NUM_FEATURES + f] * ((double)f + 1.0) * 0.1;
        }
    }
}

int main(void) {
    uint64_t seed = 99999ULL;
    printf("=== Federated Learning Example ===\n\n");

    /* 1. Initialize server */
    FLServer server;
    fl_server_init(&server, NUM_PARAMS, NUM_CLIENTS, NUM_SELECTED, TOTAL_ROUNDS, LEARNING_RATE);
    printf("Server: %d clients, %d selected/round, %zu params, %d rounds\n",
           server.num_clients, server.num_selected, server.global_model.num_params,
           server.total_rounds);

    /* 2. Initialize model */
    double initial_weights[NUM_PARAMS];
    for (size_t i = 0; i < NUM_PARAMS; i++) {
        initial_weights[i] = ((double)i / (double)NUM_PARAMS) * 0.1;
    }
    fl_server_init_model(&server, initial_weights);
    printf("Initial weights: [");
    for (size_t i = 0; i < NUM_PARAMS; i++) {
        printf("%.4f%s", server.global_model.weights[i],
               i < NUM_PARAMS - 1 ? ", " : "");
    }
    printf("]\n\n");

    /* 3. Simulate FL rounds */
    FLModel local_model;
    local_model.num_params = NUM_PARAMS;
    local_model.weights = (double *)malloc(NUM_PARAMS * sizeof(double));
    local_model.version = 0;

    for (int round = 0; round < TOTAL_ROUNDS; round++) {
        printf("--- Round %d ---\n", round + 1);

        fl_random_select(&server, &seed);

        FedAvgState fedavg;
        fedavg_init(&fedavg, NUM_PARAMS);

        for (int c = 0; c < NUM_CLIENTS; c++) {
            if (!server.clients[c].selected) continue;

            fl_download_model(&server, c, local_model.weights);

            double *data   = (double *)malloc(NUM_SAMPLES * NUM_FEATURES * sizeof(double));
            double *labels = (double *)malloc(NUM_SAMPLES * sizeof(double));
            generate_synthetic_data(data, labels, NUM_SAMPLES, seed + (uint64_t)c);

            double gradients[NUM_PARAMS];
            hfl_client_train(&local_model, data, NUM_SAMPLES, NUM_FEATURES,
                            gradients, 3, LEARNING_RATE);

            fl_upload_update(&server, gradients, c, NUM_SAMPLES);
            fedavg_accumulate(&fedavg, gradients, NUM_SAMPLES);

            double norm = fl_compute_update_norm(gradients, NUM_PARAMS);
            printf("  Client %d: update norm=%.4f  samples=%zu\n",
                   c, norm, (size_t)NUM_SAMPLES);

            free(data);
            free(labels);
        }

        fedavg_apply(&fedavg, server.global_model.weights, LEARNING_RATE);
        fedavg_free(&fedavg);

        printf("  Model v%d weights: [", server.global_model.version);
        for (size_t i = 0; i < NUM_PARAMS; i++) {
            printf("%.4f%s", server.global_model.weights[i],
                   i < NUM_PARAMS - 1 ? ", " : "");
        }
        printf("]\n");

        int conv = fl_check_convergence(&server, 0.001);
        if (conv) printf("  CONVERGED!\n");

        server.current_round++;
        server.global_model.version++;
    }

    free(local_model.weights);

    /* 4. DP in FL */
    {
        printf("\n--- DP-FL Update Protection ---\n");
        double test_gradients[NUM_PARAMS];
        for (size_t i = 0; i < NUM_PARAMS; i++) {
            test_gradients[i] = 0.05;
        }
        printf("  Before DP: [");
        for (size_t i = 0; i < NUM_PARAMS; i++) {
            printf("%.4f%s", test_gradients[i], i < NUM_PARAMS - 1 ? ", " : "");
        }
        printf("]\n");

        fl_dp_protect_update(test_gradients, NUM_PARAMS, 8.0, 1e-5, 0.1, &seed);
        printf("  After DP:  [");
        for (size_t i = 0; i < NUM_PARAMS; i++) {
            printf("%.4f%s", test_gradients[i], i < NUM_PARAMS - 1 ? ", " : "");
        }
        printf("]\n");
    }

    /* 5. Secure aggregation */
    {
        printf("\n--- Secure Aggregation ---\n");
        SecureAggState sa;
        secagg_init(&sa, NUM_PARAMS, 3);
        double update_a[NUM_PARAMS] = {0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8};
        double update_b[NUM_PARAMS] = {0.15, 0.25, 0.35, 0.45, 0.55, 0.65, 0.75, 0.85};
        double update_c[NUM_PARAMS] = {0.05, 0.15, 0.25, 0.35, 0.45, 0.55, 0.65, 0.75};
        secagg_add_update(&sa, update_a, 0);
        secagg_add_update(&sa, update_b, 1);
        secagg_add_update(&sa, update_c, 2);
        double result[NUM_PARAMS];
        secagg_finalize(&sa, result);
        printf("  Secure aggregated result: [");
        for (size_t i = 0; i < NUM_PARAMS; i++) {
            printf("%.4f%s", result[i], i < NUM_PARAMS - 1 ? ", " : "");
        }
        printf("]\n");
        secagg_free(&sa);
    }

    /* 6. Vertical FL */
    {
        printf("\n--- Vertical FL ---\n");
        VFLParty party_a, party_b;
        vfl_party_init(&party_a, 4, 1);
        vfl_party_init(&party_b, 4, 2);
        double vfeatures[2 * 4] = {1.0,0.5,0.2,0.8, 0.3,0.7,0.1,0.9};
        double vlabels[2] = {1.0, 0.0};
        vfl_party_compute(&party_a, vfeatures, vlabels, 2);
        vfl_party_compute(&party_b, vfeatures + 4, vlabels, 2);
        printf("  Party 1 partial gradients: [%.4f, %.4f, %.4f, %.4f]\n",
               party_a.partial_gradients[0], party_a.partial_gradients[1],
               party_a.partial_gradients[2], party_a.partial_gradients[3]);
        vfl_party_free(&party_a);
        vfl_party_free(&party_b);
    }

    /* 7. Weighted client selection */
    {
        printf("\n--- Weighted Client Selection ---\n");
        double quality[NUM_CLIENTS] = {1.0, 0.8, 0.9, 0.3, 0.5, 0.95, 0.7, 0.2, 0.85, 0.6};
        fl_weighted_select(&server, quality);
        printf("  Selected clients: ");
        for (int i = 0; i < NUM_CLIENTS; i++) {
            if (server.clients[i].selected) printf("%d(%.2f) ", i, quality[i]);
        }
        printf("\n");
    }

    fl_server_free(&server);
    printf("\n=== FL Example Complete ===\n");
    return 0;
}
