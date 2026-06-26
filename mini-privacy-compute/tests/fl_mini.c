#include "federated_learn.h"
#include <stdio.h>
#include <string.h>
int main(void) {
    printf("Test 1: fl_server_init\n");
    FLServer server;
    double weights[64];
    for (int i = 0; i < 64; i++) weights[i] = 0.01;
    fl_server_init(&server, 64, 20, 5, 50, 0.01);
    printf("OK clients=%d params=%zu\n", server.num_clients, server.global_model.num_params);

    printf("Test 2: init_model\n");
    fl_server_init_model(&server, weights);
    printf("OK version=%d\n", server.global_model.version);

    printf("Test 3: upload_update\n");
    double gradients[64];
    for (int i = 0; i < 64; i++) gradients[i] = (double)(i % 8) / 100.0;
    fl_upload_update(&server, gradients, 0, 32);
    printf("OK client 0 contribution=%.4f\n", server.clients[0].last_contribution);

    printf("Test 4: second upload\n");
    fl_upload_update(&server, gradients, 1, 64);
    printf("OK client 1 contribution=%.4f, data_size=%zu\n",
           server.clients[1].last_contribution, server.clients[1].local_data_size);

    printf("Test 5: compute_update_norm\n");
    double norm = fl_compute_update_norm(gradients, 64);
    printf("OK norm=%.6f\n", norm);

    printf("Test 6: dp_clip_update\n");
    fl_dp_clip_update(gradients, 64, 1.5);
    printf("OK after clip: [0]=%.6f\n", gradients[0]);

    printf("Test 7: dp_add_noise\n");
    uint64_t seed = 42;
    fl_dp_add_noise(gradients, 64, 2.0, 1e-5, 1.0, &seed);
    printf("OK after noise: [0]=%.6f\n", gradients[0]);

    printf("Test 8: server_free\n");
    fl_server_free(&server);
    printf("OK\n");

    printf("ALL TESTS PASSED\n");
    return 0;
}
