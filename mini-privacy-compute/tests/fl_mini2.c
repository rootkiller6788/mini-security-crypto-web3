#include "federated_learn.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    printf("Test: hfl_client_train\n");
    FLModel model;
    model.num_params = 8;
    model.weights = (double *)calloc(8, sizeof(double));
    for (size_t i = 0; i < 8; i++) model.weights[i] = (double)i / 80.0;
    double data[10 * 8];
    for (int i = 0; i < 80; i++) data[i] = (double)(i % 10) / 100.0;
    double gradients[8];
    hfl_client_train(&model, data, 10, 8, gradients, 3, 0.01);
    printf("gradients: ");
    for (int i = 0; i < 8; i++) printf("%.4f ", gradients[i]);
    printf("\nOK\n");
    free(model.weights);

    printf("Test: fedavg\n");
    FedAvgState state;
    fedavg_init(&state, 8);
    fedavg_accumulate(&state, gradients, 10);
    double global[8] = {0};
    fedavg_apply(&state, global, 0.01);
    printf("global[0]=%.6f\n", global[0]);
    fedavg_free(&state);
    printf("OK\n");

    printf("Test: secagg\n");
    SecureAggState sa;
    secagg_init(&sa, 4, 3);
    double u1[4] = {1,2,3,4};
    double u2[4] = {2,3,4,5};
    secagg_add_update(&sa, u1, 0);
    secagg_add_update(&sa, u2, 1);
    double res[4];
    secagg_finalize(&sa, res);
    printf("result: %.2f %.2f %.2f %.2f\n", res[0], res[1], res[2], res[3]);
    secagg_free(&sa);
    printf("OK\n");

    printf("Test: vfl\n");
    VFLParty p;
    vfl_party_init(&p, 4, 1);
    double feats[8] = {1,0.5,0.2,0.8, 0.3,0.7,0.1,0.9};
    double labels[2] = {1.0, 0.0};
    vfl_party_compute(&p, feats, labels, 2);
    printf("grads: %.4f %.4f %.4f %.4f\n",
           p.partial_gradients[0], p.partial_gradients[1],
           p.partial_gradients[2], p.partial_gradients[3]);
    vfl_party_free(&p);
    printf("OK\n");

    printf("ALL PASSED\n");
    return 0;
}
