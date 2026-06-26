#include "federated_learn.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define STEP(s) do { printf("%s\n", s); fflush(stdout); } while(0)
int main(void) {
    STEP("1 FLModel");
    FLModel model;
    memset(&model, 0, sizeof(model));
    model.num_params = 8;
    model.weights = (double *)calloc(8, sizeof(double));
    for (size_t i = 0; i < 8; i++) model.weights[i] = (double)i / 80.0;

    STEP("2 data");
    double *data = (double *)malloc(10 * 8 * sizeof(double));
    for (int i = 0; i < 80; i++) data[i] = (double)(i % 10) / 100.0;

    STEP("3 gradients");
    double *gradients = (double *)calloc(8, sizeof(double));

    STEP("4 hfl_client_train");
    hfl_client_train(&model, data, 10, 8, gradients, 3, 0.01);

    STEP("5 print");
    printf("gradients: ");
    for (int i = 0; i < 8; i++) printf("%.4f ", gradients[i]);
    printf("\n"); fflush(stdout);

    free(model.weights); free(data);

    STEP("6 fedavg_init");
    FedAvgState state;
    memset(&state, 0, sizeof(state));
    fedavg_init(&state, 8);

    STEP("7 fedavg_accumulate");
    fedavg_accumulate(&state, gradients, 10);
    free(gradients);

    STEP("8 fedavg_apply");
    double global[8] = {1,1,1,1,1,1,1,1};
    fedavg_apply(&state, global, 0.01);

    STEP("9 fedavg_free");
    fedavg_free(&state);

    STEP("10 secagg");
    SecureAggState sa;
    memset(&sa, 0, sizeof(sa));
    secagg_init(&sa, 4, 3);
    double u1[4] = {1,2,3,4};
    secagg_add_update(&sa, u1, 0);
    double res[4];
    secagg_finalize(&sa, res);
    printf("res[0]=%.2f\n", res[0]); fflush(stdout);
    secagg_free(&sa);

    STEP("11 vfl");
    VFLParty p;
    memset(&p, 0, sizeof(p));
    vfl_party_init(&p, 4, 1);
    double feats[8] = {1,0.5,0.2,0.8, 0.3,0.7,0.1,0.9};
    double labels[2] = {1.0, 0.0};
    vfl_party_compute(&p, feats, labels, 2);
    printf("grads[0]=%.4f\n", p.partial_gradients[0]); fflush(stdout);
    vfl_party_free(&p);

    STEP("DONE");
    return 0;
}
