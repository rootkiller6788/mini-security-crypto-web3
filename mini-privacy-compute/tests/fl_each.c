#include "federated_learn.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    printf("T1 "); fflush(stdout);
    FLModel model;
    memset(&model, 0, sizeof(model));
    model.num_params = 8;
    model.weights = (double *)calloc(8, sizeof(double));
    for (size_t i = 0; i < 8; i++) model.weights[i] = (double)i / 80.0;
    printf("OK\nT2 "); fflush(stdout);

    double *data = (double *)malloc(10 * 8 * sizeof(double));
    for (int i = 0; i < 80; i++) data[i] = (double)(i % 10) / 100.0;
    printf("OK\nT3 "); fflush(stdout);

    double *gradients = (double *)calloc(8, sizeof(double));
    hfl_client_train(&model, data, 10, 8, gradients, 3, 0.01);
    printf("OK\nT4 "); fflush(stdout);

    free(model.weights);
    free(data);
    free(gradients);
    printf("OK\nALL PASSED\n");
    return 0;
}
