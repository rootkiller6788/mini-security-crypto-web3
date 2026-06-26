#include "federated_learn.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    printf("Test start\n"); fflush(stdout);
    FedAvgState state;
    memset(&state, 0, sizeof(state));
    fedavg_init(&state, 8);
    printf("init OK\n"); fflush(stdout);
    double grad[8] = {0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8};
    fedavg_accumulate(&state, grad, 10);
    printf("accumulate OK\n"); fflush(stdout);
    double global[8] = {1,1,1,1,1,1,1,1};
    fedavg_apply(&state, global, 0.01);
    printf("apply OK global[0]=%.6f\n", global[0]); fflush(stdout);
    fedavg_free(&state);
    printf("free OK\n"); fflush(stdout);
    printf("PASS\n");
    return 0;
}
