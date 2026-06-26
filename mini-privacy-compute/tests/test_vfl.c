#include "federated_learn.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    printf("Test start\n"); fflush(stdout);
    VFLParty p;
    memset(&p, 0, sizeof(p));
    vfl_party_init(&p, 4, 1);
    printf("init OK\n"); fflush(stdout);
    double feats[8] = {1,0.5,0.2,0.8, 0.3,0.7,0.1,0.9};
    double labels[2] = {1.0, 0.0};
    vfl_party_compute(&p, feats, labels, 2);
    printf("compute OK\n"); fflush(stdout);
    printf("grads[0]=%.4f\n", p.partial_gradients[0]); fflush(stdout);
    vfl_party_free(&p);
    printf("free OK\n"); fflush(stdout);
    printf("PASS\n");
    return 0;
}
