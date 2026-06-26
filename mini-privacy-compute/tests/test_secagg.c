#include "federated_learn.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    printf("Test start\n"); fflush(stdout);
    SecureAggState sa;
    memset(&sa, 0, sizeof(sa));
    secagg_init(&sa, 4, 3);
    printf("init OK\n"); fflush(stdout);
    double u1[4] = {1,2,3,4};
    double u2[4] = {2,3,4,5};
    secagg_add_update(&sa, u1, 0);
    printf("add1 OK\n"); fflush(stdout);
    secagg_add_update(&sa, u2, 1);
    printf("add2 OK\n"); fflush(stdout);
    double res[4];
    secagg_finalize(&sa, res);
    printf("finalize OK res[0]=%.2f\n", res[0]); fflush(stdout);
    secagg_free(&sa);
    printf("free OK\n"); fflush(stdout);
    printf("PASS\n");
    return 0;
}
