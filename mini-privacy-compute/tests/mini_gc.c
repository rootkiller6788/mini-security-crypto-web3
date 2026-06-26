#include "secure_mpc_comp.h"
#include <stdio.h>
#include <string.h>
int main(void) {
    printf("Test: gc\n");
    GarbledCircuit gc;
    gc_init(&gc, 2, 2, 1);
    gc_set_gate(&gc, 0, 0, 2, 4, 0);
    gc_set_gate(&gc, 1, 1, 3, 5, 1);
    gc_set_gate(&gc, 2, 4, 5, 6, 2);
    gc_garble(&gc, 54321ULL);
    uint8_t ia[2] = {1, 0};
    uint8_t ib[2] = {1, 1};
    uint8_t out[1];
    gc_evaluate(&gc, ia, ib, out);
    printf("result: %d\n", out[0]);
    gc_free(&gc);
    printf("OK\n");
    return 0;
}
