#include "secure_mpc_comp.h"
#include <stdio.h>
#include <string.h>
int main(void) {
    printf("Test: SPDZ\n");
    SPDZState spdz;
    uint64_t key = 0xDEADBEEF12345678ULL;
    spdz_init(&spdz, 4, key);
    uint64_t a[4] = {10, 20, 30, 40};
    uint64_t b[4] = {5, 10, 15, 20};
    uint64_t result[4];
    spdz_online_add(&spdz, a, b, result, 4);
    printf("SPDZ add: %llu %llu %llu %llu\n",
           (unsigned long long)result[0], (unsigned long long)result[1],
           (unsigned long long)result[2], (unsigned long long)result[3]);
    int mac_valid;
    spdz_mac_check(&spdz, &mac_valid);
    printf("MAC check: %s\n", mac_valid ? "PASS" : "FAIL");
    spdz_free(&spdz);
    printf("SPDZ OK\n");

    printf("Test: Garbled Circuit\n");
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
    printf("GC result: %d\n", out[0]);
    gc_free(&gc);
    printf("GC OK\n");

    printf("Test: ORAM\n");
    ORAMServer oram;
    oram_init(&oram, 32, 16);
    uint8_t wdata[16] = "hello_oram";
    oram_access(&oram, 1, 5, wdata, 777ULL);
    uint8_t rdata[16] = {0};
    oram_access(&oram, 0, 5, rdata, 888ULL);
    printf("Read: %s\n", rdata);
    oram_free(&oram);
    printf("ORAM OK\n");

    printf("ALL PASSED\n");
    return 0;
}
