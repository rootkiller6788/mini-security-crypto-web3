#include "secure_mpc_comp.h"
#include <stdio.h>
#include <string.h>
int main(void) {
    printf("Test: spdz\n");
    SPDZState spdz;
    uint64_t key = 0xDEADBEEF12345678ULL;
    spdz_init(&spdz, 4, key);
    uint64_t a[4] = {10, 20, 30, 40};
    uint64_t b[4] = {5, 10, 15, 20};
    uint64_t result[4];
    spdz_online_add(&spdz, a, b, result, 4);
    printf("result: %llu %llu %llu %llu\n",
           (unsigned long long)result[0], (unsigned long long)result[1],
           (unsigned long long)result[2], (unsigned long long)result[3]);
    int mac_valid;
    spdz_mac_check(&spdz, &mac_valid);
    printf("MAC: %s\n", mac_valid ? "PASS" : "FAIL");
    spdz_free(&spdz);
    printf("OK\n");
    return 0;
}
