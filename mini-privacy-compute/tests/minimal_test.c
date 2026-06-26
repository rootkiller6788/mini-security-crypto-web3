#include "secure_mpc_comp.h"
#include <stdio.h>
int main(void) {
    printf("Test 1: init\n");
    SecretSharing ss;
    uint64_t prime = 1000000007ULL;
    ss_init(&ss, 3, prime);
    printf("OK\nTest 2: share\n");
    uint64_t shares[3];
    ss_share(&ss, 100, shares);
    printf("OK: %llu %llu %llu\n", (unsigned long long)shares[0], (unsigned long long)shares[1], (unsigned long long)shares[2]);
    printf("Test 3: reconstruct\n");
    uint64_t result;
    ss_reconstruct(&ss, shares, &result);
    printf("OK: %llu\n", (unsigned long long)result);
    ss_free(&ss);
    printf("ALL PASSED\n");
    return 0;
}
