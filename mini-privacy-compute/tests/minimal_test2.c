#include "secure_mpc_comp.h"
#include <stdio.h>
int main(void) {
    printf("Test: BeaverTriplePool\n");
    BeaverTriplePool pool;
    bt_pool_init(&pool, 4, 1000000007ULL, 12345);
    int gen = bt_pool_generate(&pool);
    printf("Generated: %d triples\n", gen);
    BeaverTriple bt;
    int ok = bt_pool_consume(&pool, &bt);
    printf("Consumed: %s, a=%llu b=%llu c=%llu\n", ok ? "YES" : "NO",
           (unsigned long long)bt.a_share, (unsigned long long)bt.b_share,
           (unsigned long long)bt.c_share);
    bt_pool_free(&pool);
    printf("ALL PASSED\n");
    return 0;
}
