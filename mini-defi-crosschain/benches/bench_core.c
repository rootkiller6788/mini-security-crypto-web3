/*
 * mini-defi-crosschain — Benchmark: AMM, lending, stablecoin/CDP, bridge, oracle
 *
 * Usage: bench_core [iterations]
 */
#include "../include/amm_swap.h"
#include "../include/lending_proto.h"
#include "../include/stablecoin.h"
#include "../include/crosschain_bridge.h"
#include "../include/oracle_price.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now_ms(void) {
    return (double)clock() / (double)(CLOCKS_PER_SEC / 1000);
}

int main(int argc, char **argv) {
    int N = (argc > 1) ? atoi(argv[1]) : 5000;
    printf("=== mini-defi-crosschain Benchmarks (iterations=%d) ===\n\n", N);

    /* AMM swap calculation */
    {
        AMMPool pool;
        amm_pool_init(&pool, 1000000, 2000000, AMM_FEE_BPS);
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            amm_get_amount_out(10000, 1000000, 2000000, AMM_FEE_BPS);
            amm_get_price(&pool, true);
        }
        double dt = now_ms() - t0;
        printf("  amm_get_amount_out+price:             %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    /* AMM V3 swap */
    {
        AMMV3Pool v3pool;
        amm_v3_pool_init(&v3pool, 7922816251426433759ULL, 60);
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            amm_v3_swap(&v3pool, 1000, true);
        }
        double dt = now_ms() - t0;
        printf("  amm_v3_swap:                          %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    /* Lending: deposit + borrow rate */
    {
        LendingMarket market;
        lending_market_init(&market, 200, 2000, 15000, 8000, 1000);
        LendingAccount account;
        memset(&account, 0, sizeof(account));
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            lending_deposit(&account, &market, 50000);
            lending_borrow_rate(&market);
            lending_accrue_interest(&market, (uint64_t)time(NULL));
        }
        double dt = now_ms() - t0;
        printf("  lending_deposit+rate+accrue:          %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    /* CDP vault mint + health */
    {
        StablecoinSystem sys;
        stablecoin_system_init(&sys, STABLECOIN_OVERCOLLATERALIZED);
        CDPVault vault;
        cdp_vault_init(&vault, STABLECOIN_MIN_COLLATERAL_RATIO_BPS);
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            cdp_mint(&vault, &sys, 50000, 100, 2000);
            cdp_get_health(&vault, 100, 100);
        }
        double dt = now_ms() - t0;
        printf("  cdp_mint+get_health:                  %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    /* Cross-chain bridge event processing */
    {
        Bridge bridge;
        bridge_init(&bridge, BRIDGE_LOCK_MINT, BRIDGE_MULTI_SIG, 1);
        uint8_t sender[20] = {0xAA}, receiver[20] = {0xBB};
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            bridge_lock(&bridge, sender, receiver, 1000, 2);
            bridge_get_event_nonce(&bridge);
        }
        double dt = now_ms() - t0;
        printf("  bridge_lock+get_event_nonce:          %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    /* Oracle price feed */
    {
        OraclePriceFeed feed;
        oracle_feed_init(&feed, ORACLE_MEDIAN, 3600);
        uint8_t addr[20]; memset(addr, 0x11, 20);
        oracle_add_node(&feed, addr, 1000);
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            oracle_submit_price(&feed, addr, 150000000, (uint64_t)time(NULL));
            oracle_get_median(NULL, 0);
            oracle_is_stale(&feed, (uint64_t)time(NULL));
        }
        double dt = now_ms() - t0;
        printf("  oracle_submit+median+is_stale:        %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    printf("\n=== Benchmarks complete ===\n");
    return 0;
}
