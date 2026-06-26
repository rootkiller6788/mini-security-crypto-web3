/*
 * mini-defi-crosschain — Full Demo: DeFi & Cross-chain
 *
 * Demonstrates: AMM swap (V2/V3), lending protocol, stablecoin/CDP,
 *               cross-chain bridge, oracle price feeds.
 */
#include "../include/amm_swap.h"
#include "../include/lending_proto.h"
#include "../include/stablecoin.h"
#include "../include/crosschain_bridge.h"
#include "../include/oracle_price.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    printf("=== mini-defi-crosschain: DeFi & Cross-chain Demo ===\n\n");

    /* Step 1: AMM (Automated Market Maker) */
    printf("-- Step 1: AMM Swap (Constant Product) --\n");
    AMMPool pool;
    amm_pool_init(&pool, 1000000000, 2000000000, AMM_FEE_BPS);
    printf("Pool: %llu ETH / %llu USDC (fee=%.2f%%)\n",
           (unsigned long long)pool.reserve0, (unsigned long long)pool.reserve1,
           (double)AMM_FEE_BPS / 100.0);

    uint64_t out = amm_get_amount_out(100000, pool.reserve0, pool.reserve1, AMM_FEE_BPS);
    printf("Swap 0.001 ETH -> %llu USDC\n", (unsigned long long)out);

    uint64_t price = amm_get_price(&pool, true);
    printf("ETH price: %.6f USDC\n", (double)price / 1000000.0);

    uint64_t impact = amm_price_impact_bps(500000, pool.reserve0, pool.reserve1, AMM_FEE_BPS);
    printf("Price impact (0.005 ETH swap): %.2f%%\n", (double)impact / 100.0);

    AMMSwapResult swap_r = amm_swap(&pool, 100000, true, 50);
    printf("Swap executed: %llu in -> %llu out (impact=%.2f%%, fee=%llu)\n",
           (unsigned long long)swap_r.input_amount, (unsigned long long)swap_r.output_amount,
           (double)swap_r.price_impact_bps / 100.0, (unsigned long long)swap_r.fee_amount);

    /* AMM V3 Concentrated Liquidity */
    AMMV3Pool v3pool;
    amm_v3_pool_init(&v3pool, 7922816251426433759ULL, 60);
    printf("\nV3 Pool: sqrtPriceX96=%llu, tickSpacing=%llu\n",
           (unsigned long long)v3pool.sqrt_price_x96, (unsigned long long)v3pool.tick_spacing);
    uint64_t v3_out = amm_v3_swap(&v3pool, 50000, true);
    printf("V3 swap: 50000 -> %llu\n", (unsigned long long)v3_out);

    /* Step 2: Lending Protocol */
    printf("\n-- Step 2: Lending Protocol --\n");
    LendingMarket market;
    lending_market_init(&market, 200, 2000, 15000, 8000, 1000);
    printf("Lending market: base=2%%, kink=20%%, max=150%%\n");

    LendingAccount account;
    memset(&account, 0, sizeof(account));
    uint64_t ctoken = lending_deposit(&account, &market, 1000000);
    printf("Deposited 1,000,000 -> %llu cTokens\n", (unsigned long long)ctoken);

    uint64_t borrow_amt = lending_borrow(&account, &market, 500000, 1000000);
    printf("Borrowed: %llu (collateral=1,000,000)\n", (unsigned long long)borrow_amt);

    lending_accrue_interest(&market, (uint64_t)1000000);
    printf("After interest accrual: borrow_rate=%.2f%%, supply_rate=%.2f%%\n",
           (double)lending_borrow_rate(&market) / 100.0,
           (double)lending_supply_rate(&market) / 100.0);

    LendingHealth health = lending_get_health(&account, &market, 800000, 1000000, 7500, 8000);
    printf("Health factor: %.2f%% (borrow_limit=%llu, borrow_value=%llu)\n",
           (double)health.health_factor_bps / 100.0,
           (unsigned long long)health.borrow_limit, (unsigned long long)health.borrow_value);

    /* Step 3: Stablecoin / CDP */
    printf("\n-- Step 3: Stablecoin / CDP Vault --\n");
    StablecoinSystem sc_sys;
    stablecoin_system_init(&sc_sys, STABLECOIN_OVERCOLLATERALIZED);
    printf("Stablecoin system: overcollateralized (min ratio=%.0f%%)\n",
           (double)STABLECOIN_MIN_COLLATERAL_RATIO_BPS / 100.0);

    CDPVault vault;
    cdp_vault_init(&vault, STABLECOIN_MIN_COLLATERAL_RATIO_BPS);
    CDPMintResult mint_r = cdp_mint(&vault, &sc_sys, 200000, 100, 10000);
    printf("CDP mint: %llu collateral -> %llu stablecoins (fee=%llu)\n",
           (unsigned long long)mint_r.required_collateral,
           (unsigned long long)mint_r.mint_amount, (unsigned long long)mint_r.fee_amount);

    CDPHealth cdp_h = cdp_get_health(&vault, 100, 100);
    printf("CDP health: ratio=%.2f%%, safe=%s\n",
           (double)cdp_h.collateral_ratio_bps / 100.0,
           cdp_is_safe(&vault, 100, 100) ? "YES" : "LIQUIDATION RISK");

    /* Step 4: Cross-chain Bridge */
    printf("\n-- Step 4: Cross-chain Bridge --\n");
    Bridge bridge;
    bridge_init(&bridge, BRIDGE_LOCK_MINT, BRIDGE_MULTI_SIG, 1);
    uint8_t pubkey[64]; memset(pubkey, 0x01, 64);
    uint8_t val_addr[20]; memset(val_addr, 0xAA, 20);
    bridge_add_validator(&bridge, pubkey, val_addr, 10000);
    memset(pubkey, 0x02, 64); memset(val_addr, 0xBB, 20);
    bridge_add_validator(&bridge, pubkey, val_addr, 10000);
    printf("Bridge initialized: chain=%llu, model=Lock-Mint, validators=%d\n",
           (unsigned long long)bridge.chain_id, bridge.validator_count);

    uint8_t sender[20]; memset(sender, 0x11, 20);
    uint8_t receiver[20]; memset(receiver, 0x22, 20);
    bool locked = bridge_lock(&bridge, sender, receiver, 50000, 2);
    printf("Lock 50,000 tokens (chain 1->2): %s\n", locked ? "SUCCESS" : "FAILED");

    uint64_t nonce = bridge_get_event_nonce(&bridge);
    printf("Next event nonce: %llu\n", (unsigned long long)nonce);

    /* Step 5: Oracle Price Feed */
    printf("\n-- Step 5: Oracle Price Feed --\n");
    OraclePriceFeed feed;
    oracle_feed_init(&feed, ORACLE_MEDIAN, 3600);
    printf("Oracle feed: type=Median, heartbeat=3600s\n");

    uint8_t o1[20]; memset(o1, 0xA1, 20);
    uint8_t o2[20]; memset(o2, 0xA2, 20);
    uint8_t o3[20]; memset(o3, 0xA3, 20);
    oracle_add_node(&feed, o1, 1000);
    oracle_add_node(&feed, o2, 2000);
    oracle_add_node(&feed, o3, 1500);
    printf("Oracle nodes: %d (total stake)\n", feed.oracle_count);

    oracle_submit_price(&feed, o1, 150000000, (uint64_t)1);
    oracle_submit_price(&feed, o2, 155000000, (uint64_t)2);
    oracle_submit_price(&feed, o3, 152000000, (uint64_t)3);
    oracle_update_aggregate(&feed);
    printf("Price submitted: %.6f (median of 3 nodes)\n",
           (double)oracle_get_price(&feed) / 100000000.0);

    bool stale = oracle_is_stale(&feed, (uint64_t)3700);
    printf("Is stale (>3600s): %s\n", stale ? "YES" : "NO");

    printf("\nDeFi & cross-chain demo complete!\n");
    return 0;
}
