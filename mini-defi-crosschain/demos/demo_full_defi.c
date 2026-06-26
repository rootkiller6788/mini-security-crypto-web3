#include "amm_swap.h"
#include "lending_proto.h"
#include "stablecoin.h"
#include "oracle_price.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t demo_rand_seed = 0xFULLDEF1;

static uint32_t demo_rand(void) {
    demo_rand_seed = demo_rand_seed * 1103515245 + 12345;
    return demo_rand_seed;
}

static bool demo_flash_callback(uint64_t amount, uint64_t fee, uint8_t data[32]) {
    printf("      [Flash] Arbitrage executed: borrow=%llu, fee=%llu\n",
           (unsigned long long)amount, (unsigned long long)fee);
    (void)data;
    return true;
}

static void print_separator(const char *title) {
    printf("\n  --- %s ---\n", title);
}

int main(void) {
    printf("================================================================\n");
    printf("  FULL DeFi DEMO -- AMM + Lending + Stablecoin + Oracle\n");
    printf("================================================================\n");
    printf("  This demo simulates a complete DeFi ecosystem:\n");
    printf("   - ETH/USDC AMM pool with swaps and liquidity provision\n");
    printf("   - Lending market with deposits, borrows, liquidation\n");
    printf("   - CDP stablecoin (DAI model) with mint/close/liquidate\n");
    printf("   - Oracle price feeds for all assets\n");
    printf("================================================================\n");

    printf("\n");
    printf("==============================================================\n");
    printf("  PHASE 1: Setup DeFi Infrastructure\n");
    printf("==============================================================\n\n");

    printf("[1.1] Initialize ETH/USDC AMM pool...\n");
    AMMPool eth_usdc_pool;
    amm_pool_init(&eth_usdc_pool, 100000000000000000000ULL,
                  200000000000ULL, AMM_FEE_BPS);
    printf("      Reserve0 (ETH):  %llu\n",
           (unsigned long long)eth_usdc_pool.reserve0);
    printf("      Reserve1 (USDC): %llu\n",
           (unsigned long long)eth_usdc_pool.reserve1);
    printf("      ETH Price: $%llu.%02llu\n\n",
           (unsigned long long)(amm_get_price(&eth_usdc_pool, true) / 1000000),
           (unsigned long long)(amm_get_price(&eth_usdc_pool, true) % 1000000));

    printf("[1.2] Initialize USDC/DAI stable pool...\n");
    AMMPool usdc_dai_pool;
    amm_pool_init(&usdc_dai_pool, 500000000000ULL, 500000000000ULL, 10);
    printf("      USDC/DAI pool: 1 USDC = %llu.%06llu DAI\n\n",
           (unsigned long long)(amm_get_price(&usdc_dai_pool, true) / 1000000),
           (unsigned long long)(amm_get_price(&usdc_dai_pool, true) % 1000000));

    printf("[1.3] Initialize lending market...\n");
    LendingMarket lend_market;
    lending_market_init(&lend_market, 200, 3000, 15000, 8000, 1000);
    printf("      Base rate: 2%%, Kink rate: 30%%, Max: 150%%,\n");
    printf("      Kink utilization: 80%%, Reserve factor: 10%%\n\n");

    printf("[1.4] Initialize DAI stablecoin system...\n");
    StablecoinSystem dai_system;
    stablecoin_system_init(&dai_system, STABLECOIN_OVERCOLLATERALIZED);
    printf("      Liquidation ratio: 150%%\n");
    printf("      Stability fee: 5%%\n");
    printf("      Debt ceiling: %llu DAI\n\n",
           (unsigned long long)dai_system.debt_ceiling);

    printf("[1.5] Initialize oracle feeds...\n");
    OraclePriceFeed eth_oracle;
    oracle_feed_init(&eth_oracle, ORACLE_CHAINLINK, 86400);
    uint8_t oracle_nodes[5][20];
    for (int i = 0; i < 5; i++) {
        memset(oracle_nodes[i], (uint8_t)(0xCC + i), 20);
        oracle_add_node(&eth_oracle, oracle_nodes[i], 1000 + (uint64_t)i * 500);
    }
    uint64_t eth_prices[] = {200000000000ULL, 199000000000ULL, 201000000000ULL,
                              200500000000ULL, 198500000000ULL};
    uint64_t ts = 1000000;
    for (int i = 0; i < 5; i++) {
        oracle_submit_price(&eth_oracle, oracle_nodes[i], eth_prices[i], ts + (uint64_t)i);
    }
    oracle_update_aggregate(&eth_oracle);
    printf("      ETH/USD median: $%llu.%02llu\n\n",
           (unsigned long long)(eth_oracle.median_price / 100000000),
           (unsigned long long)((eth_oracle.median_price % 100000000) / 1000000));

    printf("\n");
    printf("==============================================================\n");
    printf("  PHASE 2: AMM Trading Operations\n");
    printf("==============================================================\n\n");

    AMMTWAPOracle twap_oracle;
    amm_twap_init(&twap_oracle);

    uint64_t cumulative_volume = 0;
    uint64_t cumulative_fees = 0;

    for (int day = 1; day <= 5; day++) {
        uint64_t amount = (demo_rand() % 5000000000000000000ULL) + 100000000000000000ULL;
        bool direction = (demo_rand() % 2) == 0;
        AMMSwapResult trade = amm_swap(&eth_usdc_pool, amount, direction, 50);
        cumulative_volume += trade.input_amount;
        cumulative_fees += trade.fee_amount;
        if (day <= 3) {
            printf("      Day %d: Swap %llu.%04llu %s -> %llu.%06llu %s (fee=%llu.%04llu, impact=%llu.%02llu%%)\n",
                   day,
                   (unsigned long long)(trade.input_amount / (direction ? 1000000000000000000ULL : 1000000)),
                   (unsigned long long)(trade.input_amount % (direction ? 1000000000000000000ULL : 1000000)),
                   direction ? "ETH" : "USDC",
                   (unsigned long long)(trade.output_amount / (direction ? 1000000 : 1000000000000000000ULL)),
                   (unsigned long long)(trade.output_amount % (direction ? 1000000 : 1000000000000000000ULL)),
                   direction ? "USDC" : "ETH",
                   (unsigned long long)(trade.fee_amount / (direction ? 1000000000000000000ULL : 1000000)),
                   (unsigned long long)(trade.fee_amount % (direction ? 1000000000000000000ULL : 1000000)),
                   (unsigned long long)(trade.price_impact_bps / 100),
                   (unsigned long long)(trade.price_impact_bps % 100));
        }
        amm_twap_update(&twap_oracle, &eth_usdc_pool);
    }
    printf("      ... (2 more days omitted)\n");
    printf("      Cumulative volume: %llu.%06llu\n",
           (unsigned long long)(cumulative_volume / 1000000),
           (unsigned long long)(cumulative_volume % 1000000));
    printf("      Cumulative fees:   %llu.%06llu\n",
           (unsigned long long)(cumulative_fees / 1000000),
           (unsigned long long)(cumulative_fees % 1000000));
    printf("      Final ETH price:   $%llu.%02llu\n\n",
           (unsigned long long)(amm_get_price(&eth_usdc_pool, true) / 1000000),
           (unsigned long long)(amm_get_price(&eth_usdc_pool, true) % 1000000));

    printf("[2.1] Add liquidity (2 ETH + proportional USDC)...\n");
    AMMLiquidityResult liquidity;
    uint64_t eth_amount = 2000000000000000000ULL;
    uint64_t optimal_usdc = (eth_amount * eth_usdc_pool.reserve1)
                            / eth_usdc_pool.reserve0;
    liquidity = amm_add_liquidity(&eth_usdc_pool, eth_amount,
                                   optimal_usdc, 0, 0);
    printf("      LP tokens: %llu\n", (unsigned long long)liquidity.lp_tokens);
    printf("      LP share:  %llu.%02llu%%\n\n",
           (unsigned long long)(liquidity.lp_tokens * 10000 / eth_usdc_pool.total_supply / 100),
           (unsigned long long)(liquidity.lp_tokens * 10000 / eth_usdc_pool.total_supply % 100));

    printf("\n");
    printf("==============================================================\n");
    printf("  PHASE 3: Lending Operations\n");
    printf("==============================================================\n\n");

    LendingAccount alice, bob, carol, liquidator;
    memset(&alice, 0, sizeof(alice));
    memset(&bob, 0, sizeof(bob));
    memset(&carol, 0, sizeof(carol));
    memset(&liquidator, 0, sizeof(liquidator));

    printf("[3.1] Alice deposits 50000 USDC...\n");
    uint64_t alice_ct = lending_deposit(&alice, &lend_market, 50000000000ULL);
    printf("      cTokens: %llu\n", (unsigned long long)alice_ct);

    printf("[3.2] Bob deposits 30000 USDC...\n");
    uint64_t bob_ct = lending_deposit(&bob, &lend_market, 30000000000ULL);
    printf("      cTokens: %llu\n", (unsigned long long)bob_ct);

    printf("[3.3] Current rates...\n");
    uint64_t util = lending_utilization_rate(&lend_market);
    uint64_t br = lending_borrow_rate(&lend_market);
    uint64_t sr = lending_supply_rate(&lend_market);
    printf("      Util: %llu.%02llu%%, Borrow: %llu.%02llu%%, Supply: %llu.%02llu%%\n\n",
           (unsigned long long)(util / 100),
           (unsigned long long)(util % 100),
           (unsigned long long)(br / 100),
           (unsigned long long)(br % 100),
           (unsigned long long)(sr / 100),
           (unsigned long long)(sr % 100));

    printf("[3.4] Alice borrows 30000 USDC against 50000 collateral...\n");
    uint64_t alice_borrow = lending_borrow(&alice, &lend_market,
                                            30000000000ULL, 50000000000ULL);
    printf("      Borrowed: %llu USDC\n\n", (unsigned long long)alice_borrow);

    printf("[3.5] Interest accrues over 6 months...\n");
    lending_accrue_interest(&lend_market,
                             lend_market.last_update + 180 * 86400);
    uint64_t new_exchange = lending_exchange_rate(&lend_market);
    util = lending_utilization_rate(&lend_market);
    br = lending_borrow_rate(&lend_market);
    printf("      Util: %llu.%02llu%%, Borrow rate: %llu.%02llu%%\n",
           (unsigned long long)(util / 100),
           (unsigned long long)(util % 100),
           (unsigned long long)(br / 100),
           (unsigned long long)(br % 100));
    printf("      Exchange rate: %llu.%06llu\n\n",
           (unsigned long long)(new_exchange / LENDING_KINK_PRECISION),
           (unsigned long long)(new_exchange % LENDING_KINK_PRECISION));

    printf("[3.6] Health factor checks...\n");
    LendingHealth alice_health = lending_get_health(
        &alice, &lend_market,
        30000000000ULL, 45000000000ULL,
        LENDING_MAX_LTV_BPS, LENDING_LIQUIDATION_THRESHOLD_BPS);
    printf("      Alice: Health=%llu.%02llu (borrow=%llu, limit=%llu)\n",
           (unsigned long long)(alice_health.health_factor_bps / 10000),
           (unsigned long long)(alice_health.health_factor_bps % 10000),
           (unsigned long long)alice_health.borrow_value,
           (unsigned long long)alice_health.borrow_limit);

    LendingHealth bob_health = lending_get_health(
        &bob, &lend_market,
        0, 30000000000ULL,
        LENDING_MAX_LTV_BPS, LENDING_LIQUIDATION_THRESHOLD_BPS);
    printf("      Bob:   Health=%llu.%02llu (no borrow)\n\n",
           (unsigned long long)(bob_health.health_factor_bps / 10000),
           (unsigned long long)(bob_health.health_factor_bps % 10000));

    printf("[3.7] Liquidation scenario (Alice underwater)...\n");
    LendingLiquidation liq = lending_liquidate(
        &liquidator, &alice, &lend_market,
        20000000000ULL, 100000000ULL);
    printf("      Repaid: %llu, Seized: %llu, Bonus: %llu\n\n",
           (unsigned long long)liq.repay_amount,
           (unsigned long long)liq.seize_collateral,
           (unsigned long long)liq.bonus_collateral);

    printf("[3.8] Flash loan for arbitrage...\n");
    uint8_t flash_data[32];
    memset(flash_data, 0x13, 32);
    LendingFlashLoan flash = lending_flash_loan(
        &lend_market, 5000000000ULL, flash_data, demo_flash_callback);
    printf("      Result: %s (fee: %llu)\n\n",
           flash.success ? "SUCCESS" : "FAILED",
           (unsigned long long)flash.fee);

    printf("\n");
    printf("==============================================================\n");
    printf("  PHASE 4: Stablecoin CDP Operations\n");
    printf("==============================================================\n\n");

    uint64_t collateral_price = oracle_get_price(&eth_oracle);
    if (collateral_price == 0) collateral_price = 200000000000ULL;

    printf("[4.1] User opens CDP with 10 ETH...\n");
    CDPVault cdp1;
    cdp_vault_init(&cdp1, STABLECOIN_MIN_COLLATERAL_RATIO_BPS);
    uint64_t mint_debt = 10000000000000000000000ULL;
    CDPMintResult mint_r = cdp_mint(&cdp1, &dai_system,
                                     10000000000000000000ULL,
                                     collateral_price, mint_debt);
    printf("      Minted: %llu DAI against %llu ETH\n",
           (unsigned long long)mint_r.mint_amount,
           (unsigned long long)cdp1.locked_collateral);
    printf("      Stability fee: %llu DAI\n", (unsigned long long)mint_r.fee_amount);

    CDPHealth cdp1_health = cdp_get_health(&cdp1, collateral_price, 100000000ULL);
    printf("      Collateral ratio: %llu.%02llu%%\n\n",
           (unsigned long long)(cdp1_health.collateral_ratio_bps / 100),
           (unsigned long long)(cdp1_health.collateral_ratio_bps % 100));

    printf("[4.2] Fee accrual over time...\n");
    uint64_t fee1 = stablecoin_accrue_stability_fee(
        &cdp1, dai_system.stability_fee_bps, cdp1.last_fee_update + 30 * 86400);
    printf("      30 days fee: %llu DAI (new debt: %llu)\n\n",
           (unsigned long long)fee1,
           (unsigned long long)cdp1.minted_debt);

    printf("[4.3] Market crash - ETH drops 40%%...\n");
    uint64_t crashed_price = collateral_price * 60 / 100;
    CDPHealth crash_health = cdp_get_health(&cdp1, crashed_price, 100000000ULL);
    printf("      Ratio after crash: %llu.%02llu%%\n",
           (unsigned long long)(crash_health.collateral_ratio_bps / 100),
           (unsigned long long)(crash_health.collateral_ratio_bps % 100));
    printf("      Safe: %s\n",
           cdp_is_safe(&cdp1, crashed_price, 100000000ULL) ? "YES" : "NO - LIQUIDATABLE!");

    CDPLiquidationResult liq_result = cdp_liquidate(
        &cdp1, &dai_system, crashed_price, 100000000ULL);
    printf("      Liquidated: %llu ETH seized for %llu DAI\n",
           (unsigned long long)liq_result.seized_collateral,
           (unsigned long long)liq_result.covered_debt);
    printf("      Penalty: %llu ETH\n\n",
           (unsigned long long)liq_result.penalty_amount);

    printf("[4.4] User 2 opens and closes CDP (no crash)...\n");
    CDPVault cdp2;
    cdp_vault_init(&cdp2, STABLECOIN_MIN_COLLATERAL_RATIO_BPS);
    cdp_mint(&cdp2, &dai_system, 5000000000000000000ULL,
             collateral_price, 5000000000000000000000ULL);
    printf("      Opened: %llu DAI / %llu ETH\n",
           (unsigned long long)cdp2.minted_debt,
           (unsigned long long)cdp2.locked_collateral);

    CDPCloseResult close_r = cdp_close(
        &cdp2, &dai_system, collateral_price, cdp2.minted_debt);
    printf("      Closed: %llu DAI burned, %llu ETH returned\n",
           (unsigned long long)close_r.burned_debt,
           (unsigned long long)close_r.returned_collateral);
    printf("      Fee paid: %llu DAI\n\n",
           (unsigned long long)close_r.fee_amount);

    printf("\n");
    printf("==============================================================\n");
    printf("  PHASE 5: Multi-hop Swap + TWAP\n");
    printf("==============================================================\n\n");

    printf("[5.1] USDC -> ETH -> DAI multi-hop (arbitrage path)...\n");
    AMMPool hop1, hop2;
    amm_pool_init(&hop1, 1000000000000ULL, 100000000000000000000ULL, AMM_FEE_BPS);
    amm_pool_init(&hop2, 100000000000000000000ULL, 200000000000ULL, AMM_FEE_BPS);

    AMMPool multi_path[2] = {hop1, hop2};
    AMMSwapResult multi = amm_multihop_swap(multi_path, 2,
                                             10000000ULL, 200);
    printf("      10 USDC -> %llu.%06llu DAI (hops: USDC-ETH-DAI)\n",
           (unsigned long long)(multi.output_amount / 1000000),
           (unsigned long long)(multi.output_amount % 1000000));
    printf("      Fees: %llu, Impact: %llu.%02llu%%\n\n",
           (unsigned long long)multi.fee_amount,
           (unsigned long long)(multi.price_impact_bps / 100),
           (unsigned long long)(multi.price_impact_bps % 100));

    printf("[5.2] TWAP Oracle over simulated window...\n");
    uint64_t twap_val = amm_twap_get(&twap_oracle, 5);
    printf("      TWAP (5-period): %llu.%06llu\n\n",
           (unsigned long long)(twap_val / 1000000),
           (unsigned long long)(twap_val % 1000000));

    printf("\n");
    printf("==============================================================\n");
    printf("  FINAL SUMMARY\n");
    printf("==============================================================\n");
    printf("  AMM Pool:     ETH/USDC, reserve0=%llu, reserve1=%llu\n",
           (unsigned long long)eth_usdc_pool.reserve0,
           (unsigned long long)eth_usdc_pool.reserve1);
    printf("  Lending:      Deposits=%llu, Borrows=%llu, Reserves=%llu\n",
           (unsigned long long)lend_market.total_deposits,
           (unsigned long long)lend_market.total_borrows,
           (unsigned long long)lend_market.total_reserves);
    printf("  Stablecoin:   Supply=%llu DAI, Debt=%llu DAI\n",
           (unsigned long long)dai_system.total_supply,
           (unsigned long long)dai_system.total_debt);
    printf("  Oracle:       ETH/USD median=$%llu.%02llu\n",
           (unsigned long long)(eth_oracle.median_price / 100000000),
           (unsigned long long)((eth_oracle.median_price % 100000000) / 1000000));
    printf("\n================================================================\n");
    printf("  Full DeFi Demo Complete!\n");
    printf("================================================================\n");
    return 0;
}
