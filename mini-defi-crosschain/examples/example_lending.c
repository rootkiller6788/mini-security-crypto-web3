#include "lending_proto.h"
#include "oracle_price.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool flash_callback(uint64_t amount, uint64_t fee, uint8_t data[32]) {
    printf("    [Callback] Received %llu tokens, fee=%llu\n",
           (unsigned long long)amount, (unsigned long long)fee);
    printf("    [Callback] Arbitrage simulated, repaying %llu + %llu fee...\n",
           (unsigned long long)amount, (unsigned long long)fee);
    (void)data;
    return true;
}

int main(void) {
    printf("========================================================\n");
    printf("  Lending Protocol Demo -- Compound/Aave Model\n");
    printf("========================================================\n\n");

    LendingMarket market;
    printf("[STEP 1] Initialize lending market (kink model)...\n");
    lending_market_init(&market, 200, 3000, 15000, 8000, 1000);
    printf("  IR params: base=2%%, kink_rate=30%%, max=150%%, kink=80%%\n");
    printf("  Reserve factor: 10%%\n\n");

    printf("[STEP 2] Initial deposits (100000 USDC)...\n");
    LendingAccount alice, bob, carol, liquidator;
    memset(&alice, 0, sizeof(alice));
    memset(&bob, 0, sizeof(bob));
    memset(&carol, 0, sizeof(carol));
    memset(&liquidator, 0, sizeof(liquidator));

    uint64_t alice_dep = lending_deposit(&alice, &market, 100000000000ULL);
    printf("  Alice deposits 100000 USD -> %llu cTokens\n",
           (unsigned long long)alice_dep);
    printf("  Market: deposits=%llu, borrows=%llu\n\n",
           (unsigned long long)market.total_deposits,
           (unsigned long long)market.total_borrows);

    printf("[STEP 3] Bob deposits 50000 USDC...\n");
    uint64_t bob_dep = lending_deposit(&bob, &market, 50000000000ULL);
    printf("  Bob deposits 50000 USD -> %llu cTokens\n",
           (unsigned long long)bob_dep);
    printf("  Market: deposits=%llu\n\n",
           (unsigned long long)market.total_deposits);

    printf("[STEP 4] Utilization & interest rates...\n");
    uint64_t util = lending_utilization_rate(&market);
    uint64_t borrow_rate = lending_borrow_rate(&market);
    uint64_t supply_rate = lending_supply_rate(&market);
    printf("  Utilization: %llu.%02llu%%\n",
           (unsigned long long)(util / 100),
           (unsigned long long)(util % 100));
    printf("  Borrow rate: %llu.%02llu%% APR\n",
           (unsigned long long)(borrow_rate / 100),
           (unsigned long long)(borrow_rate % 100));
    printf("  Supply rate: %llu.%02llu%% APR\n\n",
           (unsigned long long)(supply_rate / 100),
           (unsigned long long)(supply_rate % 100));

    printf("[STEP 5] Alice borrows (over-collateralized)...\n");
    uint64_t max_borrow = lending_max_borrow(100000000000ULL, LENDING_MAX_LTV_BPS);
    printf("  Max borrow at %llu%% LTV: %llu USDC\n",
           (unsigned long long)(LENDING_MAX_LTV_BPS / 100),
           (unsigned long long)max_borrow);
    uint64_t borrow_amt = lending_borrow(&alice, &market, 50000000000ULL, 100000000000ULL);
    printf("  Alice borrows %llu USDC\n\n", (unsigned long long)borrow_amt);

    printf("[STEP 6] Interest accrual simulation (1 year)...\n");
    lending_accrue_interest(&market, market.last_update + 365 * 86400);
    uint64_t new_util = lending_utilization_rate(&market);
    uint64_t new_br = lending_borrow_rate(&market);
    printf("  After 1 year: utilization=%llu.%02llu%%, borrow_rate=%llu.%02llu%%\n",
           (unsigned long long)(new_util / 100),
           (unsigned long long)(new_util % 100),
           (unsigned long long)(new_br / 100),
           (unsigned long long)(new_br % 100));

    uint64_t exchange = lending_exchange_rate(&market);
    printf("  Exchange rate: %llu.%06llu\n\n",
           (unsigned long long)(exchange / LENDING_KINK_PRECISION),
           (unsigned long long)(exchange % LENDING_KINK_PRECISION));

    printf("[STEP 7] Health factor check...\n");
    LendingHealth health = lending_get_health(&alice, &market,
                                               75000000000ULL,
                                               95000000000ULL,
                                               LENDING_MAX_LTV_BPS,
                                               LENDING_LIQUIDATION_THRESHOLD_BPS);
    printf("  Borrow value: %llu\n", (unsigned long long)health.borrow_value);
    printf("  Collateral value: %llu\n", (unsigned long long)health.collateral_value);
    printf("  Borrow limit: %llu\n", (unsigned long long)health.borrow_limit);
    printf("  Health factor: %llu.%02llu (safe > 10000)\n\n",
           (unsigned long long)(health.health_factor_bps / 10000),
           (unsigned long long)(health.health_factor_bps % 10000));

    printf("[STEP 8] Liquidation scenario (health < 1)...\n");
    LendingLiquidation liq = lending_liquidate(&liquidator, &alice,
                                                &market, 30000000000ULL, 100000000);
    printf("  Liquidator repays: %llu USDC\n",
           (unsigned long long)liq.repay_amount);
    printf("  Seizes collateral: %llu\n",
           (unsigned long long)liq.seize_collateral);
    printf("  Bonus: %llu\n", (unsigned long long)liq.bonus_collateral);
    printf("  Remaining debt: %llu\n\n",
           (unsigned long long)liq.remaining_debt);

    printf("[STEP 9] Flash Loan...\n");
    uint8_t flash_data[32] = {0};
    flash_data[0] = 0x42;
    LendingFlashLoan flash = lending_flash_loan(&market, 10000000000ULL,
                                                  flash_data, flash_callback);
    printf("  Flash loan result: success=%s, fee=%llu\n\n",
           flash.success ? "YES" : "NO",
           (unsigned long long)flash.fee);

    printf("[STEP 10] Repay & Redeem...\n");
    uint64_t repaid = lending_repay(&alice, &market, 20000000000ULL);
    printf("  Alice repays: %llu USDC\n", (unsigned long long)repaid);

    uint64_t redeemed = lending_redeem(&bob, &market, bob.ctoken_balance / 2);
    printf("  Bob redeems 50%%: %llu USDC returned\n\n",
           (unsigned long long)redeemed);

    printf("[STEP 11] Utilization table (different levels)...\n");
    printf("  %-10s %-12s %-12s\n", "Util%%", "Borrow Rate", "Supply Rate");
    printf("  %-10s %-12s %-12s\n", "------", "-----------", "-----------");
    uint64_t levels[] = {0, 2000, 4000, 6000, 8000, 9000, 10000};
    for (int i = 0; i < 7; i++) {
        LendingMarket sim_market;
        lending_market_init(&sim_market, 200, 3000, 15000, 8000, 1000);
        sim_market.total_deposits = 100000000000ULL;
        sim_market.total_borrows = sim_market.total_deposits * levels[i] / 10000;
        uint64_t br = lending_borrow_rate(&sim_market);
        uint64_t sr = lending_supply_rate(&sim_market);
        printf("  %llu.%02llu%%    %llu.%02llu%%      %llu.%02llu%%\n",
               (unsigned long long)(levels[i] / 100),
               (unsigned long long)(levels[i] % 100),
               (unsigned long long)(br / 100),
               (unsigned long long)(br % 100),
               (unsigned long long)(sr / 100),
               (unsigned long long)(sr % 100));
    }

    printf("\n========================================================\n");
    printf("  Lending Protocol Demo Complete\n");
    printf("========================================================\n");
    return 0;
}
