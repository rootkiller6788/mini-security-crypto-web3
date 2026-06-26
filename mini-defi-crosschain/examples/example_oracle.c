#include "oracle_price.h"
#include "stablecoin.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_health(const CDPVault *vault, uint64_t collateral_price,
                         uint64_t debt_price) {
    CDPHealth h = cdp_get_health(vault, collateral_price, debt_price);
    printf("  Collateral: %llu ETH @ $%llu = $%llu\n",
           (unsigned long long)vault->locked_collateral,
           (unsigned long long)collateral_price,
           (unsigned long long)h.collateral_value);
    printf("  Debt:       %llu DAI @ $%llu = $%llu\n",
           (unsigned long long)vault->minted_debt,
           (unsigned long long)debt_price,
           (unsigned long long)h.debt_value);
    printf("  Ratio:      %llu.%02llu%%\n",
           (unsigned long long)(h.collateral_ratio_bps / 100),
           (unsigned long long)(h.collateral_ratio_bps % 100));
    printf("  Safe:       %s\n\n",
           cdp_is_safe(vault, collateral_price, debt_price) ? "YES" : "LIQUIDATABLE");
}

int main(void) {
    printf("========================================================\n");
    printf("  Stablecoin + Oracle Demo -- CDP Model & Price Feeds\n");
    printf("========================================================\n\n");

    printf("[SECTION A: Oracle Price Feeds]\n\n");

    printf("[STEP 1] Initialize Chainlink-style oracle...\n");
    OraclePriceFeed eth_feed, btc_feed, dai_feed;
    oracle_feed_init(&eth_feed, ORACLE_CHAINLINK, 86400);
    oracle_feed_init(&btc_feed, ORACLE_CHAINLINK, 86400);
    oracle_feed_init(&dai_feed, ORACLE_CHAINLINK, 86400);
    printf("  Price feeds: ETH/USD, BTC/USD, DAI/USD initialized\n\n");

    printf("[STEP 2] Add oracle nodes (decentralized validators)...\n");
    uint8_t node_addrs[7][20];
    for (int i = 0; i < 7; i++) {
        memset(node_addrs[i], (uint8_t)(0xA0 + i), 20);
    }
    uint64_t stakes[] = {1000, 2000, 1500, 3000, 800, 1200, 2500};
    for (int i = 0; i < 7; i++) {
        oracle_add_node(&eth_feed, node_addrs[i], stakes[i]);
    }
    printf("  7 oracle nodes added to ETH/USD feed\n\n");

    printf("[STEP 3] Submit price observations (simulated)...\n");
    uint64_t eth_prices[] = {
        200000000000ULL, 198000000000ULL, 201000000000ULL,
        200500000000ULL, 199500000000ULL, 202000000000ULL,
        200200000000ULL
    };
    uint64_t ts = 1000000;
    for (int i = 0; i < 7; i++) {
        oracle_submit_price(&eth_feed, node_addrs[i], eth_prices[i], ts + (uint64_t)i);
    }
    oracle_update_aggregate(&eth_feed);
    printf("  Median price: $%llu.%02llu\n",
           (unsigned long long)(eth_feed.median_price / 100000000),
           (unsigned long long)((eth_feed.median_price % 100000000) / 1000000));
    printf("  Latest price: $%llu.%02llu\n\n",
           (unsigned long long)(eth_feed.latest_price / 100000000),
           (unsigned long long)((eth_feed.latest_price % 100000000) / 1000000));

    printf("[STEP 4] Median price calculation test...\n");
    printf("  Input prices: ");
    for (int i = 0; i < 7; i++) {
        printf("$%llu ", (unsigned long long)(eth_prices[i] / 100000000));
    }
    printf("\n");
    uint64_t median = oracle_get_median(eth_prices, 7);
    printf("  Median: $%llu.%02llu\n\n",
           (unsigned long long)(median / 100000000),
           (unsigned long long)((median % 100000000) / 1000000));

    printf("[STEP 5] Stale price check...\n");
    bool fresh = !oracle_is_stale(&eth_feed, ts + 100000);
    bool stale = oracle_is_stale(&eth_feed, ts + 10000000);
    printf("  Check at ts+100k: %s\n", fresh ? "FRESH" : "STALE");
    printf("  Check at ts+10M:  %s\n\n", stale ? "STALE" : "FRESH");

    printf("[STEP 6] TWAP Tracker...\n");
    TWAPTracker twap;
    twap_tracker_init(&twap);
    uint64_t price_path[] = {200, 198, 201, 203, 205, 204, 206, 208};
    uint64_t time_path[] =  {0, 300, 600, 900, 1200, 1500, 1800, 2100};
    for (int i = 0; i < 8; i++) {
        twap_tracker_update(&twap, price_path[i], time_path[i] + 1000000);
    }
    uint64_t twap_price = twap_tracker_compute(&twap, 1800);
    printf("  TWAP (1800s window): %llu.%04llu\n\n",
           (unsigned long long)(twap_price / 10000),
           (unsigned long long)(twap_price % 10000));

    printf("[STEP 7] Simulate data feeds...\n");
    OraclePriceFeed sim_feeds[4];
    oracle_simulate_data_feeds(sim_feeds, 4);
    printf("  Simulated feeds:\n");
    for (int i = 0; i < 4; i++) {
        printf("    %s: $%llu.%02llu\n",
               sim_feeds[i].feed_id,
               (unsigned long long)(sim_feeds[i].latest_price / 100000000),
               (unsigned long long)((sim_feeds[i].latest_price % 100000000) / 1000000));
    }
    printf("\n");

    printf("[STEP 8] Price conversion...\n");
    uint64_t eth_in_btc = oracle_convert_price(
        200000000000ULL, 3500000000000ULL, 100000000ULL);
    printf("  1 ETH = %llu.%06llu BTC\n\n",
           (unsigned long long)(eth_in_btc / 100000000),
           (unsigned long long)(eth_in_btc % 100000000));

    printf("\n[SECTION B: Stablecoin CDP (DAI Model)]\n\n");

    printf("[STEP 9] Initialize DAI system...\n");
    StablecoinSystem dai_sys;
    stablecoin_system_init(&dai_sys, STABLECOIN_OVERCOLLATERALIZED);
    printf("  Type: over-collateralized (DAI model)\n");
    printf("  Liquidation ratio: %llu%%\n",
           (unsigned long long)(dai_sys.liquidation_ratio_bps / 100));
    printf("  Stability fee: %llu.%%\n",
           (unsigned long long)(dai_sys.stability_fee_bps / 100));
    printf("  Debt ceiling: %llu DAI\n\n",
           (unsigned long long)dai_sys.debt_ceiling);

    printf("[STEP 10] Create CDP vault (open a position)...\n");
    CDPVault vault;
    cdp_vault_init(&vault, STABLECOIN_MIN_COLLATERAL_RATIO_BPS);
    printf("  Vault: min ratio=%llu%%\n\n",
           (unsigned long long)(vault.min_ratio_bps / 100));

    printf("[STEP 11] Lock 10 ETH ($$2000/ETH) to mint DAI...\n");
    uint64_t eth_coll = 10000000000000000000ULL;
    uint64_t eth_price = 200000000000ULL;
    uint64_t dai_debt = 10000000000000000000000ULL;
    CDPMintResult mint = cdp_mint(&vault, &dai_sys, eth_coll, eth_price, dai_debt);
    printf("  Minted: %llu DAI\n", (unsigned long long)mint.mint_amount);
    printf("  Fee:    %llu DAI\n", (unsigned long long)mint.fee_amount);
    printf("  Req'd collateral: %llu ETH\n\n",
           (unsigned long long)mint.required_collateral);

    print_health(&vault, eth_price, 100000000ULL);

    printf("[STEP 12] Accrue stability fee (1 year)...\n");
    uint64_t fee = stablecoin_accrue_stability_fee(&vault,
        dai_sys.stability_fee_bps, vault.last_fee_update + 365 * 86400);
    printf("  Stability fee accrued: %llu DAI\n", (unsigned long long)fee);
    printf("  New debt: %llu DAI\n\n",
           (unsigned long long)vault.minted_debt);

    printf("[STEP 13] ETH drops to $1400 -> liquidation...\n");
    uint64_t low_eth = 140000000000ULL;
    print_health(&vault, low_eth, 100000000ULL);

    CDPLiquidationResult liq = cdp_liquidate(&vault, &dai_sys,
                                              low_eth, 100000000ULL);
    printf("  Liquidation result:\n");
    printf("    Seized collateral: %llu ETH\n",
           (unsigned long long)liq.seized_collateral);
    printf("    Covered debt:     %llu DAI\n",
           (unsigned long long)liq.covered_debt);
    printf("    Penalty amount:   %llu ETH\n\n",
           (unsigned long long)liq.penalty_amount);

    printf("[STEP 14] Close CDP (return DAI, get collateral back)...\n");
    CDPVault close_vault;
    cdp_vault_init(&close_vault, STABLECOIN_MIN_COLLATERAL_RATIO_BPS);
    CDPMintResult mint2 = cdp_mint(&close_vault, &dai_sys,
                                    eth_coll, eth_price, dai_debt);
    printf("  Vault: %llu DAI debt, %llu ETH locked\n",
           (unsigned long long)close_vault.minted_debt,
           (unsigned long long)close_vault.locked_collateral);

    CDPCloseResult close = cdp_close(&close_vault, &dai_sys,
                                      eth_price, dai_debt / 2);
    printf("  Closed: %llu DAI burned, %llu ETH returned\n\n",
           (unsigned long long)close.burned_debt,
           (unsigned long long)close.returned_collateral);

    printf("[STEP 15] Emergency shutdown...\n");
    stablecoin_emergency_shutdown(&dai_sys);
    printf("  Status: shutdown=%s, settlement=%s\n",
           dai_sys.emergency_shutdown ? "YES" : "NO",
           dai_sys.global_settlement ? "YES" : "NO");
    stablecoin_settle(&dai_sys, eth_price, 100000000ULL);
    printf("  After settle: global_settlement=%s\n\n",
           dai_sys.global_settlement ? "YES" : "NO");

    printf("[STEP 16] Algorithmic stablecoin...\n");
    uint64_t supply = 1000000000000ULL;
    uint64_t price = 95000;
    uint64_t target = 100000;
    printf("  Before: supply=%llu, price=%llu\n",
           (unsigned long long)supply, (unsigned long long)price);
    algorithmic_mint(&supply, &price, target);
    printf("  After (mint, price<target): supply=%llu, price=%llu\n",
           (unsigned long long)supply, (unsigned long long)price);

    price = 105000;
    algorithmic_burn(&supply, &price, target);
    printf("  After (burn, price>target): supply=%llu, price=%llu\n\n",
           (unsigned long long)supply, (unsigned long long)price);

    printf("========================================================\n");
    printf("  Stablecoin + Oracle Demo Complete\n");
    printf("========================================================\n");
    return 0;
}
