/*
 * mini-defi-crosschain — Core Tests
 *
 * Unit tests for AMM swap, lending protocol, stablecoin/CDP, cross-chain bridge, oracle.
 */
#include "../include/amm_swap.h"
#include "../include/lending_proto.h"
#include "../include/stablecoin.h"
#include "../include/crosschain_bridge.h"
#include "../include/oracle_price.h"
#include <stdio.h>
#include <string.h>

static int tests_run = 0, tests_passed = 0;

#define TEST(name) do { tests_run++; printf("  TEST %s ... ", name); } while(0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); return 1; } while(0)
#define CHECK(cond, msg) if (!(cond)) FAIL(msg)

/* ── AMM Tests ── */
static int test_amm_pool_init(void) {
    TEST("amm_pool_init");
    AMMPool pool;
    amm_pool_init(&pool, 1000000000, 2000000000, AMM_FEE_BPS);
    CHECK(pool.reserve0 == 1000000000, "reserve0 wrong");
    CHECK(pool.reserve1 == 2000000000, "reserve1 wrong");
    PASS();
    return 0;
}

static int test_amm_get_amount_out(void) {
    TEST("amm_get_amount_out");
    uint64_t out = amm_get_amount_out(100000, 1000000000, 2000000000, AMM_FEE_BPS);
    CHECK(out > 0, "amount out is zero");
    /* With constant product: (100000 * 0.997 * 2000000000) / (1000000000 + 100000 * 0.997) */
    CHECK(out < 100000 * 2, "amount out unreasonably large");
    PASS();
    return 0;
}

static int test_amm_swap(void) {
    TEST("amm_swap");
    AMMPool pool;
    amm_pool_init(&pool, 1000000000, 2000000000, AMM_FEE_BPS);
    AMMSwapResult r = amm_swap(&pool, 100000, true, 50);
    CHECK(r.input_amount == 100000, "input amount wrong");
    CHECK(r.output_amount > 0, "output is zero");
    CHECK(r.fee_amount > 0, "fee is zero");
    PASS();
    return 0;
}

static int test_amm_v3_pool(void) {
    TEST("amm_v3_pool");
    AMMV3Pool v3;
    amm_v3_pool_init(&v3, 7922816251426433759ULL, 60);
    uint64_t out = amm_v3_swap(&v3, 50000, true);
    CHECK(out > 0, "v3 swap output is zero");
    PASS();
    return 0;
}

/* ── Lending Protocol Tests ── */
static int test_lending_deposit_borrow(void) {
    TEST("lending_deposit_borrow");
    LendingMarket market;
    lending_market_init(&market, 200, 2000, 15000, 8000, 1000);
    LendingAccount account; memset(&account, 0, sizeof(account));
    uint64_t ctoken = lending_deposit(&account, &market, 1000000);
    CHECK(ctoken > 0, "ctoken is zero");
    uint64_t borrowed = lending_borrow(&account, &market, 500000, 1000000);
    CHECK(borrowed == 500000, "borrow amount wrong");
    PASS();
    return 0;
}

static int test_lending_health(void) {
    TEST("lending_health");
    LendingMarket market;
    lending_market_init(&market, 200, 2000, 15000, 8000, 1000);
    LendingAccount account; memset(&account, 0, sizeof(account));
    lending_deposit(&account, &market, 1000000);
    lending_borrow(&account, &market, 300000, 1000000);
    LendingHealth health = lending_get_health(&account, &market, 800000, 1000000, 7500, 8000);
    CHECK(health.health_factor_bps > 5000, "health factor too low");
    PASS();
    return 0;
}

/* ── Stablecoin/CDP Tests ── */
static int test_stablecoin_cdp_mint(void) {
    TEST("stablecoin_cdp_mint");
    StablecoinSystem sc_sys;
    stablecoin_system_init(&sc_sys, STABLECOIN_OVERCOLLATERALIZED);
    CDPVault vault;
    cdp_vault_init(&vault, STABLECOIN_MIN_COLLATERAL_RATIO_BPS);
    /* 300M collateral units @ price=100M/unit (= 300M USD value) */
    /* mint 100M DAI debt (= 100M USD value, 300% collateral ratio) */
    CDPMintResult result = cdp_mint(&vault, &sc_sys, 300000000, 100000000, 100000000);
    CHECK(result.mint_amount > 0, "mint amount is zero");
    CHECK(result.success, "mint should succeed");
    CHECK(result.required_collateral > 0, "collateral is zero");
    PASS();
    return 0;
}

static int test_cdp_is_safe(void) {
    TEST("cdp_is_safe");
    CDPVault vault;
    cdp_vault_init(&vault, STABLECOIN_MIN_COLLATERAL_RATIO_BPS);
    StablecoinSystem sc_sys;
    stablecoin_system_init(&sc_sys, STABLECOIN_OVERCOLLATERALIZED);
    cdp_mint(&vault, &sc_sys, 300000000, 100000000, 100000000);
    CHECK(cdp_is_safe(&vault, 100000000, 100000000), "CDP should be safe");
    PASS();
    return 0;
}

/* ── Cross-chain Bridge Tests ── */
static int test_bridge_init_lock(void) {
    TEST("bridge_init_lock");
    Bridge bridge;
    bridge_init(&bridge, BRIDGE_LOCK_MINT, BRIDGE_MULTI_SIG, 1);
    uint8_t pk[64]; memset(pk, 0x01, 64);
    uint8_t addr[20]; memset(addr, 0xAA, 20);
    bridge_add_validator(&bridge, pk, addr, 10000);
    uint8_t sender[20]; memset(sender, 0x11, 20);
    uint8_t receiver[20]; memset(receiver, 0x22, 20);
    CHECK(bridge_lock(&bridge, sender, receiver, 50000, 2), "lock failed");
    CHECK(bridge.chain_id == 1, "chain_id wrong");
    PASS();
    return 0;
}

/* ── Oracle Tests ── */
static int test_oracle_median_price(void) {
    TEST("oracle_median_price");
    OraclePriceFeed feed;
    oracle_feed_init(&feed, ORACLE_MEDIAN, 3600);
    uint8_t o1[20]; memset(o1, 0xA1, 20);
    uint8_t o2[20]; memset(o2, 0xA2, 20);
    uint8_t o3[20]; memset(o3, 0xA3, 20);
    oracle_add_node(&feed, o1, 1000);
    oracle_add_node(&feed, o2, 2000);
    oracle_add_node(&feed, o3, 1500);
    oracle_submit_price(&feed, o1, 150000000, 1);
    oracle_submit_price(&feed, o2, 155000000, 2);
    oracle_submit_price(&feed, o3, 152000000, 3);
    oracle_update_aggregate(&feed);
    uint64_t price = oracle_get_price(&feed);
    CHECK(price > 0, "price is zero");
    CHECK(price == 152000000, "median should be 152000000");
    PASS();
    return 0;
}

static int test_oracle_stale(void) {
    TEST("oracle_stale");
    OraclePriceFeed feed;
    oracle_feed_init(&feed, ORACLE_MEDIAN, 3600);
    uint8_t o1[20]; memset(o1, 0xA1, 20);
    oracle_add_node(&feed, o1, 1000);
    oracle_submit_price(&feed, o1, 100000000, 1);
    oracle_update_aggregate(&feed);
    CHECK(!oracle_is_stale(&feed, 100), "should not be stale at 100s");
    CHECK(oracle_is_stale(&feed, 3700), "should be stale after heartbeat");
    PASS();
    return 0;
}

int main(void) {
    printf("=== mini-defi-crosschain Unit Tests ===\n\n");

    int failed = 0;
    failed += test_amm_pool_init();
    failed += test_amm_get_amount_out();
    failed += test_amm_swap();
    failed += test_amm_v3_pool();
    failed += test_lending_deposit_borrow();
    failed += test_lending_health();
    failed += test_stablecoin_cdp_mint();
    failed += test_cdp_is_safe();
    failed += test_bridge_init_lock();
    failed += test_oracle_median_price();
    failed += test_oracle_stale();

    printf("\n=== Results: %d/%d passed, %d failed ===\n",
           tests_passed, tests_run, failed);
    return failed > 0 ? 1 : 0;
}
