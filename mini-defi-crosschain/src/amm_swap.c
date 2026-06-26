#include "amm_swap.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t amm_rand_seed = 0xDEF1DEF1;

static uint32_t amm_rand(void) {
    amm_rand_seed = amm_rand_seed * 1103515245 + 12345;
    return amm_rand_seed;
}

static uint64_t amm_mul_div(uint64_t a, uint64_t b, uint64_t c) {
    if (c == 0) return 0;
    return (a * b) / c;
}

void amm_pool_init(AMMPool *pool, uint64_t r0, uint64_t r1, uint64_t fee_bps) {
    memset(pool, 0, sizeof(AMMPool));
    pool->reserve0 = r0;
    pool->reserve1 = r1;
    pool->total_supply = r0 + r1;
    pool->fee_bps = fee_bps > 0 ? fee_bps : AMM_FEE_BPS;
    pool->version = AMM_V2_CONSTANT_PRODUCT;
}

uint64_t amm_get_amount_out(uint64_t amount_in, uint64_t reserve_in,
                            uint64_t reserve_out, uint64_t fee_bps) {
    if (amount_in == 0 || reserve_in == 0 || reserve_out == 0) return 0;
    uint64_t amount_in_with_fee = amount_in * (AMM_FEE_DENOM - fee_bps);
    uint64_t numerator = amount_in_with_fee * reserve_out;
    uint64_t denominator = reserve_in * AMM_FEE_DENOM + amount_in_with_fee;
    return numerator / denominator;
}

AMMSwapResult amm_swap(AMMPool *pool, uint64_t amount_in, bool zero_for_one,
                       uint64_t slippage_bps) {
    AMMSwapResult result;
    memset(&result, 0, sizeof(result));

    uint64_t reserve_in = zero_for_one ? pool->reserve0 : pool->reserve1;
    uint64_t reserve_out = zero_for_one ? pool->reserve1 : pool->reserve0;

    uint64_t expected_out = amm_get_amount_out(amount_in, reserve_in,
                                               reserve_out, pool->fee_bps);
    if (expected_out == 0) return result;

    uint64_t min_out = expected_out * (AMM_FEE_DENOM - slippage_bps) / AMM_FEE_DENOM;

    uint64_t fee_amount = amount_in * pool->fee_bps / AMM_FEE_DENOM;
    uint64_t impact = amm_price_impact_bps(amount_in, reserve_in, reserve_out,
                                           pool->fee_bps);

    if (zero_for_one) {
        pool->reserve0 += amount_in;
        pool->reserve1 -= expected_out;
    } else {
        pool->reserve1 += amount_in;
        pool->reserve0 -= expected_out;
    }

    result.input_amount = amount_in;
    result.output_amount = expected_out;
    result.fee_amount = fee_amount;
    result.price_impact_bps = impact;

    (void)min_out;
    return result;
}

uint64_t amm_get_amount_in(uint64_t amount_out, uint64_t reserve_in,
                           uint64_t reserve_out, uint64_t fee_bps) {
    if (amount_out == 0 || reserve_in == 0 || reserve_out <= amount_out) return 0;
    uint64_t numerator = reserve_in * amount_out * AMM_FEE_DENOM;
    uint64_t denominator = (reserve_out - amount_out) * (AMM_FEE_DENOM - fee_bps);
    return numerator / denominator + 1;
}

AMMLiquidityResult amm_add_liquidity(AMMPool *pool, uint64_t amount0_desired,
                                     uint64_t amount1_desired,
                                     uint64_t amount0_min, uint64_t amount1_min) {
    AMMLiquidityResult result;
    memset(&result, 0, sizeof(result));

    if (pool->total_supply == 0) {
        result.lp_tokens = amount0_desired + amount1_desired;
        result.amount0 = amount0_desired;
        result.amount1 = amount1_desired;
        pool->reserve0 = amount0_desired;
        pool->reserve1 = amount1_desired;
        pool->total_supply = result.lp_tokens;
        return result;
    }

    uint64_t amount1_optimal = amm_mul_div(amount0_desired, pool->reserve1,
                                           pool->reserve0);
    if (amount1_optimal <= amount1_desired) {
        if (amount1_optimal < amount1_min) return result;
        result.amount0 = amount0_desired;
        result.amount1 = amount1_optimal;
    } else {
        uint64_t amount0_optimal = amm_mul_div(amount1_desired, pool->reserve0,
                                               pool->reserve1);
        if (amount0_optimal < amount0_min) return result;
        result.amount0 = amount0_optimal;
        result.amount1 = amount1_desired;
    }

    result.lp_tokens = amm_mul_div(result.amount0, pool->total_supply,
                                   pool->reserve0);
    pool->reserve0 += result.amount0;
    pool->reserve1 += result.amount1;
    pool->total_supply += result.lp_tokens;

    return result;
}

uint64_t amm_remove_liquidity(AMMPool *pool, uint64_t lp_amount) {
    if (lp_amount == 0 || pool->total_supply == 0) return 0;

    uint64_t amount0 = amm_mul_div(lp_amount, pool->reserve0, pool->total_supply);
    uint64_t amount1 = amm_mul_div(lp_amount, pool->reserve1, pool->total_supply);

    pool->reserve0 -= amount0;
    pool->reserve1 -= amount1;
    pool->total_supply -= lp_amount;

    return amount0 + amount1;
}

uint64_t amm_get_price(const AMMPool *pool, bool zero_for_one) {
    if (pool->reserve0 == 0 || pool->reserve1 == 0) return 0;
    return zero_for_one
        ? (pool->reserve1 * AMM_PRECISION) / pool->reserve0
        : (pool->reserve0 * AMM_PRECISION) / pool->reserve1;
}

uint64_t amm_price_impact_bps(uint64_t amount_in, uint64_t reserve_in,
                               uint64_t reserve_out, uint64_t fee_bps) {
    if (amount_in == 0 || reserve_in == 0 || reserve_out == 0) return 0;
    uint64_t spot_price = (reserve_out * AMM_PRECISION) / reserve_in;
    uint64_t amount_out = amm_get_amount_out(amount_in, reserve_in, reserve_out, fee_bps);
    if (amount_out == 0) return AMM_FEE_DENOM;
    uint64_t exec_price = (amount_out * AMM_PRECISION) / amount_in;
    if (spot_price <= exec_price) return 0;
    uint64_t diff = spot_price - exec_price;
    return (diff * AMM_FEE_DENOM) / spot_price;
}

void amm_twap_init(AMMTWAPOracle *oracle) {
    memset(oracle, 0, sizeof(AMMTWAPOracle));
}

void amm_twap_update(AMMTWAPOracle *oracle, const AMMPool *pool) {
    if (oracle->count > 0) {
        AMMObservation *last = &oracle->observations[oracle->index];
        uint64_t elapsed = amm_rand() % 15 + 1;
        uint64_t price = amm_get_price(pool, true);
        oracle->accum_price0 += price * elapsed;
        oracle->accum_price1 += amm_get_price(pool, false) * elapsed;
        (void)last;
    }

    oracle->observations[oracle->index].amount = pool->reserve0;
    oracle->observations[oracle->index].timestamp = amm_rand() + 1000000;
    oracle->index = (oracle->index + 1) % AMM_TWAP_PERIODS;
    if (oracle->count < AMM_TWAP_PERIODS) oracle->count++;
}

uint64_t amm_twap_get(const AMMTWAPOracle *oracle, uint64_t window) {
    if (oracle->count < 2 || window == 0) return oracle->accum_price0 > 0 ? oracle->accum_price0 : 0;
    uint64_t twap = oracle->accum_price0 / window;
    return twap > 0 ? twap : AMM_PRECISION;
}

void amm_v3_pool_init(AMMV3Pool *pool, uint64_t sqrt_price_x96,
                      uint64_t tick_spacing) {
    memset(pool, 0, sizeof(AMMV3Pool));
    pool->sqrt_price_x96 = sqrt_price_x96;
    pool->current_tick = 0;
    pool->tick_spacing = tick_spacing > 0 ? tick_spacing : 60;
    pool->fee_protocol_bps = 0;
}

uint64_t amm_v3_swap(AMMV3Pool *pool, uint64_t amount_in, bool zero_for_one) {
    if (amount_in == 0) return 0;
    uint64_t fee = amount_in * AMM_FEE_BPS / AMM_FEE_DENOM;
    uint64_t net_in = amount_in - fee;
    /* Uniswap V3: sqrt_price_x96 is Q64.96 fixed-point.
     * For practical simulation, use a proportional model. */
    uint64_t sqrt_price = pool->sqrt_price_x96 / 10000000000000000000ULL;
    if (sqrt_price == 0) sqrt_price = 1;
    uint64_t out = (net_in * AMM_PRECISION) / sqrt_price;
    out = out * 99 / 100;
    pool->sqrt_price_x96 = zero_for_one
        ? pool->sqrt_price_x96 - (amount_in / 1000000)
        : pool->sqrt_price_x96 + (amount_in / 1000000);
    if (zero_for_one) {
        pool->current_tick -= (int32_t)(amount_in / 100000);
    } else {
        pool->current_tick += (int32_t)(amount_in / 100000);
    }
    return out;
}

uint64_t amm_v3_add_liquidity(AMMV3Pool *pool, uint64_t tick_lower,
                               uint64_t tick_upper, uint64_t amount0,
                               uint64_t amount1) {
    uint64_t liquidity = amount0 + amount1;
    if (tick_lower < tick_upper) {
        liquidity = (amount0 > amount1 ? amount0 : amount1)
                  + (amount0 < amount1 ? amount0 : amount1) / 2;
    }
    (void)pool;
    (void)tick_lower;
    (void)tick_upper;
    (void)amount0;
    (void)amount1;
    return liquidity;
}

AMMSwapResult amm_multihop_swap(AMMPool pools[], int num_pools,
                                 uint64_t amount_in, uint64_t slippage_bps) {
    AMMSwapResult result;
    memset(&result, 0, sizeof(result));
    if (num_pools <= 0 || num_pools > AMM_MAX_HOPS) return result;

    uint64_t current_amount = amount_in;
    uint64_t total_fee = 0;
    uint64_t total_impact = 0;

    for (int i = 0; i < num_pools; i++) {
        uint64_t reserve_in = pools[i].reserve0;
        uint64_t reserve_out = pools[i].reserve1;
        uint64_t out = amm_get_amount_out(current_amount, reserve_in,
                                          reserve_out, pools[i].fee_bps);
        if (out == 0) {
            memset(&result, 0, sizeof(result));
            return result;
        }
        uint64_t fee = current_amount * pools[i].fee_bps / AMM_FEE_DENOM;
        uint64_t impact = amm_price_impact_bps(current_amount, reserve_in,
                                               reserve_out, pools[i].fee_bps);
        total_fee += fee;
        total_impact += impact;
        current_amount = out;
    }

    uint64_t min_out = current_amount * (AMM_FEE_DENOM - slippage_bps)
                       / AMM_FEE_DENOM;
    result.input_amount = amount_in;
    result.output_amount = current_amount;
    result.fee_amount = total_fee;
    result.price_impact_bps = total_impact;
    (void)min_out;
    return result;
}
