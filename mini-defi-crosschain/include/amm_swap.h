#ifndef AMM_SWAP_H
#define AMM_SWAP_H

#include <stdbool.h>
#include <stdint.h>

#define AMM_FEE_BPS          30
#define AMM_FEE_DENOM        10000
#define AMM_MAX_HOPS         5
#define AMM_TWAP_PERIODS     8
#define AMM_PRECISION        1000000000ULL

typedef enum {
    AMM_V2_CONSTANT_PRODUCT,
    AMM_V3_CONCENTRATED,
    AMM_STABLE_SWAP
} AMMVersion;

typedef struct {
    uint64_t reserve0;
    uint64_t reserve1;
    uint64_t total_supply;
    uint64_t fee_bps;
    AMMVersion version;
} AMMPool;

typedef struct {
    uint64_t amount;
    uint64_t timestamp;
} AMMObservation;

typedef struct {
    AMMObservation observations[AMM_TWAP_PERIODS];
    int index;
    int count;
    uint64_t accum_price0;
    uint64_t accum_price1;
} AMMTWAPOracle;

typedef struct {
    uint64_t tick_lower;
    uint64_t tick_upper;
    uint64_t liquidity;
    uint64_t fee_growth_inside0;
    uint64_t fee_growth_inside1;
} AMMV3Position;

typedef struct {
    AMMPool pool;
    uint64_t sqrt_price_x96;
    int32_t current_tick;
    uint64_t tick_spacing;
    uint64_t fee_protocol_bps;
} AMMV3Pool;

typedef struct {
    uint64_t input_amount;
    uint64_t output_amount;
    uint64_t price_impact_bps;
    uint64_t fee_amount;
} AMMSwapResult;

typedef struct {
    uint64_t lp_tokens;
    uint64_t amount0;
    uint64_t amount1;
} AMMLiquidityResult;

void        amm_pool_init(AMMPool *pool, uint64_t r0, uint64_t r1, uint64_t fee_bps);
uint64_t    amm_get_amount_out(uint64_t amount_in, uint64_t reserve_in, uint64_t reserve_out, uint64_t fee_bps);
AMMSwapResult amm_swap(AMMPool *pool, uint64_t amount_in, bool zero_for_one, uint64_t slippage_bps);
uint64_t    amm_get_amount_in(uint64_t amount_out, uint64_t reserve_in, uint64_t reserve_out, uint64_t fee_bps);
AMMLiquidityResult amm_add_liquidity(AMMPool *pool, uint64_t amount0_desired, uint64_t amount1_desired, uint64_t amount0_min, uint64_t amount1_min);
uint64_t    amm_remove_liquidity(AMMPool *pool, uint64_t lp_amount);
uint64_t    amm_get_price(const AMMPool *pool, bool zero_for_one);
uint64_t    amm_price_impact_bps(uint64_t amount_in, uint64_t reserve_in, uint64_t reserve_out, uint64_t fee_bps);
void        amm_twap_init(AMMTWAPOracle *oracle);
void        amm_twap_update(AMMTWAPOracle *oracle, const AMMPool *pool);
uint64_t    amm_twap_get(const AMMTWAPOracle *oracle, uint64_t window);
void        amm_v3_pool_init(AMMV3Pool *pool, uint64_t sqrt_price_x96, uint64_t tick_spacing);
uint64_t    amm_v3_swap(AMMV3Pool *pool, uint64_t amount_in, bool zero_for_one);
uint64_t    amm_v3_add_liquidity(AMMV3Pool *pool, uint64_t tick_lower, uint64_t tick_upper, uint64_t amount0, uint64_t amount1);
AMMSwapResult amm_multihop_swap(AMMPool pools[], int num_pools, uint64_t amount_in, uint64_t slippage_bps);

#endif
