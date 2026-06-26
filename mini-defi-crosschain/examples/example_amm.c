#include "amm_swap.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    printf("========================================================\n");
    printf("  AMM / Swap Demo -- Constant Product & Multi-Hop\n");
    printf("========================================================\n\n");

    AMMPool pool;
    printf("[STEP 1] Initialize ETH/DAI pool (reserves: 100 ETH, 200000 DAI)...\n");
    amm_pool_init(&pool, 100000000000000000000ULL, 200000000000ULL, AMM_FEE_BPS);
    printf("  Pool: reserve0(ETH)=%llu, reserve1(DAI)=%llu, fee=%llu bps\n",
           (unsigned long long)pool.reserve0,
           (unsigned long long)pool.reserve1,
           (unsigned long long)pool.fee_bps);
    printf("  Total supply: %llu LP tokens\n\n",
           (unsigned long long)pool.total_supply);

    printf("[STEP 2] Get price...\n");
    uint64_t eth_price = amm_get_price(&pool, true);
    uint64_t dai_price = amm_get_price(&pool, false);
    printf("  ETH/DAI price: %llu.%06llu\n",
           (unsigned long long)(eth_price / 1000000),
           (unsigned long long)(eth_price % 1000000));
    printf("  DAI/ETH price: %llu.%06llu\n\n",
           (unsigned long long)(dai_price / 1000000),
           (unsigned long long)(dai_price % 1000000));

    printf("[STEP 3] Swap 1 ETH -> DAI (0.3%% fee)...\n");
    AMMSwapResult swap1 = amm_swap(&pool, 1000000000000000000ULL, true, 50);
    printf("  Input:  1.000000 ETH\n");
    printf("  Output: %llu.%06llu DAI\n",
           (unsigned long long)(swap1.output_amount / 1000000),
           (unsigned long long)(swap1.output_amount % 1000000));
    printf("  Fee:    %llu.%06llu ETH\n",
           (unsigned long long)(swap1.fee_amount / 1000000000000000000ULL),
           (unsigned long long)(swap1.fee_amount % 1000000000000000000ULL));
    printf("  Impact: %llu.%02llu%%\n\n",
           (unsigned long long)(swap1.price_impact_bps / 100),
           (unsigned long long)(swap1.price_impact_bps % 100));

    printf("[STEP 4] Swap 10000 DAI -> ETH...\n");
    AMMSwapResult swap2 = amm_swap(&pool, 10000000000000ULL, false, 50);
    printf("  Input:  10000.000000 DAI\n");
    printf("  Output: %llu.%06llu ETH\n",
           (unsigned long long)(swap2.output_amount / 1000000000000000000ULL),
           (unsigned long long)(swap2.output_amount % 1000000000000000000ULL));
    printf("  Impact: %llu.%02llu%%\n\n",
           (unsigned long long)(swap2.price_impact_bps / 100),
           (unsigned long long)(swap2.price_impact_bps % 100));

    printf("[STEP 5] Price impact analysis for different sizes...\n");
    printf("  %-14s %-14s %s\n", "Trade Size", "Price Impact", "Slippage");
    printf("  %-14s %-14s %s\n", "----------", "------------", "--------");
    uint64_t sizes[] = {
        100000000000000000ULL,
        500000000000000000ULL,
        1000000000000000000ULL,
        5000000000000000000ULL,
        10000000000000000000ULL,
        50000000000000000000ULL
    };
    for (int i = 0; i < 6; i++) {
        AMMPool temp = pool;
        uint64_t reserve0_before = temp.reserve0;
        uint64_t reserve1_before = temp.reserve1;
        AMMSwapResult r = amm_swap(&temp, sizes[i], true, 50);
        char size_label[32];
        double eth = (double)sizes[i] / 1e18;
        if (eth >= 1.0) {
            sprintf(size_label, "%.2f ETH", eth);
        } else {
            sprintf(size_label, "%.4f ETH", eth);
        }
        printf("  %-14s %llu.%02llu%%        %llu.%06llu DAI\n",
               size_label,
               (unsigned long long)(r.price_impact_bps / 100),
               (unsigned long long)(r.price_impact_bps % 100),
               (unsigned long long)(r.output_amount / 1000000),
               (unsigned long long)(r.output_amount % 1000000));
        (void)reserve0_before;
        (void)reserve1_before;
    }
    printf("\n");

    printf("[STEP 6] Add liquidity (proportional)...\n");
    AMMPool liq_pool;
    amm_pool_init(&liq_pool, 100000000000000000000ULL, 200000000000ULL, AMM_FEE_BPS);
    AMMLiquidityResult lr = amm_add_liquidity(&liq_pool,
        1000000000000000000ULL,
        2000000000ULL,
        0, 0);
    printf("  Added: %llu.%06llu ETH, %llu.%06llu DAI\n",
           (unsigned long long)(lr.amount0 / 1000000000000000000ULL),
           (unsigned long long)(lr.amount0 % 1000000000000000000ULL),
           (unsigned long long)(lr.amount1 / 1000000),
           (unsigned long long)(lr.amount1 % 1000000));
    printf("  LP tokens minted: %llu\n\n",
           (unsigned long long)lr.lp_tokens);

    printf("[STEP 7] Remove liquidity (50%% of LP)...\n");
    uint64_t removed = amm_remove_liquidity(&liq_pool, lr.lp_tokens / 2);
    printf("  Redeemed value: %llu (in underlying units)\n\n",
           (unsigned long long)removed);

    printf("[STEP 8] Multi-hop swap: USDC -> ETH -> DAI...\n");
    AMMPool hop_pools[2];
    amm_pool_init(&hop_pools[0], 1000000000000ULL, 100000000000000000000ULL, AMM_FEE_BPS);
    amm_pool_init(&hop_pools[1], 100000000000000000000ULL, 200000000000ULL, AMM_FEE_BPS);
    printf("  Pool 1 (USDC/ETH): reserve0=%llu USDC, reserve1=%llu ETH\n",
           (unsigned long long)hop_pools[0].reserve0,
           (unsigned long long)hop_pools[0].reserve1);
    printf("  Pool 2 (ETH/DAI):  reserve0=%llu ETH,  reserve1=%llu DAI\n",
           (unsigned long long)hop_pools[1].reserve0,
           (unsigned long long)hop_pools[1].reserve1);

    AMMSwapResult mh = amm_multihop_swap(hop_pools, 2,
                                         100000000ULL, 100);
    printf("  Input:  100 USDC\n");
    printf("  Output: %llu.%06llu DAI\n",
           (unsigned long long)(mh.output_amount / 1000000),
           (unsigned long long)(mh.output_amount % 1000000));
    printf("  Total fee: %llu.%06llu USDC\n",
           (unsigned long long)(mh.fee_amount / 1000000),
           (unsigned long long)(mh.fee_amount % 1000000));
    printf("  Total impact: %llu.%02llu%%\n\n",
           (unsigned long long)(mh.price_impact_bps / 100),
           (unsigned long long)(mh.price_impact_bps % 100));

    printf("[STEP 9] TWAP Oracle...\n");
    AMMTWAPOracle oracle;
    amm_twap_init(&oracle);
    for (int i = 0; i < 8; i++) {
        amm_twap_update(&oracle, &pool);
    }
    uint64_t twap = amm_twap_get(&oracle, 3600);
    printf("  TWAP (1h): %llu.%06llu\n\n",
           (unsigned long long)(twap / 1000000),
           (unsigned long long)(twap % 1000000));

    printf("[STEP 10] V3 Concentrated Liquidity...\n");
    AMMV3Pool v3_pool;
    amm_v3_pool_init(&v3_pool, 79228162514264337593543950336ULL, 60);
    printf("  V3 pool: sqrtPriceX96=%llu, tick=%d\n",
           (unsigned long long)v3_pool.sqrt_price_x96, v3_pool.current_tick);

    uint64_t v3_out = amm_v3_swap(&v3_pool, 1000000000000000000ULL, true);
    printf("  V3 Swap (1 ETH in): %llu out\n",
           (unsigned long long)v3_out);

    uint64_t v3_liq = amm_v3_add_liquidity(&v3_pool, 1000, 2000,
                                           1000000000000000000ULL,
                                           2000000000ULL);
    printf("  V3 LP added: %llu liquidity units\n\n",
           (unsigned long long)v3_liq);

    printf("========================================================\n");
    printf("  AMM Demo Complete\n");
    printf("========================================================\n");
    return 0;
}
