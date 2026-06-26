#ifndef YIELD_AGGREGATOR_H
#define YIELD_AGGREGATOR_H

#include <stdbool.h>
#include <stdint.h>

#define YIELD_MAX_POOLS          32
#define YIELD_MAX_HOPS           10
#define YIELD_BPS_DENOM          10000
#define YIELD_PRECISION          1000000000ULL
#define YIELD_SECONDS_PER_YEAR   31536000

typedef enum {
    YIELD_STRAT_COMPOUNDING,
    YIELD_STRAT_REBALANCING,
    YIELD_STRAT_DELTA_NEUTRAL,
    YIELD_STRAT_LEVERAGED,
    YIELD_STRAT_AUTO_HARVEST
} YieldStrategyType;

typedef enum {
    YIELD_POOL_LENDING,
    YIELD_POOL_AMM_LP,
    YIELD_POOL_STAKING,
    YIELD_POOL_REWARDS
} YieldPoolType;

typedef struct {
    YieldPoolType type;
    uint64_t tvl;
    uint64_t total_supply;
    uint64_t reward_rate;
    uint64_t apy_bps;
    uint64_t fee_rate_bps;
    uint64_t impermanent_loss_bps;
    uint64_t utilization;
    bool     active;
    uint8_t  pool_id[32];
} YieldPool;

typedef struct {
    YieldStrategyType strategy;
    uint64_t total_value_locked;
    uint64_t total_rewards_claimed;
    uint64_t compound_count;
    uint64_t last_harvest_time;
    uint64_t performance_fee_bps;
    YieldPool pools[YIELD_MAX_POOLS];
    int      pool_count;
    uint64_t allocation_bps[YIELD_MAX_POOLS];
    bool     active;
} YieldStrategy;

typedef struct {
    uint64_t amount_reward;
    uint64_t amount_reinvested;
    uint64_t fee_amount;
    uint64_t gas_cost;
    uint64_t net_profit;
    uint64_t time_saved;
} YieldHarvestResult;

typedef struct {
    uint64_t current_apy_bps;
    uint64_t projected_apy_bps;
    uint64_t total_deposited;
    uint64_t total_yield_earned;
    uint64_t compound_apy_bps;
    uint64_t time_in_pool;
    double   sharpe_ratio;
} YieldPosition;

typedef struct {
    YieldPool *route[YIELD_MAX_HOPS];
    int        hop_count;
    uint64_t   total_yield_bps;
    uint64_t   expected_yield_bps;
    uint64_t   total_fee_bps;
    uint64_t   total_risk_bps;
    bool       valid;
} YieldRoute;

typedef struct {
    uint64_t apy;
    uint64_t risk;
    uint64_t weight;
    uint64_t allocation;
} EfficientFrontierPoint;

typedef struct {
    uint64_t optimal_freq;
    uint64_t expected_net_apy;
    uint64_t gas_cost_saved;
    bool     should_compound;
} YieldCompoundOptimization;

void        yield_pool_init(YieldPool *pool, YieldPoolType type, uint64_t tvl, uint64_t apy_bps, uint64_t fee_bps);
uint64_t    yield_calculate_apy(uint64_t apr_bps, uint64_t compound_periods);
uint64_t    yield_calculate_apr_from_apy(uint64_t apy_bps, uint64_t compound_periods);
uint64_t    yield_compound_value(uint64_t principal, uint64_t apy_bps, uint64_t seconds, uint64_t compound_freq_seconds);
uint64_t    yield_optimal_compound_frequency(uint64_t apy_bps, uint64_t gas_cost, uint64_t position_size);
void        yield_strategy_init(YieldStrategy *strategy, YieldStrategyType type, uint64_t performance_fee);
int         yield_strategy_add_pool(YieldStrategy *strategy, const YieldPool *pool, uint64_t allocation_bps);
bool        yield_strategy_remove_pool(YieldStrategy *strategy, int pool_index);
bool        yield_strategy_rebalance(YieldStrategy *strategy, const uint64_t *target_allocations);
YieldHarvestResult yield_strategy_harvest(YieldStrategy *strategy, uint64_t gas_price);
YieldRoute  yield_find_optimal_route(const YieldPool *pools, int count, uint64_t deposit_amount);
uint64_t    yield_route_expected_return(const YieldRoute *route, uint64_t amount);
void        yield_route_sort_by_yield(YieldRoute *routes, int count);
uint64_t    yield_impermanent_loss(uint64_t price_ratio_bps, uint64_t deposited);
uint64_t    yield_risk_adjusted_return(uint64_t apy_bps, uint64_t volatility_bps);
uint64_t    yield_max_drawdown_estimate(uint64_t apy_bps, uint64_t volatility_bps);
void        yield_efficient_frontier(EfficientFrontierPoint *frontier, int *count, const YieldPool *pools, int num_pools);
uint64_t    yield_optimal_deposit_split(uint64_t amount, const YieldPool *pools, int count, uint64_t *allocations);
double      yield_sharpe_ratio(uint64_t apy_bps, uint64_t volatility_bps, uint64_t risk_free_bps);
uint64_t    yield_portfolio_apy(const uint64_t *allocations, const YieldPool *pools, int count, uint64_t total);
YieldCompoundOptimization yield_optimize_compounding(const YieldPool *pool, uint64_t position, uint64_t gas_price, uint64_t reward_rate);
uint64_t    yield_mev_protected_apy(uint64_t base_apy, uint64_t mev_leakage_bps);
bool        yield_is_sandwich_susceptible(const YieldPool *pool, uint64_t amount);

#endif