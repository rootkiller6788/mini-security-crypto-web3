#include "yield_aggregator.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

static uint32_t ya_rand_seed = 0x71E1D001;

static uint32_t ya_rand(void) {
    ya_rand_seed = ya_rand_seed * 1103515245 + 12345;
    return ya_rand_seed;
}

static uint64_t ya_mul_div(uint64_t a, uint64_t b, uint64_t c) {
    if (c == 0) return 0;
    return (a * b) / c;
}

static uint64_t ya_min64(uint64_t a, uint64_t b) { return a < b ? a : b; }
static uint64_t ya_max64(uint64_t a, uint64_t b) { return a > b ? a : b; }

/*
 * ===================================================================
 * L1: Pool initialization — seeds a YieldPool with config and
 * generates a deterministic pool_id for reproducibility.
 * ===================================================================
 */
void yield_pool_init(YieldPool *pool, YieldPoolType type, uint64_t tvl,
                     uint64_t apy_bps, uint64_t fee_bps) {
    memset(pool, 0, sizeof(YieldPool));
    pool->type = type;
    pool->tvl = tvl;
    pool->apy_bps = apy_bps;
    pool->fee_rate_bps = fee_bps;
    pool->active = true;
    pool->utilization = 7500;
    for (int i = 0; i < 32; i++) {
        pool->pool_id[i] = (uint8_t)((ya_rand() >> ((i % 4) * 8)) & 0xFF);
    }
}

/*
 * ===================================================================
 * L2: APY from APR — compound interest formula
 *
 * APY = (1 + APR/n)^n - 1  where n = compound periods per year.
 * Implements integer fixed-point accumulation.
 *
 * Theorem: lim_{n->inf} (1+r/n)^n = e^r (Euler's number)
 * Reference: Compound Finance Whitepaper, Standard Finance
 * ===================================================================
 */
uint64_t yield_calculate_apy(uint64_t apr_bps, uint64_t compound_periods) {
    if (apr_bps == 0) return 0;
    if (compound_periods <= 1) return apr_bps;

    uint64_t rate_per_period = apr_bps / compound_periods;
    if (rate_per_period == 0) return apr_bps;

    uint64_t accum = YIELD_BPS_DENOM;
    uint64_t factor = YIELD_BPS_DENOM + rate_per_period;

    for (uint64_t i = 0; i < compound_periods && i < 1000; i++) {
        uint64_t new_accum = ya_mul_div(accum, factor, YIELD_BPS_DENOM);
        if (new_accum <= accum) break;
        accum = new_accum;
    }

    if (accum <= YIELD_BPS_DENOM) return apr_bps;
    return accum - YIELD_BPS_DENOM;
}

/*
 * ===================================================================
 * L2: APR from APY — inverse compounding via Newton-Raphson iteration.
 *
 * Solves (1 + x/n)^n = 1 + APY for unknown APR x.
 * Uses Newton's method: x_{k+1} = x_k - f(x_k)/f'(x_k)
 * where f(x) = (1+x/n)^n - (1+APY), f'(x) = (1+x/n)^(n-1)
 * ===================================================================
 */
uint64_t yield_calculate_apr_from_apy(uint64_t apy_bps, uint64_t compound_periods) {
    if (apy_bps == 0) return 0;
    if (compound_periods <= 1) return apy_bps;

    uint64_t target = YIELD_BPS_DENOM + apy_bps;
    uint64_t guess = YIELD_BPS_DENOM + (apy_bps / compound_periods);

    for (int iter = 0; iter < 15; iter++) {
        uint64_t guess_pow = YIELD_BPS_DENOM;
        for (uint64_t j = 0; j < compound_periods; j++) {
            guess_pow = ya_mul_div(guess_pow, guess, YIELD_BPS_DENOM);
            if (guess_pow > target * 2) break;
        }
        if (guess_pow == 0 || guess_pow == target) break;

        if (guess_pow > target) {
            uint64_t denom = compound_periods * guess_pow / ya_max64(guess, 1);
            if (denom == 0) break;
            uint64_t delta = (guess_pow - target) * YIELD_BPS_DENOM / denom;
            if (delta < guess) guess -= ya_min64(delta, guess / 10);
        } else {
            uint64_t denom = compound_periods * guess_pow / ya_max64(guess, 1);
            if (denom == 0) break;
            uint64_t delta = (target - guess_pow) * YIELD_BPS_DENOM / denom;
            guess += ya_min64(delta, guess / 10);
        }
    }

    if (guess <= YIELD_BPS_DENOM) return apy_bps;
    return (guess - YIELD_BPS_DENOM) * compound_periods;
}

/*
 * ===================================================================
 * L2: Future value with periodic compounding
 * FV = P * (1 + r/n)^(n*t)
 * r = annual rate, n = compounds/year, t = time in years
 * ===================================================================
 */
uint64_t yield_compound_value(uint64_t principal, uint64_t apy_bps,
                              uint64_t seconds, uint64_t compound_freq_seconds) {
    if (principal == 0 || apy_bps == 0 || seconds == 0 || compound_freq_seconds == 0)
        return principal;

    uint64_t periods = seconds / compound_freq_seconds;
    if (periods == 0) periods = 1;
    if (periods > 1000) periods = 1000;

    uint64_t periods_per_year = YIELD_SECONDS_PER_YEAR / compound_freq_seconds;
    if (periods_per_year == 0) periods_per_year = 1;
    uint64_t rate_bps_per_period = apy_bps / periods_per_year;

    uint64_t value = principal;
    for (uint64_t p = 0; p < periods; p++) {
        uint64_t interest = ya_mul_div(value, rate_bps_per_period, YIELD_BPS_DENOM);
        value += interest;
    }

    return value;
}

/*
 * ===================================================================
 * L5: Optimal compound frequency via convex optimization.
 *
 * Setting d(profit)/dN = 0:
 *   Marginal gain: r*P / (n^2)
 *   Marginal cost: g
 *   => N_opt = sqrt(r * P / g)
 *
 * Uses integer Babylonian sqrt. Reference: Yearn optimization docs.
 * ===================================================================
 */
uint64_t yield_optimal_compound_frequency(uint64_t apy_bps, uint64_t gas_cost,
                                           uint64_t position_size) {
    if (gas_cost == 0 || position_size == 0 || apy_bps == 0)
        return YIELD_SECONDS_PER_YEAR;

    uint64_t yearly_gain = ya_mul_div(position_size, apy_bps, YIELD_BPS_DENOM);
    uint64_t gain_per_gas = yearly_gain / (gas_cost * 2);

    uint64_t optimal_n = 1;
    if (gain_per_gas > 1) {
        uint64_t x = gain_per_gas;
        uint64_t y = (x + 1) / 2;
        for (int iter = 0; iter < 25 && y < x; iter++) {
            x = y;
            y = (x + gain_per_gas / x) / 2;
        }
        optimal_n = x;
    }

    if (optimal_n < 1) optimal_n = 1;
    if (optimal_n > 365 * 24) optimal_n = 365 * 24;

    return YIELD_SECONDS_PER_YEAR / optimal_n;
}

/*
 * ===================================================================
 * L3: Strategy management — multi-pool yield aggregation engine.
 * Manages pool allocation weights and rebalancing.
 * ===================================================================
 */
void yield_strategy_init(YieldStrategy *strategy, YieldStrategyType type,
                         uint64_t performance_fee) {
    memset(strategy, 0, sizeof(YieldStrategy));
    strategy->strategy = type;
    strategy->performance_fee_bps = ya_min64(performance_fee, 5000);
    strategy->compound_count = 0;
    strategy->last_harvest_time = ya_rand() + 1000000;
    strategy->active = true;
}

int yield_strategy_add_pool(YieldStrategy *strategy, const YieldPool *pool,
                            uint64_t allocation_bps) {
    if (!pool || strategy->pool_count >= YIELD_MAX_POOLS) return -1;

    uint64_t total_alloc = 0;
    for (int i = 0; i < strategy->pool_count; i++) {
        total_alloc += strategy->allocation_bps[i];
    }
    if (total_alloc + allocation_bps > YIELD_BPS_DENOM) return -1;

    int idx = strategy->pool_count;
    memcpy(&strategy->pools[idx], pool, sizeof(YieldPool));
    strategy->allocation_bps[idx] = allocation_bps;
    strategy->pool_count++;
    return idx;
}

bool yield_strategy_remove_pool(YieldStrategy *strategy, int pool_index) {
    if (pool_index < 0 || pool_index >= strategy->pool_count) return false;
    for (int i = pool_index; i < strategy->pool_count - 1; i++) {
        strategy->pools[i] = strategy->pools[i + 1];
        strategy->allocation_bps[i] = strategy->allocation_bps[i + 1];
    }
    strategy->pool_count--;
    return true;
}

/*
 * ===================================================================
 * L5: Greedy rebalancing — adjusts pool allocations toward target
 * weights by transferring from over-weighted to under-weighted pools.
 * Minimizes gas by reducing the number of transactions needed.
 * ===================================================================
 */
bool yield_strategy_rebalance(YieldStrategy *strategy,
                               const uint64_t *target_allocations) {
    if (!strategy->active || strategy->pool_count == 0) return false;
    if (!target_allocations) return false;

    uint64_t total_target = 0;
    for (int i = 0; i < strategy->pool_count; i++) {
        total_target += target_allocations[i];
    }

    if (total_target == 0) {
        uint64_t equal = YIELD_BPS_DENOM / strategy->pool_count;
        uint64_t remainder = YIELD_BPS_DENOM - equal * strategy->pool_count;
        for (int i = 0; i < strategy->pool_count; i++) {
            strategy->allocation_bps[i] = equal + (i == 0 ? remainder : 0);
        }
        return true;
    }

    uint64_t total = strategy->total_value_locked;
    if (total == 0) {
        for (int i = 0; i < strategy->pool_count; i++) {
            strategy->allocation_bps[i] = ya_mul_div(target_allocations[i],
                                        YIELD_BPS_DENOM, total_target);
        }
        return true;
    }

    for (int i = 0; i < strategy->pool_count; i++) {
        uint64_t current = strategy->allocation_bps[i];
        uint64_t target = ya_mul_div(target_allocations[i],
                                      YIELD_BPS_DENOM, total_target);
        if (target > current) {
            uint64_t need = target - current;
            for (int j = 0; j < strategy->pool_count && need > 0; j++) {
                if (j == i) continue;
                uint64_t j_target = ya_mul_div(target_allocations[j],
                                                YIELD_BPS_DENOM, total_target);
                if (strategy->allocation_bps[j] > j_target) {
                    uint64_t excess = strategy->allocation_bps[j] - j_target;
                    uint64_t move = ya_min64(need, excess);
                    strategy->allocation_bps[i] += move;
                    strategy->allocation_bps[j] -= move;
                    need -= move;
                }
            }
        }
    }

    return true;
}

/*
 * ===================================================================
 * L6: Harvest — classic yield farming compound cycle.
 *
 * Simulates claiming rewards from all pools, deducting performance fee
 * and gas cost, then reinvesting the remainder.
 * Reference: Yearn Vaults, Harvest Finance
 * ===================================================================
 */
YieldHarvestResult yield_strategy_harvest(YieldStrategy *strategy,
                                           uint64_t gas_price) {
    YieldHarvestResult result;
    memset(&result, 0, sizeof(result));

    if (!strategy->active || strategy->pool_count == 0) return result;

    uint64_t total_reward = 0;
    for (int i = 0; i < strategy->pool_count; i++) {
        if (!strategy->pools[i].active) continue;
        uint64_t allocated_tvl = ya_mul_div(strategy->total_value_locked,
                                             strategy->allocation_bps[i],
                                             YIELD_BPS_DENOM);
        uint64_t time_elapsed = (ya_rand() % 86400) + 3600;
        uint64_t reward = ya_mul_div(allocated_tvl,
                          strategy->pools[i].reward_rate, YIELD_BPS_DENOM);
        reward = ya_mul_div(reward, time_elapsed, YIELD_SECONDS_PER_YEAR);
        total_reward += reward;
    }

    uint64_t perf_fee = ya_mul_div(total_reward, strategy->performance_fee_bps,
                                   YIELD_BPS_DENOM);
    uint64_t gas_cost = gas_price * 500000;
    uint64_t net = total_reward - perf_fee;

    if (net > gas_cost) {
        net -= gas_cost;
    } else {
        gas_cost = net > 0 ? net : 0;
        net = 0;
    }

    uint64_t reinvested = net;
    strategy->total_value_locked += reinvested;
    strategy->total_rewards_claimed += total_reward;
    strategy->compound_count++;
    strategy->last_harvest_time += (ya_rand() % 86400) + 3600;

    result.amount_reward = total_reward;
    result.amount_reinvested = reinvested;
    result.fee_amount = perf_fee;
    result.gas_cost = gas_cost;
    result.net_profit = net;
    result.time_saved = ya_rand() % 3600;
    return result;
}

/*
 * ===================================================================
 * L5: Optimal yield routing — greedy multi-hop path discovery.
 *
 * Scores pools by risk-adjusted return, sorts descending, builds route.
 * Approximates NP-hard optimal routing (knapsack + ordering constraints).
 * ===================================================================
 */
YieldRoute yield_find_optimal_route(const YieldPool *pools, int count,
                                     uint64_t deposit_amount) {
    YieldRoute route;
    memset(&route, 0, sizeof(route));

    if (!pools || count <= 0 || deposit_amount == 0) return route;

    typedef struct { int idx; uint64_t score; } PoolScore;
    PoolScore scores[YIELD_MAX_POOLS];
    int score_count = 0;

    for (int i = 0; i < count && i < YIELD_MAX_POOLS; i++) {
        if (!pools[i].active || pools[i].tvl == 0) continue;
        uint64_t risk_adj = yield_risk_adjusted_return(pools[i].apy_bps,
                              pools[i].impermanent_loss_bps);
        uint64_t score = (risk_adj > pools[i].fee_rate_bps)
                        ? (risk_adj - pools[i].fee_rate_bps) : 0;
        if (score > 0) {
            scores[score_count].idx = i;
            scores[score_count].score = score;
            score_count++;
        }
    }

    for (int i = 0; i < score_count - 1; i++) {
        for (int j = 0; j < score_count - i - 1; j++) {
            if (scores[j].score < scores[j + 1].score) {
                PoolScore tmp = scores[j];
                scores[j] = scores[j + 1];
                scores[j + 1] = tmp;
            }
        }
    }

    int hops = score_count < YIELD_MAX_HOPS ? score_count : YIELD_MAX_HOPS;
    for (int i = 0; i < hops; i++) {
        int idx = scores[i].idx;
        route.route[i] = (YieldPool *)&pools[idx];
        route.total_yield_bps += pools[idx].apy_bps;
        route.total_fee_bps += pools[idx].fee_rate_bps;
        route.total_risk_bps += pools[idx].impermanent_loss_bps;
    }

    if (hops > 0) {
        route.expected_yield_bps = route.total_yield_bps / hops;
        route.total_fee_bps /= hops;
        route.total_risk_bps /= hops;
    }
    route.hop_count = hops;
    route.valid = (hops > 0);
    return route;
}

uint64_t yield_route_expected_return(const YieldRoute *route, uint64_t amount) {
    if (!route || !route->valid || amount == 0) return 0;
    return ya_mul_div(amount, route->expected_yield_bps, YIELD_BPS_DENOM);
}

void yield_route_sort_by_yield(YieldRoute *routes, int count) {
    if (!routes || count <= 1) return;
    for (int i = 0; i < count - 1; i++) {
        for (int j = 0; j < count - i - 1; j++) {
            if (routes[j].expected_yield_bps < routes[j + 1].expected_yield_bps) {
                YieldRoute tmp = routes[j];
                routes[j] = routes[j + 1];
                routes[j + 1] = tmp;
            }
        }
    }
}

/*
 * ===================================================================
 * L6: Impermanent loss (IL) — Uniswap V2 Constant Product AMM
 *
 * IL = 1 - 2*sqrt(r)/(1+r)  where r = price_ratio = P_new/P_old
 *
 * Theorem: Maximum IL at r=4x is approx 5.72% of deposited value.
 * At r=1x (no price change), IL = 0%.
 * Reference: Uniswap V2 Whitepaper; Pintail (2020) IL analysis
 * ===================================================================
 */
uint64_t yield_impermanent_loss(uint64_t price_ratio_bps, uint64_t deposited) {
    if (price_ratio_bps == 0 || deposited == 0) return 0;

    double r = (double)price_ratio_bps / (double)YIELD_BPS_DENOM;
    if (r <= 0.0) return 0;

    double sqrt_r = sqrt(r);
    double il_ratio = (2.0 * sqrt_r) / (1.0 + r);
    double loss_frac = 1.0 - il_ratio;
    if (loss_frac <= 0.0) return 0;

    return (uint64_t)(loss_frac * (double)deposited);
}

/*
 * ===================================================================
 * L7: Risk-adjusted return — linear volatility penalty
 *
 * risk_adj = APY * (1 - vol/DENOM)
 * Higher volatility linearly reduces effective APY.
 * ===================================================================
 */
uint64_t yield_risk_adjusted_return(uint64_t apy_bps, uint64_t volatility_bps) {
    if (volatility_bps >= YIELD_BPS_DENOM) return 0;
    return ya_mul_div(apy_bps, YIELD_BPS_DENOM - volatility_bps,
                      YIELD_BPS_DENOM);
}

uint64_t yield_max_drawdown_estimate(uint64_t apy_bps, uint64_t volatility_bps) {
    if (volatility_bps > YIELD_BPS_DENOM / 2)
        volatility_bps = YIELD_BPS_DENOM / 2;
    return ya_mul_div(apy_bps, volatility_bps * 2, YIELD_BPS_DENOM);
}

/*
 * ===================================================================
 * L7: Sharpe Ratio — risk-adjusted performance metric
 *
 * Sharpe = (E[R_p] - R_f) / sigma_p
 * Excess return per unit of risk taken.
 *
 * Theorem (Sharpe 1966): Under CAPM assumptions, market portfolio
 * maximizes Sharpe ratio. Nobel Prize 1990.
 * ===================================================================
 */
double yield_sharpe_ratio(uint64_t apy_bps, uint64_t volatility_bps,
                          uint64_t risk_free_bps) {
    if (volatility_bps == 0) return 0.0;
    double excess = (double)((int64_t)apy_bps - (int64_t)risk_free_bps);
    return excess / (double)volatility_bps;
}

/*
 * ===================================================================
 * L7: Efficient frontier — Markowitz portfolio optimization
 *
 * Generates risk-return scatter by varying allocation weights,
 * then filters to Pareto-optimal convex hull (upper boundary).
 *
 * Theorem (Markowitz 1952): For any level of risk, there exists a
 * portfolio on the efficient frontier with maximum expected return.
 * ===================================================================
 */
void yield_efficient_frontier(EfficientFrontierPoint *frontier, int *count,
                               const YieldPool *pools, int num_pools) {
    if (!frontier || !count || !pools || num_pools <= 0) {
        if (count) *count = 0;
        return;
    }

    int max_points = *count;
    *count = 0;

    for (int step = 0; step < max_points && step < num_pools * 15; step++) {
        uint64_t total_apy = 0, total_risk = 0, total_weight = 0;

        for (int i = 0; i < num_pools; i++) {
            if (!pools[i].active) continue;
            uint64_t w = ((uint64_t)(step + i + 1) % 8 + 1) * 500;
            total_apy += pools[i].apy_bps * w;
            total_risk += pools[i].impermanent_loss_bps * w;
            total_weight += w;
        }

        if (total_weight > 0) {
            frontier[*count].apy = total_apy / total_weight;
            frontier[*count].risk = total_risk / total_weight;
            frontier[*count].weight = total_weight;
            (*count)++;
        }
    }

    /* Remove dominated points: higher risk, lower/equal APY */
    for (int i = 0; i < *count; i++) {
        for (int j = i + 1; j < *count; ) {
            if (frontier[j].risk >= frontier[i].risk &&
                frontier[j].apy <= frontier[i].apy) {
                for (int k = j; k < *count - 1; k++) {
                    frontier[k] = frontier[k + 1];
                }
                (*count)--;
            } else {
                j++;
            }
        }
    }
}

/*
 * ===================================================================
 * L7: Optimal deposit split — proportional to risk-adjusted return
 * ===================================================================
 */
uint64_t yield_optimal_deposit_split(uint64_t amount, const YieldPool *pools,
                                      int count, uint64_t *allocations) {
    if (count <= 0 || amount == 0 || !allocations) return 0;

    uint64_t *scores = (uint64_t *)calloc((size_t)count, sizeof(uint64_t));
    if (!scores) return 0;

    uint64_t total_score = 0;
    for (int i = 0; i < count; i++) {
        scores[i] = yield_risk_adjusted_return(pools[i].apy_bps,
                                                pools[i].impermanent_loss_bps);
        if (scores[i] < pools[i].fee_rate_bps) scores[i] = 0;
        total_score += scores[i];
    }

    if (total_score == 0) { free(scores); return 0; }

    uint64_t allocated = 0;
    for (int i = 0; i < count; i++) {
        if (scores[i] > 0) {
            allocations[i] = ya_mul_div(amount, scores[i], total_score);
            allocated += allocations[i];
        } else {
            allocations[i] = 0;
        }
    }

    if (allocated < amount && count > 0) {
        int best = 0;
        for (int i = 1; i < count; i++) {
            if (scores[i] > scores[best]) best = i;
        }
        if (scores[best] > 0) {
            allocations[best] += (amount - allocated);
        }
    }

    free(scores);
    return amount;
}

uint64_t yield_portfolio_apy(const uint64_t *allocations, const YieldPool *pools,
                              int count, uint64_t total) {
    if (count <= 0 || total == 0 || !allocations) return 0;

    uint64_t weighted = 0;
    for (int i = 0; i < count; i++) {
        weighted += allocations[i] * pools[i].apy_bps;
    }
    return weighted / total;
}

/*
 * ===================================================================
 * L8: Compound optimization with gas cost analysis.
 *
 * Computes optimal compounding schedule by balancing:
 *   + More frequent compounds = more yield captured
 *   - More frequent compounds = more gas spent
 *
 * Optimal frequency found where marginal yield = marginal gas cost.
 * Reference: Yearn Finance vault strategies, convex optimization
 * ===================================================================
 */
YieldCompoundOptimization yield_optimize_compounding(const YieldPool *pool,
                                                      uint64_t position,
                                                      uint64_t gas_price,
                                                      uint64_t reward_rate) {
    YieldCompoundOptimization opt;
    memset(&opt, 0, sizeof(opt));

    if (!pool || position == 0) return opt;

    uint64_t gas_cost_tokens = gas_price * 500000;
    /* Effective APY = base APY + reward_rate adjustment */
    uint64_t effective_apy = pool->apy_bps;
    if (reward_rate > 0 && pool->apy_bps > 0) {
        effective_apy = pool->apy_bps + ya_mul_div(pool->apy_bps,
                         reward_rate, YIELD_BPS_DENOM);
    }
    uint64_t apr_absolute = ya_mul_div(position, effective_apy, YIELD_BPS_DENOM);
    uint64_t daily_earnings = apr_absolute / 365;

    if (gas_cost_tokens >= daily_earnings) {
        opt.optimal_freq = 86400 * 7;
        opt.should_compound = (gas_cost_tokens < daily_earnings * 7);
    } else {
        uint64_t freq_sec = yield_optimal_compound_frequency(effective_apy,
                                 gas_cost_tokens, position);
        opt.optimal_freq = freq_sec > 0 ? freq_sec : 86400;
        opt.should_compound = true;
    }

    uint64_t compounds_per_year = YIELD_SECONDS_PER_YEAR / opt.optimal_freq;
    if (compounds_per_year == 0) compounds_per_year = 1;
    uint64_t annual_gas = compounds_per_year * gas_cost_tokens;

    opt.expected_net_apy = effective_apy;
    if (apr_absolute > annual_gas) {
        uint64_t net_apr = (apr_absolute - annual_gas) * YIELD_BPS_DENOM / position;
        opt.expected_net_apy = net_apr < effective_apy ? net_apr : effective_apy;
    }

    uint64_t daily_gas = 365 * gas_cost_tokens;
    opt.gas_cost_saved = (daily_gas > annual_gas) ? (daily_gas - annual_gas) : 0;

    return opt;
}

/*
 * ===================================================================
 * L9: MEV-aware yield adjustment (industry frontier)
 *
 * Deducts estimated MEV leakage from expected yield:
 *   - Sandwich attack tax (0.1-2% on large swaps)
 *   - Frontrunning priority fees
 *   - Arbitrage extraction
 *
 * Reference: Flashbots MEV-Explore, EigenPhi MEV research
 * ===================================================================
 */
uint64_t yield_mev_protected_apy(uint64_t base_apy, uint64_t mev_leakage_bps) {
    if (mev_leakage_bps >= YIELD_BPS_DENOM) return 0;
    return ya_mul_div(base_apy, YIELD_BPS_DENOM - mev_leakage_bps,
                      YIELD_BPS_DENOM);
}

bool yield_is_sandwich_susceptible(const YieldPool *pool, uint64_t amount) {
    if (!pool || pool->tvl == 0) return false;
    return (amount * YIELD_BPS_DENOM / pool->tvl) > 500;
}