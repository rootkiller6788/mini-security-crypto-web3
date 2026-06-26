#include "lending_proto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t lending_rand_seed = 0xCAFEBABE;

static uint32_t lending_rand(void) {
    lending_rand_seed = lending_rand_seed * 1103515245 + 12345;
    return lending_rand_seed;
}

void lending_market_init(LendingMarket *market, uint64_t base_rate,
                         uint64_t kink_rate, uint64_t max_rate,
                         uint64_t kink_util, uint64_t reserve_factor) {
    memset(market, 0, sizeof(LendingMarket));
    market->ir_params.model = LENDING_UTILIZATION_KINK;
    market->ir_params.base_rate_bps = base_rate > 0 ? base_rate : 200;
    market->ir_params.kink_rate_bps = kink_rate > 0 ? kink_rate : 3000;
    market->ir_params.max_rate_bps = max_rate > 0 ? max_rate : 15000;
    market->ir_params.kink_utilization_bps = kink_util > 0 ? kink_util : 8000;
    market->reserve_factor_bps = reserve_factor > 0 ? reserve_factor : 1000;
    market->borrow_index = LENDING_KINK_PRECISION;
    market->supply_index = LENDING_KINK_PRECISION;
    market->last_update = 1000000;
}

uint64_t lending_utilization_rate(const LendingMarket *market) {
    if (market->total_deposits == 0) return 0;
    return (market->total_borrows * LENDING_BPS_DENOM) / market->total_deposits;
}

uint64_t lending_borrow_rate(const LendingMarket *market) {
    uint64_t util = lending_utilization_rate(market);
    const LendingIRParams *p = &market->ir_params;

    if (util <= p->kink_utilization_bps) {
        return p->base_rate_bps +
               (p->kink_rate_bps - p->base_rate_bps) * util
               / p->kink_utilization_bps;
    } else {
        uint64_t extra_util = util - p->kink_utilization_bps;
        uint64_t gap = LENDING_BPS_DENOM - p->kink_utilization_bps;
        return p->kink_rate_bps +
               (p->max_rate_bps - p->kink_rate_bps) * extra_util / gap;
    }
}

uint64_t lending_supply_rate(const LendingMarket *market) {
    uint64_t borrow = lending_borrow_rate(market);
    uint64_t util = lending_utilization_rate(market);
    uint64_t rate = borrow * util / LENDING_BPS_DENOM;
    uint64_t reserve_part = rate * market->reserve_factor_bps / LENDING_BPS_DENOM;
    return rate - reserve_part;
}

uint64_t lending_deposit(LendingAccount *account, LendingMarket *market,
                         uint64_t amount) {
    if (amount == 0) return 0;

    lending_accrue_interest(market, market->last_update + (lending_rand() % 3600));

    uint64_t rate = lending_exchange_rate(market);
    uint64_t ctokens = (amount * LENDING_KINK_PRECISION) / rate;

    account->ctoken_balance += ctokens;
    account->principal += amount;
    account->interest_index = market->supply_index;
    market->total_deposits += amount;

    return ctokens;
}

uint64_t lending_redeem(LendingAccount *account, LendingMarket *market,
                        uint64_t ctoken_amount) {
    if (ctoken_amount == 0 || ctoken_amount > account->ctoken_balance) return 0;

    lending_accrue_interest(market, market->last_update + (lending_rand() % 3600));

    uint64_t rate = lending_exchange_rate(market);
    uint64_t underlying = (ctoken_amount * rate) / LENDING_KINK_PRECISION;

    if (underlying > market->total_deposits) {
        underlying = market->total_deposits;
    }

    account->ctoken_balance -= ctoken_amount;
    market->total_deposits -= underlying;

    return underlying;
}

uint64_t lending_borrow(LendingAccount *account, LendingMarket *market,
                        uint64_t amount, uint64_t collateral_value) {
    if (amount == 0) return 0;

    lending_accrue_interest(market, market->last_update + (lending_rand() % 3600));

    uint64_t new_borrows = market->total_borrows + amount;
    if (new_borrows > market->total_deposits) return 0;

    uint64_t max_borrow = lending_max_borrow(collateral_value, LENDING_MAX_LTV_BPS);
    uint64_t current_borrow = account->principal;
    if (current_borrow + amount > max_borrow) return 0;

    account->principal += amount;
    market->total_borrows += amount;

    return amount;
}

uint64_t lending_repay(LendingAccount *account, LendingMarket *market,
                       uint64_t amount) {
    if (amount == 0 || account->principal == 0) return 0;

    lending_accrue_interest(market, market->last_update + (lending_rand() % 3600));

    uint64_t repay = amount > account->principal ? account->principal : amount;
    account->principal -= repay;
    market->total_borrows -= repay;

    return repay;
}

void lending_accrue_interest(LendingMarket *market, uint64_t current_time) {
    if (current_time <= market->last_update) return;
    if (market->total_borrows == 0) {
        market->last_update = current_time;
        return;
    }

    uint64_t elapsed = current_time - market->last_update;
    uint64_t borrow_rate_per_sec = lending_borrow_rate(market) / (365 * 86400);

    uint64_t interest_factor = borrow_rate_per_sec * elapsed;
    uint64_t new_borrow_index = market->borrow_index
        + (market->borrow_index * interest_factor / LENDING_BPS_DENOM);

    uint64_t reserve_growth = (new_borrow_index - market->borrow_index)
        * market->total_borrows * market->reserve_factor_bps
        / (LENDING_BPS_DENOM * LENDING_KINK_PRECISION);

    market->total_reserves += reserve_growth;
    market->borrow_index = new_borrow_index;
    market->supply_index = market->borrow_index;
    market->last_update = current_time;
}

LendingHealth lending_get_health(LendingAccount *account, LendingMarket *market,
                                  uint64_t borrow_value, uint64_t collateral_value,
                                  uint64_t ltv_bps, uint64_t liquidation_threshold_bps) {
    LendingHealth health;
    memset(&health, 0, sizeof(health));
    health.borrow_value = borrow_value;
    health.collateral_value = collateral_value;
    health.borrow_limit = collateral_value * ltv_bps / LENDING_BPS_DENOM;

    if (borrow_value == 0) {
        health.health_factor_bps = LENDING_BPS_DENOM * 10;
    } else {
        uint64_t threshold = collateral_value * liquidation_threshold_bps
                             / LENDING_BPS_DENOM;
        health.health_factor_bps = (threshold * LENDING_BPS_DENOM) / borrow_value;
    }
    (void)account;
    (void)market;
    return health;
}

LendingLiquidation lending_liquidate(LendingAccount *liquidator,
                                      LendingAccount *borrower,
                                      LendingMarket *market,
                                      uint64_t repay_amount, uint64_t price) {
    LendingLiquidation result;
    memset(&result, 0, sizeof(result));

    uint64_t max_repay = borrower->principal / 2;
    uint64_t actual_repay = repay_amount > max_repay ? max_repay : repay_amount;

    uint64_t collateral_seized = actual_repay * LENDING_BPS_DENOM / price;
    uint64_t bonus = collateral_seized * LENDING_LIQUIDATION_BONUS_BPS
                     / LENDING_BPS_DENOM;
    uint64_t total_seized = collateral_seized + bonus;

    borrower->principal -= actual_repay;
    market->total_borrows -= actual_repay;
    if (borrower->principal > 0 && borrower->ctoken_balance > total_seized) {
        borrower->ctoken_balance -= total_seized;
    }

    result.repay_amount = actual_repay;
    result.seize_collateral = total_seized;
    result.bonus_collateral = bonus;
    result.remaining_debt = borrower->principal;

    (void)liquidator;
    return result;
}

LendingFlashLoan lending_flash_loan(LendingMarket *market, uint64_t amount,
                                     uint8_t data[32],
                                     bool (*callback)(uint64_t amount,
                                                      uint64_t fee, uint8_t d[32])) {
    LendingFlashLoan result;
    memset(&result, 0, sizeof(result));

    if (amount > market->total_deposits) return result;

    uint64_t fee = amount * LENDING_FLASH_LOAN_FEE_BPS / LENDING_BPS_DENOM;
    uint64_t total_repay = amount + fee;

    bool success = callback(amount, fee, data);

    if (success) {
        result.amount = amount;
        result.fee = fee;
        result.success = true;
        market->total_deposits += fee;
    }

    memcpy(result.data, data, 32);
    return result;
}

uint64_t lending_exchange_rate(const LendingMarket *market) {
    if (market->total_deposits == 0) return LENDING_KINK_PRECISION;
    uint64_t total = market->total_deposits + market->total_borrows;
    return (total * LENDING_KINK_PRECISION) / market->total_deposits;
}

uint64_t lending_max_borrow(uint64_t collateral_value, uint64_t ltv_bps) {
    return collateral_value * ltv_bps / LENDING_BPS_DENOM;
}
