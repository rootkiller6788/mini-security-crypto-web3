#ifndef LENDING_PROTO_H
#define LENDING_PROTO_H

#include <stdbool.h>
#include <stdint.h>

#define LENDING_BPS_DENOM        10000
#define LENDING_KINK_PRECISION   1000000
#define LENDING_MAX_LTV_BPS      7500
#define LENDING_LIQUIDATION_BONUS_BPS 800
#define LENDING_LIQUIDATION_THRESHOLD_BPS 8000
#define LENDING_FLASH_LOAN_FEE_BPS 9

typedef enum {
    LENDING_UTILIZATION_LINEAR,
    LENDING_UTILIZATION_KINK
} LendingIRModel;

typedef struct {
    LendingIRModel model;
    uint64_t base_rate_bps;
    uint64_t kink_rate_bps;
    uint64_t max_rate_bps;
    uint64_t kink_utilization_bps;
} LendingIRParams;

typedef struct {
    uint64_t total_deposits;
    uint64_t total_borrows;
    uint64_t total_reserves;
    uint64_t reserve_factor_bps;
    LendingIRParams ir_params;
    uint64_t last_update;
    uint64_t borrow_index;
    uint64_t supply_index;
} LendingMarket;

typedef struct {
    uint64_t ctoken_balance;
    uint64_t principal;
    uint64_t interest_index;
} LendingAccount;

typedef struct {
    uint64_t market_id;
    uint64_t deposited;
    uint64_t borrowed;
    uint64_t last_accrual_index;
} LendingPosition;

typedef struct {
    uint64_t borrow_value;
    uint64_t borrow_limit;
    uint64_t collateral_value;
    uint64_t health_factor_bps;
} LendingHealth;

typedef struct {
    uint64_t repay_amount;
    uint64_t seize_collateral;
    uint64_t bonus_collateral;
    uint64_t remaining_debt;
} LendingLiquidation;

typedef struct {
    uint64_t amount;
    uint64_t fee;
    uint8_t  data[32];
    bool     success;
} LendingFlashLoan;

void     lending_market_init(LendingMarket *market, uint64_t base_rate, uint64_t kink_rate, uint64_t max_rate, uint64_t kink_util, uint64_t reserve_factor);
uint64_t lending_utilization_rate(const LendingMarket *market);
uint64_t lending_borrow_rate(const LendingMarket *market);
uint64_t lending_supply_rate(const LendingMarket *market);
uint64_t lending_deposit(LendingAccount *account, LendingMarket *market, uint64_t amount);
uint64_t lending_redeem(LendingAccount *account, LendingMarket *market, uint64_t ctoken_amount);
uint64_t lending_borrow(LendingAccount *account, LendingMarket *market, uint64_t amount, uint64_t collateral_value);
uint64_t lending_repay(LendingAccount *account, LendingMarket *market, uint64_t amount);
void     lending_accrue_interest(LendingMarket *market, uint64_t current_time);
LendingHealth lending_get_health(LendingAccount *account, LendingMarket *market, uint64_t borrow_value, uint64_t collateral_value, uint64_t ltv_bps, uint64_t liquidation_threshold_bps);
LendingLiquidation lending_liquidate(LendingAccount *liquidator, LendingAccount *borrower, LendingMarket *market, uint64_t repay_amount, uint64_t price);
LendingFlashLoan lending_flash_loan(LendingMarket *market, uint64_t amount, uint8_t data[32], bool (*callback)(uint64_t amount, uint64_t fee, uint8_t data[32]));
uint64_t lending_exchange_rate(const LendingMarket *market);
uint64_t lending_max_borrow(uint64_t collateral_value, uint64_t ltv_bps);

#endif
