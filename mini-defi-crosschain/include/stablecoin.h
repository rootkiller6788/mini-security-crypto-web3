#ifndef STABLECOIN_H
#define STABLECOIN_H

#include <stdbool.h>
#include <stdint.h>

#define STABLECOIN_LIQUIDATION_RATIO_BPS 15000
#define STABLECOIN_MIN_COLLATERAL_RATIO_BPS 15000
#define STABLECOIN_LIQUIDATION_PENALTY_BPS 1300
#define STABLECOIN_STABILITY_FEE_BPS 500
#define STABLECOIN_DEBT_CEILING 1000000000000ULL
#define STABLECOIN_PRICE_PRECISION 100000000

typedef enum {
    STABLECOIN_OVERCOLLATERALIZED,
    STABLECOIN_ALGORITHMIC,
    STABLECOIN_CENTRALIZED_FIAT
} StablecoinType;

typedef struct {
    StablecoinType type;
    uint64_t total_supply;
    uint64_t total_debt;
    uint64_t debt_ceiling;
    uint64_t stability_fee_bps;
    uint64_t liquidation_ratio_bps;
    uint64_t liquidation_penalty_bps;
    bool     emergency_shutdown;
    bool     global_settlement;
    uint64_t surplus_buffer;
    uint64_t bad_debt;
} StablecoinSystem;

typedef struct {
    uint64_t locked_collateral;
    uint64_t minted_debt;
    uint64_t min_ratio_bps;
    uint64_t last_fee_update;
    bool     active;
} CDPVault;

typedef struct {
    uint64_t vault_id;
    uint64_t collateral_value;
    uint64_t debt_value;
    uint64_t collateral_ratio_bps;
    uint64_t max_liquidatable;
    uint64_t liquidation_profit;
} CDPHealth;

typedef struct {
    uint64_t mint_amount;
    uint64_t fee_amount;
    uint64_t required_collateral;
    bool     success;
} CDPMintResult;

typedef struct {
    uint64_t returned_collateral;
    uint64_t burned_debt;
    uint64_t fee_amount;
} CDPCloseResult;

typedef struct {
    uint64_t seized_collateral;
    uint64_t covered_debt;
    uint64_t penalty_amount;
} CDPLiquidationResult;

void     stablecoin_system_init(StablecoinSystem *sys, StablecoinType type);
uint64_t stablecoin_collateral_required(uint64_t debt_amount, uint64_t collateral_price, uint64_t ratio_bps);
void     cdp_vault_init(CDPVault *vault, uint64_t min_ratio);
CDPMintResult cdp_mint(CDPVault *vault, StablecoinSystem *sys, uint64_t collateral_amount, uint64_t collateral_price, uint64_t debt_amount);
CDPCloseResult cdp_close(CDPVault *vault, StablecoinSystem *sys, uint64_t collateral_price, uint64_t amount);
CDPLiquidationResult cdp_liquidate(CDPVault *vault, StablecoinSystem *sys, uint64_t collateral_price, uint64_t debt_price);
CDPHealth cdp_get_health(const CDPVault *vault, uint64_t collateral_price, uint64_t debt_price);
bool     cdp_is_safe(const CDPVault *vault, uint64_t collateral_price, uint64_t debt_price);
void     stablecoin_emergency_shutdown(StablecoinSystem *sys);
void     stablecoin_settle(StablecoinSystem *sys, uint64_t collateral_price, uint64_t debt_price);
uint64_t stablecoin_accrue_stability_fee(CDPVault *vault, uint64_t stability_fee_bps, uint64_t current_time);
void     algorithmic_mint(uint64_t *supply, uint64_t *price, uint64_t target_price);
void     algorithmic_burn(uint64_t *supply, uint64_t *price, uint64_t target_price);

#endif
