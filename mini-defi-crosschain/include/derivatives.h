#ifndef DERIVATIVES_H
#define DERIVATIVES_H

#include <stdbool.h>
#include <stdint.h>

#define DERIV_BPS_DENOM          10000
#define DERIV_PRECISION          1000000000ULL
#define DERIV_MAX_PERP_POSITIONS 64
#define DERIV_FUNDING_INTERVAL   28800
#define DERIV_LIQUIDATION_THRESHOLD_BPS 6250

/* L1: Option types and definitions */
typedef enum {
    DERIV_OPTION_CALL,
    DERIV_OPTION_PUT
} DerivOptionType;

typedef enum {
    DERIV_OPTION_EUROPEAN,
    DERIV_OPTION_AMERICAN
} DerivOptionStyle;

typedef enum {
    DERIV_PERP_SIDE_LONG,
    DERIV_PERP_SIDE_SHORT
} DerivPerpSide;

/* L1: Options contract (L4: Black-Scholes model) */
typedef struct {
    DerivOptionType type;
    DerivOptionStyle style;
    uint64_t strike_price;
    uint64_t expiry;
    uint64_t premium;
    uint64_t notional;
    uint8_t  underlying[32];
    bool     settled;
    uint64_t settlement_price;
} DerivOption;

/* L1: Greeks — risk sensitivities */
typedef struct {
    double delta;
    double gamma;
    double theta;
    double vega;
    double rho;
} DerivGreeks;

/* L1: Perpetual futures */
typedef struct {
    uint8_t  pair[16];
    uint64_t mark_price;
    uint64_t index_price;
    uint64_t funding_rate_bps;
    uint64_t next_funding_time;
    uint64_t open_interest_long;
    uint64_t open_interest_short;
    uint64_t max_leverage_bps;
    uint64_t maintenance_margin_bps;
} DerivPerpMarket;

typedef struct {
    uint64_t position_id;
    DerivPerpSide side;
    uint64_t size;
    uint64_t entry_price;
    uint64_t leverage_bps;
    uint64_t margin;
    uint64_t unrealized_pnl;
    uint64_t liquidation_price;
    uint64_t last_funding_time;
    bool     active;
} DerivPerpPosition;

/* L1: Synthetic assets */
typedef struct {
    uint8_t  synth_id[32];
    uint8_t  underlying_id[32];
    uint64_t collateralization_ratio_bps;
    uint64_t total_supply;
    uint64_t debt_pool;
    uint64_t exchange_rate;
} DerivSynth;

/* L1: Core API — Options */
DerivOption  deriv_option_create(DerivOptionType type, DerivOptionStyle style, uint64_t strike, uint64_t expiry, uint64_t notional);
uint64_t     deriv_option_price_bs(DerivOptionType type, uint64_t spot, uint64_t strike, uint64_t expiry, double volatility, double risk_free);
uint64_t     deriv_option_intrinsic_value(const DerivOption *option, uint64_t spot);
uint64_t     deriv_option_time_value(const DerivOption *option, uint64_t spot, double volatility, double risk_free);
uint64_t     deriv_option_payoff(const DerivOption *option, uint64_t spot);

/* L4: Black-Scholes model implementation */
double       deriv_cdf_normal(double x);
double       deriv_d1(uint64_t spot, uint64_t strike, uint64_t time_to_expiry, double vol, double r);
double       deriv_d2(double d1, double vol, uint64_t time_to_expiry);

/* L5: Greeks calculation using numerical methods */
DerivGreeks  deriv_option_compute_greeks(DerivOptionType type, uint64_t spot, uint64_t strike, uint64_t expiry, double vol, double r);
double       deriv_option_delta(DerivOptionType type, double d1);
double       deriv_option_gamma(double d1, uint64_t spot, double vol, uint64_t time_to_expiry);
double       deriv_option_theta(DerivOptionType type, uint64_t spot, double d1, double d2, double vol, uint64_t time_to_expiry, double r, uint64_t strike);
double       deriv_option_vega(uint64_t spot, double d1, uint64_t time_to_expiry);
double       deriv_option_rho(DerivOptionType type, uint64_t strike, double d2, uint64_t time_to_expiry, double r);

/* L5: Perpetual futures — funding rate mechanism */
void         deriv_perp_market_init(DerivPerpMarket *market, uint64_t max_leverage, uint64_t maintenance_margin);
uint64_t     deriv_perp_calc_funding_rate(const DerivPerpMarket *market, uint64_t mark_price, uint64_t index_price);
void         deriv_perp_update_funding(DerivPerpMarket *market, uint64_t current_time);
uint64_t     deriv_perp_calc_liquidation_price(const DerivPerpPosition *pos, DerivPerpSide side, uint64_t entry_price, uint64_t leverage_bps);
uint64_t     deriv_perp_calc_pnl(const DerivPerpPosition *pos, uint64_t current_price);
void         deriv_perp_open_position(DerivPerpMarket *market, DerivPerpPosition *pos, DerivPerpSide side, uint64_t size, uint64_t entry_price, uint64_t leverage_bps, uint64_t margin);
bool         deriv_perp_close_position(DerivPerpPosition *pos, uint64_t exit_price);
bool         deriv_perp_is_liquidatable(const DerivPerpPosition *pos, uint64_t current_price);

/* L6: Put-Call Parity verification */
bool         deriv_put_call_parity(uint64_t call_price, uint64_t put_price, uint64_t spot, uint64_t strike, uint64_t expiry, double r);
uint64_t     deriv_parity_implied_rate(uint64_t call_price, uint64_t put_price, uint64_t spot, uint64_t strike);

/* L7: Synthetic assets */
void         deriv_synth_init(DerivSynth *synth, uint64_t cratio_bps);
uint64_t     deriv_synth_mint(DerivSynth *synth, uint64_t collateral, uint64_t collateral_price);
uint64_t     deriv_synth_burn(DerivSynth *synth, uint64_t synth_amount, uint64_t collateral_price);

/* L8: Advanced — optimal hedging with multiple instruments */
typedef struct {
    uint64_t delta_neutral_size;
    uint64_t hedge_cost;
    uint64_t expected_impermanent;
    double   net_delta;
} DerivHedgePlan;

DerivHedgePlan deriv_optimal_hedge(uint64_t exposure, const DerivGreeks *greeks, uint64_t option_price, uint64_t budget);

/* L9: Volatility surface (industry frontier — documented) */
uint64_t     deriv_implied_volatility(uint64_t option_price, uint64_t spot, uint64_t strike, uint64_t expiry, double r);
double       deriv_volatility_smile_correction(uint64_t strike, uint64_t atm_strike, double atm_vol);

#endif
