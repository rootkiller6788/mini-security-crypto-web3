#include "derivatives.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

static uint32_t deriv_rand_seed = 0xD3B1F001;

static uint32_t deriv_rand(void) {
    deriv_rand_seed = deriv_rand_seed * 1103515245 + 12345;
    return deriv_rand_seed;
}

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

/* ===================================================================
 * L4: Normal CDF approximation (Abramowitz & Stegun §26.2.17)
 *
 * Phi(x) = 1 - phi(x) * (c1*k + c2*k^2 + c3*k^3 + c4*k^4 + c5*k^5)
 * where k = 1/(1 + p*|x|), p = 0.2316419
 * Maximum error: 7.5e-8
 *
 * Used for Black-Scholes d1/d2 probability computation.
 * ===================================================================
 */
double deriv_cdf_normal(double x) {
    const double p  = 0.2316419;
    const double b1 = 0.319381530;
    const double b2 = -0.356563782;
    const double b3 = 1.781477937;
    const double b4 = -1.821255978;
    const double b5 = 1.330274429;

    double t = 1.0 / (1.0 + p * fabs(x));
    double phi = exp(-0.5 * x * x) / sqrt(2.0 * M_PI);
    double cdf = 1.0 - phi * (b1*t + b2*t*t + b3*t*t*t + b4*t*t*t*t + b5*t*t*t*t*t);

    return (x >= 0.0) ? cdf : (1.0 - cdf);
}

/* ===================================================================
 * L4: Black-Scholes d1 parameter
 *
 * d1 = [ln(S/K) + (r + sigma^2/2)*T] / (sigma * sqrt(T))
 *
 * S = spot, K = strike, T = time to expiry (years),
 * sigma = volatility, r = risk-free rate
 *
 * Reference: Black & Scholes (1973) "The Pricing of Options and
 * Corporate Liabilities", Journal of Political Economy
 * ===================================================================
 */
double deriv_d1(uint64_t spot, uint64_t strike, uint64_t time_to_expiry,
                double vol, double r) {
    double S = (double)spot / (double)DERIV_PRECISION;
    double K = (double)strike / (double)DERIV_PRECISION;
    double T = (double)time_to_expiry / (double)DERIV_PRECISION;

    if (vol <= 0.0 || T <= 0.0) return 0.0;
    if (K <= 0.0 || S <= 0.0) return 0.0;

    double sigma_sqrt_T = vol * sqrt(T);
    double numerator = log(S / K) + (r + 0.5 * vol * vol) * T;
    return numerator / sigma_sqrt_T;
}

double deriv_d2(double d1, double vol, uint64_t time_to_expiry) {
    double T = (double)time_to_expiry / (double)DERIV_PRECISION;
    return d1 - vol * sqrt(T);
}

/* ===================================================================
 * L1: Option constructor
 * =================================================================== */
DerivOption deriv_option_create(DerivOptionType type, DerivOptionStyle style,
                                 uint64_t strike, uint64_t expiry,
                                 uint64_t notional) {
    DerivOption opt;
    memset(&opt, 0, sizeof(opt));
    opt.type = type;
    opt.style = style;
    opt.strike_price = strike;
    opt.expiry = expiry;
    opt.notional = notional > 0 ? notional : DERIV_PRECISION;
    opt.premium = 0;
    opt.settled = false;
    return opt;
}

/* ===================================================================
 * L4: Black-Scholes option pricing
 *
 * Call: C = S*Phi(d1) - K*e^{-rT}*Phi(d2)
 * Put:  P = K*e^{-rT}*Phi(-d2) - S*Phi(-d1)
 *
 * Returns price scaled by DERIV_PRECISION.
 * ===================================================================
 */
uint64_t deriv_option_price_bs(DerivOptionType type, uint64_t spot,
                                uint64_t strike, uint64_t expiry,
                                double volatility, double risk_free) {
    double d1 = deriv_d1(spot, strike, expiry, volatility, risk_free);
    double d2_val = deriv_d2(d1, volatility, expiry);
    double S = (double)spot / (double)DERIV_PRECISION;
    double K = (double)strike / (double)DERIV_PRECISION;
    double T = (double)expiry / (double)DERIV_PRECISION;

    double discount = exp(-risk_free * T);
    double price;

    if (type == DERIV_OPTION_CALL) {
        price = S * deriv_cdf_normal(d1) - K * discount * deriv_cdf_normal(d2_val);
    } else {
        price = K * discount * deriv_cdf_normal(-d2_val)
              - S * deriv_cdf_normal(-d1);
    }

    if (price < 0.0) price = 0.0;
    return (uint64_t)(price * DERIV_PRECISION);
}

/* ===================================================================
 * L2: Intrinsic value — payoff if exercised now
 *
 * Call: max(S - K, 0)
 * Put:  max(K - S, 0)
 * ===================================================================
 */
uint64_t deriv_option_intrinsic_value(const DerivOption *option, uint64_t spot) {
    if (!option) return 0;
    if (option->type == DERIV_OPTION_CALL) {
        return spot > option->strike_price ? spot - option->strike_price : 0;
    } else {
        return option->strike_price > spot ? option->strike_price - spot : 0;
    }
}

/* ===================================================================
 * L2: Time value = option price - intrinsic value
 *
 * Represents the premium paid for potential future favorable movement.
 * Time value decays to zero at expiry (theta).
 * ===================================================================
 */
uint64_t deriv_option_time_value(const DerivOption *option, uint64_t spot,
                                  double volatility, double risk_free) {
    if (!option) return 0;
    uint64_t price = deriv_option_price_bs(option->type, spot,
                                            option->strike_price,
                                            option->expiry,
                                            volatility, risk_free);
    uint64_t intrinsic = deriv_option_intrinsic_value(option, spot);
    if (price <= intrinsic) return 0;
    return price - intrinsic;
}

/* ===================================================================
 * L6: Option payoff at expiry
 * =================================================================== */
uint64_t deriv_option_payoff(const DerivOption *option, uint64_t spot) {
    if (!option || option->settled) return 0;
    return deriv_option_intrinsic_value(option, spot);
}

/* ===================================================================
 * L5: Greeks — risk sensitivities via analytical formulas
 *
 * Delta: dV/dS — sensitivity to underlying price change
 * Gamma: d^2V/dS^2 — rate of delta change (convexity)
 * Theta: dV/dt — time decay (always negative for long options)
 * Vega:  dV/dsigma — sensitivity to volatility
 * Rho:   dV/dr — sensitivity to interest rate
 *
 * Reference: Hull "Options, Futures, and Other Derivatives" Ch.19
 * ===================================================================
 */
double deriv_option_delta(DerivOptionType type, double d1) {
    if (type == DERIV_OPTION_CALL) return deriv_cdf_normal(d1);
    return deriv_cdf_normal(d1) - 1.0;
}

double deriv_option_gamma(double d1, uint64_t spot, double vol,
                          uint64_t time_to_expiry) {
    double S = (double)spot / (double)DERIV_PRECISION;
    double T = (double)time_to_expiry / (double)DERIV_PRECISION;
    if (S <= 0.0 || vol <= 0.0 || T <= 0.0) return 0.0;
    double phi_d1 = exp(-0.5 * d1 * d1) / sqrt(2.0 * M_PI);
    return phi_d1 / (S * vol * sqrt(T));
}

double deriv_option_theta(DerivOptionType type, uint64_t spot, double d1,
                           double d2_val, double vol, uint64_t time_to_expiry,
                           double r, uint64_t strike) {
    double S = (double)spot / (double)DERIV_PRECISION;
    double K = (double)strike / (double)DERIV_PRECISION;
    double T = (double)time_to_expiry / (double)DERIV_PRECISION;
    if (vol <= 0.0 || T <= 0.0) return 0.0;

    double phi_d1 = exp(-0.5 * d1 * d1) / sqrt(2.0 * M_PI);
    double term1 = -(S * phi_d1 * vol) / (2.0 * sqrt(T));

    if (type == DERIV_OPTION_CALL) {
        double term2 = -r * K * exp(-r * T) * deriv_cdf_normal(d2_val);
        return term1 + term2;
    } else {
        double term2 = r * K * exp(-r * T) * deriv_cdf_normal(-d2_val);
        return term1 + term2;
    }
}

double deriv_option_vega(uint64_t spot, double d1, uint64_t time_to_expiry) {
    double S = (double)spot / (double)DERIV_PRECISION;
    double T = (double)time_to_expiry / (double)DERIV_PRECISION;
    if (T <= 0.0) return 0.0;
    double phi_d1 = exp(-0.5 * d1 * d1) / sqrt(2.0 * M_PI);
    return S * phi_d1 * sqrt(T);
}

double deriv_option_rho(DerivOptionType type, uint64_t strike, double d2_val,
                         uint64_t time_to_expiry, double r) {
    double K = (double)strike / (double)DERIV_PRECISION;
    double T = (double)time_to_expiry / (double)DERIV_PRECISION;
    if (type == DERIV_OPTION_CALL) {
        return K * T * exp(-r * T) * deriv_cdf_normal(d2_val);
    } else {
        return -K * T * exp(-r * T) * deriv_cdf_normal(-d2_val);
    }
}

DerivGreeks deriv_option_compute_greeks(DerivOptionType type, uint64_t spot,
                                          uint64_t strike, uint64_t expiry,
                                          double vol, double r) {
    DerivGreeks greeks;
    memset(&greeks, 0, sizeof(greeks));

    double d1 = deriv_d1(spot, strike, expiry, vol, r);
    double d2_val = deriv_d2(d1, vol, expiry);

    greeks.delta = deriv_option_delta(type, d1);
    greeks.gamma = deriv_option_gamma(d1, spot, vol, expiry);
    greeks.theta = deriv_option_theta(type, spot, d1, d2_val, vol, expiry, r, strike);
    greeks.vega  = deriv_option_vega(spot, d1, expiry);
    greeks.rho   = deriv_option_rho(type, strike, d2_val, expiry, r);

    return greeks;
}

/* ===================================================================
 * L5: Perpetual futures — funding rate mechanism
 *
 * Funding Rate = (mark_price - index_price) / index_price
 * Paid between longs and shorts every funding_interval seconds.
 * Keeps perpetual contract price anchored to spot index.
 *
 * Reference: BitMEX perpetual swap specification (2016)
 * ===================================================================
 */
void deriv_perp_market_init(DerivPerpMarket *market, uint64_t max_leverage,
                             uint64_t maintenance_margin) {
    memset(market, 0, sizeof(DerivPerpMarket));
    market->max_leverage_bps = max_leverage > 0 ? max_leverage : 10000;
    market->maintenance_margin_bps = maintenance_margin > 0
                                     ? maintenance_margin : 500;
    market->next_funding_time = DERIV_FUNDING_INTERVAL;
}

uint64_t deriv_perp_calc_funding_rate(const DerivPerpMarket *market,
                                       uint64_t mark_price,
                                       uint64_t index_price) {
    if (index_price == 0) return 0;

    /* funding = (mark - index) / index, expressed in bps */
    int64_t diff = (int64_t)mark_price - (int64_t)index_price;
    if (diff <= 0) return 0;
    uint64_t raw_rate = (uint64_t)(diff * (int64_t)DERIV_BPS_DENOM
                                   / (int64_t)index_price);
    /* Cap funding rate using market's maintenance margin as risk limit */
    uint64_t cap = market ? market->maintenance_margin_bps * 2 : 1000;
    return raw_rate > cap ? cap : raw_rate;
}

void deriv_perp_update_funding(DerivPerpMarket *market, uint64_t current_time) {
    if (!market || current_time < market->next_funding_time) return;
    market->funding_rate_bps = deriv_perp_calc_funding_rate(market,
                                market->mark_price, market->index_price);
    market->next_funding_time = current_time + DERIV_FUNDING_INTERVAL;
}

uint64_t deriv_perp_calc_liquidation_price(const DerivPerpPosition *pos,
                                            DerivPerpSide side,
                                            uint64_t entry_price,
                                            uint64_t leverage_bps) {
    if (leverage_bps == 0 || entry_price == 0) return 0;

    /* liquidation = entry * (1 - 1/leverage + maintenance_margin)
     * Adjusted by position size — larger positions get tighter margins */
    uint64_t mm_bps = DERIV_LIQUIDATION_THRESHOLD_BPS;
    if (pos && pos->size > 0) {
        /* Larger positions = slightly tighter liquidation for risk management */
        uint64_t size_factor = pos->size / 1000;
        if (size_factor > 500) mm_bps = (mm_bps * 95) / 100;
    }
    uint64_t one_over_lev = DERIV_BPS_DENOM / leverage_bps;
    uint64_t buffer = mm_bps / 10;

    if (side == DERIV_PERP_SIDE_LONG) {
        uint64_t adj = entry_price * one_over_lev / DERIV_BPS_DENOM;
        if (adj >= entry_price) return 1;
        return entry_price - adj + buffer;
    } else {
        uint64_t adj = entry_price * one_over_lev / DERIV_BPS_DENOM;
        return entry_price + adj - buffer;
    }
}

uint64_t deriv_perp_calc_pnl(const DerivPerpPosition *pos,
                             uint64_t current_price) {
    if (!pos || !pos->active) return 0;

    if (pos->side == DERIV_PERP_SIDE_LONG) {
        if (current_price <= pos->entry_price) return 0;
        int64_t pnl = (int64_t)(current_price - pos->entry_price) * (int64_t)pos->size
                     / (int64_t)pos->entry_price;
        return (uint64_t)(pnl > 0 ? pnl : 0);
    } else {
        if (current_price >= pos->entry_price) return 0;
        int64_t pnl = (int64_t)(pos->entry_price - current_price) * (int64_t)pos->size
                     / (int64_t)pos->entry_price;
        return (uint64_t)(pnl > 0 ? pnl : 0);
    }
}

void deriv_perp_open_position(DerivPerpMarket *market, DerivPerpPosition *pos,
                               DerivPerpSide side, uint64_t size,
                               uint64_t entry_price, uint64_t leverage_bps,
                               uint64_t margin) {
    if (!pos || !market || size == 0) return;

    memset(pos, 0, sizeof(DerivPerpPosition));
    pos->position_id = deriv_rand();
    pos->side = side;
    pos->size = size;
    pos->entry_price = entry_price;
    pos->leverage_bps = leverage_bps > market->max_leverage_bps
                       ? market->max_leverage_bps : leverage_bps;
    pos->margin = margin;
    pos->liquidation_price = deriv_perp_calc_liquidation_price(pos, side,
                               entry_price, leverage_bps);
    pos->active = true;

    if (side == DERIV_PERP_SIDE_LONG) market->open_interest_long += size;
    else market->open_interest_short += size;
}

bool deriv_perp_close_position(DerivPerpPosition *pos, uint64_t exit_price) {
    if (!pos || !pos->active) return false;
    pos->unrealized_pnl = deriv_perp_calc_pnl(pos, exit_price);
    pos->active = false;
    return true;
}

bool deriv_perp_is_liquidatable(const DerivPerpPosition *pos,
                                 uint64_t current_price) {
    if (!pos || !pos->active) return false;
    if (pos->side == DERIV_PERP_SIDE_LONG)
        return current_price <= pos->liquidation_price;
    else
        return current_price >= pos->liquidation_price;
}

/* ===================================================================
 * L6: Put-Call Parity verification
 *
 * Theorem: C - P = S - K*e^{-rT}
 * This is a no-arbitrage condition. Any deviation implies arbitrage.
 *
 * If parity does not hold within tolerance, there exists a risk-free
 * arbitrage opportunity (conversion/reversal strategy).
 *
 * Reference: Stoll (1969), "The Relationship Between Put and Call
 * Option Prices", Journal of Finance
 * ===================================================================
 */
bool deriv_put_call_parity(uint64_t call_price, uint64_t put_price,
                            uint64_t spot, uint64_t strike,
                            uint64_t expiry, double r) {
    double S = (double)spot / (double)DERIV_PRECISION;
    double K = (double)strike / (double)DERIV_PRECISION;
    double T = (double)expiry / (double)DERIV_PRECISION;
    double C = (double)call_price / (double)DERIV_PRECISION;
    double P = (double)put_price / (double)DERIV_PRECISION;

    double lhs = C - P;
    double rhs = S - K * exp(-r * T);
    double tolerance = 0.001 * S; /* 0.1% of spot as tolerance */

    return fabs(lhs - rhs) < tolerance;
}

uint64_t deriv_parity_implied_rate(uint64_t call_price, uint64_t put_price,
                                    uint64_t spot, uint64_t strike) {
    /* r = -ln((S - C + P)/K) / T  — approximate for one period */
    int64_t diff = (int64_t)spot - (int64_t)call_price + (int64_t)put_price;
    if (diff <= 0 || strike == 0) return 0;
    return (uint64_t)(((int64_t)diff * (int64_t)DERIV_BPS_DENOM)
                     / (int64_t)strike - (int64_t)DERIV_BPS_DENOM);
}

/* ===================================================================
 * L7: Synthetic assets — mint/burn with overcollateralization
 * =================================================================== */
void deriv_synth_init(DerivSynth *synth, uint64_t cratio_bps) {
    memset(synth, 0, sizeof(DerivSynth));
    synth->collateralization_ratio_bps = cratio_bps > DERIV_BPS_DENOM
                                         ? cratio_bps : DERIV_BPS_DENOM * 150 / 100;
}

uint64_t deriv_synth_mint(DerivSynth *synth, uint64_t collateral,
                           uint64_t collateral_price) {
    if (!synth || collateral == 0 || collateral_price == 0) return 0;
    uint64_t collateral_value = collateral * collateral_price / DERIV_PRECISION;
    uint64_t mintable = collateral_value * DERIV_BPS_DENOM
                       / synth->collateralization_ratio_bps;
    synth->debt_pool += mintable;
    synth->total_supply += mintable;
    synth->exchange_rate = synth->debt_pool > 0
                          ? synth->total_supply * DERIV_PRECISION / synth->debt_pool
                          : DERIV_PRECISION;
    return mintable;
}

uint64_t deriv_synth_burn(DerivSynth *synth, uint64_t synth_amount,
                           uint64_t collateral_price) {
    if (!synth || synth_amount == 0 || synth_amount > synth->total_supply)
        return 0;
    uint64_t debt_repaid = synth_amount * synth->exchange_rate
                          / DERIV_PRECISION;
    synth->total_supply -= synth_amount;
    synth->debt_pool -= debt_repaid;
    uint64_t collateral_returned = debt_repaid * DERIV_PRECISION
                                  / collateral_price;
    return collateral_returned;
}

/* ===================================================================
 * L8: Optimal hedging — compute delta-neutral hedge position
 *
 * To hedge a delta-D exposure, take opposite position of size D in
 * the underlying, scaled by the option's delta.
 *
 * Hedge_size = -Delta * exposure / option_price
 * ===================================================================
 */
DerivHedgePlan deriv_optimal_hedge(uint64_t exposure, const DerivGreeks *greeks,
                                    uint64_t option_price, uint64_t budget) {
    DerivHedgePlan plan;
    memset(&plan, 0, sizeof(plan));

    if (!greeks || option_price == 0 || budget == 0) return plan;

    double abs_delta = fabs(greeks->delta);
    plan.net_delta = greeks->delta;
    plan.delta_neutral_size = (uint64_t)((double)exposure * abs_delta
                                         / (double)DERIV_PRECISION);

    if (option_price > 0) {
        plan.hedge_cost = plan.delta_neutral_size * option_price
                         / DERIV_PRECISION;
        if (plan.hedge_cost > budget) {
            plan.delta_neutral_size = budget * DERIV_PRECISION / option_price;
            plan.hedge_cost = budget;
        }
    }

    /* Expected impermanent loss from gamma exposure */
    plan.expected_impermanent = (uint64_t)(greeks->gamma * 1000.0);
    return plan;
}

/* ===================================================================
 * L9: Implied volatility — Newton-Raphson solver
 *
 * Given an observed option price, find the volatility sigma such that:
 * BS(sigma) - observed_price = 0
 *
 * Uses iterative Newton's method: sigma_{k+1} = sigma_k - f/f'
 * where f = BS(sigma) - price, f' = vega(sigma)
 *
 * Reference: Manaster & Koehler (1982), "The Calculation of Implied
 * Variances from the Black-Scholes Model", Journal of Finance
 * =================================================================== */
uint64_t deriv_implied_volatility(uint64_t option_price, uint64_t spot,
                                   uint64_t strike, uint64_t expiry, double r) {
    if (option_price == 0 || spot == 0 || strike == 0) return 0;

    double target = (double)option_price / (double)DERIV_PRECISION;
    double vol = 0.30; /* initial guess: 30% volatility */
    double S = (double)spot / DERIV_PRECISION;
    double K = (double)strike / DERIV_PRECISION;

    for (int iter = 0; iter < 50; iter++) {
        double d1 = deriv_d1(spot, strike, expiry, vol, r);
        double d2_val = deriv_d2(d1, vol, expiry);
        double price;
        DerivOptionType type = (S >= K) ? DERIV_OPTION_CALL : DERIV_OPTION_PUT;

        if (type == DERIV_OPTION_CALL) {
            price = S * deriv_cdf_normal(d1)
                  - K * exp(-r * (double)expiry/DERIV_PRECISION) * deriv_cdf_normal(d2_val);
        } else {
            price = K * exp(-r * (double)expiry/DERIV_PRECISION) * deriv_cdf_normal(-d2_val)
                  - S * deriv_cdf_normal(-d1);
        }

        double diff = price - target;
        if (fabs(diff) < 1e-10 * DERIV_PRECISION) break;

        double vega = deriv_option_vega(spot, d1, expiry);
        if (fabs(vega) < 1e-12) break;

        vol = vol - diff / vega;
        if (vol <= 0.001) { vol = 0.001; break; }
        if (vol > 5.0) { vol = 5.0; break; }
    }

    return (uint64_t)(vol * (double)DERIV_BPS_DENOM);
}

/* ===================================================================
 * L9: Volatility smile correction
 *
 * In practice, implied volatility varies with strike (smile/skew),
 * contradicting the BS assumption of constant volatility.
 *
 * Simple parabolic smile: vol(k) = atm_vol + alpha*(k - 1)^2
 * where k = K/S (moneyness)
 *
 * Reference: Derman & Kani (1994), "Riding on a Smile"
 * =================================================================== */
double deriv_volatility_smile_correction(uint64_t strike, uint64_t atm_strike,
                                          double atm_vol) {
    if (atm_strike == 0) return atm_vol;
    double moneyness = (double)strike / (double)atm_strike;
    double deviation = moneyness - 1.0;
    double alpha = 0.05; /* smile curvature parameter */
    return atm_vol + alpha * deviation * deviation;
}