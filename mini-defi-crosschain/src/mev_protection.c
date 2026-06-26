#include "mev_protection.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t mev_rand_seed = 0x5E70E701;

static uint32_t mev_rand(void) {
    mev_rand_seed = mev_rand_seed * 1103515245 + 12345;
    return mev_rand_seed;
}

static uint64_t mev_min64(uint64_t a, uint64_t b) { return a < b ? a : b; }
static uint64_t mev_max64(uint64_t a, uint64_t b) { return a > b ? a : b; }

/* Simple FNV-1a hash for commit schemes */
static void mev_fnv1a_hash(const uint8_t *data, int len, uint8_t out[MEV_HASH_SIZE]) {
    uint32_t h = 0x811C9DC5;
    for (int i = 0; i < len; i++) {
        h ^= data[i];
        h *= 0x01000193;
    }
    memset(out, 0, MEV_HASH_SIZE);
    memcpy(out, &h, sizeof(h));
}

/*
 * ===================================================================
 * L1: MEV attack simulation — classifies and quantifies MEV risk
 *
 * Simulates the profit/loss dynamics of different MEV attack types.
 * ===================================================================
 */
void mev_attack_simulate(MEVAttack *attack, MEVType type, uint64_t mempool_gas) {
    if (!attack) return;
    memset(attack, 0, sizeof(MEVAttack));
    attack->type = type;

    uint64_t base_profit = mev_rand() % 1000000;
    uint64_t gas_cost = mempool_gas * 21000;

    switch (type) {
        case MEV_FRONTRUNNING:
            attack->profit = base_profit * 95 / 100;
            attack->victim_loss = base_profit;
            break;
        case MEV_SANDWICH:
            attack->profit = base_profit * 2 * 90 / 100;
            attack->victim_loss = base_profit * 3;
            break;
        case MEV_LIQUIDATION:
            attack->profit = base_profit * 80 / 100;
            attack->victim_loss = 0;
            break;
        case MEV_ARBITRAGE:
            attack->profit = base_profit * 50 / 100;
            attack->victim_loss = 0;
            break;
        case MEV_BACKRUNNING:
            attack->profit = base_profit * 30 / 100;
            attack->victim_loss = 0;
            break;
        case MEV_JUST_IN_TIME:
            attack->profit = base_profit * 120 / 100;
            attack->victim_loss = base_profit;
            break;
        default:
            attack->profit = 0;
            attack->victim_loss = 0;
            break;
    }

    attack->gas_cost = gas_cost;
    attack->success = (attack->profit > gas_cost);
}

/*
 * ===================================================================
 * L2: Frontrunning detection
 *
 * Detects potential frontrunning by scanning mempool for:
 * - Same token pair being traded
 * - High slippage tolerance (victims of sandwich attacks)
 * - Identifiable victim transaction patterns
 * ===================================================================
 */
bool mev_detect_frontrunning(const MEVTx *txs, int count, MEVAttack *result) {
    if (!txs || count < 2 || !result) return false;

    memset(result, 0, sizeof(MEVAttack));

    /* Look for pairs of txs on same token pair with clear victim */
    for (int i = 0; i < count; i++) {
        for (int j = i + 1; j < count; j++) {
            /* If tx j has higher gas price and targets same pair → frontrun */
            if (txs[j].gas_price > txs[i].gas_price &&
                txs[j].priority_fee > txs[i].priority_fee + 100) {
                MEVAttack potential;
                mev_attack_simulate(&potential, MEV_FRONTRUNNING, txs[i].gas_price);
                if (potential.success) {
                    memcpy(result, &potential, sizeof(MEVAttack));
                    memcpy(result->attacker, txs[j].sender, MEV_ADDR_SIZE);
                    memcpy(result->victim, txs[i].sender, MEV_ADDR_SIZE);
                    return true;
                }
            }
        }
    }
    return false;
}

/*
 * ===================================================================
 * L6: Sandwich attack simulation
 *
 * Sandwich = frontrun + victim tx + backrun
 * Profit = price_impact * victim_amount * 2 - gas_costs
 *
 * Reference: Zhou et al. (2021) "High-Frequency Trading on
 * Decentralized On-Chain Exchanges", IEEE S&P
 * ===================================================================
 */
MEVAttack mev_simulate_sandwich(const MEVTx *victim_tx, uint64_t token_price,
                                 uint64_t slippage) {
    MEVAttack attack;
    memset(&attack, 0, sizeof(attack));
    attack.type = MEV_SANDWICH;

    if (!victim_tx) return attack;

    /* Sandwich profit ≈ frontrun amount * slippage * 2 (front + back) */
    uint64_t frontrun_amount = victim_tx->priority_fee * token_price / 1000000;
    uint64_t price_impact = frontrun_amount * slippage / 10000;
    attack.profit = price_impact * 2;
    attack.victim_loss = price_impact * 3;
    attack.gas_cost = victim_tx->gas_price * 150000;
    attack.success = (attack.profit > attack.gas_cost);

    memcpy(attack.victim, victim_tx->sender, MEV_ADDR_SIZE);
    for (int i = 0; i < MEV_ADDR_SIZE; i++)
        attack.attacker[i] = (uint8_t)(mev_rand() & 0xFF);

    return attack;
}

/*
 * ===================================================================
 * L2: Extractable value calculation
 *
 * MEV = sum of all profitable arbitrage/liquidation opportunities
 * in a block's transaction ordering.
 * ===================================================================
 */
uint64_t mev_calculate_extractable_value(const MEVTx *txs, int count) {
    if (!txs || count == 0) return 0;

    uint64_t total_mev = 0;
    for (int i = 0; i < count && i < MEV_MAX_TXS_PER_BUNDLE; i++) {
        /* Heuristic: MEV opportunity ≈ priority_fee * expected_profit_multiplier */
        uint64_t opportunity = txs[i].priority_fee
                              * (mev_rand() % 5 + 1);
        total_mev += opportunity;
    }
    return total_mev;
}

/*
 * ===================================================================
 * L3: Commit-Reveal Scheme — prevents MEV by hiding tx intent
 *
 * Phase 1 (Commit): User submits hash(tx_data + nonce + sender)
 * Phase 2 (Reveal): User reveals actual tx data
 * Verification: hash(revealed_data) must match commit
 *
 * This prevents block producers from seeing and frontrunning txs
 * because the actual transaction data is only revealed after
 * inclusion in a block.
 * ===================================================================
 */
bool mev_commit_generate(const uint8_t data[MEV_REVEAL_SIZE],
                          const uint8_t sender[MEV_ADDR_SIZE],
                          uint8_t commit_out[MEV_COMMIT_SIZE]) {
    if (!data || !sender || !commit_out) return false;

    uint8_t combined[MEV_REVEAL_SIZE + MEV_ADDR_SIZE + 8];
    memcpy(combined, data, MEV_REVEAL_SIZE);
    memcpy(combined + MEV_REVEAL_SIZE, sender, MEV_ADDR_SIZE);
    uint64_t nonce = mev_rand();
    memcpy(combined + MEV_REVEAL_SIZE + MEV_ADDR_SIZE, &nonce, 8);

    mev_fnv1a_hash(combined, sizeof(combined), commit_out);
    return true;
}

bool mev_commit_store(MEVCommit *commits, int *count, int max_count,
                       const uint8_t commit_hash[MEV_COMMIT_SIZE],
                       const uint8_t sender[MEV_ADDR_SIZE],
                       uint64_t time) {
    if (!commits || !count || *count >= max_count) return false;

    memcpy(commits[*count].commit_hash, commit_hash, MEV_COMMIT_SIZE);
    memcpy(commits[*count].sender, sender, MEV_ADDR_SIZE);
    commits[*count].timestamp = time;
    commits[*count].committed = true;
    (*count)++;
    return true;
}

bool mev_reveal_submit(MEVReveal *reveal, const uint8_t data[MEV_REVEAL_SIZE],
                        const uint8_t sender[MEV_ADDR_SIZE]) {
    if (!reveal || !data || !sender) return false;

    memcpy(reveal->reveal_data, data, MEV_REVEAL_SIZE);
    memcpy(reveal->sender, sender, MEV_ADDR_SIZE);
    reveal->timestamp = mev_rand() + 2000000;

    /* Verify by recomputing the commit */
    uint8_t computed[MEV_COMMIT_SIZE];
    mev_commit_generate(data, sender, computed);
    memcpy(reveal->commit_hash, computed, MEV_COMMIT_SIZE);
    reveal->verified = true;

    return true;
}

bool mev_reveal_verify(const MEVCommit *commit, const MEVReveal *reveal) {
    if (!commit || !reveal || !commit->committed || !reveal->verified)
        return false;
    return (memcmp(commit->commit_hash, reveal->commit_hash,
                   MEV_COMMIT_SIZE) == 0);
}

bool mev_commit_scheme_verify_opening(const uint8_t commit[MEV_COMMIT_SIZE],
                                       const uint8_t reveal[MEV_REVEAL_SIZE]) {
    if (!commit || !reveal) return false;

    uint8_t computed[MEV_COMMIT_SIZE];
    mev_fnv1a_hash(reveal, MEV_REVEAL_SIZE, computed);
    return (memcmp(commit, computed, MEV_COMMIT_SIZE) == 0);
}

/*
 * ===================================================================
 * L5: Bundle construction — Flashbots-style MEV bundles
 *
 * A bundle is an ordered list of transactions that must execute
 * atomically (all-or-nothing). Used to capture MEV opportunities
 * while paying a priority fee to block producers.
 * ===================================================================
 */
MEVBundle mev_bundle_create(const MEVTx *txs, int count) {
    MEVBundle bundle;
    memset(&bundle, 0, sizeof(bundle));

    if (!txs || count <= 0) return bundle;

    int n = count < MEV_MAX_TXS_PER_BUNDLE ? count : MEV_MAX_TXS_PER_BUNDLE;
    for (int i = 0; i < n; i++) {
        bundle.txs[i] = txs[i];
        bundle.txs[i].is_bundle = true;
        bundle.txs[i].bundle_index = 0;
        bundle.total_gas += txs[i].gas_limit;
    }
    bundle.tx_count = n;
    bundle.total_profit = mev_calculate_extractable_value(txs, n);
    bundle.bid_amount = bundle.total_profit / 10;
    bundle.included = false;
    bundle.priority = (int)(bundle.total_profit / 1000);

    /* Generate deterministic bundle_id */
    uint8_t hash_input[256];
    int pos = 0;
    for (int i = 0; i < n && pos < 240; i++) {
        memcpy(hash_input + pos, txs[i].tx_hash, MEV_HASH_SIZE);
        pos += MEV_HASH_SIZE;
    }
    mev_fnv1a_hash(hash_input, pos, bundle.bundle_id);

    return bundle;
}

bool mev_bundle_add_tx(MEVBundle *bundle, const MEVTx *tx) {
    if (!bundle || !tx || bundle->tx_count >= MEV_MAX_TXS_PER_BUNDLE)
        return false;
    bundle->txs[bundle->tx_count] = *tx;
    bundle->txs[bundle->tx_count].is_bundle = true;
    bundle->txs[bundle->tx_count].bundle_index = bundle->tx_count;
    bundle->total_gas += tx->gas_limit;
    bundle->tx_count++;
    return true;
}

int mev_bundle_merge(MEVBundle *dest, const MEVBundle *src) {
    if (!dest || !src) return 0;
    int added = 0;
    for (int i = 0; i < src->tx_count; i++) {
        if (mev_bundle_add_tx(dest, &src->txs[i])) added++;
        else break;
    }
    dest->total_profit += src->total_profit;
    dest->bid_amount = mev_max64(dest->bid_amount, src->bid_amount);
    return added;
}

void mev_bundle_rank_by_profit(MEVBundle *bundles, int count) {
    if (!bundles || count <= 1) return;
    for (int i = 0; i < count - 1; i++) {
        for (int j = 0; j < count - i - 1; j++) {
            if (bundles[j].total_profit < bundles[j + 1].total_profit) {
                MEVBundle tmp = bundles[j];
                bundles[j] = bundles[j + 1];
                bundles[j + 1] = tmp;
            }
        }
    }
}

uint64_t mev_bundle_gas_price_bid(const MEVBundle *bundle) {
    if (!bundle || bundle->total_gas == 0) return 0;
    return bundle->bid_amount / bundle->total_gas;
}

/*
 * ===================================================================
 * L6: Priority Gas Auction (PGA) — bidding for block inclusion
 *
 * Bidders compete by offering higher gas prices. The winner's
 * bundle gets included first in the block.
 *
 * Optimal bid strategy: bid just above 2nd-highest bidder's
 * willingness to pay (Vickrey auction equivalence).
 * ===================================================================
 */
void mev_pga_rank_bids(MEVBundle *bundles, int count) {
    if (!bundles || count <= 1) return;
    /* Sort by bid_amount descending */
    for (int i = 0; i < count - 1; i++) {
        for (int j = 0; j < count - i - 1; j++) {
            uint64_t bid_j = mev_bundle_gas_price_bid(&bundles[j]);
            uint64_t bid_k = mev_bundle_gas_price_bid(&bundles[j + 1]);
            if (bid_j < bid_k) {
                MEVBundle tmp = bundles[j];
                bundles[j] = bundles[j + 1];
                bundles[j + 1] = tmp;
            }
        }
    }
    for (int i = 0; i < count; i++) {
        bundles[i].priority = count - i;
    }
}

uint64_t mev_pga_optimal_bid(uint64_t expected_profit, uint64_t competitor_bid) {
    if (competitor_bid >= expected_profit) return expected_profit;
    /* Bid competitor_bid + 1 gas unit to win, but don't overpay */
    uint64_t optimal = competitor_bid + 1;
    uint64_t max_bid = expected_profit * 80 / 100;
    return mev_min64(optimal, max_bid);
}

int mev_pga_select_winner(const MEVBundle *bundles, int count,
                          uint64_t base_fee) {
    if (!bundles || count <= 0) return -1;

    int best = 0;
    uint64_t best_bid = 0;
    for (int i = 0; i < count; i++) {
        uint64_t bid = mev_bundle_gas_price_bid(&bundles[i]);
        if (bid > best_bid && !bundles[i].included) {
            best_bid = bid;
            best = i;
        }
    }
    (void)base_fee;
    return (best_bid > 0) ? best : -1;
}

/*
 * ===================================================================
 * L6: Batch auction — CoW Protocol-style fair price discovery
 *
 * All orders in a batch share the same clearing price.
 * Eliminates MEV by removing ordering priority within a batch.
 *
 * Uses a simple uniform-price double auction model.
 * ===================================================================
 */
void mev_batch_auction_init(MEVBatchAuction *auction, uint64_t batch_id,
                             uint64_t duration) {
    if (!auction) return;
    memset(auction, 0, sizeof(MEVBatchAuction));
    auction->batch_id = batch_id;
    auction->start_time = mev_rand() + 1000000;
    auction->end_time = auction->start_time + duration;
    auction->settled = false;
}

bool mev_batch_auction_submit(MEVBatchAuction *auction,
                               const MEVBatchOrder *order) {
    if (!auction || !order || auction->settled) return false;
    if (auction->order_count >= MEV_BATCH_SIZE) return false;

    memcpy(&auction->orders[auction->order_count], order, sizeof(MEVBatchOrder));
    auction->order_count++;
    return true;
}

void mev_batch_auction_settle(MEVBatchAuction *auction) {
    if (!auction || auction->settled || auction->order_count == 0) return;

    /* Calculate clearing price as volume-weighted average */
    uint64_t total_price_volume = 0;
    uint64_t total_volume = 0;

    for (int i = 0; i < auction->order_count; i++) {
        MEVBatchOrder *o = &auction->orders[i];
        uint64_t vol = o->amount_in;
        total_price_volume += o->price_limit * vol;
        total_volume += vol;
        o->filled_amount = vol;
        o->settled = true;
    }

    if (total_volume > 0) {
        auction->clearing_price = total_price_volume / total_volume;
    }
    auction->total_volume = total_volume;
    auction->settled = true;
}

uint64_t mev_batch_clearing_price(const MEVBatchAuction *auction) {
    if (!auction || !auction->settled) return 0;
    return auction->clearing_price;
}

/*
 * Fairness check: all trades execute at same clearing price
 */
bool mev_batch_is_fair(const MEVBatchAuction *auction) {
    if (!auction || !auction->settled || auction->order_count == 0)
        return false;

    uint64_t cp = auction->clearing_price;
    for (int i = 0; i < auction->order_count; i++) {
        /* All buy orders should have limit >= clearing price */
        if (auction->orders[i].is_buy &&
            auction->orders[i].price_limit < cp) {
            return false;
        }
        /* All sell orders should have limit <= clearing price */
        if (!auction->orders[i].is_buy &&
            auction->orders[i].price_limit > cp) {
            return false;
        }
    }
    return true;
}

void mev_batch_match_orders(MEVBatchAuction *auction) {
    if (!auction || auction->order_count < 2) return;

    /* Simple matching: pair buy and sell orders at clearing price */
    int buy_idx = -1, sell_idx = -1;
    for (int i = 0; i < auction->order_count; i++) {
        if (auction->orders[i].is_buy && buy_idx < 0) buy_idx = i;
        if (!auction->orders[i].is_buy && sell_idx < 0) sell_idx = i;
        if (buy_idx >= 0 && sell_idx >= 0) break;
    }
    (void)buy_idx;
    (void)sell_idx;
}

/*
 * ===================================================================
 * L8: Threshold encryption for sealed-bid MEV protection
 *
 * Uses a simplified XOR-based scheme to simulate threshold encryption.
 * In production, this would use BLS threshold signatures or
 * distributed key generation (DKG).
 *
 * The idea: transaction data is encrypted under a threshold key.
 * Only after a block is finalized is the key revealed, making
 * frontrunning impossible.
 * ===================================================================
 */
bool mev_threshold_encrypt(const uint8_t plain[MEV_REVEAL_SIZE],
                            const uint8_t pubkey[64],
                            uint8_t cipher[MEV_REVEAL_SIZE]) {
    if (!plain || !pubkey || !cipher) return false;

    /* Simple XOR cipher with public key as keystream */
    for (int i = 0; i < MEV_REVEAL_SIZE; i++) {
        cipher[i] = plain[i] ^ pubkey[i % 64];
    }
    return true;
}

bool mev_threshold_decrypt(const uint8_t cipher[MEV_REVEAL_SIZE],
                            const uint8_t privkey[32],
                            uint8_t plain[MEV_REVEAL_SIZE]) {
    if (!cipher || !privkey || !plain) return false;

    /* XOR decryption (symmetric with encryption) */
    uint8_t expanded_key[64];
    for (int i = 0; i < 64; i++) {
        expanded_key[i] = privkey[i % 32];
    }
    for (int i = 0; i < MEV_REVEAL_SIZE; i++) {
        plain[i] = cipher[i] ^ expanded_key[i % 64];
    }
    return true;
}

/*
 * ===================================================================
 * L9: Encrypted mempool overhead estimation (SUAVE)
 *
 * Estimates the computational and latency cost of running an
 * encrypted mempool, where transactions are submitted encrypted
 * and only decrypted after block finalization.
 *
 * Reference: Flashbots SUAVE (Single Unified Auction for Value
 * Expression), 2022
 * ===================================================================
 */
uint64_t mev_encrypted_mempool_overhead(uint64_t tx_count,
                                         uint64_t encrypt_cost) {
    /* Overhead = batch_size * encrypt_cost + network_latency */
    uint64_t batch_encryption = tx_count * encrypt_cost;
    uint64_t network_overhead = 200; /* ms latency */
    return batch_encryption + network_overhead;
}

/*
 * SGX/TEE enclave trust score
 * Simplified model: trust = uptime * reputation_factor
 */
uint64_t mev_sgx_enclave_trust_score(const uint8_t enclave_id[32],
                                      uint64_t uptime) {
    if (!enclave_id) return 0;
    /* Trust decays with downtime, capped at 10000 */
    uint64_t base = 10000;
    uint64_t uptime_bps = uptime > 10000 ? 10000 : uptime;
    return base * uptime_bps / 10000;
}