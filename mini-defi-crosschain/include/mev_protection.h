#ifndef MEV_PROTECTION_H
#define MEV_PROTECTION_H

#include <stdbool.h>
#include <stdint.h>

#define MEV_MAX_BUNDLES          64
#define MEV_MAX_TXS_PER_BUNDLE   16
#define MEV_HASH_SIZE            32
#define MEV_COMMIT_SIZE          32
#define MEV_REVEAL_SIZE          64
#define MEV_ADDR_SIZE            20
#define MEV_MAX_BLOCKS           256
#define MEV_BATCH_SIZE           128

/* L1: MEV types and core structures */
typedef enum {
    MEV_FRONTRUNNING,
    MEV_BACKRUNNING,
    MEV_SANDWICH,
    MEV_LIQUIDATION,
    MEV_ARBITRAGE,
    MEV_JUST_IN_TIME
} MEVType;

typedef enum {
    MEV_AUCTION_FCFS,
    MEV_AUCTION_PGA,
    MEV_AUCTION_SEALED_BID,
    MEV_AUCTION_BATCH
} MEVAuctionType;

typedef struct {
    uint8_t  tx_hash[MEV_HASH_SIZE];
    uint8_t  sender[MEV_ADDR_SIZE];
    uint64_t gas_price;
    uint64_t gas_limit;
    uint64_t priority_fee;
    bool     is_bundle;
    int      bundle_index;
} MEVTx;

typedef struct {
    MEVType  type;
    uint8_t  attacker[MEV_ADDR_SIZE];
    uint8_t  victim[MEV_ADDR_SIZE];
    uint64_t profit;
    uint64_t victim_loss;
    uint64_t gas_cost;
    bool     success;
} MEVAttack;

typedef struct {
    uint8_t  bundle_id[MEV_HASH_SIZE];
    MEVTx    txs[MEV_MAX_TXS_PER_BUNDLE];
    int      tx_count;
    uint64_t total_profit;
    uint64_t total_gas;
    uint64_t bid_amount;
    bool     included;
    int      priority;
} MEVBundle;

/* L3: Commit-Reveal scheme */
typedef struct {
    uint8_t  commit_hash[MEV_COMMIT_SIZE];
    uint8_t  sender[MEV_ADDR_SIZE];
    uint64_t timestamp;
    bool     committed;
} MEVCommit;

typedef struct {
    uint8_t  commit_hash[MEV_COMMIT_SIZE];
    uint8_t  reveal_data[MEV_REVEAL_SIZE];
    uint8_t  sender[MEV_ADDR_SIZE];
    uint64_t timestamp;
    bool     verified;
} MEVReveal;

/* L6: Batch auction engine */
typedef struct {
    uint8_t  order_id[MEV_HASH_SIZE];
    uint8_t  trader[MEV_ADDR_SIZE];
    uint8_t  token_in[MEV_ADDR_SIZE];
    uint8_t  token_out[MEV_ADDR_SIZE];
    uint64_t amount_in;
    uint64_t min_amount_out;
    uint64_t price_limit;
    bool     is_buy;
    uint64_t filled_amount;
    bool     settled;
} MEVBatchOrder;

typedef struct {
    MEVBatchOrder orders[MEV_BATCH_SIZE];
    int           order_count;
    uint64_t      clearing_price;
    uint64_t      total_volume;
    uint64_t      batch_id;
    uint64_t      start_time;
    uint64_t      end_time;
    bool          settled;
} MEVBatchAuction;

/* L1: Core API — MEV detection and simulation */
void        mev_attack_simulate(MEVAttack *attack, MEVType type, uint64_t mempool_gas);
bool        mev_detect_frontrunning(const MEVTx *txs, int count, MEVAttack *result);
MEVAttack   mev_simulate_sandwich(const MEVTx *victim_tx, uint64_t token_price, uint64_t slippage);
uint64_t    mev_calculate_extractable_value(const MEVTx *txs, int count);

/* L3: Commit-Reveal pattern */
bool        mev_commit_generate(const uint8_t data[MEV_REVEAL_SIZE], const uint8_t sender[MEV_ADDR_SIZE], uint8_t commit_out[MEV_COMMIT_SIZE]);
bool        mev_commit_store(MEVCommit *commits, int *count, int max_count, const uint8_t commit_hash[MEV_COMMIT_SIZE], const uint8_t sender[MEV_ADDR_SIZE], uint64_t time);
bool        mev_reveal_submit(MEVReveal *reveal, const uint8_t data[MEV_REVEAL_SIZE], const uint8_t sender[MEV_ADDR_SIZE]);
bool        mev_reveal_verify(const MEVCommit *commit, const MEVReveal *reveal);
bool        mev_commit_scheme_verify_opening(const uint8_t commit[MEV_COMMIT_SIZE], const uint8_t reveal[MEV_REVEAL_SIZE]);

/* L5: Bundle construction and ranking (Flashbots-style) */
MEVBundle   mev_bundle_create(const MEVTx *txs, int count);
int         mev_bundle_merge(MEVBundle *dest, const MEVBundle *src);
bool        mev_bundle_add_tx(MEVBundle *bundle, const MEVTx *tx);
void        mev_bundle_rank_by_profit(MEVBundle *bundles, int count);
uint64_t    mev_bundle_gas_price_bid(const MEVBundle *bundle);

/* L6: Priority Gas Auction (PGA) */
void        mev_pga_rank_bids(MEVBundle *bundles, int count);
uint64_t    mev_pga_optimal_bid(uint64_t expected_profit, uint64_t competitor_bid);
int         mev_pga_select_winner(const MEVBundle *bundles, int count, uint64_t base_fee);

/* L6: Batch auction matching (CoW Protocol style) */
void        mev_batch_auction_init(MEVBatchAuction *auction, uint64_t batch_id, uint64_t duration);
bool        mev_batch_auction_submit(MEVBatchAuction *auction, const MEVBatchOrder *order);
void        mev_batch_auction_settle(MEVBatchAuction *auction);
uint64_t    mev_batch_clearing_price(const MEVBatchAuction *auction);
bool        mev_batch_is_fair(const MEVBatchAuction *auction);
void        mev_batch_match_orders(MEVBatchAuction *auction);

/* L8: Advanced — threshold encryption for sealed-bid MEV protection */
bool        mev_threshold_encrypt(const uint8_t plain[MEV_REVEAL_SIZE], const uint8_t pubkey[64], uint8_t cipher[MEV_REVEAL_SIZE]);
bool        mev_threshold_decrypt(const uint8_t cipher[MEV_REVEAL_SIZE], const uint8_t privkey[32], uint8_t plain[MEV_REVEAL_SIZE]);

/* L9: SUAVE / encrypted mempools (industry frontier — documented) */
uint64_t    mev_encrypted_mempool_overhead(uint64_t tx_count, uint64_t encrypt_cost);
uint64_t    mev_sgx_enclave_trust_score(const uint8_t enclave_id[32], uint64_t uptime);

#endif
