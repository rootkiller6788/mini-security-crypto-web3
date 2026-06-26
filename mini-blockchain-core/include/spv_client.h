#ifndef SPV_CLIENT_H
#define SPV_CLIENT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * SPV (Simplified Payment Verification) ? Bitcoin Whitepaper ?8
 *
 * Lightweight client that verifies transactions without storing the full blockchain.
 * Validates block headers form a valid PoW chain (Nakamoto consensus) and uses
 * Merkle proofs to confirm transaction inclusion.
 *
 * Core theorem (Nakamoto 2008): If a majority of CPU power is controlled by honest
 * nodes, the honest chain will grow fastest and outpace any competing chains.
 *
 * CAP theorem application: Bitcoin prioritizes Partition tolerance and Consistency
 * over Availability (eventual consistency via longest-chain rule).
 *
 * References:
 *   - Nakamoto, S. "Bitcoin: A Peer-to-Peer Electronic Cash System" (2008) ?8
 *   - BIP 37: Connection Bloom Filtering
 *   - Bitcoin Core headers-first sync
 */

#define SPV_HASH_LEN           32
#define SPV_MAX_HEADERS        2016
#define SPV_BLOOM_FILTER_SIZE  2048
#define SPV_BLOOM_HASH_COUNT   5
#define SPV_MAX_MATCHES        64

/* ?? Block header (SPV context) ?? */

typedef struct {
    int32_t  version;
    uint8_t  prev_block_hash[SPV_HASH_LEN];
    uint8_t  merkle_root[SPV_HASH_LEN];
    uint32_t timestamp;
    uint32_t bits;
    uint32_t nonce;
    uint8_t  block_hash[SPV_HASH_LEN];
    uint32_t height;
    uint64_t chain_work;
} spv_header;

/* ?? SPV header chain ?? */

typedef struct {
    spv_header *headers;
    size_t      count;
    size_t      capacity;
    uint64_t    total_work;
    uint32_t    best_height;
} spv_header_chain;

/* ?? Bloom filter (BIP 37) ?? */

typedef struct {
    uint8_t  filter[SPV_BLOOM_FILTER_SIZE / 8];
    uint32_t n_hash_funcs;
    uint32_t n_tweak;
    uint8_t  n_flags;
} spv_bloom_filter;

/* ?? Transaction match record ?? */

typedef struct {
    uint8_t  txid[SPV_HASH_LEN];
    uint8_t  block_hash[SPV_HASH_LEN];
    uint32_t block_height;
    uint32_t tx_index;
    uint32_t timestamp;
} spv_tx_match;

/* ?? Merkle batch proof ?? */

typedef struct {
    spv_tx_match matches[SPV_MAX_MATCHES];
    size_t       match_count;
} spv_match_result;

/* ?? API ?? */

/* Header chain management */
int  spv_chain_init(spv_header_chain *chain, size_t capacity);
void spv_chain_free(spv_header_chain *chain);
int  spv_chain_add_header(spv_header_chain *chain, const spv_header *header,
                           const uint8_t block_hash[SPV_HASH_LEN]);
int  spv_chain_get_best_height(const spv_header_chain *chain, uint32_t *height);
int  spv_chain_validate(const spv_header_chain *chain, int *valid);
int  spv_chain_find_fork(const spv_header_chain *a, const spv_header_chain *b,
                          spv_header **fork);
int  spv_chain_calc_work(spv_header_chain *chain);

/* Header validation */
int  spv_validate_header_link(const spv_header *prev, const spv_header *curr,
                               int *valid);
int  spv_check_pow(const spv_header *header, int *valid);
int  spv_estimate_difficulty(const spv_header *header, uint64_t *difficulty);

/* Bloom filter (BIP 37) ? probabilistic transaction monitoring */
int  spv_bloom_init(spv_bloom_filter *bf, uint32_t n_hash_funcs,
                     uint32_t n_tweak, uint8_t n_flags);
void spv_bloom_free(spv_bloom_filter *bf);
int  spv_bloom_add(spv_bloom_filter *bf, const uint8_t *data, size_t len);
int  spv_bloom_contains(const spv_bloom_filter *bf, const uint8_t *data,
                         size_t len, int *found);
int  spv_bloom_add_txid(spv_bloom_filter *bf, const uint8_t txid[SPV_HASH_LEN]);
int  spv_bloom_add_address(spv_bloom_filter *bf, const uint8_t *address,
                             size_t addr_len);

/* SPV transaction verification */
int  spv_verify_tx_in_block(const uint8_t txid[SPV_HASH_LEN],
                             const uint8_t merkle_root[SPV_HASH_LEN],
                             const uint8_t *merkle_proof_path, int proof_depth,
                             int *path_directions, size_t tx_index,
                             size_t tx_count, int *verified);

/* NHash (Nakamoto consensus) time computation */
int  spv_nakamoto_confidence(const spv_header_chain *chain,
                              uint32_t tx_block_height, int confirmations,
                              double *confidence);

/* Utility */
void spv_sha256d(const uint8_t *data, size_t len, uint8_t out[SPV_HASH_LEN]);
uint32_t spv_murmur_hash(const uint8_t *data, size_t len, uint32_t seed);

#ifdef __cplusplus
}
#endif

#endif
