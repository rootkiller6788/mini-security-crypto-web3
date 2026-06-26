#ifndef CONSENSUS_POW_H
#define CONSENSUS_POW_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define POW_HASH_LEN        32
#define POW_TARGET_LEN      32
#define POW_MAX_BLOCK_SIZE  (1024 * 1024 * 4)
#define POW_DIFFICULTY_PERIOD  2016
#define POW_TARGET_SPACING     600
#define POW_MAX_NONCE         UINT64_MAX
#define POW_GENESIS_BITS      0x1d00ffff

typedef struct pow_block_s pow_block;

typedef struct {
    int32_t  version;
    uint8_t  prev_block_hash[POW_HASH_LEN];
    uint8_t  merkle_root[POW_HASH_LEN];
    uint32_t timestamp;
    uint32_t bits;
    uint32_t nonce;
} pow_block_header;

struct pow_block_s {
    pow_block_header header;
    uint32_t         tx_count;
    uint8_t         *tx_data;
    size_t           tx_data_len;
    uint8_t          block_hash[POW_HASH_LEN];
    uint32_t         height;
    uint64_t         chain_work;
    pow_block       *prev;
    pow_block       *next;
    pow_block       *uncles[2];
    int              uncle_count;
};

typedef struct pow_chain_s {
    pow_block *head;
    pow_block *tail;
    size_t     length;
    uint64_t   total_work;
} pow_chain;

typedef struct {
    uint8_t bytes[POW_TARGET_LEN];
} pow_target;

void pow_sha256(const uint8_t *data, size_t len, uint8_t out[POW_HASH_LEN]);
void pow_sha256d(const uint8_t *data, size_t len, uint8_t out[POW_HASH_LEN]);

int  pow_block_hash(const pow_block_header *header, uint8_t out[POW_HASH_LEN]);
int  pow_validate_hash(const uint8_t hash[POW_HASH_LEN], const pow_target *target, int *valid);

int  pow_mine(pow_block *block, const pow_target *target, uint64_t max_nonce);
int  pow_mine_incremental(pow_block *block, const pow_target *target,
                          uint64_t start_nonce, uint64_t count, uint64_t *found_nonce);

int  pow_target_from_bits(uint32_t bits, pow_target *target);
int  pow_target_to_bits(const pow_target *target, uint32_t *bits);
int  pow_target_get_difficulty(const pow_target *target, uint64_t *difficulty);

int  pow_adjust_target(const pow_chain *chain, uint32_t new_height, pow_target *new_target);
int  pow_adjust_target_multialgo(const pow_chain *chain, uint32_t new_height,
                                 int algo_index, pow_target *new_target);

int  pow_block_create(pow_block *block, int32_t version, const uint8_t prev_hash[POW_HASH_LEN],
                      const uint8_t merkle_root[POW_HASH_LEN], uint32_t timestamp, uint32_t bits);
void pow_block_free(pow_block *block);
int  pow_block_serialize(const pow_block *block, uint8_t *buf, size_t *len, size_t bufsz);
int  pow_block_deserialize(pow_block *block, const uint8_t *buf, size_t len);

int  pow_validate_block(const pow_block *block, const pow_target *target,
                        const uint8_t expected_merkle[POW_HASH_LEN], int *valid);
int  pow_validate_block_header(const pow_block_header *header, const pow_target *target, int *valid);

int  pow_chain_init(pow_chain *chain);
void pow_chain_free(pow_chain *chain);
int  pow_chain_add_block(pow_chain *chain, pow_block *block);
int  pow_chain_remove_block(pow_chain *chain, pow_block *block);
int  pow_chain_get_height(const pow_chain *chain, uint32_t *height);
int  pow_chain_get_tip(pow_chain *chain, pow_block **tip);
int  pow_chain_get_by_height(const pow_chain *chain, uint32_t height, pow_block **block);

int  pow_chain_reorg(pow_chain *chain, pow_chain *candidate);
int  pow_chain_compare(const pow_chain *a, const pow_chain *b, int *longer);

int  pow_block_add_uncle(pow_block *block, pow_block *uncle);
int  pow_ghost_score(const pow_block *block, uint64_t *score);

#ifdef __cplusplus
}
#endif

#endif
