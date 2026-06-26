#include "consensus_pow.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/sha.h>

void pow_sha256(const uint8_t *data, size_t len, uint8_t out[POW_HASH_LEN]) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, len);
    SHA256_Final(out, &ctx);
}

void pow_sha256d(const uint8_t *data, size_t len, uint8_t out[POW_HASH_LEN]) {
    uint8_t tmp[POW_HASH_LEN];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, len);
    SHA256_Final(tmp, &ctx);
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, tmp, POW_HASH_LEN);
    SHA256_Final(out, &ctx);
}

int pow_block_hash(const pow_block_header *header, uint8_t out[POW_HASH_LEN]) {
    if (!header || !out) return -1;
    uint8_t buf[80];
    size_t off = 0;
    memcpy(buf + off, &header->version, 4);  off += 4;
    memcpy(buf + off, header->prev_block_hash, 32); off += 32;
    memcpy(buf + off, header->merkle_root, 32); off += 32;
    memcpy(buf + off, &header->timestamp, 4); off += 4;
    memcpy(buf + off, &header->bits, 4); off += 4;
    memcpy(buf + off, &header->nonce, 4); off += 4;
    pow_sha256d(buf, off, out);
    return 0;
}

static int hash_less_than(const uint8_t a[POW_HASH_LEN], const uint8_t b[POW_HASH_LEN]) {
    for (int i = 0; i < POW_HASH_LEN; i++) {
        if (a[i] < b[i]) return 1;
        if (a[i] > b[i]) return 0;
    }
    return 0;
}

int pow_validate_hash(const uint8_t hash[POW_HASH_LEN], const pow_target *target, int *valid) {
    if (!hash || !target || !valid) return -1;
    *valid = hash_less_than(hash, target->bytes) ? 1 : 0;
    return 0;
}

int pow_mine(pow_block *block, const pow_target *target, uint64_t max_nonce) {
    if (!block || !target) return -1;
    uint8_t hash[POW_HASH_LEN];
    block->header.nonce = 0;
    while (block->header.nonce < max_nonce) {
        pow_block_hash(&block->header, hash);
        if (hash_less_than(hash, target->bytes)) {
            memcpy(block->block_hash, hash, POW_HASH_LEN);
            return 0;
        }
        block->header.nonce++;
        if (block->header.nonce == 0) break;
    }
    return -1;
}

int pow_mine_incremental(pow_block *block, const pow_target *target,
                          uint64_t start_nonce, uint64_t count, uint64_t *found_nonce) {
    if (!block || !target || !found_nonce) return -1;
    uint8_t hash[POW_HASH_LEN];
    uint64_t end = start_nonce + count;
    if (end < start_nonce) end = UINT64_MAX;
    for (uint64_t nonce = start_nonce; nonce < end; nonce++) {
        block->header.nonce = (uint32_t)(nonce & 0xFFFFFFFF);
        pow_block_hash(&block->header, hash);
        if (hash_less_than(hash, target->bytes)) {
            *found_nonce = nonce;
            memcpy(block->block_hash, hash, POW_HASH_LEN);
            return 0;
        }
    }
    *found_nonce = 0;
    return -1;
}

int pow_target_from_bits(uint32_t bits, pow_target *target) {
    if (!target) return -1;
    memset(target, 0, sizeof(pow_target));
    uint8_t exponent = (uint8_t)(bits >> 24);
    uint32_t coefficient = bits & 0x00FFFFFF;
    if (exponent <= 3) {
        target->bytes[POW_TARGET_LEN - 1] = (uint8_t)(exponent > 0 ? (coefficient >> (8 * (3 - exponent))) : coefficient >> 16);
        return 0;
    }
    int shift = exponent - 3;
    int byte_idx = POW_TARGET_LEN - shift;
    if (byte_idx >= 0) target->bytes[byte_idx] = (uint8_t)(coefficient >> 16);
    if (byte_idx + 1 < POW_TARGET_LEN) target->bytes[byte_idx + 1] = (uint8_t)(coefficient >> 8);
    if (byte_idx + 2 < POW_TARGET_LEN) target->bytes[byte_idx + 2] = (uint8_t)(coefficient);
    return 0;
}

int pow_target_to_bits(const pow_target *target, uint32_t *bits) {
    if (!target || !bits) return -1;
    int first = -1;
    for (int i = 0; i < POW_TARGET_LEN; i++) {
        if (target->bytes[i] != 0) { first = i; break; }
    }
    if (first == -1) { *bits = 0; return 0; }
    int exponent = POW_TARGET_LEN - first;
    uint32_t coefficient = (uint32_t)target->bytes[first] << 16;
    if (first + 1 < POW_TARGET_LEN) coefficient |= (uint32_t)target->bytes[first + 1] << 8;
    if (first + 2 < POW_TARGET_LEN) coefficient |= (uint32_t)target->bytes[first + 2];
    *bits = ((uint32_t)exponent << 24) | (coefficient & 0x00FFFFFF);
    return 0;
}

int pow_target_get_difficulty(const pow_target *target, uint64_t *difficulty) {
    if (!target || !difficulty) return -1;
    pow_target genesis;
    pow_target_from_bits(POW_GENESIS_BITS, &genesis);
    double ratio = 0.0;
    for (int i = 0; i < POW_TARGET_LEN; i++) {
        ratio = ratio * 256.0 + (double)genesis.bytes[i];
    }
    double tval = 0.0;
    for (int i = 0; i < POW_TARGET_LEN; i++) {
        tval = tval * 256.0 + (double)target->bytes[i];
    }
    if (tval < 1.0) tval = 1.0;
    *difficulty = (uint64_t)(ratio / tval);
    return 0;
}

int pow_adjust_target(const pow_chain *chain, uint32_t new_height, pow_target *new_target) {
    if (!chain || !new_target) return -1;
    if (new_height % POW_DIFFICULTY_PERIOD != 0) return -1;
    if (new_height < (uint32_t)POW_DIFFICULTY_PERIOD) {
        pow_target_from_bits(POW_GENESIS_BITS, new_target);
        return 0;
    }
    pow_block *start_block = NULL;
    pow_block *end_block = NULL;
    pow_chain_get_tip((pow_chain *)chain, &end_block);
    if (!end_block) return -1;
    uint32_t end_bits = end_block->header.bits;
    start_block = end_block;
    for (int i = 0; i < POW_DIFFICULTY_PERIOD && start_block; i++) {
        start_block = start_block->prev;
    }
    if (!start_block) return -1;
    uint32_t actual_timespan = end_block->header.timestamp - start_block->header.timestamp;
    uint32_t target_timespan = POW_DIFFICULTY_PERIOD * POW_TARGET_SPACING;
    if (actual_timespan < target_timespan / 4) actual_timespan = target_timespan / 4;
    if (actual_timespan > target_timespan * 4) actual_timespan = target_timespan * 4;
    uint64_t new_difficulty = 0;
    pow_target current;
    pow_target_from_bits(end_bits, &current);
    pow_target_get_difficulty(&current, &new_difficulty);
    new_difficulty = (new_difficulty * target_timespan) / actual_timespan;
    if (new_difficulty < 1) new_difficulty = 1;
    pow_target genesis;
    pow_target_from_bits(POW_GENESIS_BITS, &genesis);
    double gen_val = 0.0;
    for (int i = 0; i < POW_TARGET_LEN; i++) gen_val = gen_val * 256.0 + genesis.bytes[i];
    double nt_val = gen_val / (double)new_difficulty;
    for (int i = POW_TARGET_LEN - 1; i >= 0; i--) {
        new_target->bytes[i] = (uint8_t)((uint64_t)nt_val & 0xFF);
        nt_val = (nt_val - (double)(uint64_t)nt_val) * 256.0;
    }
    return 0;
}

int pow_adjust_target_multialgo(const pow_chain *chain, uint32_t new_height,
                                 int algo_index, pow_target *new_target) {
    (void)algo_index;
    return pow_adjust_target(chain, new_height, new_target);
}

int pow_block_create(pow_block *block, int32_t version, const uint8_t prev_hash[POW_HASH_LEN],
                      const uint8_t merkle_root[POW_HASH_LEN], uint32_t timestamp, uint32_t bits) {
    if (!block || !prev_hash || !merkle_root) return -1;
    memset(block, 0, sizeof(pow_block));
    block->header.version = version;
    memcpy(block->header.prev_block_hash, prev_hash, POW_HASH_LEN);
    memcpy(block->header.merkle_root, merkle_root, POW_HASH_LEN);
    block->header.timestamp = timestamp;
    block->header.bits = bits;
    block->header.nonce = 0;
    block->uncle_count = 0;
    return 0;
}

void pow_block_free(pow_block *block) {
    if (!block) return;
    free(block->tx_data);
    block->tx_data = NULL;
    block->tx_data_len = 0;
}

int pow_block_serialize(const pow_block *block, uint8_t *buf, size_t *len, size_t bufsz) {
    if (!block || !buf || !len || bufsz < 80) return -1;
    memset(buf, 0, bufsz);
    size_t off = 0;
    memcpy(buf + off, &block->header.version, 4); off += 4;
    memcpy(buf + off, block->header.prev_block_hash, 32); off += 32;
    memcpy(buf + off, block->header.merkle_root, 32); off += 32;
    memcpy(buf + off, &block->header.timestamp, 4); off += 4;
    memcpy(buf + off, &block->header.bits, 4); off += 4;
    memcpy(buf + off, &block->header.nonce, 4); off += 4;
    memcpy(buf + off, &block->tx_count, 4); off += 4;
    if (block->tx_data && block->tx_data_len > 0 && off + block->tx_data_len <= bufsz) {
        memcpy(buf + off, block->tx_data, block->tx_data_len);
        off += block->tx_data_len;
    }
    *len = off;
    return 0;
}

int pow_block_deserialize(pow_block *block, const uint8_t *buf, size_t len) {
    if (!block || !buf || len < 84) return -1;
    memset(block, 0, sizeof(pow_block));
    size_t off = 0;
    memcpy(&block->header.version, buf + off, 4); off += 4;
    memcpy(block->header.prev_block_hash, buf + off, 32); off += 32;
    memcpy(block->header.merkle_root, buf + off, 32); off += 32;
    memcpy(&block->header.timestamp, buf + off, 4); off += 4;
    memcpy(&block->header.bits, buf + off, 4); off += 4;
    memcpy(&block->header.nonce, buf + off, 4); off += 4;
    memcpy(&block->tx_count, buf + off, 4); off += 4;
    size_t remaining = len - off;
    if (remaining > 0) {
        block->tx_data = malloc(remaining);
        if (!block->tx_data) return -1;
        memcpy(block->tx_data, buf + off, remaining);
        block->tx_data_len = remaining;
    }
    return 0;
}

int pow_validate_block(const pow_block *block, const pow_target *target,
                        const uint8_t expected_merkle[POW_HASH_LEN], int *valid) {
    if (!block || !target || !expected_merkle || !valid) return -1;
    *valid = 0;
    if (memcmp(block->header.merkle_root, expected_merkle, POW_HASH_LEN) != 0) return 0;
    uint8_t hash[POW_HASH_LEN];
    pow_block_hash(&block->header, hash);
    if (memcmp(hash, block->block_hash, POW_HASH_LEN) != 0) return 0;
    if (!hash_less_than(hash, target->bytes)) return 0;
    *valid = 1;
    return 0;
}

int pow_validate_block_header(const pow_block_header *header, const pow_target *target, int *valid) {
    if (!header || !target || !valid) return -1;
    *valid = 0;
    uint8_t hash[POW_HASH_LEN];
    pow_block_hash(header, hash);
    *valid = hash_less_than(hash, target->bytes) ? 1 : 0;
    return 0;
}

int pow_chain_init(pow_chain *chain) {
    if (!chain) return -1;
    chain->head = NULL;
    chain->tail = NULL;
    chain->length = 0;
    chain->total_work = 0;
    return 0;
}

void pow_chain_free(pow_chain *chain) {
    if (!chain) return;
    pow_block *cur = chain->head;
    while (cur) {
        pow_block *next = cur->next;
        pow_block_free(cur);
        free(cur);
        cur = next;
    }
    chain->head = NULL;
    chain->tail = NULL;
    chain->length = 0;
    chain->total_work = 0;
}

int pow_chain_add_block(pow_chain *chain, pow_block *block) {
    if (!chain || !block) return -1;
    block->prev = NULL;
    block->next = NULL;
    if (!chain->head) {
        chain->head = block;
        chain->tail = block;
        chain->length = 1;
        chain->total_work = 0;
        pow_target t;
        pow_target_from_bits(POW_GENESIS_BITS, &t);
        uint64_t diff;
        pow_target_get_difficulty(&t, &diff);
        chain->total_work += diff;
        block->chain_work = diff;
        block->height = 0;
        return 0;
    }
    block->prev = chain->tail;
    block->prev->next = block;
    block->height = block->prev->height + 1;
    pow_target t;
    pow_target_from_bits(block->header.bits, &t);
    uint64_t diff;
    pow_target_get_difficulty(&t, &diff);
    block->chain_work = block->prev->chain_work + diff;
    chain->total_work = block->chain_work;
    chain->tail = block;
    chain->length++;
    return 0;
}

int pow_chain_remove_block(pow_chain *chain, pow_block *block) {
    if (!chain || !block) return -1;
    if (block->prev) block->prev->next = block->next;
    else chain->head = block->next;
    if (block->next) block->next->prev = block->prev;
    else chain->tail = block->prev;
    chain->length--;
    return 0;
}

int pow_chain_get_height(const pow_chain *chain, uint32_t *height) {
    if (!chain || !height) return -1;
    *height = chain->tail ? chain->tail->height : 0;
    return 0;
}

int pow_chain_get_tip(pow_chain *chain, pow_block **tip) {
    if (!chain || !tip) return -1;
    *tip = chain->tail;
    return 0;
}

int pow_chain_get_by_height(const pow_chain *chain, uint32_t height, pow_block **block) {
    if (!chain || !block) return -1;
    pow_block *cur = chain->tail;
    while (cur) {
        if (cur->height == height) { *block = cur; return 0; }
        if (cur->height < height) break;
        cur = cur->prev;
    }
    *block = NULL;
    return -1;
}

int pow_chain_reorg(pow_chain *chain, pow_chain *candidate) {
    if (!chain || !candidate) return -1;
    int longer = 0;
    if (pow_chain_compare(candidate, chain, &longer) != 0) return -1;
    if (!longer) return 0;
    pow_block *fork = NULL;
    pow_block *a = chain->tail;
    pow_block *b = candidate->tail;
    while (a && b) {
        if (memcmp(a->block_hash, b->block_hash, POW_HASH_LEN) == 0) { fork = a; break; }
        a = a->prev;
        b = b->prev;
    }
    while (chain->tail && chain->tail != fork) {
        pow_block *removed = chain->tail;
        chain->tail = chain->tail->prev;
        pow_block_free(removed);
        free(removed);
        chain->length--;
    }
    if (chain->tail) chain->tail->next = NULL;
    pow_block *to_add = candidate->tail;
    pow_block *stack[1024];
    int sp = 0;
    while (to_add && to_add != fork) {
        stack[sp++] = to_add;
        to_add = to_add->prev;
    }
    for (int i = sp - 1; i >= 0; i--) {
        pow_block *nb = malloc(sizeof(pow_block));
        if (!nb) return -1;
        memcpy(nb, stack[i], sizeof(pow_block));
        nb->tx_data = NULL;
        if (stack[i]->tx_data && stack[i]->tx_data_len > 0) {
            nb->tx_data = malloc(stack[i]->tx_data_len);
            if (!nb->tx_data) { free(nb); return -1; }
            memcpy(nb->tx_data, stack[i]->tx_data, stack[i]->tx_data_len);
            nb->tx_data_len = stack[i]->tx_data_len;
        }
        pow_chain_add_block(chain, nb);
    }
    return 0;
}

int pow_chain_compare(const pow_chain *a, const pow_chain *b, int *longer) {
    if (!a || !b || !longer) return -1;
    *longer = (a->total_work > b->total_work) ? 1 : 0;
    return 0;
}

int pow_block_add_uncle(pow_block *block, pow_block *uncle) {
    if (!block || !uncle || block->uncle_count >= 2) return -1;
    block->uncles[block->uncle_count++] = uncle;
    return 0;
}

int pow_ghost_score(const pow_block *block, uint64_t *score) {
    if (!block || !score) return -1;
    *score = block->chain_work;
    for (int i = 0; i < block->uncle_count; i++) {
        if (block->uncles[i]) *score += block->uncles[i]->chain_work / 32;
    }
    return 0;
}
