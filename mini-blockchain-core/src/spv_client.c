#include "spv_client.h"
#include "merkle_tree.h"
#include "consensus_pow.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include <openssl/sha.h>

/* ?? SHA256d utility ?? */
void spv_sha256d(const uint8_t *data, size_t len, uint8_t out[SPV_HASH_LEN]) {
    uint8_t tmp[SPV_HASH_LEN];
    SHA256(data, len, tmp);
    SHA256(tmp, SPV_HASH_LEN, out);
}

/* ?? MurmurHash3-32 (used in BIP 37 bloom filters) ?? */
uint32_t spv_murmur_hash(const uint8_t *data, size_t len, uint32_t seed) {
    const uint32_t c1 = 0xcc9e2d51;
    const uint32_t c2 = 0x1b873593;
    uint32_t h = seed;
    for (size_t i = 0; i + 4 <= len; i += 4) {
        uint32_t k = (uint32_t)data[i] | ((uint32_t)data[i+1] << 8) |
                     ((uint32_t)data[i+2] << 16) | ((uint32_t)data[i+3] << 24);
        k *= c1; k = (k << 15) | (k >> 17); k *= c2;
        h ^= k; h = (h << 13) | (h >> 19); h = h * 5 + 0xe6546b64;
    }
    uint32_t k = 0;
    switch (len & 3) {
    case 3: k |= (uint32_t)data[len - 3] << 16; /* fall through */
    case 2: k |= (uint32_t)data[len - 2] << 8;  /* fall through */
    case 1: k |= (uint32_t)data[len - 1];
        k *= c1; k = (k << 15) | (k >> 17); k *= c2; h ^= k; break;
    default: break;
    }
    h ^= (uint32_t)len;
    h ^= h >> 16; h *= 0x85ebca6b;
    h ^= h >> 13; h *= 0xc2b2ae35; h ^= h >> 16;
    return h;
}

/* ?? Header chain management ?? */

int spv_chain_init(spv_header_chain *chain, size_t capacity) {
    if (!chain || capacity == 0) return -1;
    chain->headers = calloc(capacity, sizeof(spv_header));
    if (!chain->headers) return -1;
    chain->count = 0;
    chain->capacity = capacity;
    chain->total_work = 0;
    chain->best_height = 0;
    return 0;
}

void spv_chain_free(spv_header_chain *chain) {
    if (!chain) return;
    free(chain->headers);
    memset(chain, 0, sizeof(spv_header_chain));
}

int spv_chain_add_header(spv_header_chain *chain, const spv_header *header,
                          const uint8_t block_hash[SPV_HASH_LEN]) {
    if (!chain || !header || !block_hash) return -1;
    if (chain->count >= chain->capacity) {
        size_t nc = chain->capacity * 2;
        spv_header *tmp = realloc(chain->headers, nc * sizeof(spv_header));
        if (!tmp) return -1;
        chain->headers = tmp;
        chain->capacity = nc;
    }
    spv_header *h = &chain->headers[chain->count];
    memcpy(h, header, sizeof(spv_header));
    memcpy(h->block_hash, block_hash, SPV_HASH_LEN);
    h->height = chain->count;
    if (chain->count > 0) {
        spv_header *prev = &chain->headers[chain->count - 1];
        int valid = 0;
        spv_validate_header_link(prev, h, &valid);
        if (!valid) return -1;
        uint64_t diff = 0;
        spv_estimate_difficulty(h, &diff);
        h->chain_work = prev->chain_work + diff;
    } else {
        uint64_t diff = 0;
        spv_estimate_difficulty(h, &diff);
        h->chain_work = diff;
    }
    chain->total_work = h->chain_work;
    chain->best_height = h->height;
    chain->count++;
    return 0;
}

int spv_chain_get_best_height(const spv_header_chain *chain, uint32_t *height) {
    if (!chain || !height) return -1;
    *height = chain->best_height;
    return 0;
}

/* Link validation: check prev_hash match and PoW */
int spv_validate_header_link(const spv_header *prev, const spv_header *curr,
                               int *valid) {
    if (!prev || !curr || !valid) return -1;
    *valid = 0;
    uint8_t computed_hash[SPV_HASH_LEN];
    /* Use PoW block hash algorithm on prev header */
    pow_block_header hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.version = prev->version;
    memcpy(hdr.prev_block_hash, prev->prev_block_hash, SPV_HASH_LEN);
    memcpy(hdr.merkle_root, prev->merkle_root, SPV_HASH_LEN);
    hdr.timestamp = prev->timestamp;
    hdr.bits = prev->bits;
    hdr.nonce = prev->nonce;
    pow_block_hash(&hdr, computed_hash);
    if (memcmp(computed_hash, curr->prev_block_hash, SPV_HASH_LEN) != 0) return 0;
    if (curr->timestamp < prev->timestamp) return 0;
    *valid = 1;
    return 0;
}

int spv_check_pow(const spv_header *header, int *valid) {
    if (!header || !valid) return -1;
    *valid = 0;
    pow_block_header hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.version = header->version;
    memcpy(hdr.prev_block_hash, header->prev_block_hash, SPV_HASH_LEN);
    memcpy(hdr.merkle_root, header->merkle_root, SPV_HASH_LEN);
    hdr.timestamp = header->timestamp;
    hdr.bits = header->bits;
    hdr.nonce = header->nonce;
    uint8_t hash[SPV_HASH_LEN];
    pow_block_hash(&hdr, hash);
    pow_target target;
    pow_target_from_bits(header->bits, &target);
    int pow_ok = 0;
    pow_validate_hash(hash, &target, &pow_ok);
    if (!pow_ok) return 0;
    *valid = (memcmp(hash, header->block_hash, SPV_HASH_LEN) == 0) ? 1 : 0;
    return 0;
}

int spv_chain_validate(const spv_header_chain *chain, int *valid) {
    if (!chain || !valid) return -1;
    *valid = 0;
    if (chain->count == 0) { *valid = 1; return 0; }
    for (size_t i = 0; i < chain->count; i++) {
        int pow_ok = 0;
        spv_check_pow(&chain->headers[i], &pow_ok);
        if (!pow_ok) return 0;
    }
    for (size_t i = 1; i < chain->count; i++) {
        int link_ok = 0;
        spv_validate_header_link(&chain->headers[i-1], &chain->headers[i], &link_ok);
        if (!link_ok) return 0;
    }
    *valid = 1;
    return 0;
}

int spv_chain_find_fork(const spv_header_chain *a, const spv_header_chain *b,
                          spv_header **fork) {
    if (!a || !b || !fork) return -1;
    *fork = NULL;
    size_t min_count = (a->count < b->count) ? a->count : b->count;
    for (size_t i = 0; i < min_count; i++) {
        if (memcmp(a->headers[i].block_hash, b->headers[i].block_hash,
                   SPV_HASH_LEN) != 0) {
            *fork = (i > 0) ? &a->headers[i - 1] : NULL;
            return 0;
        }
    }
    *fork = &a->headers[min_count - 1];
    return 0;
}

int spv_chain_calc_work(spv_header_chain *chain) {
    if (!chain) return -1;
    chain->total_work = 0;
    for (size_t i = 0; i < chain->count; i++) {
        uint64_t diff = 0;
        spv_estimate_difficulty(&chain->headers[i], &diff);
        chain->headers[i].chain_work = (i > 0)
            ? chain->headers[i-1].chain_work + diff : diff;
    }
    if (chain->count > 0)
        chain->total_work = chain->headers[chain->count-1].chain_work;
    return 0;
}

/* Difficulty estimate from bits */
int spv_estimate_difficulty(const spv_header *header, uint64_t *difficulty) {
    if (!header || !difficulty) return -1;
    pow_target target;
    pow_target_from_bits(header->bits, &target);
    return pow_target_get_difficulty(&target, difficulty) == 0 ? 0 : -1;
}

/* ?? Bloom filter (BIP 37) ?? */

static void bloom_set_bit(spv_bloom_filter *bf, uint32_t bit) {
    bit %= (SPV_BLOOM_FILTER_SIZE);
    bf->filter[bit / 8] |= (uint8_t)(1 << (bit % 8));
}

static int bloom_get_bit(const spv_bloom_filter *bf, uint32_t bit) {
    bit %= (SPV_BLOOM_FILTER_SIZE);
    return (bf->filter[bit / 8] >> (bit % 8)) & 1;
}

int spv_bloom_init(spv_bloom_filter *bf, uint32_t n_hash_funcs,
                     uint32_t n_tweak, uint8_t n_flags) {
    if (!bf) return -1;
    memset(bf, 0, sizeof(spv_bloom_filter));
    bf->n_hash_funcs = (n_hash_funcs > 0) ? n_hash_funcs : SPV_BLOOM_HASH_COUNT;
    bf->n_tweak = n_tweak;
    bf->n_flags = n_flags;
    return 0;
}

void spv_bloom_free(spv_bloom_filter *bf) {
    if (!bf) return;
    memset(bf, 0, sizeof(spv_bloom_filter));
}

int spv_bloom_add(spv_bloom_filter *bf, const uint8_t *data, size_t len) {
    if (!bf || !data || len == 0) return -1;
    for (uint32_t i = 0; i < bf->n_hash_funcs; i++) {
        uint32_t seed = i * 0xFBA4C795 + bf->n_tweak;
        uint32_t hash = spv_murmur_hash(data, len, seed);
        bloom_set_bit(bf, hash);
    }
    return 0;
}

int spv_bloom_contains(const spv_bloom_filter *bf, const uint8_t *data,
                         size_t len, int *found) {
    if (!bf || !data || !found) return -1;
    *found = 1;
    for (uint32_t i = 0; i < bf->n_hash_funcs; i++) {
        uint32_t seed = i * 0xFBA4C795 + bf->n_tweak;
        uint32_t hash = spv_murmur_hash(data, len, seed);
        if (!bloom_get_bit(bf, hash)) { *found = 0; break; }
    }
    return 0;
}

int spv_bloom_add_txid(spv_bloom_filter *bf, const uint8_t txid[SPV_HASH_LEN]) {
    if (!bf || !txid) return -1;
    return spv_bloom_add(bf, txid, SPV_HASH_LEN);
}

int spv_bloom_add_address(spv_bloom_filter *bf, const uint8_t *address,
                             size_t addr_len) {
    if (!bf || !address) return -1;
    return spv_bloom_add(bf, address, addr_len);
}

/* ?? SPV Merkle verification ?? */

/*
 * Verify a transaction is included in a block given the Merkle proof path.
 *
 * Algorithm (from Bitcoin whitepaper ?8):
 *   Given txid, merkle_root, and the Merkle proof path (sibling hashes +
 *   direction bits), recompute the Merkle root and compare.
 *
 * Complexity: O(log n) where n = tx_count.
 */
int spv_verify_tx_in_block(const uint8_t txid[SPV_HASH_LEN],
                             const uint8_t merkle_root[SPV_HASH_LEN],
                             const uint8_t *merkle_proof_path, int proof_depth,
                             int *path_directions, size_t tx_index,
                             size_t tx_count, int *verified) {
    if (!txid || !merkle_root || !merkle_proof_path || !path_directions ||
        !verified) return -1;
    *verified = 0;
    if (proof_depth <= 0) return 0;

    uint8_t current[SPV_HASH_LEN];
    memcpy(current, txid, SPV_HASH_LEN);

    /* Walk up the tree, hashing with sibling at each level */
    for (int i = 0; i < proof_depth; i++) {
        uint8_t combined[SPV_HASH_LEN * 2];
        if (path_directions[i] == 0) {
            /* tx is left child, sibling is right */
            memcpy(combined, current, SPV_HASH_LEN);
            memcpy(combined + SPV_HASH_LEN, merkle_proof_path + i * SPV_HASH_LEN,
                   SPV_HASH_LEN);
        } else {
            /* tx is right child, sibling is left */
            memcpy(combined, merkle_proof_path + i * SPV_HASH_LEN, SPV_HASH_LEN);
            memcpy(combined + SPV_HASH_LEN, current, SPV_HASH_LEN);
        }
        spv_sha256d(combined, SPV_HASH_LEN * 2, current);
    }

    *verified = (memcmp(current, merkle_root, SPV_HASH_LEN) == 0) ? 1 : 0;
    return 0;
}

/* ?? Nakamoto confidence (L4: CAP theorem consequence) ?? */

/*
 * Nakamoto consensus confidence:
 *   P(attack succeeds) = 1 - sum_{k=0..z} (lambda^k * e^{-lambda} / k!) *
 *                        (1 - (q/p)^{z-k})
 * where z = confirmations, q = attacker hash rate fraction,
 *       lambda = z * (q/p)
 *       p = 1 - q (honest hash rate fraction)
 *
 * This formula, from the Bitcoin whitepaper ?11, quantifies the probability
 * that an attacker with q fraction of total hash power can rewrite z blocks
 * of history.
 *
 * We compute an exponential approximation (valid for small q):
 *   confidence ? 1 - (q / (1-q))^{confirmations}
 * (valid when confirmations is large enough)
 */
int spv_nakamoto_confidence(const spv_header_chain *chain,
                              uint32_t tx_block_height, int confirmations,
                              double *confidence) {
    if (!chain || !confidence) return -1;
    *confidence = 0.0;
    if (confirmations <= 0) { *confidence = 0.0; return 0; }

    /* Assume 30% attacker (q = 0.3) ? conservative estimate */
    double q = 0.3;
    double p = 1.0 - q;

    if (q >= 0.5) { *confidence = 0.0; return 0; }

    /* Satoshi's formula: CDF of Poisson distribution */
    double lambda = (double)confirmations * (q / p);
    double poisson_sum = 0.0;
    double term = exp(-lambda);

    for (int k = 0; k <= confirmations; k++) {
        if (k > 0) term *= lambda / (double)k;
        double attack_success = 1.0 - pow(q / p, (double)(confirmations - k));
        if (attack_success < 0.0) attack_success = 0.0;
        poisson_sum += term * attack_success;
        if (term < 1e-15) break;
    }

    *confidence = 1.0 - poisson_sum;
    if (*confidence < 0.0) *confidence = 0.0;
    if (*confidence > 1.0) *confidence = 1.0;
    return 0;
}
