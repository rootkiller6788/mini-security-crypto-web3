#include "tx_pool.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/sha.h>

uint64_t txpool_time_now(void) {
    return (uint64_t)time(NULL);
}

int txpool_compute_txid(const uint8_t *raw, size_t raw_len, uint8_t txid[TXPOOL_TXID_LEN]) {
    if (!raw || !txid || raw_len == 0) return -1;
    SHA256_CTX ctx;
    uint8_t tmp[TXPOOL_TXID_LEN];
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, raw, raw_len);
    SHA256_Final(tmp, &ctx);
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, tmp, TXPOOL_TXID_LEN);
    SHA256_Final(txid, &ctx);
    return 0;
}

int txpool_init(txpool *pool, size_t max_size) {
    if (!pool) return -1;
    if (max_size == 0 || max_size > TXPOOL_MAX_POOL_SIZE) max_size = TXPOOL_DEFAULT_MAX;
    pool->txs = calloc(max_size, sizeof(txpool_tx));
    if (!pool->txs) return -1;
    pool->count = 0;
    pool->capacity = max_size;
    pool->max_size = max_size;
    pool->min_gas_price = 1;
    pool->rbf_ratio = 1.1;
    return 0;
}

void txpool_free(txpool *pool) {
    if (!pool) return;
    for (size_t i = 0; i < pool->count; i++) {
        free(pool->txs[i].raw);
    }
    free(pool->txs);
    pool->txs = NULL;
    pool->count = 0;
    pool->capacity = 0;
}

int txpool_validate_tx(const uint8_t *raw, size_t raw_len, int *valid) {
    if (!raw || !valid) return -1;
    *valid = 0;
    if (raw_len < 10) return 0;
    uint32_t version;
    memcpy(&version, raw, 4);
    if (version < 1 || version > 2) return 0;
    *valid = 1;
    return 0;
}

int txpool_contains(txpool *pool, const uint8_t txid[TXPOOL_TXID_LEN], int *found) {
    if (!pool || !txid || !found) return -1;
    *found = 0;
    for (size_t i = 0; i < pool->count; i++) {
        if (memcmp(pool->txs[i].txid, txid, TXPOOL_TXID_LEN) == 0) { *found = 1; return 0; }
    }
    return 0;
}

int txpool_get(txpool *pool, const uint8_t txid[TXPOOL_TXID_LEN], txpool_tx **tx) {
    if (!pool || !txid || !tx) return -1;
    for (size_t i = 0; i < pool->count; i++) {
        if (memcmp(pool->txs[i].txid, txid, TXPOOL_TXID_LEN) == 0) { *tx = &pool->txs[i]; return 0; }
    }
    *tx = NULL;
    return -1;
}

int txpool_add(txpool *pool, const uint8_t *raw, size_t raw_len, int from_local,
                const uint8_t *from_addr, int *accepted) {
    if (!pool || !raw || !accepted) return -1;
    *accepted = 0;
    int valid = 0;
    if (txpool_validate_tx(raw, raw_len, &valid) != 0 || !valid) return 0;
    uint8_t txid[TXPOOL_TXID_LEN];
    if (txpool_compute_txid(raw, raw_len, txid) != 0) return -1;
    int found = 0;
    if (txpool_contains(pool, txid, &found) != 0) return -1;
    if (found) { *accepted = 0; return 0; }
    if (pool->count >= pool->max_size) {
        txpool_evict_lowest_gas(pool, 1);
        if (pool->count >= pool->max_size) return 0;
    }
    txpool_tx *tx = &pool->txs[pool->count];
    tx->raw = malloc(raw_len);
    if (!tx->raw) return -1;
    memcpy(tx->raw, raw, raw_len);
    tx->raw_len = raw_len;
    memcpy(tx->txid, txid, TXPOOL_TXID_LEN);
    tx->fee = 0;
    tx->gas_price = pool->min_gas_price;
    tx->gas_limit = 21000;
    tx->nonce = 0;
    tx->arrival_time = txpool_time_now();
    tx->from_local = from_local;
    if (from_addr) memcpy(tx->from_addr, from_addr, TXPOOL_ADDR_LEN);
    else memset(tx->from_addr, 0, TXPOOL_ADDR_LEN);
    pool->count++;
    *accepted = 1;
    return 0;
}

int txpool_remove(txpool *pool, const uint8_t txid[TXPOOL_TXID_LEN]) {
    if (!pool || !txid) return -1;
    for (size_t i = 0; i < pool->count; i++) {
        if (memcmp(pool->txs[i].txid, txid, TXPOOL_TXID_LEN) == 0) {
            free(pool->txs[i].raw);
            if (i < pool->count - 1) {
                memmove(&pool->txs[i], &pool->txs[i + 1], (pool->count - i - 1) * sizeof(txpool_tx));
            }
            pool->count--;
            return 0;
        }
    }
    return -1;
}

int txpool_size(const txpool *pool, size_t *count) {
    if (!pool || !count) return -1;
    *count = pool->count;
    return 0;
}

int txpool_is_full(const txpool *pool, int *full) {
    if (!pool || !full) return -1;
    *full = (pool->count >= pool->max_size) ? 1 : 0;
    return 0;
}

static int txpool_compare_gas_desc(const void *a, const void *b) {
    const txpool_tx *ta = (const txpool_tx *)a;
    const txpool_tx *tb = (const txpool_tx *)b;
    if (ta->gas_price > tb->gas_price) return -1;
    if (ta->gas_price < tb->gas_price) return 1;
    return 0;
}

static int txpool_compare_fee_desc(const void *a, const void *b) {
    const txpool_tx *ta = (const txpool_tx *)a;
    const txpool_tx *tb = (const txpool_tx *)b;
    if (ta->fee > tb->fee) return -1;
    if (ta->fee < tb->fee) return 1;
    return 0;
}

static int txpool_compare_arrival_asc(const void *a, const void *b) {
    const txpool_tx *ta = (const txpool_tx *)a;
    const txpool_tx *tb = (const txpool_tx *)b;
    if (ta->arrival_time < tb->arrival_time) return -1;
    if (ta->arrival_time > tb->arrival_time) return 1;
    return 0;
}

int txpool_sort_by_gas(txpool *pool) {
    if (!pool) return -1;
    qsort(pool->txs, pool->count, sizeof(txpool_tx), txpool_compare_gas_desc);
    return 0;
}

int txpool_sort_by_fee(txpool *pool) {
    if (!pool) return -1;
    qsort(pool->txs, pool->count, sizeof(txpool_tx), txpool_compare_fee_desc);
    return 0;
}

int txpool_sort_by_arrival(txpool *pool) {
    if (!pool) return -1;
    qsort(pool->txs, pool->count, sizeof(txpool_tx), txpool_compare_arrival_asc);
    return 0;
}

int txpool_selector_init(txpool_selector *sel, size_t capacity) {
    if (!sel || capacity == 0) return -1;
    sel->entries = calloc(capacity, sizeof(txpool_tx));
    if (!sel->entries) return -1;
    sel->count = 0;
    sel->capacity = capacity;
    return 0;
}

void txpool_selector_free(txpool_selector *sel) {
    if (!sel) return;
    free(sel->entries);
    sel->entries = NULL;
    sel->count = 0;
    sel->capacity = 0;
}

int txpool_select(txpool *pool, size_t max_count, size_t max_bytes,
                   txpool_selector *selected) {
    if (!pool || !selected) return -1;
    txpool_selector_free(selected);
    if (txpool_selector_init(selected, max_count) != 0) return -1;
    size_t total_bytes = 0;
    for (size_t i = 0; i < pool->count && selected->count < max_count; i++) {
        if (total_bytes + pool->txs[i].raw_len > max_bytes) continue;
        memcpy(&selected->entries[selected->count], &pool->txs[i], sizeof(txpool_tx));
        selected->entries[selected->count].raw = NULL;
        selected->count++;
        total_bytes += pool->txs[i].raw_len;
    }
    return 0;
}

int txpool_select_by_gas(txpool *pool, size_t max_count, size_t max_bytes,
                          txpool_selector *selected) {
    if (!pool) return -1;
    txpool_sort_by_gas(pool);
    return txpool_select(pool, max_count, max_bytes, selected);
}

int txpool_replace_by_fee(txpool *pool, const uint8_t *new_raw, size_t new_raw_len,
                           const uint8_t txid[TXPOOL_TXID_LEN], int *replaced) {
    if (!pool || !new_raw || !txid || !replaced) return -1;
    *replaced = 0;
    txpool_tx *existing = NULL;
    if (txpool_get(pool, txid, &existing) != 0) return 0;
    uint64_t new_gas_price = pool->min_gas_price * 2;
    if (new_gas_price > existing->gas_price * (uint64_t)(pool->rbf_ratio * 100) / 100) {
        free(existing->raw);
        existing->raw = malloc(new_raw_len);
        if (!existing->raw) return -1;
        memcpy(existing->raw, new_raw, new_raw_len);
        existing->raw_len = new_raw_len;
        existing->gas_price = new_gas_price;
        existing->arrival_time = txpool_time_now();
        *replaced = 1;
    }
    return 0;
}

int txpool_get_next_nonce(const txpool *pool, int *nonce) {
    if (!pool || !nonce) return -1;
    int max_nonce = -1;
    for (size_t i = 0; i < pool->count; i++) {
        if ((int)pool->txs[i].nonce > max_nonce) max_nonce = (int)pool->txs[i].nonce;
    }
    *nonce = max_nonce + 1;
    return 0;
}

int txpool_prune(txpool *pool, size_t target_size) {
    if (!pool) return -1;
    if (pool->count <= target_size) return 0;
    txpool_sort_by_gas(pool);
    size_t remove_count = pool->count - target_size;
    for (size_t i = 0; i < remove_count; i++) {
        free(pool->txs[pool->count - 1 - i].raw);
    }
    pool->count = target_size;
    return 0;
}

int txpool_evict_lowest_gas(txpool *pool, size_t count) {
    if (!pool || count == 0) return -1;
    txpool_sort_by_gas(pool);
    if (count > pool->count) count = pool->count;
    pool->count -= count;
    return 0;
}

int txpool_get_all(txpool *pool, txpool_selector *all) {
    if (!pool || !all) return -1;
    txpool_selector_free(all);
    if (txpool_selector_init(all, pool->count) != 0) return -1;
    for (size_t i = 0; i < pool->count; i++) {
        memcpy(&all->entries[i], &pool->txs[i], sizeof(txpool_tx));
        all->entries[i].raw = NULL;
    }
    all->count = pool->count;
    return 0;
}

int txpool_get_by_nonce_range(txpool *pool, uint32_t min_nonce, uint32_t max_nonce,
                               txpool_selector *out) {
    if (!pool || !out) return -1;
    txpool_selector_free(out);
    if (txpool_selector_init(out, pool->count) != 0) return -1;
    for (size_t i = 0; i < pool->count; i++) {
        if (pool->txs[i].nonce >= min_nonce && pool->txs[i].nonce <= max_nonce) {
            memcpy(&out->entries[out->count], &pool->txs[i], sizeof(txpool_tx));
            out->entries[out->count].raw = NULL;
            out->count++;
        }
    }
    return 0;
}

int txpool_remove_below_nonce(txpool *pool, uint32_t min_nonce) {
    if (!pool) return -1;
    size_t write = 0;
    for (size_t i = 0; i < pool->count; i++) {
        if (pool->txs[i].nonce >= min_nonce) {
            if (write != i) memcpy(&pool->txs[write], &pool->txs[i], sizeof(txpool_tx));
            write++;
        } else {
            free(pool->txs[i].raw);
        }
    }
    pool->count = write;
    return 0;
}
