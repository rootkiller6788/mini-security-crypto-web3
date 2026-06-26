#ifndef TX_POOL_H
#define TX_POOL_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TXPOOL_TXID_LEN       32
#define TXPOOL_MAX_POOL_SIZE  50000
#define TXPOOL_DEFAULT_MAX    5000
#define TXPOOL_ADDR_LEN       64
#define TXPOOL_SIG_LEN        128

typedef struct {
    uint8_t  txid[TXPOOL_TXID_LEN];
    uint8_t *raw;
    size_t   raw_len;
    uint64_t fee;
    uint64_t gas_price;
    uint64_t gas_limit;
    uint32_t nonce;
    uint64_t arrival_time;
    int      from_local;
    uint8_t  from_addr[TXPOOL_ADDR_LEN];
} txpool_tx;

typedef struct {
    txpool_tx *txs;
    size_t     count;
    size_t     capacity;
    size_t     max_size;
    uint64_t   min_gas_price;
    double     rbf_ratio;
} txpool;

typedef struct {
    txpool_tx *entries;
    size_t     count;
    size_t     capacity;
} txpool_selector;

int  txpool_init(txpool *pool, size_t max_size);
void txpool_free(txpool *pool);

int  txpool_add(txpool *pool, const uint8_t *raw, size_t raw_len, int from_local,
                const uint8_t *from_addr, int *accepted);
int  txpool_remove(txpool *pool, const uint8_t txid[TXPOOL_TXID_LEN]);
int  txpool_contains(txpool *pool, const uint8_t txid[TXPOOL_TXID_LEN], int *found);
int  txpool_get(txpool *pool, const uint8_t txid[TXPOOL_TXID_LEN], txpool_tx **tx);
int  txpool_size(const txpool *pool, size_t *count);
int  txpool_is_full(const txpool *pool, int *full);

int  txpool_validate_tx(const uint8_t *raw, size_t raw_len, int *valid);

int  txpool_sort_by_gas(txpool *pool);
int  txpool_sort_by_fee(txpool *pool);
int  txpool_sort_by_arrival(txpool *pool);

int  txpool_select(txpool *pool, size_t max_count, size_t max_bytes,
                   txpool_selector *selected);
int  txpool_select_by_gas(txpool *pool, size_t max_count, size_t max_bytes,
                          txpool_selector *selected);

int  txpool_replace_by_fee(txpool *pool, const uint8_t *new_raw, size_t new_raw_len,
                           const uint8_t txid[TXPOOL_TXID_LEN], int *replaced);
int  txpool_get_next_nonce(const txpool *pool, int *nonce);

int  txpool_prune(txpool *pool, size_t target_size);
int  txpool_evict_lowest_gas(txpool *pool, size_t count);

int  txpool_compute_txid(const uint8_t *raw, size_t raw_len, uint8_t txid[TXPOOL_TXID_LEN]);
uint64_t txpool_time_now(void);

int  txpool_selector_init(txpool_selector *sel, size_t capacity);
void txpool_selector_free(txpool_selector *sel);

int  txpool_get_all(txpool *pool, txpool_selector *all);
int  txpool_get_by_nonce_range(txpool *pool, uint32_t min_nonce, uint32_t max_nonce,
                               txpool_selector *out);
int  txpool_remove_below_nonce(txpool *pool, uint32_t min_nonce);

#ifdef __cplusplus
}
#endif

#endif
