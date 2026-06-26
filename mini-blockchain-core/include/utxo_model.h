#ifndef UTXO_MODEL_H
#define UTXO_MODEL_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UTOX_MODEL_SHA256_LEN    32
#define UTOX_MODEL_TXID_LEN      32
#define UTOX_MODEL_MAX_INPUTS    256
#define UTOX_MODEL_MAX_OUTPUTS   256
#define UTOX_MODEL_SIG_MAXLEN    72
#define UTOX_MODEL_PUBKEY_LEN    33
#define UTOX_MODEL_SCRIPTSIG_MAX 256
#define UTOX_MODEL_SCRIPTPUB_MAX 256
#define UTOX_MODEL_ADDRESS_LEN   35

typedef struct {
    uint8_t  prev_txid[UTOX_MODEL_TXID_LEN];
    uint32_t vout;
    uint8_t  scriptSig[UTOX_MODEL_SCRIPTSIG_MAX];
    uint16_t scriptSig_len;
} utxo_txin;

typedef struct {
    uint64_t value;
    uint8_t  scriptPubKey[UTOX_MODEL_SCRIPTPUB_MAX];
    uint16_t scriptPubKey_len;
} utxo_txout;

typedef struct {
    uint8_t  txid[UTOX_MODEL_TXID_LEN];
    utxo_txin  inputs[UTOX_MODEL_MAX_INPUTS];
    uint16_t   input_count;
    utxo_txout outputs[UTOX_MODEL_MAX_OUTPUTS];
    uint16_t   output_count;
    uint32_t   locktime;
    uint32_t   version;
} utxo_transaction;

typedef struct {
    uint8_t  txid[UTOX_MODEL_TXID_LEN];
    uint32_t vout;
    uint64_t value;
    uint8_t  scriptPubKey[UTOX_MODEL_SCRIPTPUB_MAX];
    uint16_t scriptPubKey_len;
    uint32_t height;
    int      spent;
} utxo_entry;

typedef struct {
    utxo_entry *entries;
    size_t      count;
    size_t      capacity;
} utxo_set;

typedef struct {
    uint8_t key[UTOX_MODEL_PUBKEY_LEN];
    int     compressed;
} utxo_pubkey;

typedef struct {
    uint8_t r[UTOX_MODEL_SHA256_LEN];
    uint8_t s[UTOX_MODEL_SHA256_LEN];
    uint8_t v;
} utxo_signature;

int  utxo_tx_create(utxo_transaction *tx);
int  utxo_tx_add_input(utxo_transaction *tx, const uint8_t prev_txid[UTOX_MODEL_TXID_LEN], uint32_t vout);
int  utxo_tx_add_output(utxo_transaction *tx, uint64_t value, const uint8_t *scriptPubKey, uint16_t len);
void utxo_tx_compute_txid(utxo_transaction *tx);
void utxo_tx_sha256(const uint8_t *data, size_t len, uint8_t out[UTOX_MODEL_SHA256_LEN]);
void utxo_tx_double_sha256(const uint8_t *data, size_t len, uint8_t out[UTOX_MODEL_SHA256_LEN]);

int  utxo_set_init(utxo_set *set, size_t capacity);
void utxo_set_free(utxo_set *set);
int  utxo_set_add(utxo_set *set, const utxo_entry *entry);
int  utxo_set_find(utxo_set *set, const uint8_t txid[UTOX_MODEL_TXID_LEN], uint32_t vout, utxo_entry **out);
int  utxo_set_remove(utxo_set *set, const uint8_t txid[UTOX_MODEL_TXID_LEN], uint32_t vout);
int  utxo_set_spend(utxo_set *set, const uint8_t txid[UTOX_MODEL_TXID_LEN], uint32_t vout);
int  utxo_set_is_spent(utxo_set *set, const uint8_t txid[UTOX_MODEL_TXID_LEN], uint32_t vout);

int  utxo_verify_sig(const uint8_t *msg_hash, const uint8_t *pubkey, size_t pubkey_len,
                     const uint8_t *sig, size_t sig_len);
int  utxo_verify_tx_inputs(const utxo_transaction *tx, const utxo_set *utxos);

int  utxo_coin_selection(const utxo_set *utxos, uint64_t target, uint64_t fee_per_byte,
                         utxo_entry **selected, size_t *count, uint64_t *total,
                         uint64_t *change);

int  utxo_serialize_tx(const utxo_transaction *tx, uint8_t *buf, size_t *len, size_t bufsz);
int  utxo_deserialize_tx(utxo_transaction *tx, const uint8_t *buf, size_t len);

void utxo_pubkey_to_address(const uint8_t pubkey[UTOX_MODEL_PUBKEY_LEN], int compressed,
                            char addr[UTOX_MODEL_ADDRESS_LEN]);

#ifdef __cplusplus
}
#endif

#endif
