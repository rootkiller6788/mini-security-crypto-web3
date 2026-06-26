#include "utxo_model.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/ripemd.h>

int utxo_tx_create(utxo_transaction *tx) {
    if (!tx) return -1;
    memset(tx, 0, sizeof(utxo_transaction));
    tx->version = 1;
    tx->locktime = 0;
    tx->input_count = 0;
    tx->output_count = 0;
    return 0;
}

int utxo_tx_add_input(utxo_transaction *tx, const uint8_t prev_txid[UTOX_MODEL_TXID_LEN], uint32_t vout) {
    if (!tx || !prev_txid) return -1;
    if (tx->input_count >= UTOX_MODEL_MAX_INPUTS) return -1;
    utxo_txin *in = &tx->inputs[tx->input_count];
    memcpy(in->prev_txid, prev_txid, UTOX_MODEL_TXID_LEN);
    in->vout = vout;
    in->scriptSig_len = 0;
    memset(in->scriptSig, 0, UTOX_MODEL_SCRIPTSIG_MAX);
    tx->input_count++;
    return 0;
}

int utxo_tx_add_output(utxo_transaction *tx, uint64_t value, const uint8_t *scriptPubKey, uint16_t len) {
    if (!tx || !scriptPubKey) return -1;
    if (tx->output_count >= UTOX_MODEL_MAX_OUTPUTS) return -1;
    if (len > UTOX_MODEL_SCRIPTPUB_MAX) return -1;
    utxo_txout *out = &tx->outputs[tx->output_count];
    out->value = value;
    memcpy(out->scriptPubKey, scriptPubKey, len);
    out->scriptPubKey_len = len;
    tx->output_count++;
    return 0;
}

void utxo_tx_sha256(const uint8_t *data, size_t len, uint8_t out[UTOX_MODEL_SHA256_LEN]) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, len);
    SHA256_Final(out, &ctx);
}

void utxo_tx_double_sha256(const uint8_t *data, size_t len, uint8_t out[UTOX_MODEL_SHA256_LEN]) {
    uint8_t tmp[UTOX_MODEL_SHA256_LEN];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, len);
    SHA256_Final(tmp, &ctx);
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, tmp, UTOX_MODEL_SHA256_LEN);
    SHA256_Final(out, &ctx);
}

void utxo_tx_compute_txid(utxo_transaction *tx) {
    if (!tx) return;
    size_t sz = 0;
    uint8_t buf[4096];
    int r = utxo_serialize_tx(tx, buf, &sz, sizeof(buf));
    if (r != 0) return;
    utxo_tx_double_sha256(buf, sz, tx->txid);
}

int utxo_set_init(utxo_set *set, size_t capacity) {
    if (!set || capacity == 0) return -1;
    set->entries = calloc(capacity, sizeof(utxo_entry));
    if (!set->entries) return -1;
    set->count = 0;
    set->capacity = capacity;
    return 0;
}

void utxo_set_free(utxo_set *set) {
    if (!set) return;
    free(set->entries);
    set->entries = NULL;
    set->count = 0;
    set->capacity = 0;
}

int utxo_set_add(utxo_set *set, const utxo_entry *entry) {
    if (!set || !entry) return -1;
    if (set->count >= set->capacity) {
        size_t new_cap = set->capacity * 2;
        utxo_entry *tmp = realloc(set->entries, new_cap * sizeof(utxo_entry));
        if (!tmp) return -1;
        set->entries = tmp;
        set->capacity = new_cap;
    }
    memcpy(&set->entries[set->count], entry, sizeof(utxo_entry));
    set->entries[set->count].spent = 0;
    set->count++;
    return 0;
}

int utxo_set_find(utxo_set *set, const uint8_t txid[UTOX_MODEL_TXID_LEN], uint32_t vout, utxo_entry **out) {
    if (!set || !txid || !out) return -1;
    for (size_t i = 0; i < set->count; i++) {
        if (memcmp(set->entries[i].txid, txid, UTOX_MODEL_TXID_LEN) == 0 && set->entries[i].vout == vout) {
            *out = &set->entries[i];
            return 0;
        }
    }
    *out = NULL;
    return -1;
}

int utxo_set_remove(utxo_set *set, const uint8_t txid[UTOX_MODEL_TXID_LEN], uint32_t vout) {
    if (!set || !txid) return -1;
    for (size_t i = 0; i < set->count; i++) {
        if (memcmp(set->entries[i].txid, txid, UTOX_MODEL_TXID_LEN) == 0 && set->entries[i].vout == vout) {
            if (i < set->count - 1) {
                memmove(&set->entries[i], &set->entries[i + 1], (set->count - i - 1) * sizeof(utxo_entry));
            }
            set->count--;
            return 0;
        }
    }
    return -1;
}

int utxo_set_spend(utxo_set *set, const uint8_t txid[UTOX_MODEL_TXID_LEN], uint32_t vout) {
    if (!set || !txid) return -1;
    for (size_t i = 0; i < set->count; i++) {
        if (memcmp(set->entries[i].txid, txid, UTOX_MODEL_TXID_LEN) == 0 && set->entries[i].vout == vout) {
            if (set->entries[i].spent) return -1;
            set->entries[i].spent = 1;
            return 0;
        }
    }
    return -1;
}

int utxo_set_is_spent(utxo_set *set, const uint8_t txid[UTOX_MODEL_TXID_LEN], uint32_t vout) {
    if (!set || !txid) return 1;
    for (size_t i = 0; i < set->count; i++) {
        if (memcmp(set->entries[i].txid, txid, UTOX_MODEL_TXID_LEN) == 0 && set->entries[i].vout == vout) {
            return set->entries[i].spent ? 1 : 0;
        }
    }
    return 1;
}

int utxo_verify_sig(const uint8_t *msg_hash, const uint8_t *pubkey, size_t pubkey_len,
                     const uint8_t *sig, size_t sig_len) {
    if (!msg_hash || !pubkey || !sig) return -1;
    int ret = -1;
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ec) return -1;
    const unsigned char *p = pubkey;
    EC_KEY *pub = NULL;
    if (pubkey_len == 33) {
        if (!o2i_ECPublicKey(&ec, &p, (long)pubkey_len)) goto cleanup;
    } else {
        if (!o2i_ECPublicKey(&ec, &p, (long)pubkey_len)) goto cleanup;
    }
    ECDSA_SIG *ecdsa_sig = ECDSA_SIG_new();
    if (!ecdsa_sig) goto cleanup;
    const unsigned char *s = sig;
    if (!d2i_ECDSA_SIG(&ecdsa_sig, &s, (long)sig_len)) {
        ECDSA_SIG_free(ecdsa_sig);
        goto cleanup;
    }
    ret = ECDSA_do_verify(msg_hash, 32, ecdsa_sig, ec);
    ECDSA_SIG_free(ecdsa_sig);
cleanup:
    EC_KEY_free(ec);
    return (ret == 1) ? 0 : -1;
}

int utxo_verify_tx_inputs(const utxo_transaction *tx, const utxo_set *utxos) {
    if (!tx || !utxos) return -1;
    uint64_t total_in = 0;
    for (uint16_t i = 0; i < tx->input_count; i++) {
        utxo_entry *entry = NULL;
        if (utxo_set_find((utxo_set *)utxos, tx->inputs[i].prev_txid, tx->inputs[i].vout, &entry) != 0) return -1;
        if (!entry || entry->spent) return -1;
        total_in += entry->value;
    }
    uint64_t total_out = 0;
    for (uint16_t i = 0; i < tx->output_count; i++) {
        total_out += tx->outputs[i].value;
    }
    if (total_in < total_out) return -1;
    return 0;
}

static int utxo_entry_compare_by_value_desc(const void *a, const void *b) {
    const utxo_entry *ea = (const utxo_entry *)a;
    const utxo_entry *eb = (const utxo_entry *)b;
    if (ea->value > eb->value) return -1;
    if (ea->value < eb->value) return 1;
    return 0;
}

static int utxo_entry_compare_by_value_asc(const void *a, const void *b) {
    const utxo_entry *ea = (const utxo_entry *)a;
    const utxo_entry *eb = (const utxo_entry *)b;
    if (ea->value > eb->value) return 1;
    if (ea->value < eb->value) return -1;
    return 0;
}

int utxo_coin_selection(const utxo_set *utxos, uint64_t target, uint64_t fee_per_byte,
                         utxo_entry **selected, size_t *count, uint64_t *total,
                         uint64_t *change) {
    if (!utxos || !selected || !count || !total || !change) return -1;
    *count = 0;
    *total = 0;
    *change = 0;
    size_t n = utxos->count;
    if (n == 0) return -1;
    utxo_entry *sorted = malloc(n * sizeof(utxo_entry));
    if (!sorted) return -1;
    memcpy(sorted, utxos->entries, n * sizeof(utxo_entry));
    qsort(sorted, n, sizeof(utxo_entry), utxo_entry_compare_by_value_desc);
    uint64_t sum = 0;
    size_t sel = 0;
    for (size_t i = 0; i < n; i++) {
        if (sorted[i].spent) continue;
        sum += sorted[i].value;
        sel++;
        if (sum >= target + fee_per_byte * 200) break;
    }
    if (sum < target) {
        free(sorted);
        return -1;
    }
    *selected = malloc(sel * sizeof(utxo_entry));
    if (!*selected) {
        free(sorted);
        return -1;
    }
    size_t idx = 0;
    for (size_t i = 0; i < n && idx < sel; i++) {
        if (sorted[i].spent) continue;
        memcpy(&(*selected)[idx], &sorted[i], sizeof(utxo_entry));
        idx++;
    }
    *count = sel;
    *total = sum;
    if (sum > target) *change = sum - target;
    free(sorted);
    return 0;
}

int utxo_serialize_tx(const utxo_transaction *tx, uint8_t *buf, size_t *len, size_t bufsz) {
    if (!tx || !buf || !len || bufsz < 8) return -1;
    memset(buf, 0, bufsz);
    size_t off = 0;
    memcpy(buf + off, &tx->version, 4); off += 4;
    memcpy(buf + off, &tx->input_count, 2); off += 2;
    for (uint16_t i = 0; i < tx->input_count; i++) {
        if (off + 64 > bufsz) return -1;
        memcpy(buf + off, tx->inputs[i].prev_txid, UTOX_MODEL_TXID_LEN); off += 32;
        memcpy(buf + off, &tx->inputs[i].vout, 4); off += 4;
        memcpy(buf + off, &tx->inputs[i].scriptSig_len, 2); off += 2;
        memcpy(buf + off, tx->inputs[i].scriptSig, tx->inputs[i].scriptSig_len);
        off += tx->inputs[i].scriptSig_len;
    }
    memcpy(buf + off, &tx->output_count, 2); off += 2;
    for (uint16_t i = 0; i < tx->output_count; i++) {
        if (off + 16 > bufsz) return -1;
        memcpy(buf + off, &tx->outputs[i].value, 8); off += 8;
        memcpy(buf + off, &tx->outputs[i].scriptPubKey_len, 2); off += 2;
        memcpy(buf + off, tx->outputs[i].scriptPubKey, tx->outputs[i].scriptPubKey_len);
        off += tx->outputs[i].scriptPubKey_len;
    }
    memcpy(buf + off, &tx->locktime, 4); off += 4;
    *len = off;
    return 0;
}

int utxo_deserialize_tx(utxo_transaction *tx, const uint8_t *buf, size_t len) {
    if (!tx || !buf || len < 8) return -1;
    memset(tx, 0, sizeof(utxo_transaction));
    size_t off = 0;
    memcpy(&tx->version, buf + off, 4); off += 4;
    memcpy(&tx->input_count, buf + off, 2); off += 2;
    if (tx->input_count > UTOX_MODEL_MAX_INPUTS) return -1;
    for (uint16_t i = 0; i < tx->input_count; i++) {
        if (off + 64 > len) return -1;
        memcpy(tx->inputs[i].prev_txid, buf + off, 32); off += 32;
        memcpy(&tx->inputs[i].vout, buf + off, 4); off += 4;
        memcpy(&tx->inputs[i].scriptSig_len, buf + off, 2); off += 2;
        if (tx->inputs[i].scriptSig_len > UTOX_MODEL_SCRIPTSIG_MAX) return -1;
        memcpy(tx->inputs[i].scriptSig, buf + off, tx->inputs[i].scriptSig_len);
        off += tx->inputs[i].scriptSig_len;
    }
    memcpy(&tx->output_count, buf + off, 2); off += 2;
    if (tx->output_count > UTOX_MODEL_MAX_OUTPUTS) return -1;
    for (uint16_t i = 0; i < tx->output_count; i++) {
        if (off + 16 > len) return -1;
        memcpy(&tx->outputs[i].value, buf + off, 8); off += 8;
        memcpy(&tx->outputs[i].scriptPubKey_len, buf + off, 2); off += 2;
        if (tx->outputs[i].scriptPubKey_len > UTOX_MODEL_SCRIPTPUB_MAX) return -1;
        memcpy(tx->outputs[i].scriptPubKey, buf + off, tx->outputs[i].scriptPubKey_len);
        off += tx->outputs[i].scriptPubKey_len;
    }
    memcpy(&tx->locktime, buf + off, 4); off += 4;
    return 0;
}

void utxo_pubkey_to_address(const uint8_t pubkey[UTOX_MODEL_PUBKEY_LEN], int compressed,
                            char addr[UTOX_MODEL_ADDRESS_LEN]) {
    if (!pubkey || !addr) return;
    uint8_t sha256_out[32];
    utxo_tx_sha256(pubkey, compressed ? 33 : 65, sha256_out);
    uint8_t ripe_out[20];
    RIPEMD160_CTX rctx;
    RIPEMD160_Init(&rctx);
    RIPEMD160_Update(&rctx, sha256_out, 32);
    RIPEMD160_Final(ripe_out, &rctx);
    memset(addr, 0, UTOX_MODEL_ADDRESS_LEN);
    for (int i = 0; i < 20; i++) {
        sprintf(addr + i * 2, "%02x", ripe_out[i]);
    }
}
