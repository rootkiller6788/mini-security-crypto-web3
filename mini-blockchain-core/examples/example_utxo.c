#include "utxo_model.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(void) {
    printf("=== UTXO Model Example ===\n\n");

    utxo_transaction tx;
    utxo_tx_create(&tx);

    uint8_t prev_txid[UTOX_MODEL_TXID_LEN];
    memset(prev_txid, 0xAB, UTOX_MODEL_TXID_LEN);

    utxo_tx_add_input(&tx, prev_txid, 0);

    uint8_t script_pub[25] = {0x76, 0xA9, 0x14};
    for (int i = 3; i < 23; i++) script_pub[i] = (uint8_t)(0x10 + i);
    script_pub[23] = 0x88;
    script_pub[24] = 0xAC;

    utxo_tx_add_output(&tx, 5000000000ULL, script_pub, 25);
    utxo_tx_add_output(&tx, 1000000000ULL, script_pub, 25);

    utxo_tx_compute_txid(&tx);

    printf("Transaction version: %u\n", tx.version);
    printf("Input count: %u\n", tx.input_count);
    printf("Output count: %u\n", tx.output_count);
    printf("TxID: ");
    for (int i = 0; i < 16; i++) printf("%02x", tx.txid[i]);
    printf("\n\n");

    utxo_set utxos;
    utxo_set_init(&utxos, 100);

    utxo_entry e1;
    memset(&e1, 0, sizeof(e1));
    memcpy(e1.txid, prev_txid, UTOX_MODEL_TXID_LEN);
    e1.vout = 0;
    e1.value = 10000000000ULL;
    e1.height = 100;
    memcpy(e1.scriptPubKey, script_pub, 25);
    e1.scriptPubKey_len = 25;
    e1.spent = 0;
    utxo_set_add(&utxos, &e1);

    utxo_entry e2;
    memset(&e2, 0, sizeof(e2));
    memset(e2.txid, 0xCD, UTOX_MODEL_TXID_LEN);
    e2.vout = 1;
    e2.value = 3000000000ULL;
    e2.height = 101;
    memcpy(e2.scriptPubKey, script_pub, 25);
    e2.scriptPubKey_len = 25;
    e2.spent = 0;
    utxo_set_add(&utxos, &e2);

    printf("UTXO set count: %zu\n", utxos.count);

    int spent = utxo_set_is_spent(&utxos, prev_txid, 0);
    printf("UTXO %02x... vout=0 spent: %s\n", prev_txid[0], spent ? "yes" : "no");

    utxo_set_spend(&utxos, prev_txid, 0);
    spent = utxo_set_is_spent(&utxos, prev_txid, 0);
    printf("After spend, spent: %s\n", spent ? "yes" : "no");

    uint64_t target = 5000000000ULL;
    utxo_entry *selected = NULL;
    size_t count = 0;
    uint64_t total = 0;
    uint64_t change = 0;

    int r = utxo_coin_selection(&utxos, target, 1, &selected, &count, &total, &change);
    if (r == 0) {
        printf("\nCoin selection for %llu satoshi:\n", (unsigned long long)target);
        printf("  Selected %zu UTXOs, total: %llu, change: %llu\n",
               count, (unsigned long long)total, (unsigned long long)change);
        free(selected);
    } else {
        printf("\nInsufficient funds for %llu satoshi\n", (unsigned long long)target);
    }

    uint8_t ser_buf[4096];
    size_t ser_len = 0;
    utxo_serialize_tx(&tx, ser_buf, &ser_len, sizeof(ser_buf));
    printf("\nSerialized tx size: %zu bytes\n", ser_len);

    utxo_transaction tx2;
    utxo_deserialize_tx(&tx2, ser_buf, ser_len);
    printf("Deserialized: version=%u, inputs=%u, outputs=%u\n",
           tx2.version, tx2.input_count, tx2.output_count);

    char addr[UTOX_MODEL_ADDRESS_LEN];
    uint8_t pubkey[33];
    memset(pubkey, 0x03, 33);
    utxo_pubkey_to_address(pubkey, 1, addr);
    printf("\nAddress from pubkey: %s\n", addr);

    utxo_set_free(&utxos);
    printf("\nUTXO model example complete.\n");
    return 0;
}
