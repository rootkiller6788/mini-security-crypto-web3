#include "merkle_tree.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(void) {
    printf("=== Merkle Tree Example ===\n\n");

    merkle_tree tree;
    merkle_tree_init(&tree);

    const char *txs[] = {
        "tx: Alice pays Bob 5 BTC",
        "tx: Bob pays Charlie 2 BTC",
        "tx: Charlie pays Dave 1 BTC",
        "tx: Dave pays Eve 0.5 BTC",
        "tx: Eve pays Alice 0.3 BTC",
        "tx: Alice pays Frank 4 BTC",
        "tx: Frank pays Grace 2.5 BTC",
        "tx: Grace pays Henry 1.2 BTC",
    };
    size_t n = sizeof(txs) / sizeof(txs[0]);

    for (size_t i = 0; i < n; i++) {
        merkle_tree_add_leaf(&tree, (const uint8_t *)txs[i], strlen(txs[i]));
    }

    merkle_tree_rebuild(&tree);

    merkle_hash root;
    merkle_tree_get_root(&tree, &root);
    printf("Merkle root after %zu leaves: ", n);
    for (int i = 0; i < 8; i++) printf("%02x", root.hash[i]);
    printf("...\n");

    size_t leaf_count;
    merkle_tree_leaf_count(&tree, &leaf_count);
    printf("Leaf count: %zu\n\n", leaf_count);

    size_t test_idx = 3;
    merkle_proof proof;
    if (merkle_proof_generate(&tree, test_idx, &proof) == 0) {
        printf("Merkle proof for leaf %zu:\n", test_idx);
        printf("  Path depth: %d\n", proof.path_depth);
        printf("  Leaf hash: ");
        for (int i = 0; i < 8; i++) printf("%02x", proof.leaf_hash.hash[i]);
        printf("...\n");

        for (int i = 0; i < proof.path_depth; i++) {
            printf("  Step %d: dir=%s hash=", i, proof.directions[i] ? "right" : "left");
            for (int j = 0; j < 4; j++) printf("%02x", proof.path[i].hash[j]);
            printf("...\n");
        }

        int valid = 0;
        merkle_proof_verify(&root, &proof, &valid);
        printf("  Proof valid: %s\n\n", valid ? "YES" : "NO");
    }

    size_t bad_idx = 5;
    merkle_proof bad_proof;
    if (merkle_proof_generate(&tree, bad_idx, &bad_proof) == 0) {
        bad_proof.directions[0] ^= 1;
        int valid = 0;
        merkle_proof_verify(&root, &bad_proof, &valid);
        printf("Tampered proof valid: %s\n\n", valid ? "YES" : "NO");
    }

    merkle_tree tree2;
    merkle_tree_init(&tree2);
    for (size_t i = 0; i < n; i++) {
        merkle_tree_add_leaf(&tree2, (const uint8_t *)txs[i], strlen(txs[i]));
    }
    merkle_tree_rebuild(&tree2);

    int equal = 0;
    merkle_tree_compare_roots(&tree, &tree2, &equal);
    printf("Both trees equal: %s\n\n", equal ? "YES" : "NO");

    printf("=== Patricia Merkle Trie (Ethereum State) ===\n\n");

    patricia_merkle_trie trie;
    patricia_trie_init(&trie);

    struct {
        const uint8_t *key;
        size_t key_len;
        const uint8_t *value;
        size_t value_len;
    } entries[] = {
        {(const uint8_t *)"\x0a\x00\x11", 3, (const uint8_t *)"100 ETH", 7},
        {(const uint8_t *)"\x0a\x00\x22", 3, (const uint8_t *)"200 ETH", 7},
        {(const uint8_t *)"\x0b\x11\x33", 3, (const uint8_t *)"300 ETH", 7},
        {(const uint8_t *)"\x0b\x11\x44", 3, (const uint8_t *)"400 ETH", 7},
    };
    size_t ne = sizeof(entries) / sizeof(entries[0]);

    for (size_t i = 0; i < ne; i++) {
        patricia_trie_insert(&trie, entries[i].key, entries[i].key_len,
                            entries[i].value, entries[i].value_len);
    }

    uint8_t *val = NULL;
    size_t vlen = 0;
    if (patricia_trie_lookup(&trie, entries[0].key, entries[0].key_len, &val, &vlen) == 0) {
        printf("Lookup key 0a0011: %.*s\n", (int)vlen, val);
    }

    patricia_trie_delete(&trie, entries[0].key, entries[0].key_len);
    if (patricia_trie_lookup(&trie, entries[0].key, entries[0].key_len, &val, &vlen) != 0) {
        printf("Key 0a0011 deleted successfully\n");
    }

    patricia_trie_free(&trie);
    merkle_tree_free(&tree);
    merkle_tree_free(&tree2);

    printf("\nMerkle tree example complete.\n");
    return 0;
}
