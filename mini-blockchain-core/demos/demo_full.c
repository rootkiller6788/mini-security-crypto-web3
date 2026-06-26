/*
 * mini-blockchain-core — Full Demo: Blockchain Fundamentals
 *
 * Demonstrates: UTXO model, Merkle tree, PoW consensus,
 *               transaction pool, P2P network.
 */
#include "../include/utxo_model.h"
#include "../include/merkle_tree.h"
#include "../include/consensus_pow.h"
#include "../include/tx_pool.h"
#include "../include/p2p_network.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

int main(void) {
    printf("╔══════════════════════════════════════════╗\n");
    printf("║   mini-blockchain-core: Blockchain Core ║\n");
    printf("╚══════════════════════════════════════════╝\n\n");

    /* Step 1: SHA256 Hashing */
    printf("── Step 1: Cryptographic Hashing ──\n");
    const char *block_data = "BLOCK#1: Alice pays Bob 50 BTC";
    uint8_t hash[UTOX_MODEL_SHA256_LEN];
    utxo_tx_double_sha256((const uint8_t *)block_data, strlen(block_data), hash);
    printf("Data: \"%s\"\n", block_data);
    printf("SHA256(SHA256(data)) = ");
    for (int i = 0; i < 16; i++) printf("%02x", hash[i]);
    printf("...\n");

    /* Step 2: UTXO Model */
    printf("\n── Step 2: UTXO Transaction Model ──\n");
    utxo_set set;
    utxo_set_init(&set, 256);

    utxo_entry e1; memset(&e1, 0, sizeof(e1));
    e1.txid[0] = 0x01; e1.vout = 0; e1.value = 100000;
    e1.script_pubkey[0] = 0x76; e1.script_len = 1;
    utxo_set_add(&set, &e1);

    utxo_entry e2; memset(&e2, 0, sizeof(e2));
    e2.txid[0] = 0x02; e2.vout = 1; e2.value = 250000;
    e2.script_pubkey[0] = 0xA9; e2.script_len = 1;
    utxo_set_add(&set, &e2);

    printf("UTXO set: %zu entries, total=%llu satoshis\n",
           set.count, (unsigned long long)utxo_set_total_value(&set));

    utxo_entry *selected[16]; size_t count; uint64_t total, change;
    utxo_coin_selection(&set, 150000, 2, selected, &count, &total, &change);
    printf("Coin selection for 150,000 satoshis:\n");
    printf("  Selected %zu UTXOs, total=%llu, change=%llu\n",
           count, (unsigned long long)total, (unsigned long long)change);

    utxo_tx tx;
    utxo_tx_init(&tx, 1);
    utxo_tx_add_input(&tx, e1.txid, e1.vout, e1.script_pubkey, e1.script_len);
    utxo_tx_add_output(&tx, 90000, NULL, 0);
    utxo_tx_add_output(&tx, 5000, NULL, 0);
    printf("Transaction: %zu inputs, %zu outputs, fee=%llu\n",
           tx.num_inputs, tx.num_outputs, (unsigned long long)utxo_tx_compute_fee(&tx, &set));

    /* Step 3: Merkle Tree */
    printf("\n── Step 3: Merkle Tree ──\n");
    merkle_tree tree;
    merkle_tree_init(&tree);
    for (int i = 0; i < 8; i++) {
        uint8_t leaf[32];
        memset(leaf, (uint8_t)i, 32);
        merkle_tree_add_leaf(&tree, leaf, 32);
    }
    merkle_tree_rebuild(&tree);
    merkle_hash root;
    merkle_tree_get_root(&tree, &root);
    printf("Merkle tree: %d leaves, root=", tree.leaf_count);
    for (int i = 0; i < 8; i++) printf("%02x", root.bytes[i]);
    printf("...\n");

    merkle_hash leaf0, leaf5;
    merkle_tree_get_leaf_hash(&tree, 0, &leaf0);
    merkle_tree_get_leaf_hash(&tree, 5, &leaf5);
    printf("Leaf[0] hash: "); for (int i = 0; i < 4; i++) printf("%02x", leaf0.bytes[i]); printf("...\n");
    printf("Leaf[5] hash: "); for (int i = 0; i < 4; i++) printf("%02x", leaf5.bytes[i]); printf("...\n");

    /* Step 4: Proof of Work */
    printf("\n── Step 4: Proof of Work Mining ──\n");
    pow_block block;
    memset(&block, 0, sizeof(block));
    block.header.version = 1;
    block.header.timestamp = (uint32_t)time(NULL);
    block.header.bits = 0x1f00ffff;

    pow_target target;
    pow_target_from_bits(block.header.bits, &target);
    printf("Target difficulty: 0x%08x (%s)\n", block.header.bits,
           target.value < 0x00000000FFFF0000ULL ? "low (fast mine)" : "high");

    uint8_t block_hash[32];
    pow_block_hash(&block.header, block_hash);
    printf("Block hash (nonce=0): ");
    for (int i = 0; i < 8; i++) printf("%02x", block_hash[i]);
    printf("...\n");

    bool mined = pow_mine(&block, &target, 100000);
    printf("Mining result: %s after nonce=%u\n",
           mined ? "BLOCK MINED!" : "not found (100k limit)",
           block.header.nonce);

    /* Step 5: Transaction Pool */
    printf("\n── Step 5: Transaction Pool ──\n");
    txpool pool;
    txpool_init(&pool, 1000);

    uint8_t from1[TXPOOL_ADDR_LEN]; memset(from1, 0xAA, TXPOOL_ADDR_LEN);
    uint8_t from2[TXPOOL_ADDR_LEN]; memset(from2, 0xBB, TXPOOL_ADDR_LEN);

    int accepted;
    uint8_t raw1[] = "TX: Alice->Bob 1000 satoshis, fee=100";
    txpool_add(&pool, raw1, sizeof(raw1), 2, from1, &accepted);
    uint8_t raw2[] = "TX: Bob->Carol 500 satoshis, fee=50";
    txpool_add(&pool, raw2, sizeof(raw2), 1, from2, &accepted);
    uint8_t raw3[] = "TX: Dave->Eve 2000 satoshis, fee=200";
    txpool_add(&pool, raw3, sizeof(raw3), 3, from1, &accepted);

    printf("TxPool: %d transactions\n", pool.count);
    txpool_sort_by_fee(&pool);
    printf("Sorted by fee (highest first):\n");
    for (int i = 0; i < pool.count; i++) {
        printf("  [%d] fee_rate=%u\n", i, pool.entries[i].fee_rate);
    }

    /* Step 6: P2P Network */
    printf("\n── Step 6: P2P Network (Node Discovery) ──\n");
    uint8_t node_id[P2P_NODE_ID_LEN];
    p2p_generate_node_id(node_id);
    printf("Node ID: ");
    for (int i = 0; i < 8; i++) printf("%02x", node_id[i]);
    printf("...\n");

    p2p_node_t node;
    p2p_node_init(&node, node_id);
    node.port = 8333;
    printf("Node initialized: port=%d\n", node.port);

    uint8_t peer1_id[P2P_NODE_ID_LEN]; memset(peer1_id, 0x11, P2P_NODE_ID_LEN);
    uint8_t peer2_id[P2P_NODE_ID_LEN]; memset(peer2_id, 0x22, P2P_NODE_ID_LEN);
    p2p_add_peer(&node, peer1_id, "192.168.1.10", 8333);
    p2p_add_peer(&node, peer2_id, "10.0.0.5", 8333);
    printf("Peers connected: %d\n", node.peer_count);

    /* Cleanup */
    utxo_set_free(&set);
    merkle_tree_free(&tree);
    txpool_free(&pool);

    printf("\n✓ Full blockchain core demo complete!\n");
    return 0;
}
