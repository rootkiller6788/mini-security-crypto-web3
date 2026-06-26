/*
 * mini-blockchain-core — Core Tests
 *
 * Unit tests for UTXO, Merkle tree, PoW consensus, P2P network, tx pool.
 */
#include "../include/utxo_model.h"
#include "../include/merkle_tree.h"
#include "../include/consensus_pow.h"
#include "../include/p2p_network.h"
#include "../include/tx_pool.h"
#include <stdio.h>
#include <string.h>

static int tests_run = 0, tests_passed = 0;

#define TEST(name) do { tests_run++; printf("  TEST %s ... ", name); } while(0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); return 1; } while(0)
#define CHECK(cond, msg) if (!(cond)) FAIL(msg)

/* ── UTXO Tests ── */
static int test_utxo_tx_create(void) {
    TEST("utxo_tx_create");
    utxo_transaction tx;
    CHECK(utxo_tx_create(&tx) == 0, "tx create failed");
    CHECK(tx.input_count == 0, "input count non-zero");
    CHECK(tx.output_count == 0, "output count non-zero");
    PASS();
    return 0;
}

static int test_utxo_tx_add_input_output(void) {
    TEST("utxo_tx_add_input_output");
    utxo_transaction tx;
    utxo_tx_create(&tx);
    uint8_t prev_txid[UTOX_MODEL_TXID_LEN]; memset(prev_txid, 0xAB, UTOX_MODEL_TXID_LEN);
    CHECK(utxo_tx_add_input(&tx, prev_txid, 0) == 0, "add input failed");
    uint8_t spk[32]; memset(spk, 0xCD, 32);
    CHECK(utxo_tx_add_output(&tx, 5000000000ULL, spk, 32) == 0, "add output failed");
    CHECK(tx.input_count == 1, "input count wrong");
    CHECK(tx.output_count == 1, "output count wrong");
    CHECK(tx.outputs[0].value == 5000000000ULL, "output value wrong");
    PASS();
    return 0;
}

static int test_utxo_set_add_find(void) {
    TEST("utxo_set_add_find");
    utxo_set set;
    CHECK(utxo_set_init(&set, 128) == 0, "set init failed");
    utxo_entry entry; memset(&entry, 0, sizeof(entry));
    memset(entry.txid, 0x01, UTOX_MODEL_TXID_LEN);
    entry.vout = 0; entry.value = 100000000;
    CHECK(utxo_set_add(&set, &entry) == 0, "add entry failed");
    utxo_entry *found;
    CHECK(utxo_set_find(&set, entry.txid, entry.vout, &found) == 0, "find failed");
    CHECK(found->value == 100000000, "found value wrong");
    utxo_set_free(&set);
    PASS();
    return 0;
}

/* ── Merkle Tree Tests ── */
static int test_merkle_tree_basic(void) {
    TEST("merkle_tree_basic");
    merkle_tree tree;
    CHECK(merkle_tree_init(&tree) == 0, "tree init failed");
    const char *tx1 = "tx-aaa", *tx2 = "tx-bbb", *tx3 = "tx-ccc";
    CHECK(merkle_tree_add_leaf(&tree, (const uint8_t *)tx1, strlen(tx1)) == 0, "add leaf1 failed");
    CHECK(merkle_tree_add_leaf(&tree, (const uint8_t *)tx2, strlen(tx2)) == 0, "add leaf2 failed");
    CHECK(merkle_tree_add_leaf(&tree, (const uint8_t *)tx3, strlen(tx3)) == 0, "add leaf3 failed");
    size_t count;
    CHECK(merkle_tree_leaf_count(&tree, &count) == 0, "leaf count failed");
    CHECK(count == 3, "leaf count wrong");
    merkle_hash root;
    CHECK(merkle_tree_get_root(&tree, &root) == 0, "get root failed");
    merkle_tree_free(&tree);
    PASS();
    return 0;
}

static int test_merkle_proof_verify(void) {
    TEST("merkle_proof_verify");
    merkle_tree tree;
    merkle_tree_init(&tree);
    const char *data[] = {"a", "b", "c", "d"};
    for (int i = 0; i < 4; i++)
        merkle_tree_add_leaf(&tree, (const uint8_t *)data[i], 1);
    merkle_tree_rebuild(&tree);
    merkle_hash root;
    merkle_tree_get_root(&tree, &root);
    merkle_proof proof;
    CHECK(merkle_proof_generate(&tree, 0, &proof) == 0, "generate proof failed");
    int valid;
    CHECK(merkle_proof_verify(&root, &proof, &valid) == 0, "verify proof failed");
    CHECK(valid, "proof should be valid");
    merkle_tree_free(&tree);
    merkle_proof_free(&proof);
    PASS();
    return 0;
}

/* ── PoW Consensus Tests ── */
static int test_pow_target_from_bits(void) {
    TEST("pow_target_from_bits");
    pow_target target;
    CHECK(pow_target_from_bits(0x1d00ffff, &target) == 0, "target from bits failed");
    uint32_t bits_out;
    CHECK(pow_target_to_bits(&target, &bits_out) == 0, "target to bits failed");
    CHECK(bits_out == 0x1d00ffff, "bits roundtrip failed");
    PASS();
    return 0;
}

static int test_pow_block_hash(void) {
    TEST("pow_block_hash");
    pow_block block; memset(&block, 0, sizeof(block));
    block.header.version = 1;
    block.header.timestamp = 1234567890;
    block.header.bits = 0x1d00ffff;
    block.header.nonce = 0;
    uint8_t hash[POW_HASH_LEN];
    CHECK(pow_block_hash(&block.header, hash) == 0, "block hash failed");
    int is_zero = 1;
    for (int i = 0; i < POW_HASH_LEN; i++)
        if (hash[i] != 0) is_zero = 0;
    CHECK(!is_zero, "hash is all zeros");
    PASS();
    return 0;
}

/* ── P2P Network Tests ── */
static int test_p2p_peer_manager(void) {
    TEST("p2p_peer_manager_init");
    p2p_peer_manager pm;
    CHECK(p2p_pm_init(&pm, 8333) == 0, "pm init failed");
    CHECK(pm.port == 8333, "port wrong");
    size_t count;
    p2p_pm_count(&pm, &count);
    CHECK(count == 0, "initial count should be 0");
    p2p_pm_free(&pm);
    PASS();
    return 0;
}

static int test_p2p_kad_distance(void) {
    TEST("p2p_kad_distance");
    uint8_t a[P2P_NODE_ID_LEN], b[P2P_NODE_ID_LEN], dist[P2P_NODE_ID_LEN];
    memset(a, 0xFF, P2P_NODE_ID_LEN);
    memset(b, 0x00, P2P_NODE_ID_LEN);
    CHECK(p2p_kad_distance(a, b, dist) == 0, "distance failed");
    int non_zero = 0;
    for (int i = 0; i < P2P_NODE_ID_LEN; i++)
        if (dist[i] != 0) non_zero = 1;
    CHECK(non_zero, "distance should be non-zero");
    PASS();
    return 0;
}

/* ── Tx Pool Tests ── */
static int test_txpool_init_add(void) {
    TEST("txpool_init_add");
    txpool pool;
    CHECK(txpool_init(&pool, 1000) == 0, "pool init failed");
    uint8_t raw[128]; memset(raw, 0x42, sizeof(raw));
    uint8_t addr[TXPOOL_ADDR_LEN]; memset(addr, 0xAA, TXPOOL_ADDR_LEN);
    int accepted;
    CHECK(txpool_add(&pool, raw, sizeof(raw), 1, addr, &accepted) == 0, "add tx failed");
    CHECK(accepted, "tx should be accepted");
    size_t count;
    txpool_size(&pool, &count);
    CHECK(count == 1, "pool size wrong");
    txpool_free(&pool);
    PASS();
    return 0;
}

int main(void) {
    printf("=== mini-blockchain-core Unit Tests ===\n\n");

    int failed = 0;
    failed += test_utxo_tx_create();
    failed += test_utxo_tx_add_input_output();
    failed += test_utxo_set_add_find();
    failed += test_merkle_tree_basic();
    failed += test_merkle_proof_verify();
    failed += test_pow_target_from_bits();
    failed += test_pow_block_hash();
    failed += test_p2p_peer_manager();
    failed += test_p2p_kad_distance();
    failed += test_txpool_init_add();

    printf("\n=== Results: %d/%d passed, %d failed ===\n",
           tests_passed, tests_run, failed);
    return failed > 0 ? 1 : 0;
}
