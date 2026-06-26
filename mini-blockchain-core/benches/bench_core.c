/*
 * mini-blockchain-core — Benchmark: UTXO, merkle, PoW, tx pool, P2P
 *
 * Usage: bench_core [iterations]
 */
#include "../include/utxo_model.h"
#include "../include/merkle_tree.h"
#include "../include/consensus_pow.h"
#include "../include/tx_pool.h"
#include "../include/p2p_network.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now_ms(void) {
    return (double)clock() / (double)(CLOCKS_PER_SEC / 1000);
}

int main(int argc, char **argv) {
    int N = (argc > 1) ? atoi(argv[1]) : 5000;
    printf("=== mini-blockchain-core Benchmarks (iterations=%d) ===\n\n", N);

    /* SHA256 hashing */
    {
        uint8_t data[64] = "blockchain benchmark data for hashing throughput test";
        uint8_t hash[UTOX_MODEL_SHA256_LEN];
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            utxo_tx_double_sha256(data, 64, hash);
        }
        double dt = now_ms() - t0;
        printf("  double_sha256 (64 bytes):             %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    /* Merkle tree (32 leaves) */
    {
        merkle_tree tree;
        merkle_tree_init(&tree);
        uint8_t leaf[32];
        for (int i = 0; i < 32; i++) { memset(leaf, i, 32); merkle_tree_add_leaf(&tree, leaf, 32); }
        merkle_tree_rebuild(&tree);
        merkle_hash root;
        int k = N / 10 > 0 ? N / 10 : 1;
        double t0 = now_ms();
        for (int i = 0; i < k; i++) {
            merkle_tree_get_root(&tree, &root);
        }
        double dt = now_ms() - t0;
        printf("  merkle_tree_get_root (32 leaves):     %d ops in %.1f ms  (%.1f µs/op)\n",
               k, dt, dt * 1000.0 / (double)k);
        merkle_tree_free(&tree);
    }

    /* PoW mining (low difficulty) */
    {
        pow_block block;
        pow_target target;
        memset(&block, 0, sizeof(block));
        block.header.version = 1;
        block.header.timestamp = (uint32_t)time(NULL);
        block.header.bits = 0x1f00ffff;
        pow_target_from_bits(0x1f00ffff, &target);
        int k = N / 500 > 0 ? N / 500 : 1;
        double t0 = now_ms();
        for (int i = 0; i < k; i++) {
            block.header.nonce = i;
            uint8_t hash[32];
            pow_block_hash(&block.header, hash);
        }
        double dt = now_ms() - t0;
        printf("  pow_block_hash:                       %d ops in %.1f ms  (%.1f µs/op)\n",
               k, dt, dt * 1000.0 / (double)k);
    }

    /* Transaction pool operations */
    {
        txpool pool;
        txpool_init(&pool, 1000);
        uint8_t raw[] = "benchmark-transaction-data-for-txpool-test";
        uint8_t from[TXPOOL_ADDR_LEN]; memset(from, 0xAB, TXPOOL_ADDR_LEN);
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            int accepted;
            txpool_add(&pool, raw, sizeof(raw), 1, from, &accepted);
        }
        double dt = now_ms() - t0;
        printf("  txpool_add:                           %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
        txpool_free(&pool);
    }

    /* UTXO coin selection */
    {
        utxo_set set;
        utxo_set_init(&set, 256);
        utxo_entry e; memset(&e, 0, sizeof(e)); e.value = 100000;
        for (int i = 0; i < 256; i++) { e.txid[0] = (uint8_t)i; e.vout = i; utxo_set_add(&set, &e); }
        utxo_entry *selected[16]; size_t count; uint64_t total, change;
        int k = N / 10 > 0 ? N / 10 : 1;
        double t0 = now_ms();
        for (int i = 0; i < k; i++) {
            utxo_coin_selection(&set, 500000, 2, selected, &count, &total, &change);
        }
        double dt = now_ms() - t0;
        printf("  utxo_coin_selection:                  %d ops in %.1f ms  (%.1f µs/op)\n",
               k, dt, dt * 1000.0 / (double)k);
        utxo_set_free(&set);
    }

    /* P2P node ID generation */
    {
        uint8_t node_id[P2P_NODE_ID_LEN];
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            p2p_generate_node_id(node_id);
        }
        double dt = now_ms() - t0;
        printf("  p2p_generate_node_id:                 %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    printf("\n=== Benchmarks complete ===\n");
    return 0;
}
