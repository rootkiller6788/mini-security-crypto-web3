#include "consensus_pow.h"
#include "merkle_tree.h"
#include "tx_pool.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

static void print_hash(const char *label, const uint8_t *hash, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len && i < 16; i++) printf("%02x", hash[i]);
    if (len > 16) printf("...");
    printf("\n");
}

static uint32_t get_timestamp(void) {
    return (uint32_t)time(NULL);
}

static void mine_block(pow_block *block, const pow_target *target, const char *name) {
    int r = pow_mine(block, target, 10000000);
    if (r == 0) {
        printf("[%s] Mined! nonce=%-10u hash=", name, block->header.nonce);
        for (int i = 0; i < 8; i++) printf("%02x", block->block_hash[i]);
        printf("...\n");
    } else {
        printf("[%s] Mining failed\n", name);
    }
}

int main(void) {
    printf("========================================\n");
    printf("  Mini Blockchain Core — Full Demo\n");
    printf("========================================\n\n");

    uint8_t genesis_prev[POW_HASH_LEN];
    memset(genesis_prev, 0, POW_HASH_LEN);

    pow_chain main_chain;
    pow_chain_init(&main_chain);

    merkle_tree block_tree;
    merkle_tree_init(&block_tree);

    printf("--- Phase 1: Genesis Block ---\n\n");

    uint8_t genesis_merkle[POW_HASH_LEN];
    const char *coinbase = "Genesis Coinbase: 50 BTC to Miner";
    const char *genesis_tx = "Genesis TX: network launch";
    merkle_tree_add_leaf(&block_tree, (const uint8_t *)coinbase, strlen(coinbase));
    merkle_tree_add_leaf(&block_tree, (const uint8_t *)genesis_tx, strlen(genesis_tx));
    merkle_tree_rebuild(&block_tree);

    merkle_hash gen_root;
    merkle_tree_get_root(&block_tree, &gen_root);
    memcpy(genesis_merkle, gen_root.hash, POW_HASH_LEN);

    pow_block *genesis_block = malloc(sizeof(pow_block));
    if (!genesis_block) { printf("OOM\n"); return 1; }

    pow_block_create(genesis_block, 1, genesis_prev, genesis_merkle,
                     get_timestamp(), POW_GENESIS_BITS);

    pow_target genesis_target;
    pow_target_from_bits(POW_GENESIS_BITS, &genesis_target);

    pow_target easy_target;
    memset(&easy_target, 0xFF, sizeof(easy_target));
    memset(easy_target.bytes, 0, 12);

    mine_block(genesis_block, &easy_target, "GENESIS");

    int valid = 0;
    pow_validate_block(genesis_block, &easy_target, genesis_merkle, &valid);
    printf("[GENESIS] Block valid: %s\n\n", valid ? "YES" : "NO");

    pow_chain_add_block(&main_chain, genesis_block);

    printf("--- Phase 2: Building the Chain ---\n\n");

    const char *tx_data[] = {
        "TX001: Alice pays Bob 10 BTC, fee 0.0001",
        "TX002: Bob pays Charlie 5 BTC, fee 0.0002",
        "TX003: Charlie pays Dave 2 BTC, fee 0.0001",
        "TX004: Dave pays Eve 1 BTC, fee 0.00005",
        "TX005: Eve pays Frank 0.5 BTC, fee 0.0001",
        "TX006: Frank pays Grace 4 BTC, fee 0.00015",
        "TX007: Grace pays Alice 3 BTC, fee 0.0001",
        "TX008: Alice pays Henry 6 BTC, fee 0.0003",
        "TX009: Henry pays Ivy 2.5 BTC, fee 0.0001",
        "TX010: Ivy pays Jack 1.2 BTC, fee 0.0002",
    };
    size_t num_txs = sizeof(tx_data) / sizeof(tx_data[0]);

    txpool mempool;
    txpool_init(&mempool, TXPOOL_DEFAULT_MAX);

    for (size_t i = 0; i < num_txs; i++) {
        int accepted = 0;
        txpool_add(&mempool, (const uint8_t *)tx_data[i], strlen(tx_data[i]), 0, NULL, &accepted);
    }
    printf("Mempool initialized with %zu transactions\n", mempool.count);

    pow_block *prev_block = genesis_block;
    for (int block_num = 1; block_num <= 5; block_num++) {
        printf("\n--- Mining Block %d ---\n", block_num);

        merkle_sha256d(prev_block->block_hash, POW_HASH_LEN,
                       prev_block->block_hash);

        merkle_tree tx_tree;
        merkle_tree_init(&tx_tree);

        char cb[128];
        snprintf(cb, sizeof(cb), "Block %d Coinbase: 50 BTC + fees", block_num);
        merkle_tree_add_leaf(&tx_tree, (const uint8_t *)cb, strlen(cb));

        uint8_t *sel_raw = malloc(mempool.count * 128);
        size_t sel_off = 0;
        size_t selected_count = 0;
        for (size_t i = 0; i < mempool.count && selected_count < 3; i++) {
            merkle_tree_add_leaf(&tx_tree, mempool.txs[i].raw, mempool.txs[i].raw_len);
            memcpy(sel_raw + sel_off, mempool.txs[i].txid, TXPOOL_TXID_LEN);
            sel_off += TXPOOL_TXID_LEN;
            selected_count++;
        }

        merkle_tree_rebuild(&tx_tree);
        merkle_hash tx_root;
        merkle_tree_get_root(&tx_tree, &tx_root);

        pow_block *new_block = malloc(sizeof(pow_block));
        if (!new_block) break;

        uint8_t prev_hash[POW_HASH_LEN];
        pow_block_hash(&prev_block->header, prev_hash);

        pow_block_create(new_block, 1, prev_hash, tx_root.hash,
                         get_timestamp(), 0x2070FFFF);

        char name[32];
        snprintf(name, sizeof(name), "BLOCK-%d", block_num);
        mine_block(new_block, &easy_target, name);

        pow_block_hash(&new_block->header, new_block->block_hash);
        int valid = 0;
        pow_validate_block(new_block, &easy_target, tx_root.hash, &valid);
        printf("[BLOCK-%d] Valid: %s, txs: %zu\n", block_num,
               valid ? "YES" : "NO", selected_count);

        pow_chain_add_block(&main_chain, new_block);

        for (size_t i = 0; i < selected_count; i++) {
            txpool_remove(&mempool, sel_raw + i * TXPOOL_TXID_LEN);
        }
        free(sel_raw);
        merkle_tree_free(&tx_tree);
        prev_block = new_block;
    }

    uint32_t chain_height;
    pow_chain_get_height(&main_chain, &chain_height);
    printf("\n--- Chain Summary ---\n");
    printf("Final height: %u blocks\n", chain_height);
    printf("Total chain work: %llu\n", (unsigned long long)main_chain.total_work);
    printf("Mempool remaining: %zu txs\n", mempool.count);

    pow_block *tip = NULL;
    pow_chain_get_tip(&main_chain, &tip);
    if (tip) {
        printf("Tip block: height=%u, timestamp=%u\n", tip->height, tip->header.timestamp);
        print_hash("    prev_hash", tip->header.prev_block_hash, 32);
        print_hash("    block_hash", tip->block_hash, 32);
    }

    printf("\n--- Phase 3: Difficulty Adjustment ---\n");

    pow_target new_target;
    if (pow_adjust_target(&main_chain, POW_DIFFICULTY_PERIOD, &new_target) == 0) {
        uint32_t new_bits;
        pow_target_to_bits(&new_target, &new_bits);
        uint64_t new_difficulty;
        pow_target_get_difficulty(&new_target, &new_difficulty);
        printf("New target bits: 0x%08x\n", new_bits);
        printf("New difficulty: %llu\n", (unsigned long long)new_difficulty);
    } else {
        if (chain_height < (uint32_t)POW_DIFFICULTY_PERIOD) {
            printf("Not enough blocks for difficulty adjustment (%u < %d)\n",
                   chain_height, POW_DIFFICULTY_PERIOD);
        }
    }

    printf("\n--- Phase 4: Chain Reorganization Simulation ---\n");

    pow_chain fork;
    pow_chain_init(&fork);

    pow_block *fork_genesis = malloc(sizeof(pow_block));
    memcpy(fork_genesis, genesis_block, sizeof(pow_block));
    fork_genesis->tx_data = NULL;
    fork_genesis->tx_data_len = 0;
    pow_chain_add_block(&fork, fork_genesis);

    for (int i = 0; i < 6; i++) {
        pow_block *fb = malloc(sizeof(pow_block));
        uint8_t fake_merkle[POW_HASH_LEN];
        memset(fake_merkle, (uint8_t)(0xA0 + i), POW_HASH_LEN);
        pow_block_create(fb, 1, genesis_block->block_hash, fake_merkle,
                         get_timestamp() + (uint32_t)(i * 300), 0x2070FFFF);
        mine_block(fb, &easy_target, "FORK-BLK");
        pow_chain_add_block(&fork, fb);
    }

    uint32_t fork_height;
    pow_chain_get_height(&fork, &fork_height);
    printf("Fork height: %u, main height: %u\n", fork_height, chain_height);

    int fork_longer = 0;
    pow_chain_compare(&fork, &main_chain, &fork_longer);
    printf("Fork has more work: %s\n", fork_longer ? "YES" : "NO");

    if (fork_longer) {
        printf("Performing chain reorganization...\n");
        pow_chain_reorg(&main_chain, &fork);
        pow_chain_get_height(&main_chain, &chain_height);
        printf("New main chain height: %u\n", chain_height);
    }

    printf("\n--- Phase 5: GHOST Protocol ---\n");

    pow_block *uncle = malloc(sizeof(pow_block));
    uint8_t uncle_merkle[POW_HASH_LEN];
    memset(uncle_merkle, 0x99, POW_HASH_LEN);
    pow_block_create(uncle, 1, genesis_block->block_hash, uncle_merkle,
                     get_timestamp() + 400, 0x2070FFFF);
    mine_block(uncle, &easy_target, "UNCLE");

    if (tip && uncle) {
        pow_block_add_uncle(tip, uncle);
        uint64_t ghost;
        pow_ghost_score(tip, &ghost);
        printf("Tip GHOST score: %llu (blocks main chain)\n", (unsigned long long)ghost);
    }

    printf("\n========================================\n");
    printf("  Demo Complete!\n");
    printf("========================================\n");

    pow_chain_free(&fork);
    pow_chain_free(&main_chain);
    txpool_free(&mempool);

    return 0;
}
