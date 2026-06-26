#include "consensus_pow.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

int main(void) {
    printf("=== Proof of Work Consensus Example ===\n\n");

    uint8_t genesis_prev[POW_HASH_LEN];
    memset(genesis_prev, 0, POW_HASH_LEN);

    uint8_t genesis_merkle[POW_HASH_LEN];
    memset(genesis_merkle, 0xAA, POW_HASH_LEN);

    pow_block genesis;
    pow_block_create(&genesis, 1, genesis_prev, genesis_merkle,
                     (uint32_t)time(NULL), POW_GENESIS_BITS);

    pow_target target;
    pow_target_from_bits(POW_GENESIS_BITS, &target);
    printf("Genesis bits: 0x%08x\n", POW_GENESIS_BITS);
    printf("Target: ");
    for (int i = 0; i < 8; i++) printf("%02x", target.bytes[i]);
    printf("...\n");

    uint64_t difficulty;
    pow_target_get_difficulty(&target, &difficulty);
    printf("Difficulty: %llu\n\n", (unsigned long long)difficulty);

    printf("Mining genesis block...\n");
    int r = pow_mine(&genesis, &target, 5000000);
    if (r == 0) {
        printf("  Mined! Nonce: %u\n", genesis.header.nonce);
        printf("  Block hash: ");
        for (int i = 0; i < 8; i++) printf("%02x", genesis.block_hash[i]);
        printf("...\n");
    } else {
        printf("  Mining failed (relaxed difficulty needed)\n");
    }

    int valid = 0;
    pow_validate_block(&genesis, &target, genesis_merkle, &valid);
    printf("  Block valid: %s\n\n", valid ? "YES" : "NO");

    pow_chain chain;
    pow_chain_init(&chain);
    pow_chain_add_block(&chain, &genesis);

    uint32_t height;
    pow_chain_get_height(&chain, &height);
    printf("Chain height after genesis: %u\n", height);

    uint8_t block2_merkle[POW_HASH_LEN];
    memset(block2_merkle, 0xBB, POW_HASH_LEN);

    pow_target easy_target;
    memset(&easy_target, 0xFF, sizeof(easy_target));
    memset(easy_target.bytes, 0x00, 8);

    for (int b = 1; b <= 3; b++) {
        pow_block *blk = malloc(sizeof(pow_block));
        if (!blk) break;
        pow_block_create(blk, 1, genesis.block_hash, block2_merkle,
                         genesis.header.timestamp + (uint32_t)(b * 600), 0x2070FFFF);

        r = pow_mine(blk, &easy_target, 100000);
        if (r == 0) {
            pow_chain_add_block(&chain, blk);
            printf("  Block %d mined: nonce=%u hash=", b, blk->header.nonce);
            for (int i = 0; i < 4; i++) printf("%02x", blk->block_hash[i]);
            printf("...\n");
        } else {
            free(blk);
        }
    }

    pow_chain_get_height(&chain, &height);
    printf("\nFinal chain height: %u\n", height);
    printf("Total chain work: %llu\n", (unsigned long long)chain.total_work);

    pow_block *tip = NULL;
    pow_chain_get_tip(&chain, &tip);
    if (tip) {
        printf("Tip block hash: ");
        for (int i = 0; i < 8; i++) printf("%02x", tip->block_hash[i]);
        printf("...\n");
    }

    pow_block *b2 = NULL;
    pow_chain_get_by_height(&chain, 2, &b2);
    if (b2) {
        printf("Block at height 2 found\n");
    }

    printf("\n=== GHOST Protocol ===\n\n");

    uint8_t uncle_merkle[POW_HASH_LEN];
    memset(uncle_merkle, 0xEE, POW_HASH_LEN);
    pow_block *uncle = malloc(sizeof(pow_block));
    pow_block_create(uncle, 1, genesis.block_hash, uncle_merkle,
                     genesis.header.timestamp + 500, 0x2070FFFF);
    pow_mine(uncle, &easy_target, 100000);

    if (tip) {
        pow_block_add_uncle(tip, uncle);
        printf("Uncle added to tip block\n");
        uint64_t ghost_score;
        pow_ghost_score(tip, &ghost_score);
        printf("GHOST score: %llu\n", (unsigned long long)ghost_score);
    }

    printf("\n=== Chain Reorganization ===\n\n");

    pow_chain fork_chain;
    pow_chain_init(&fork_chain);
    pow_block *fork_block = malloc(sizeof(pow_block));
    memcpy(fork_block, &genesis, sizeof(pow_block));
    pow_chain_add_block(&fork_chain, fork_block);

    for (int i = 0; i < 2; i++) {
        pow_block *fb = malloc(sizeof(pow_block));
        pow_block_create(fb, 1, genesis.block_hash, block2_merkle,
                         genesis.header.timestamp + (uint32_t)(i * 700), 0x2070FFFF);
        pow_mine(fb, &easy_target, 100000);
        pow_chain_add_block(&fork_chain, fb);
    }

    int longer = 0;
    pow_chain_compare(&fork_chain, &chain, &longer);
    printf("Fork longer than main: %s\n", longer ? "YES" : "NO");

    pow_block_free(&genesis);
    pow_chain_free(&chain);
    pow_chain_free(&fork_chain);
    free(uncle);

    printf("\nPoW example complete.\n");
    return 0;
}
