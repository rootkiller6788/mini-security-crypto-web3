#include "crosschain_bridge.h"
#include "amm_swap.h"
#include "oracle_price.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t demo2_rand_seed = 0xB41D6E02;

static uint32_t demo2_rand(void) {
    demo2_rand_seed = demo2_rand_seed * 1103515245 + 12345;
    return demo2_rand_seed;
}

static void print_hash(const char *label, const uint8_t hash[32]) {
    printf("      %s: ", label);
    for (int i = 0; i < 8; i++) printf("%02x", hash[i]);
    printf("...\n");
}

int main(void) {
    printf("================================================================\n");
    printf("  CROSSCHAIN BRIDGE DEMO -- Lock-Mint + Burn-Release + Oracle\n");
    printf("================================================================\n");
    printf("  This demo simulates a cross-chain bridge between two chains:\n");
    printf("   - Chain A (Ethereum): locks tokens, emits event\n");
    printf("   - Chain B (Polygon):  mints wrapped tokens via relayer\n");
    printf("   - Validator set: multi-sig (14/21 threshold)\n");
    printf("   - Light client: block header verification\n");
    printf("================================================================\n");

    printf("\n");
    printf("==============================================================\n");
    printf("  PHASE 1: Bridge Setup & Validator Configuration\n");
    printf("==============================================================\n\n");

    printf("[1.1] Initialize bridges on both chains...\n");
    Bridge bridge_eth, bridge_poly;
    bridge_init(&bridge_eth, BRIDGE_LOCK_MINT, BRIDGE_MULTI_SIG, 1);
    bridge_init(&bridge_poly, BRIDGE_LOCK_MINT, BRIDGE_MULTI_SIG, 137);
    printf("      Chain A (Ethereum):  bridge initialized, chain_id=1\n");
    printf("      Chain B (Polygon):    bridge initialized, chain_id=137\n\n");

    printf("[1.2] Register validators (21-node set)...\n");
    uint8_t validator_pubkeys[BRIDGE_MAX_VALIDATORS][64];
    uint8_t validator_addrs[BRIDGE_MAX_VALIDATORS][BRIDGE_ADDR_SIZE];
    uint64_t validator_stakes[BRIDGE_MAX_VALIDATORS];

    const char *val_names[] = {
        "Validator-A", "Validator-B", "Validator-C", "Validator-D",
        "Validator-E", "Validator-F", "Validator-G", "Validator-H",
        "Validator-I", "Validator-J", "Validator-K", "Validator-L",
        "Validator-M", "Validator-N", "Validator-O", "Validator-P",
        "Validator-Q", "Validator-R", "Validator-S", "Validator-T",
        "Validator-U"
    };

    for (int i = 0; i < BRIDGE_MAX_VALIDATORS; i++) {
        for (int j = 0; j < 64; j++) {
            validator_pubkeys[i][j] = (uint8_t)(demo2_rand() & 0xFF);
        }
        for (int j = 0; j < BRIDGE_ADDR_SIZE; j++) {
            validator_addrs[i][j] = (uint8_t)((0x80 + i) ^ (j * 7));
        }
        validator_stakes[i] = 10000 + (uint64_t)(demo2_rand() % 5000);

        bridge_add_validator(&bridge_eth, validator_pubkeys[i],
                             validator_addrs[i], validator_stakes[i]);
        bridge_add_validator(&bridge_poly, validator_pubkeys[i],
                             validator_addrs[i], validator_stakes[i]);
    }
    printf("      Added %d validators to both bridges\n",
           bridge_eth.validator_count);
    printf("      Multi-sig threshold: %d/%d (%.0f%%)\n",
           BRIDGE_SIG_THRESHOLD_NUM, BRIDGE_SIG_THRESHOLD_DEN,
           (float)BRIDGE_SIG_THRESHOLD_NUM * 100.0f / BRIDGE_SIG_THRESHOLD_DEN);

    uint64_t total_staked = 0;
    for (int i = 0; i < bridge_eth.validator_count; i++) {
        total_staked += bridge_eth.validators[i].stake;
    }
    printf("      Total stake: %llu\n\n",
           (unsigned long long)total_staked);

    printf("[1.3] Display validator set...\n");
    printf("      %-16s %-20s %s\n", "Validator", "Address", "Stake");
    printf("      %-16s %-20s %s\n", "---------", "-------", "-----");
    for (int i = 0; i < 5; i++) {
        printf("      %-16s %02x%02x..%02x%02x  %llu\n",
               val_names[i],
               validator_addrs[i][0], validator_addrs[i][1],
               validator_addrs[i][18], validator_addrs[i][19],
               (unsigned long long)validator_stakes[i]);
    }
    printf("      ... (%d more validators)\n\n",
           bridge_eth.validator_count - 5);

    printf("\n");
    printf("==============================================================\n");
    printf("  PHASE 2: Lock-and-Mint Flow (Ethereum -> Polygon)\n");
    printf("==============================================================\n\n");

    uint8_t alice_addr[BRIDGE_ADDR_SIZE];
    uint8_t bob_addr[BRIDGE_ADDR_SIZE];
    for (int i = 0; i < BRIDGE_ADDR_SIZE; i++) {
        alice_addr[i] = (uint8_t)(0xA0 + i);
        bob_addr[i] = (uint8_t)(0xB0 + i);
    }

    printf("[2.1] Alice locks 100 ETH on Ethereum -> mints wETH on Polygon...\n");
    uint64_t lock_amount = 100000000000000000000ULL;

    bool locked = bridge_lock(&bridge_eth, alice_addr, bob_addr,
                               lock_amount, 137);
    printf("      Lock result: %s\n", locked ? "SUCCESS" : "FAILED");
    printf("      Event nonce: %llu\n",
           (unsigned long long)bridge_eth.events[0].nonce);
    printf("      Locked total: %llu\n\n",
           (unsigned long long)bridge_eth.locked_amount);

    printf("[2.2] Relayer picks up event, creates relay message...\n");
    BridgeRelayMessage relay_msg;
    bridge_generate_message(&relay_msg, &bridge_eth.events[0], 18000000);
    printf("      Source height: %llu\n",
           (unsigned long long)relay_msg.source_height);
    printf("      Signatures collected: %d\n\n", relay_msg.sig_count);

    printf("[2.3] Verify multi-sig on Polygon side...\n");
    bool verified = bridge_verify_multisig(&bridge_poly, &relay_msg);
    printf("      Multi-sig verification: %s\n\n",
           verified ? "PASSED" : "FAILED");

    printf("[2.4] Mint wrapped ETH on Polygon...\n");
    bool minted = bridge_mint(&bridge_poly, bob_addr, lock_amount, &relay_msg);
    printf("      Mint result: %s\n", minted ? "SUCCESS" : "FAILED");
    printf("      Minted total on Polygon: %llu\n\n",
           (unsigned long long)bridge_poly.minted_amount);

    printf("[2.5] Mark event as processed...\n");
    bridge_process_event(&bridge_eth, 0);
    printf("      Event 0 processed: %s\n",
           bridge_eth.events[0].processed ? "YES" : "NO");

    printf("\n");
    printf("==============================================================\n");
    printf("  PHASE 3: Burn-and-Release Flow (Polygon -> Ethereum)\n");
    printf("==============================================================\n\n");

    printf("[3.1] Bob burns 50 wETH on Polygon...\n");
    uint64_t burn_amount = 50000000000000000000ULL;
    bool burned = bridge_burn(&bridge_poly, bob_addr, burn_amount, 1);
    printf("      Burn result: %s\n", burned ? "SUCCESS" : "FAILED");
    printf("      Event nonce: %llu\n\n",
           (unsigned long long)bridge_poly.events[1].nonce);

    printf("[3.2] Relayer creates burn->release message...\n");
    BridgeRelayMessage release_msg;
    bridge_generate_message(&release_msg, &bridge_poly.events[1], 25000000);
    printf("      Source height: %llu\n",
           (unsigned long long)release_msg.source_height);
    printf("      Signatures: %d\n\n", release_msg.sig_count);

    printf("[3.3] Verify on Ethereum, release original ETH...\n");
    bool released = bridge_release(&bridge_eth, bob_addr,
                                    burn_amount, &release_msg);
    printf("      Release result: %s\n", released ? "SUCCESS" : "FAILED");
    printf("      Locked remaining: %llu\n\n",
           (unsigned long long)bridge_eth.locked_amount);

    printf("\n");
    printf("==============================================================\n");
    printf("  PHASE 4: Multiple Events & Validation\n");
    printf("==============================================================\n\n");

    printf("[4.1] Process multiple lock events...\n");
    uint8_t users[4][BRIDGE_ADDR_SIZE];
    for (int u = 0; u < 4; u++) {
        for (int i = 0; i < BRIDGE_ADDR_SIZE; i++) {
            users[u][i] = (uint8_t)((0xC0 + u * 10 + i) & 0xFF);
        }
    }

    uint64_t amounts[] = {
        10000000000000000000ULL,
        25000000000000000000ULL,
        50000000000000000000ULL,
        150000000000000000000ULL
    };

    for (int i = 0; i < 4; i++) {
        bool r = bridge_lock(&bridge_eth, users[i], users[i],
                              amounts[i], 137);
        if (i < 3) {
            printf("      Lock %d: %llu.%04llu ETH -> %s\n",
                   i + 1,
                   (unsigned long long)(amounts[i] / 1000000000000000000ULL),
                   (unsigned long long)((amounts[i] % 1000000000000000000ULL) / 100000000000000ULL),
                   r ? "OK" : "FAIL");
        }
    }
    printf("      ... (%d total events)\n\n", bridge_eth.event_count);

    printf("[4.2] Event table...\n");
    printf("      %-6s %-8s %-10s %-22s %s\n",
           "ID", "Chain", "Amount", "Hash", "Processed");
    printf("      %-6s %-8s %-10s %-22s %s\n",
           "------", "--------", "----------", "----------------------",
           "---------");
    for (uint64_t i = 0; i < bridge_eth.event_count && i < 8; i++) {
        BridgeEvent *e = &bridge_eth.events[i];
        printf("      %-6llu %-8s %llu.ETH    ",
               (unsigned long long)i,
               e->source_chain_id == 1 ? "ETH" : "POLY",
               (unsigned long long)(e->amount / 1000000000000000000ULL));
        for (int j = 0; j < 8; j++) printf("%02x", e->tx_hash[j]);
        printf("  %s\n", e->processed ? "YES" : "NO");
    }
    printf("\n");

    printf("\n");
    printf("==============================================================\n");
    printf("  PHASE 5: Light Client Block Header Verification\n");
    printf("==============================================================\n\n");

    printf("[5.1] Simulate block header from source chain...\n");
    BridgeBlockHeader header;
    memset(&header, 0, sizeof(header));
    header.height = 18000000;
    header.timestamp = demo2_rand() + 1700000000;
    header.nonce = demo2_rand();
    for (int i = 0; i < BRIDGE_HASH_SIZE; i++) {
        header.prev_hash[i] = (uint8_t)(demo2_rand() & 0xFF);
        header.merkle_root[i] = (uint8_t)(demo2_rand() & 0xFF);
        header.state_root[i] = (uint8_t)(demo2_rand() & 0xFF);
    }
    print_hash("Prev hash", header.prev_hash);
    print_hash("Merkle root", header.merkle_root);
    print_hash("State root", header.state_root);
    printf("      Height: %llu, Time: %llu\n\n",
           (unsigned long long)header.height,
           (unsigned long long)header.timestamp);

    printf("[5.2] Create and verify header proof...\n");
    BridgeHeaderProof proof;
    memset(&proof, 0, sizeof(proof));
    memcpy(&proof.header, &header, sizeof(BridgeBlockHeader));
    for (int i = 0; i < BRIDGE_HASH_SIZE; i++) {
        proof.proof[i] = (uint8_t)(demo2_rand() & 0xFF);
    }
    proof.proof_length = BRIDGE_HASH_SIZE * 3;

    bool header_ok = bridge_verify_header(&bridge_poly, &header, &proof);
    printf("      Header verification: %s (light client)\n\n",
           header_ok ? "VALID" : "INVALID");

    printf("[5.3] Verify bridge event against header...\n");
    bool event_ok = bridge_verify_event(&bridge_poly,
                                         &bridge_eth.events[0], &header);
    printf("      Event inclusion proof: %s\n\n",
           event_ok ? "VERIFIED" : "FAILED");

    printf("\n");
    printf("==============================================================\n");
    printf("  PHASE 6: Merkle Tree + Oracle Integration\n");
    printf("==============================================================\n\n");

    printf("[6.1] Build Merkle tree from events...\n");
    uint8_t leaves[8][BRIDGE_HASH_SIZE];
    for (int i = 0; i < 8; i++) {
        uint8_t buf[sizeof(BridgeEvent)];
        memcpy(buf, &bridge_eth.events[i % bridge_eth.event_count],
               sizeof(BridgeEvent));
        memcpy(leaves[i], buf, BRIDGE_HASH_SIZE);
        for (int j = 0; j < BRIDGE_HASH_SIZE; j++) {
            leaves[i][j] ^= (uint8_t)(demo2_rand() & 0xFF);
        }
    }

    uint8_t merkle_root[BRIDGE_HASH_SIZE];
    uint32_t merkle_ok = bridge_compute_merkle_root(leaves, 4, merkle_root);
    if (merkle_ok) {
        print_hash("Merkle root (4 leaves)", merkle_root);
    }

    uint32_t merkle_ok2 = bridge_compute_merkle_root(leaves, 8, merkle_root);
    if (merkle_ok2) {
        print_hash("Merkle root (8 leaves)", merkle_root);
    }
    printf("\n");

    printf("[6.2] Oracle price feed for cross-chain assets...\n");
    OraclePriceFeed eth_oracle;
    oracle_feed_init(&eth_oracle, ORACLE_CHAINLINK, 86400);

    uint8_t node_addrs[5][20];
    for (int i = 0; i < 5; i++) {
        memset(node_addrs[i], (uint8_t)(0xD0 + i), 20);
        oracle_add_node(&eth_oracle, node_addrs[i], 2000 + (uint64_t)i * 300);
    }

    uint64_t eth_usd[] = {200000000000ULL, 201000000000ULL,
                           199500000000ULL, 200800000000ULL,
                           200300000000ULL};
    for (int i = 0; i < 5; i++) {
        oracle_submit_price(&eth_oracle, node_addrs[i],
                             eth_usd[i], demo2_rand() + 2000000);
    }
    oracle_update_aggregate(&eth_oracle);

    uint64_t eth_price = oracle_get_price(&eth_oracle);
    uint64_t btc_price = 3500000000000ULL;
    uint64_t bond_price = oracle_convert_price(btc_price, eth_price, 100000000ULL);
    printf("      ETH/USD: $%llu.%02llu\n",
           (unsigned long long)(eth_price / 100000000),
           (unsigned long long)((eth_price % 100000000) / 1000000));
    printf("      BTC/USD: $%llu.%02llu\n",
           (unsigned long long)(btc_price / 100000000),
           (unsigned long long)((btc_price % 100000000) / 1000000));
    printf("      1 BTC = %llu.%06llu ETH\n\n",
           (unsigned long long)(bond_price / 100000000),
           (unsigned long long)(bond_price % 100000000));

    printf("\n");
    printf("==============================================================\n");
    printf("  PHASE 7: Security & Edge Cases\n");
    printf("==============================================================\n\n");

    printf("[7.1] Attempt to process already-processed event...\n");
    bool dup = bridge_process_event(&bridge_eth, 0);
    printf("      Double-process attempt: %s\n\n", dup ? "ALLOWED" : "REJECTED");

    printf("[7.2] Remove a validator...\n");
    bool removed = bridge_remove_validator(&bridge_eth, validator_addrs[20]);
    printf("      Validator-U removed: %s\n", removed ? "YES" : "NO");

    printf("[7.3] Verify multi-sig with insufficient signatures...\n");
    BridgeRelayMessage bad_msg;
    memset(&bad_msg, 0, sizeof(bad_msg));
    bad_msg.sig_count = 5;
    for (int i = 0; i < 5; i++) bad_msg.sigs[i].valid = true;
    bool bad_verify = bridge_verify_multisig(&bridge_poly, &bad_msg);
    printf("      Under-threshold multi-sig: %s\n\n",
           bad_verify ? "ACCEPTED" : "REJECTED");

    printf("[7.4] Attempt release exceeding locked amount...\n");
    Bridge tmp_bridge;
    bridge_init(&tmp_bridge, BRIDGE_LOCK_MINT, BRIDGE_MULTI_SIG, 1);
    tmp_bridge.locked_amount = 1000;
    BridgeRelayMessage dummy_msg;
    memset(&dummy_msg, 0, sizeof(dummy_msg));
    dummy_msg.sig_count = BRIDGE_SIG_THRESHOLD_NUM;
    for (int i = 0; i < BRIDGE_SIG_THRESHOLD_NUM; i++) {
        dummy_msg.sigs[i].valid = true;
        memcpy(dummy_msg.sigs[i].signer, validator_addrs[i], BRIDGE_ADDR_SIZE);
    }
    bool over_release = bridge_release(&tmp_bridge, bob_addr,
                                        5000, &dummy_msg);
    printf("      Over-release attempt: %s\n\n",
           over_release ? "ALLOWED" : "REJECTED");

    printf("\n");
    printf("==============================================================\n");
    printf("  FINAL SUMMARY\n");
    printf("==============================================================\n");
    printf("  Bridge ETH:  %d validators, %llu locked, %d events\n",
           bridge_eth.validator_count,
           (unsigned long long)bridge_eth.locked_amount,
           bridge_eth.event_count);
    printf("  Bridge POLY: %d validators, %llu minted, %d events\n",
           bridge_poly.validator_count,
           (unsigned long long)bridge_poly.minted_amount,
           bridge_poly.event_count);
    printf("  Multi-sig threshold: %d/%d\n",
           BRIDGE_SIG_THRESHOLD_NUM, BRIDGE_SIG_THRESHOLD_DEN);
    printf("  Light client: %s\n",
           BRIDGE_HEADER_SIZE > 0 ? "Enabled" : "Disabled");
    printf("\n================================================================\n");
    printf("  Crosschain Bridge Demo Complete!\n");
    printf("================================================================\n");
    return 0;
}
