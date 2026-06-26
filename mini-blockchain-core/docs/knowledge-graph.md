# Knowledge Graph ? mini-blockchain-core

## L1: Definitions

| ?? | ?? | ?? |
|------|------|------|
| utxo_transaction, utxo_txin, utxo_txout | struct | utxo_model.h |
| utxo_entry, utxo_set | struct | utxo_model.h |
| utxo_pubkey, utxo_signature | struct | utxo_model.h |
| merkle_node, merkle_tree, merkle_hash | struct | merkle_tree.h |
| merkle_proof | struct | merkle_tree.h |
| patricia_node, patricia_merkle_trie | struct | merkle_tree.h |
| pow_block_header, pow_block, pow_chain | struct | consensus_pow.h |
| pow_target | struct | consensus_pow.h |
| txpool_tx, txpool, txpool_selector | struct | tx_pool.h |
| p2p_peer, p2p_peer_manager | struct | p2p_network.h |
| p2p_kad_bucket, p2p_kad_table | struct | p2p_network.h |
| p2p_message, p2p_inv_item | struct | p2p_network.h |
| p2p_bootstrap, p2p_dns_seed | struct | p2p_network.h |
| script_element, script_context | struct | script_engine.h |
| script_builder | struct | script_engine.h |
| spv_header, spv_header_chain | struct | spv_client.h |
| spv_bloom_filter, spv_tx_match | struct | spv_client.h |
| p2p_msg_type, script_opcode | enum | p2p_network.h, script_engine.h |

## L2: Core Concepts

| ?? | ?? | ??? |
|------|------|--------|
| UTXO ?? | utxo_model.c | ??????????????? |
| Merkle ? | merkle_tree.c | ????????????? |
| PoW ?? | consensus_pow.c | ??????Nonce ???target ?? |
| ??? | tx_pool.c | Mempool?Gas ???RBF |
| P2P ?? | p2p_network.c | ???????????? |
| Script VM | script_engine.c | ?????????????? |
| SPV ?? | spv_client.c | ?????????????? |

## L3: Engineering Structures

| ?? | ?? |
|------|------|
| ?????/???? | utxo_serialize_tx / utxo_deserialize_tx |
| ??? 80 ???? | pow_block_serialize / pow_block_deserialize |
| P2P ????? | p2p_msg_serialize / p2p_msg_deserialize |
| UTXO ?????? | utxo_set_add (realloc) |
| ?????? | pow_chain (head/tail/prev/next) |
| Kademlia ??? | p2p_kad_table (256 buckets ? 20 peers) |
| Script ?+AltStack | script_context (????) |
| ??????? | spv_bloom_filter (2048 bits) |

## L4: Standards/Theorems

| ??/?? | ?? | ?? |
|-----------|------|------|
| Nakamoto ????? | spv_nakamoto_confidence() | Bitcoin ?11 |
| CAP ???? | ?? | Brewer 2000 |
| FLP ????? PoW | ?? | FLP 1985 |
| BIP 11 ?? | script_multisig_lock() | Bitcoin BIP |
| BIP 16 P2SH | script_p2sh_redeem() | Bitcoin BIP |
| BIP 37 ???? | spv_bloom_*() | Bitcoin BIP |
| BIP 65 CLTV | script_cltv_lock() | Bitcoin BIP |
| BIP 112 CSV | script_eval_op(OP_CHECKSEQUENCEVERIFY) | Bitcoin BIP |
| ECDSA secp256k1 | utxo_verify_sig() | SEC2 |
| ?????? | pow_adjust_target() | Bitcoin Core |
| SHA256d ?? | utxo_tx_double_sha256() | Bitcoin Core |

## L5: Algorithms/Methods

| ?? | ??? | ?? |
|------|--------|------|
| PoW ???? | O(N) | pow_mine() |
| ?? PoW ?? | O(N) | pow_mine_incremental() |
| Merkle ??? | O(n log n) | merkle_node_build_tree() |
| Merkle ???? | O(log n) | merkle_proof_generate() |
| Merkle ???? | O(log n) | merkle_proof_verify() |
| GHOST ???? | O(1) | pow_ghost_score() |
| ???? | O(n) | pow_adjust_target() |
| ??? (??) | O(n log n) | utxo_coin_selection() |
| Patricia Trie ?? | O(k) | patricia_trie_insert() |
| Script ??? | O(n) | script_eval() |
| ScriptNum ?? | O(1) | script_read_num() |
| MurmurHash3-32 | O(n) | spv_murmur_hash() |
| ????? | O(k) | spv_bloom_add/contains() |
| Nakamoto ??? | O(z) | spv_nakamoto_confidence() |
| Kademlia XOR ?? | O(1) | p2p_kad_distance() |
| ??? | O(n) | pow_chain_reorg() |
| Kademlia ?? | O(log n) | p2p_kad_find_peers() |

## L6: Canonical Problems

| ?? | ???? | ?? |
|------|---------|------|
| ???????? | demo_blockchain.c | demos/ |
| ?????? | demo_wallet.c | demos/ |
| ???????? | spv_client.h/c | include/ + src/ |
| ????? | tx_pool.h/c | include/ + src/ |
| UTXO ???? | utxo_model.h/c | include/ + src/ |
| Merkle ??? | merkle_tree.h/c | include/ + src/ |

## L7: Applications

| ?? | ?? |
|------|------|
| P2PKH ???? | script_p2pkh_lock/unlock() |
| P2SH ???? | script_p2sh_redeem() |
| ???? | script_multisig_lock() |
| ????? | script_cltv_lock() |
| HTLC ????? | script_htlc_lock() |
| UTXO ??? | example_utxo.c |
| Merkle ???? | example_merkle.c |
| PoW ???? | example_pow.c |

## L8: Advanced Topics

| ?? | ?? |
|------|------|
| Script VM ???? (80+ opcodes) | COMPLETE |
| Patricia Merkle Trie (Ethereum ??) | COMPLETE |
| Nakamoto ?????? | COMPLETE |
| ????? (??+??) | COMPLETE |
| Chainwork ???? | COMPLETE |

## L9: Industry Frontiers

| ?? | ?? | ?? |
|------|------|------|
| Lightning Network HTLC | PARTIAL | ??????? |
| ???? (Bulletproofs) | DOCUMENTED | ???? |
| ?? (Ethereum 2.0) | DOCUMENTED | ???+??? |
| MEV ?? (PBS) | DOCUMENTED | ???-????? |
| ????? (zkSNARKs) | DOCUMENTED | Groth16, Plonk |
