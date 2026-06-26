# API 参考文档 — mini-blockchain-core

## UTXO 模型 (`utxo_model.h`)

### 交易结构

| 函数 | 说明 |
|------|------|
| `utxo_tx_create(tx)` | 创建新交易，初始化 version=1 |
| `utxo_tx_add_input(tx, txid, vout)` | 添加交易输入（引用 UTXO） |
| `utxo_tx_add_output(tx, value, script, len)` | 添加交易输出 |
| `utxo_tx_compute_txid(tx)` | 计算 txid (double-SHA256) |
| `utxo_serialize_tx(tx, buf, len, sz)` | 序列化交易 |
| `utxo_deserialize_tx(tx, buf, len)` | 反序列化交易 |

### UTXO 集合

| 函数 | 说明 |
|------|------|
| `utxo_set_init(set, cap)` | 初始化 UTXO 集合 |
| `utxo_set_add(set, entry)` | 添加 UTXO |
| `utxo_set_find(set, txid, vout, out)` | 查找 UTXO |
| `utxo_set_spend(set, txid, vout)` | 标记 UTXO 为已花费 |
| `utxo_set_is_spent(set, txid, vout)` | 检查是否已花费 |

### 签名验证

| 函数 | 说明 |
|------|------|
| `utxo_verify_sig(hash, pubkey, pklen, sig, slen)` | ECDSA secp256k1 验证 |
| `utxo_verify_tx_inputs(tx, utxos)` | 验证交易所有输入 |

### 币选择

| 函数 | 说明 |
|------|------|
| `utxo_coin_selection(utxos, target, fee, ...)` | 选择 UTXO 满足金额 |

### 地址

| 函数 | 说明 |
|------|------|
| `utxo_pubkey_to_address(pubkey, compressed, addr)` | 公钥 → Bitcoin 地址 |

---

## Merkle 树 (`merkle_tree.h`)

### 基本操作

| 函数 | 说明 |
|------|------|
| `merkle_tree_init(tree)` | 初始化 |
| `merkle_tree_add_leaf(tree, data, len)` | 添加叶子 |
| `merkle_tree_rebuild(tree)` | 重建树 |
| `merkle_tree_get_root(tree, hash)` | 获取 Merkle 根 |

### Merkle 证明

| 函数 | 说明 |
|------|------|
| `merkle_proof_generate(tree, index, proof)` | 生成证明 |
| `merkle_proof_verify(root, proof, valid)` | 验证证明 |

### Patricia Merkle Trie

| 函数 | 说明 |
|------|------|
| `patricia_trie_init(trie)` | 初始化 |
| `patricia_trie_insert(trie, key, klen, val, vlen)` | 插入 |
| `patricia_trie_lookup(trie, key, klen, val, vlen)` | 查找 |
| `patricia_trie_delete(trie, key, klen)` | 删除 |

---

## PoW 共识 (`consensus_pow.h`)

### 挖矿

| 函数 | 说明 |
|------|------|
| `pow_mine(block, target, max_nonce)` | 单线程挖矿 |
| `pow_mine_incremental(block, target, start, count, found)` | 增量挖矿 |

### 难度

| 函数 | 说明 |
|------|------|
| `pow_target_from_bits(bits, target)` | bits → target |
| `pow_target_to_bits(target, bits)` | target → bits |
| `pow_adjust_target(chain, height, new_target)` | 每 2016 块调整 |
| `pow_target_get_difficulty(target, diff)` | 获取难度值 |

### 区块与链

| 函数 | 说明 |
|------|------|
| `pow_block_create(block, ver, prev, merkle, ts, bits)` | 创建区块 |
| `pow_validate_block(block, target, merkle, valid)` | 验证区块 |
| `pow_chain_init(chain)` | 初始化链 |
| `pow_chain_add_block(chain, block)` | 添加区块 |
| `pow_chain_reorg(chain, candidate)` | 链重组 |
| `pow_chain_compare(a, b, longer)` | 比较工作量 |

### GHOST

| 函数 | 说明 |
|------|------|
| `pow_block_add_uncle(block, uncle)` | 添加叔块 |
| `pow_ghost_score(block, score)` | 计算 GHOST 分数 |

---

## 交易池 (`tx_pool.h`)

| 函数 | 说明 |
|------|------|
| `txpool_init(pool, max_size)` | 初始化 |
| `txpool_add(pool, raw, len, local, from, accepted)` | 添加交易 |
| `txpool_remove(pool, txid)` | 移除交易 |
| `txpool_sort_by_gas(pool)` | Gas 价格排序 |
| `txpool_select(pool, max, max_bytes, sel)` | 选择交易打包 |
| `txpool_replace_by_fee(pool, raw, len, txid, replaced)` | Replace-by-fee |
| `txpool_prune(pool, target_size)` | 裁剪到指定大小 |

---

## P2P 网络 (`p2p_network.h`)

### 节点管理

| 函数 | 说明 |
|------|------|
| `p2p_pm_init(pm, port)` | 初始化节点管理 |
| `p2p_pm_start(pm)` | 开始监听 |
| `p2p_pm_add_peer(pm, ip, port)` | 添加并连接节点 |
| `p2p_pm_accept(pm)` | 接受新连接 |

### 消息

| 函数 | 说明 |
|------|------|
| `p2p_msg_create(cmd, payload, len, msg)` | 创建消息 |
| `p2p_msg_send(peer, msg)` | 发送消息 |
| `p2p_msg_recv(peer, msg)` | 接收消息 |

### 广播

| 函数 | 说明 |
|------|------|
| `p2p_broadcast_tx(pm, data, len, txid)` | 广播交易 |
| `p2p_broadcast_block(pm, data, len, hash)` | 广播区块 |

### Kademlia DHT

| 函数 | 说明 |
|------|------|
| `p2p_kad_init(table)` | 初始化 DHT |
| `p2p_kad_add_peer(table, peer)` | 添加节点 |
| `p2p_kad_find_peers(table, target, results, count, max)` | 查找最近节点 |
| `p2p_kad_distance(a, b, dist)` | XOR 距离 |

### Bootstrap

| 函数 | 说明 |
|------|------|
| `p2p_bootstrap_init(bs)` | 初始化种子节点 |
| `p2p_bootstrap_add_seed(bs, host, port)` | 添加 DNS 种子 |
| `p2p_bootstrap_add_fixed(bs, ip, port)` | 添加固定节点 |
| `p2p_bootstrap_resolve(bs, pm)` | 解析并连接 |

### 工具

| 函数 | 说明 |
|------|------|
| `p2p_peer_ban(peer)` | 封禁节点 |
| `p2p_peer_score_add(peer, delta)` | 修改节点评分 |

---

## 哈希工具

所有模块均提供 `sha256` 及 `sha256d` (double-SHA256) 函数，使用 OpenSSL 的 SHA256 实现。
