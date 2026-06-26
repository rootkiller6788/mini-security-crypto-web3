# 设计文档 — mini-blockchain-core

## 架构概览

```
┌────────────────────────────────────────────────────┐
│                  mini-blockchain-core               │
├──────────┬──────────┬──────────┬────────┬──────────┤
│ UTXO     │ Merkle   │ PoW      │ TxPool │ P2P      │
│ Model    │ Tree     │ Consensus│        │ Network  │
├──────────┼──────────┼──────────┼────────┼──────────┤
│                OpenSSL (libcrypto)                  │
└────────────────────────────────────────────────────┘
```

## 模块设计

### 1. UTXO 模型 (`utxo_model`)

比特币式的未花费交易输出模型。每笔交易引用之前交易的输出作为输入，并创建新的输出。

- **数据结构**：`utxo_transaction` → `utxo_txin` + `utxo_txout`
- **防双花**：UTXO 集合维护 `spent` 标志，花费前检查
- **币选择**：贪婪算法，从大到小排序，选择满足目标的 UTXO
- **签名**：ECDSA secp256k1 (OpenSSL)，标准 DER 编码
- **地址**：SHA256 + RIPEMD160 (hash160)

### 2. Merkle 树 (`merkle_tree`)

- **标准 Merkle 树**：双 SHA256 叶哈希，偶数层复制最后一个节点
- **Merkle 证明**：包含兄弟路径和方向位的轻量级证明
- **Patricia Merkle Trie**：类似以太坊状态树，基于 nibble 的压缩前缀树
- **增量更新**：支持逐叶添加，rebuild() 重建完整树结构

### 3. PoW 共识 (`consensus_pow`)

- **挖矿算法**：`SHA256(SHA256(BlockHeader))` < target
- **难度调整**：每 2016 个块（约 2 周），实际时间范围限制在 *0.25~4
- **链重组**：最长链（最大累积工作量）规则，Nakamoto 共识
- **GHOST 协议**：叔块包含机制，叔块贡献主链权重的 1/32
- **Block header**：80 字节标准格式 (version, prev_hash, merkle_root, time, bits, nonce)

### 4. 交易池 (`tx_pool`)

- **交易验证**：基本格式检查，防止无效交易入池
- **排序**：支持按 Gas 价格、手续费、到达时间排序
- **Replace-by-fee**：更高费率交易可替换池中同 txid 交易 (rbf_ratio=1.1)
- **Gas 价格**：evict_lowest_gas() 在池满时驱逐最低费率交易
- **Nonce 管理**：按 nonce 范围查询和清理
- **容量限制**：默认 5000，可配置最大 50000

### 5. P2P 网络 (`p2p_network`)

- **节点发现**：Kademlia DHT (256 个桶，每桶 20 节点) + DNS 种子
- **握手协议**：version + verack，协议版本 70015
- **消息格式**：magic(4) + command(4) + length(4) + checksum(4) + payload
- **区块/交易传播**：INV → GETDATA → BLOCK/TX 三步协议
- **Mempool 同步**：MEMPOOL 消息请求完整交易池
- **节点评分**：正分奖励，负分惩罚，<-10 自动封禁
- **Bootstrap**：内置 4 个 DNS 种子节点 (Bitcoin 主网)

## 数据流

```
发送交易:
 User → TxPool::txpool_add() → validate → store → P2P::p2p_broadcast_tx()

接收区块:
 P2P::recv → deserialize → Pow::pow_validate_block() → Chain::add_block()
   → TxPool::remove (confirmed txs)

挖矿:
 TxPool::txpool_select_by_gas() → Merkle::compute_root() → Pow::pow_mine()
   → Chain::add_block() → P2P::p2p_broadcast_block()

同步:
 Bootstrap::resolve() → Handshake → GetHeaders → Headers → GetBlocks → Blocks
```

## 安全性考量

1. **双重花费防护**：UTXO spent 标志 + 交易输入验证
2. **女巫攻击**：PoW 算力保证，节点连接数限制
3. **Eclipse 攻击**：Kademlia DHT 分散节点发现
4. **DoS**：消息大小限制，连接超时，恶意节点封禁
5. **重放攻击**：交易包含前一个区块哈希 = 链绑定

## 可扩展性

- 模块化设计：每个 .h/.c 可独立使用
- 多算法支持：`pow_adjust_target_multialgo` 预留接口
- 可插拔序列化：`serialize/deserialize` 支持标准格式

## 依赖

| 库 | 用途 |
|----|------|
| OpenSSL/libcrypto | SHA256, ECDSA, RIPEMD160 |
| 系统 socket | P2P 网络通信 (WinSock2 / Berkeley) |
| POSIX/C99 标准库 | 内存管理、排序 |

## 编码规范

- C99 标准，无扩展
- 函数前缀按模块：`utxo_`, `merkle_`, `pow_`, `txpool_`, `p2p_`
- 错误返回：0 成功，-1 失败
- 输出参数通过指针，输入用 const
- 无全局变量，线程安全
