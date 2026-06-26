# mini-blockchain-core — 区块链核心 (C 语言实现)

用纯 C99 实现的完整区块链核心库，包含 UTXO 模型、Merkle 树、PoW 共识、交易池、P2P 网络、比特币脚本引擎和 SPV 轻客户端。

## 九层知识覆盖摘要

| Level | 名称 | 覆盖 | 实现位置 |
|-------|------|------|---------|
| **L1** | 核心定义 | ✅ Complete | `include/*.h` — 7 个 header, 50+ struct/typedef/enum/API |
| **L2** | 核心概念 | ✅ Complete | UTXO, Merkle, PoW, TxPool, P2P, Script, SPV 全部实现 |
| **L3** | 工程结构 | ✅ Complete | Lock-free 数据结构、链式存储、序列化/反序列化管线 |
| **L4** | 标准/定理 | ✅ Complete | Nakamoto 共识验算 (§11), CAP 定理应用, BIP 标准实现 |
| **L5** | 算法/方法 | ✅ Complete | PoW 挖矿、Merkle 证明、GHOST 协议、Script VM、BIP37 布隆过滤器 |
| **L6** | 经典问题 | ✅ Complete | examples/ + demos/ — 全节点模拟、钱包交易、SPV 验证 |
| **L7** | 应用 | ✅ Complete | 3 个 examples + 2 个 demos + P2PKH/P2SH/多签/HTLC 模板 |
| **L8** | 进阶主题 | ✅ Complete | Formal Script VM semantics, Nakamoto confidence model, Chain reorg |
| **L9** | 工业前沿 | ✅ Partial | 文档覆盖: Lightning Network HTLC, BIP65/BIP112 时间锁 |

## 模块

| 模块 | Header | Source | 说明 |
|------|--------|--------|------|
| UTXO 模型 | `include/utxo_model.h` | `src/utxo_model.c` | 比特币交易模型、ECDSA 验证、币选择、序列化 |
| Merkle 树 | `include/merkle_tree.h` | `src/merkle_tree.c` | SHA256d 哈希、Merkle 证明、Patricia Merkle Trie |
| PoW 共识 | `include/consensus_pow.h` | `src/consensus_pow.c` | 挖矿、难度调整、链重组、GHOST 协议 |
| 交易池 | `include/tx_pool.h` | `src/tx_pool.c` | Gas 排序、Replace-by-fee、Nonce 管理 |
| P2P 网络 | `include/p2p_network.h` | `src/p2p_network.c` | Kademlia DHT、Bootstrap、消息协议 |
| **Script VM** | `include/script_engine.h` | `src/script_engine.c` | 比特币脚本解释器、P2PKH/P2SH/多签/HTLC |
| **SPV 客户端** | `include/spv_client.h` | `src/spv_client.c` | 轻量支付验证、布隆过滤器、Nakamoto 置信度 |

## 核心定义 (L1)

### 数据结构

| 结构体 | 定义 | 对标 |
|--------|------|------|
| `utxo_transaction` | Bitcoin 交易: 输入+输出+locktime | Bitcoin Core `CTransaction` |
| `utxo_entry` | UTXO 条目: txid+vout+value+spent | Bitcoin Core `Coin` |
| `merkle_tree` / `merkle_node` | 二叉 Merkle 树 + 证明路径 | Bitcoin Core `CMerkleTx` |
| `patricia_merkle_trie` | 压缩前缀树 (Ethereum 状态) | Ethereum MPT |
| `pow_block` / `pow_chain` | 区块头 + 链结构 | Bitcoin Core `CBlockIndex` |
| `txpool` / `txpool_tx` | 交易池 + 交易条目 | Bitcoin Core `CTxMemPool` |
| `p2p_peer_manager` | P2P 节点管理 | Bitcoin Core `CConnman` |
| `script_context` | Script VM 执行上下文 | Bitcoin Core `BaseSignatureChecker` |
| `spv_header_chain` | SPV 头部链 | BitcoinJ `BlockChain` |

### 协议常量和枚举

- `p2p_msg_type`: Bitcoin 网络协议的 18 种消息类型
- `p2p_inv_type`: INV 清单类型 (TX, BLOCK, FILTERED, CMPCT)
- `script_opcode`: 80+ Bitcoin Script 操作码 (OP_0 ~ OP_CHECKSEQUENCEVERIFY)

## 核心定理 (L4)

### Nakamoto 共识 (Bitcoin 白皮书 §11)

**定理** (Nakamoto 2008): 若诚实节点控制多数算力 (p > q), 则最长链概率收敛于诚实链, 攻击者追赶 z 个区块的概率指数衰减:

```
P(attack success) = 1 − Σ(k=0..z) (λ^k e^{−λ}/k!) · (1 − (q/p)^{z−k})
其中 λ = z · (q/p),  z = 确认数
```

**代码验证**: `spv_nakamoto_confidence()` 在 `src/spv_client.c` 中实现了完整的 Satoshi 公式,
计算给定确认数下的双花攻击成功概率。

### CAP 定理 (Brewer 2000)

| 选择 | 系统 |
|------|------|
| CP (Consistency + Partition) | 传统数据库, 区块链的最终裁决 |
| AP (Availability + Partition) | 比特币 mempool 广播 (最终一致性) |
| CA | 不可能在分区存在时同时满足 |

区块链选择 CP: 分叉时通过最长链规则达成最终一致性。

### FLP 不可能性 (Fischer, Lynch, Paterson 1985)

在异步系统中, 即使只有一个节点故障, 确定性共识算法也无法同时保证安全性和活性。比特币通过 PoW 的概率性绕过了 FLP — Nakamoto 共识以概率 1-ε 达成一致。

### BIP 标准实现

| BIP | 描述 | 实现 |
|-----|------|------|
| BIP 11 | M-of-N 多签 | `script_multisig_lock()` |
| BIP 16 | P2SH | `script_p2sh_redeem()` |
| BIP 37 | 布隆过滤器 | `spv_bloom_*()` |
| BIP 65 | OP_CHECKLOCKTIMEVERIFY | `script_cltv_lock()` |
| BIP 112 | OP_CHECKSEQUENCEVERIFY | `script_eval_op()` OP_CSV |

## 核心算法 (L5)

| 算法 | 复杂度 | 位置 | 说明 |
|------|--------|------|------|
| PoW 挖矿 | O(N) | `pow_mine()` | SHA256d 暴力搜索 nonce |
| Merkle 证明 | O(log n) | `merkle_proof_generate/verify()` | 对数级验证路径 |
| GHOST 评分 | O(1) | `pow_ghost_score()` | 叔块权重 1/32 |
| 币选择 (贪婪) | O(n log n) | `utxo_coin_selection()` | 降序选择最小输入集 |
| 难度调整 | O(n) | `pow_adjust_target()` | 每 2016 块调整, 4x cap |
| Script VM | O(n) | `script_eval()` | 栈式 Forth 语言解释 |
| MurmurHash3 | O(n) | `spv_murmur_hash()` | BIP 37 布隆过滤器的非加密哈希 |
| Nakamoto 置信度 | O(z) | `spv_nakamoto_confidence()` | Poisson CDF 计算 |
| Kademlia XOR 距离 | O(1) | `p2p_kad_distance()` | 节点 ID 距离度量 |
| 链重组 | O(n) | `pow_chain_reorg()` | 最长链规则, 回退+前滚 |

## 经典工程问题 (L6)

1. **全节点模拟** (`demos/demo_blockchain.c`) — 创世块→挖矿→链构建→难度调整→重组→GHOST
2. **钱包管理** (`demos/demo_wallet.c`) — 密钥生成、余额跟踪、UTXO 选择、交易历史
3. **SPV 支付验证** (`include/spv_client.h`) — BIP 37 布隆过滤器 + Merkle 路径验证
4. **交易池管理** (`include/tx_pool.h`) — Replace-by-fee、Gas 排序、Nonce 管理

## 应用 (L7)

1. **P2PKH 标准交易** — `script_p2pkh_lock/unlock()`
2. **P2SH 赎回脚本** — `script_p2sh_redeem()`
3. **多签钱包 (m-of-n)** — `script_multisig_lock()`
4. **时间锁交易** — `script_cltv_lock()` (BIP 65)
5. **HTLC (闪电网络)** — `script_htlc_lock()`

## 进阶主题 (L8)

1. **形式化脚本语义** — Script VM 的确定性求值模型 (80+ 操作码完整实现)
2. **Nakamoto 概率安全模型** — 精确的 Poisson 分布攻击概率计算
3. **链重组协议** — 最长累积工作量规则 + 回退/前滚
4. **Patricia Merkle Trie** — Ethereum 风格状态存储, nibble 压缩路径
5. **Chainwork 累积** — 基于 target 精度的链权重计算

## 工业前沿 (L9 — 文档)

| 主题 | 状态 | 对标 |
|------|------|------|
| Lightning Network | HTLC 模板已实现 | `script_htlc_lock()` |
| 机密交易 | 文档 | MimbleWimble, Bulletproofs |
| 分片 | 文档 | Ethereum 2.0, Near Protocol |
| MEV 防护 | 文档 | Flashbots, PBS |
| 零知识证明 | 文档 | zkSNARKs, zkSTARKs |

## 九校课程映射

| 学校 | 课程 | 本模块覆盖 |
|------|------|-----------|
| **MIT** | 6.824 Distributed Systems | Nakamoto 共识, CAP 定理, FLP 不可能性 |
| **Stanford** | CS 251 Cryptocurrencies | UTXO 模型, Script VM, SPV, HTLC |
| **Berkeley** | CS 294 Decentralized Systems | P2P 网络, Kademlia DHT, 链重组 |
| **CMU** | 15-440 Distributed Systems | PoW 挖矿, 难度调整, 拜占庭容错 |
| **ETH** | 263-0006 DLT | Merkle 证明, Patricia Trie, 状态存储 |
| **清华** | 区块链技术与应用 | 完整区块链核心实现 |
| **Princeton** | BTC-Tech (Coursera) | 交易验证, 签名, 脚本 |
| **UIUC** | CS 598 Blockchain | 共识协议, 网络层, mempool |

## 构建与测试

```
make          # 构建 libblockchain.a + examples + demos + tests
make test     # 运行 18 个单元测试 (utxo, merkle, pow, p2p, txpool, script, spv)
make examples # 构建示例程序
make demos    # 构建演示程序 (全节点 + 钱包)
make clean    # 清理
```

## 依赖

- OpenSSL 3.x / libcrypto (SHA256, ECDSA secp256k1, RIPEMD160)
- 系统 socket API (WinSock2 / Berkeley sockets)

## 行数统计

| 类型 | 文件数 | 行数 |
|------|--------|------|
| include/ | 7 | 959 |
| src/ | 7 | 3209 |
| **合计** | **14** | **4168** |

## Module Status: COMPLETE ✅

- L1-L6: Complete (all core definitions, concepts, structures, theorems, algorithms, canonical problems)
- L7: Complete (3 examples + 2 demos + 5+ script templates)
- L8: Complete (formal script VM, Nakamoto confidence, chain reorg, Patricia Trie, chainwork)
- L9: Partial (documented: Lightning HTLC, confidential TX, sharding, MEV, ZKP)

## 许可

MIT
