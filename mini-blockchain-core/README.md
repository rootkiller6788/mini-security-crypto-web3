# mini-blockchain-core — 区块链核心 (C 语言实现)

用纯 C99 实现的核心区块链数据结构与共识机制库。包含 UTXO 模型、Merkle 树、PoW 共识、交易池及 P2P 网络模块。

## 模块

| 模块 | 文件 | 说明 |
|------|------|------|
| UTXO 模型 | `include/utxo_model.h` | 比特币式交易模型、ECDSA 签名验证、币选择 |
| Merkle 树 | `include/merkle_tree.h` | SHA256 叶子哈希、Merkle 证明、Patricia Merkle Trie |
| PoW 共识 | `include/consensus_pow.h` | 挖矿、难度调整、链重组、GHOST 协议 |
| 交易池 | `include/tx_pool.h` | 待处理交易、Gas 排序、Replace-by-fee、广播 |
| P2P 网络 | `include/p2p_network.h` | Kademlia DHT、握手、传播、节点评分 |

## 构建

```
make          # 构建 libblockchain.a + 示例
make examples # 构建所有示例
make demos    # 构建演示程序
make clean    # 清理
```

## 依赖

- OpenSSL / libcrypto (SHA256, ECDSA secp256k1)

## 许可

MIT
