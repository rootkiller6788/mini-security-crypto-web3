# DeFi 与跨链入门 (DeFi & Crosschain Primer)

> DeFi (去中心化金融) 使用智能合约重建传统金融服务。跨链桥连接不同的区块链网络。

---

## 1. AMM — 自动做市商 (Automated Market Maker)

### 1.1 恒定乘积公式 (x*y=k)

Uniswap V2 使用恒定乘积公式: `x * y = k`。

- `x`: Token 0 的储备量
- `y`: Token 1 的储备量
- `k`: 恒定乘积

```
(x + Δx) * (y - Δy) = k = x * y
```

推导出兑换公式 (含手续费):

```
Δy = Δx * (1 - f) * y / (x + Δx * (1 - f))
```

其中 `f` 为手续费比例 (通常 0.3% = 30 bps)。

### 1.2 价格

瞬时价格由储备比例决定:

```
P = y / x    (Token 0 对 Token 1 的价格)
```

### 1.3 滑点 & 价格冲击

交易量越大，对价格的冲击越大:

```
Price Impact = |spot_price - execution_price| / spot_price
```

```c
uint64_t amm_price_impact_bps(uint64_t amount_in, uint64_t reserve_in,
                               uint64_t reserve_out, uint64_t fee_bps);
```

### 1.4 LP 代币 (Liquidity Provider Token)

添加流动性时按比例铸造:

```
lp_tokens = amount * total_supply / reserve
```

> **注意**: 首次添加时，LP = amount0 + amount1 (初始价格锚定)

### 1.5 多跳兑换 (Multi-hop Swap)

路径: USDC → ETH → DAI

每个步骤有独立的手续费和价格冲击:

```c
AMMSwapResult amm_multihop_swap(AMMPool pools[], int num_pools,
                                 uint64_t amount_in, uint64_t slippage_bps);
```

### 1.6 Uniswap V3 集中流动性

V3 允许 LP 在自定义价格范围内提供流动性:
- tick_lower / tick_upper: 流动性范围
- 集中流动性提高资本效率 (可达 4000x)
- sqrtPriceX96: Q64.96 定点数格式的价格

### 1.7 TWAP 预言机

时间加权平均价格 (Time-Weighted Average Price):

```
TWAP = Σ(price_i * duration_i) / Σ(duration_i)
```

TWAP 用于:
- 去中心化预言机喂价
- 抵抗闪电贷价格操纵
- 计算清算价格

---

## 2. 借贷协议 (Lending Protocol)

### 2.1 Compound / Aave 模型

基本流程:
1. **存款**: 用户存入资产 → 获得 cToken (计息凭证)
2. **借款**: 需要超额抵押 → 抵押率 ≤ 75%
3. **还款**: 偿还本金 + 利息 → 解锁抵押品
4. **清算**: 健康因子 < 1 → 清算人偿还债务获得抵押品 (含奖励)

### 2.2 cToken 汇率

随着利息累积，cToken 相对于底层的汇率增长:

```
exchangeRate = (totalDeposits + totalBorrows) / cTokenSupply
```

```c
uint64_t lending_exchange_rate(const LendingMarket *market);
```

### 2.3 利率模型 (Kink Model)

利用率 (Utilization Rate):

```
U = total_borrows / total_deposits
```

分段利率:
- U ≤ Kink (80%): `rate = base + (kink_rate - base) * U / kink`
- U > Kink: `rate = kink_rate + (max - kink_rate) * (U - kink) / (1 - kink)`

```
利率
^
|                          /
|        ________________/
|       /
|      /
|     /
+-----------------------------> 利用率
    0%        80%        100%
```

### 2.4 健康因子 & 清算

```
healthFactor = collateralValue * liquidationThreshold / borrowValue
```

- healthFactor ≥ 1.0: 安全
- healthFactor < 1.0: 可清算

清算奖励: 5-10% (对抵押品的额外奖励)

```c
LendingHealth lending_get_health(LendingAccount *account,
    LendingMarket *market, uint64_t borrow_value,
    uint64_t collateral_value, uint64_t ltv_bps, ...);
```

### 2.5 闪电贷 (Flash Loan)

特性: 借出 → 使用 → 归还 在一次交易内完成

用途:
- 套利 (DEX 价差)
- 清算 (无需准备金)
- 抵押品转换

```c
LendingFlashLoan lending_flash_loan(LendingMarket *market,
    uint64_t amount, uint8_t data[32], bool (*callback)(...));
```

---

## 3. 稳定币 (Stablecoin)

### 3.1 DAI 模型 (超额抵押)

DAI 由 MakerDAO 发行，通过 CDP (Collateralized Debt Position) 机制:

```
抵押 ETH → 生成 DAI
最低抵押率: 150%
```

```c
CDPMintResult cdp_mint(CDPVault *vault, StablecoinSystem *sys,
    uint64_t collateral_amount, uint64_t collateral_price,
    uint64_t debt_amount);
```

### 3.2 稳定费 (Stability Fee)

按年化利率累积:

```
debt_new = debt_old * (1 + stability_fee)^(elapsed / year)
```

### 3.3 清算比例

- 最低抵押率: 150%
- 清算惩罚: 13%
- 清算人获得抵押品 (含 13% 折扣)

### 3.4 紧急关停 (Emergency Shutdown)

触发条件:
- 治理投票
- 预言机攻击
- 系统性风险

流程: 冻结所有操作 → 按最后价格结算

### 3.5 算法稳定币 vs 中心化稳定币

| 类型 | 代表 | 抵押 | 风险 |
|------|------|------|------|
| 超额抵押 | DAI | ETH/USDC | 清算风险 |
| 中心化法币 | USDC/USDT | 美元储备 | 托管风险 |
| 算法 | UST/Luna | 无 | 死亡螺旋 |

---

## 4. 跨链桥 (Crosschain Bridge)

### 4.1 Lock-and-Mint 模型

```
Chain A (源链)                 Chain B (目标链)
    锁定 ETH  ──Relayer──> 铸造 wETH
```

```c
bool bridge_lock(Bridge *bridge, uint8_t sender[20],
    uint8_t receiver[20], uint64_t amount, uint64_t dest_chain);
bool bridge_mint(Bridge *bridge, uint8_t receiver[20],
    uint64_t amount, const BridgeRelayMessage *msg);
```

### 4.2 Burn-and-Release 模型

```
Chain B (目标链)               Chain A (源链)
    销毁 wETH  ──Relayer──> 释放 ETH
```

### 4.3 验证器集合 (Validator Set)

**多签模式** (Multi-sig):
- N 个验证者
- 最少 M 个签名 (如 14/21)
- 缺点: 中心化风险

**轻客户端** (Light Client):
- 验证源链区块头
- 验证交易包含性证明 (Merkle Proof)
- 优点: 信任最小化

**乐观桥** (Optimistic):
- 假设有效，等待挑战期
- 欺诈证明

### 4.4 消息格式

```c
typedef struct {
    uint8_t  data[128];
    uint64_t source_height;
    int      required_signers;
    BridgeSignature sigs[BRIDGE_MAX_VALIDATORS];
    int      sig_count;
} BridgeRelayMessage;
```

### 4.5 Merkle Tree 验证

```
       Root
      /    \
    AB      CD
   /  \    /  \
  A    B  C    D

Merkle Proof: 给定 A 和路径 [B, CD]，可验证 A ∈ Root
```

---

## 5. 预言机 (Oracle)

### 5.1 Chainlink 模型

去中心化预言机网络 (DON):

```
多个独立节点 → 提交价格 → 聚合 (取中位数) → 上链
```

### 5.2 价格聚合

```c
uint64_t oracle_get_median(const uint64_t *prices, int count);
```

中位数聚合: 至少 3 个独立报价 → 排序取中位数

### 5.3 过期检查

```c
bool oracle_is_stale(const OraclePriceFeed *feed, uint64_t current_time);
```

价格必须在 `heartbeat` 时间内更新 (通常 1-24 小时)

### 5.4 TWAP 预言机

时间加权平均价格防止闪电贷操纵:

```
TWAP = Σ(price * Δt) / total_time
```

相比即时价格:
- 攻击者无法瞬间影响 TWAP
- 需要 2+ 个连续区块
- 适合大额借贷/清算决策

### 5.5 操纵抵抗

1. **时间加权**: 稀释瞬间价格波动
2. **多来源**: 降低单点故障
3. **偏离检查**: 拒绝异常价格提交
4. **质押/罚没**: 经济激励诚实行为

---

## 6. 完整 DeFi 生态交互

```
         预言机 (价格)
          ↓
    ┌─────┴──────┐
    │  Stablecoin │── 生成 DAI
    └─────────────┘
          ↓
    ┌─────────────┐
    │    AMM      │── 交易/兑换
    └─────────────┘
          ↓
    ┌─────────────┐
    │   Lending   │── 借贷/杠杆
    └─────────────┘
          ↓
    ┌─────────────┐
    │ Crosschain  │── 跨链转移
    └─────────────┘
```

---

## 参考资料

- [Uniswap V2 Whitepaper](https://uniswap.org/whitepaper.pdf)
- [Compound Whitepaper](https://compound.finance/documents/Compound.Whitepaper.pdf)
- [MakerDAO Docs](https://docs.makerdao.com/)
- [Chainlink Docs](https://docs.chain.link/)
- [Ethereum Bridge Documentation](https://ethereum.org/en/developers/docs/bridges/)
- [Uniswap V3 Concentrated Liquidity](https://uniswap.org/whitepaper-v3.pdf)
