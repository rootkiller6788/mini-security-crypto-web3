# API Reference — mini-defi-crosschain

> C99 语言实现的 DeFi 与跨链库，包含 AMM、借贷、稳定币、跨链桥和预言机模块。

---

## 模块索引

| 模块 | 头文件 | 源文件 |
|------|--------|--------|
| AMM (自动做市商) | `include/amm_swap.h` | `src/amm_swap.c` |
| 借贷协议 | `include/lending_proto.h` | `src/lending_proto.c` |
| 稳定币 | `include/stablecoin.h` | `src/stablecoin.c` |
| 跨链桥 | `include/crosschain_bridge.h` | `src/crosschain_bridge.c` |
| 预言机 | `include/oracle_price.h` | `src/oracle_price.c` |

---

## 1. AMM 模块

### 数据结构

```c
typedef struct {
    uint64_t reserve0;
    uint64_t reserve1;
    uint64_t total_supply;
    uint64_t fee_bps;
    AMMVersion version;
} AMMPool;

typedef struct {
    uint64_t input_amount;
    uint64_t output_amount;
    uint64_t price_impact_bps;
    uint64_t fee_amount;
} AMMSwapResult;
```

### API

| 函数 | 说明 |
|------|------|
| `amm_pool_init()` | 初始化 AMM 池 (储备、费率) |
| `amm_get_amount_out()` | 计算输入可兑换的输出量 |
| `amm_get_amount_in()` | 计算兑换目标量所需的输入 |
| `amm_swap()` | 执行兑换 (更新储备) |
| `amm_add_liquidity()` | 添加流动性 (铸造 LP) |
| `amm_remove_liquidity()` | 移除流动性 (销毁 LP) |
| `amm_get_price()` | 获取瞬时价格 |
| `amm_price_impact_bps()` | 计算交易的价格冲击 (bps) |
| `amm_twap_init()` | 初始化 TWAP 预言机 |
| `amm_twap_update()` | 更新 TWAP 观察值 |
| `amm_twap_get()` | 获取时间窗口内的 TWAP |
| `amm_v3_pool_init()` | 初始化 V3 集中流动性池 |
| `amm_v3_swap()` | V3 兑换 |
| `amm_v3_add_liquidity()` | V3 添加集中流动性 |
| `amm_multihop_swap()` | 多跳兑换 (路径路由) |

**手续费**: 默认 30 bps (0.3%)，定义于 `AMM_FEE_BPS`

---

## 2. 借贷模块

### 数据结构

```c
typedef struct {
    uint64_t total_deposits;
    uint64_t total_borrows;
    uint64_t total_reserves;
    uint64_t reserve_factor_bps;
    LendingIRParams ir_params;
    uint64_t borrow_index;
    uint64_t supply_index;
} LendingMarket;

typedef struct {
    uint64_t borrow_value;
    uint64_t borrow_limit;
    uint64_t collateral_value;
    uint64_t health_factor_bps;
} LendingHealth;
```

### API

| 函数 | 说明 |
|------|------|
| `lending_market_init()` | 初始化借贷市场 |
| `lending_utilization_rate()` | 计算当前利用率 |
| `lending_borrow_rate()` | 计算借款利率 |
| `lending_supply_rate()` | 计算存款利率 |
| `lending_deposit()` | 存入资产 → 获得 cToken |
| `lending_redeem()` | 使用 cToken 赎回底层资产 |
| `lending_borrow()` | 借款 (超额抵押) |
| `lending_repay()` | 偿还借款 |
| `lending_accrue_interest()` | 利息累积 |
| `lending_get_health()` | 健康因子检查 |
| `lending_liquidate()` | 清算不健康头寸 |
| `lending_flash_loan()` | 闪电贷 |
| `lending_exchange_rate()` | cToken 汇率 |
| `lending_max_borrow()` | 最大可借金额 |

**清算参数**:
- `LENDING_MAX_LTV_BPS`: 7500 (75%)
- `LENDING_LIQUIDATION_BONUS_BPS`: 800 (8%)
- `LENDING_FLASH_LOAN_FEE_BPS`: 9 (0.09%)

---

## 3. 稳定币模块

### 数据结构

```c
typedef struct {
    StablecoinType type;
    uint64_t total_supply;
    uint64_t total_debt;
    uint64_t liquidation_ratio_bps;
    bool     emergency_shutdown;
} StablecoinSystem;

typedef struct {
    uint64_t locked_collateral;
    uint64_t minted_debt;
    uint64_t min_ratio_bps;
    bool     active;
} CDPVault;
```

### API

| 函数 | 说明 |
|------|------|
| `stablecoin_system_init()` | 初始化稳定币系统 |
| `cdp_vault_init()` | 初始化 CDP 金库 |
| `cdp_mint()` | 抵押 → 生成稳定币 |
| `cdp_close()` | 归还稳定币 → 取回抵押品 |
| `cdp_liquidate()` | 清算不足抵押的金库 |
| `cdp_get_health()` | 金库健康状态 |
| `cdp_is_safe()` | 安全性检查 |
| `stablecoin_emergency_shutdown()` | 紧急关停 |
| `stablecoin_settle()` | 全局结算 |
| `stablecoin_accrue_stability_fee()` | 累积稳定费 |
| `algorithmic_mint()` | 算法铸造 (扩张) |
| `algorithmic_burn()` | 算法销毁 (收缩) |

**关键参数**:
- `STABLECOIN_LIQUIDATION_RATIO_BPS`: 15000 (150%)
- `STABLECOIN_STABILITY_FEE_BPS`: 500 (5%)
- `STABLECOIN_LIQUIDATION_PENALTY_BPS`: 1300 (13%)

---

## 4. 跨链桥模块

### 数据结构

```c
typedef struct {
    BridgeModel model;
    BridgeSecurity security;
    uint64_t chain_id;
    BridgeValidator validators[21];
    BridgeEvent events[256];
    uint64_t locked_amount;
    uint64_t minted_amount;
} Bridge;

typedef struct {
    uint8_t tx_hash[32];
    uint64_t amount;
    uint64_t source_chain_id;
    uint64_t dest_chain_id;
    bool     processed;
} BridgeEvent;
```

### API

| 函数 | 说明 |
|------|------|
| `bridge_init()` | 初始化桥 |
| `bridge_add_validator()` | 添加验证者 |
| `bridge_remove_validator()` | 移除验证者 |
| `bridge_lock()` | 锁定资产 (源链) |
| `bridge_mint()` | 铸造包装资产 (目标链) |
| `bridge_burn()` | 销毁包装资产 (目标链) |
| `bridge_release()` | 释放原始资产 (源链) |
| `bridge_verify_header()` | 验证区块头 (轻客户端) |
| `bridge_verify_event()` | 验证事件包含性 |
| `bridge_collect_signatures()` | 收集验证者签名 |
| `bridge_verify_multisig()` | 验证多签证明 |
| `bridge_generate_message()` | 生成中继消息 |
| `bridge_process_event()` | 处理跨链事件 |
| `bridge_compute_merkle_root()` | 计算 Merkle 树根 |

**安全模型**:
- `BRIDGE_MULTI_SIG`: 多签验证 (14/21)
- `BRIDGE_LIGHT_CLIENT`: 轻客户端区块头验证
- `BRIDGE_OPTIMISTIC`: 乐观验证

---

## 5. 预言机模块

### 数据结构

```c
typedef struct {
    OracleType type;
    uint8_t  feed_id[32];
    uint64_t round_id;
    uint64_t latest_price;
    uint64_t median_price;
    OracleNode oracles[31];
    bool    stale;
} OraclePriceFeed;

typedef struct {
    uint64_t prices[16];
    uint64_t timestamps[16];
    int     index;
    int     count;
} TWAPTracker;
```

### API

| 函数 | 说明 |
|------|------|
| `oracle_feed_init()` | 初始化价格馈送 |
| `oracle_add_node()` | 添加预言机节点 |
| `oracle_remove_node()` | 移除节点 |
| `oracle_submit_price()` | 节点提交价格 |
| `oracle_update_aggregate()` | 更新聚合价格 |
| `oracle_get_median()` | 计算中位数价格 |
| `oracle_is_stale()` | 检查价格过期 |
| `oracle_get_price()` | 获取当前价格 |
| `oracle_get_twap()` | 获取时间加权价格 |
| `twap_tracker_init()` | 初始化 TWAP 追踪器 |
| `twap_tracker_update()` | 更新 TWAP 数据点 |
| `twap_tracker_compute()` | 计算 TWAP 值 |
| `oracle_check_deviation()` | 检查价格偏离 |
| `oracle_time_weighted_price()` | 通用时间加权价格 |
| `oracle_convert_price()` | 价格换算 |
| `oracle_simulate_data_feeds()` | 模拟多资产喂价 |

**阈值参数**:
- `ORACLE_STALE_THRESHOLD`: 86400 秒 (24 小时)
- `ORACLE_DEVIATION_BPS`: 500 (5%)
- `ORACLE_MAX_ORACLES`: 31 个节点

---

## 6. 编译 & 使用

### 编译对象文件

```bash
make all
```

### 运行示例

```bash
make example_amm       # AMM 示例
make example_lending   # 借贷示例
make example_oracle    # 稳定币+预言机示例
```

### 运行演示

```bash
make demo_full_defi    # 完整 DeFi 生态演示
make demo_crosschain   # 跨链桥演示
```

### 清理

```bash
make clean
```

### 测试

```bash
make test
```

---

## 7. 依赖

- GCC / Clang (C99)
- `<stdint.h>`, `<stdbool.h>`, `<stdio.h>`, `<stdlib.h>`, `<string.h>`
- 无外部依赖 (独立使用)
- `-lm` 链接选项 (Makefile 配置)

---

## 8. 常量速查

### AMM
| 常量 | 值 | 说明 |
|------|-----|------|
| `AMM_FEE_BPS` | 30 | 兑换手续费 (0.3%) |
| `AMM_MAX_HOPS` | 5 | 多跳最大跳数 |
| `AMM_PRECISION` | 1e9 | 价格精度 |

### 借贷
| 常量 | 值 | 说明 |
|------|-----|------|
| `LENDING_MAX_LTV_BPS` | 7500 | 最大 LTV (75%) |
| `LENDING_LIQUIDATION_BONUS_BPS` | 800 | 清算奖励 (8%) |
| `LENDING_FLASH_LOAN_FEE_BPS` | 9 | 闪电贷手续费 |

### 稳定币
| 常量 | 值 | 说明 |
|------|-----|------|
| `STABLECOIN_LIQUIDATION_RATIO_BPS` | 15000 | 清算比例 (150%) |
| `STABLECOIN_STABILITY_FEE_BPS` | 500 | 稳定费 (5%) |
| `STABLECOIN_LIQUIDATION_PENALTY_BPS` | 1300 | 清算惩罚 (13%) |

### 跨链桥
| 常量 | 值 | 说明 |
|------|-----|------|
| `BRIDGE_MAX_VALIDATORS` | 21 | 最大验证者数 |
| `BRIDGE_SIG_THRESHOLD_NUM` | 14 | 签名阈值分子 |
| `BRIDGE_MAX_EVENTS` | 256 | 最大事件数 |

### 预言机
| 常量 | 值 | 说明 |
|------|-----|------|
| `ORACLE_MAX_ORACLES` | 31 | 最大节点数 |
| `ORACLE_STALE_THRESHOLD` | 86400 | 过期阈值 (秒) |
| `ORACLE_DEVIATION_BPS` | 500 | 最大偏离 (5%) |
