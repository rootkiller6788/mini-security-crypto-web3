# mini-smart-contract-sec 设计文档

## 概述

本项目是智能合约安全分析工具的 C99 实现，包含五大模块：EVM 仿真、重入检测、溢出检测、访问控制、形式化验证。所有模块使用纯 C 语言编写，无外部依赖（仅标准库）。

## 架构

```
┌─────────────────────────────────────────────┐
│              demo_full_audit / demo_verify   │
├─────────────────────────────────────────────┤
│  evm_sim  │ reentr  │ overflow │ access │ fv │
├───────────┴─────────┴──────────┴────────┴───┤
│              libmini_scsec.a                 │
└─────────────────────────────────────────────┘
```

## 模块设计

### 1. EVM 仿真 (evm_sim)

**设计目标**: 模拟以太坊虚拟机执行，用于分析合约行为。

**核心结构**:
- `uint256_t`: 4 个 uint64_t 模拟 256-bit 整数，支持加/减/乘
- `evm_stack_t`: 固定大小栈 (1024 words × 32B)
- `evm_memory_t`: 字节可寻址内存 (最大 1MB)
- `evm_storage_t`: key-value 持久化存储 (最大 256 slots)
- `evm_t`: 完整 EVM 状态

**Gas 模型**:
- 每操作码对应固定 gas 开销
- 通过 `GAS_COST[]` 数组查表
- 支持 out-of-gas 检测和 revert

**调用上下文**:
- `caller`: msg.sender (20 字节地址)
- `origin`: tx.origin
- `value`: msg.value (256-bit)
- `address`: 合约地址

**指令集**:
- 完整 PUSH1..PUSH32, DUP1..DUP16, SWAP1..SWAP16
- 算术/比较/位运算
- 存储 (SLOAD/SSTORE) 和内存 (MLOAD/MSTORE)
- 流控 (JUMP/JUMPI/JUMPDEST)
- 调用 (CALL/DELEGATECALL)
- 终止 (STOP/RETURN/REVERT/SELFDESTRUCT)

### 2. 重入检测 (reentrancy_check)

**设计目标**: 检测重入攻击漏洞。

**分析方法**:

1. **CEI 模式检测**: 检查函数中 external call 是否在 state update 之前
   - 事件序列分析: 收集 SLOAD/SSTORE/CALL/TRANSFER 事件
   - 时间线比较: 若 CALL 在 SSTORE 之前 → 漏洞

2. **调用图构建**: 函数间调用关系
   - 节点: 函数 (含 has_external_call, has_state_write 标记)
   - 边: 调用关系 (含事件类型)

3. **跨函数重入**: 函数 A (external call) → 函数 B (state write) → 重入风险

4. **只读重入**: view 函数读取状态时，被重入者修改了的过期数据

5. **防护检测**: ReentrancyGuard (_status flag) 模式识别

**漏洞严重性**:
- `RC_PATTERN_VULN`: 直接可重入
- `RC_PATTERN_CROSS_FUNC`: 跨函数重入路径
- `RC_PATTERN_READONLY_REENT`: 只读重入
- `RC_PATTERN_SAFE`: 安全
- `RC_PATTERN_CEI`: 遵循 CEI 但未加锁
- `RC_PATTERN_GUARDED`: 有重入锁保护

### 3. 溢出检测 (overflow_detect)

**设计目标**: 模拟 Solidity 0.8 之前的 unchecked 数学，检测溢出。

**SafeMath 模拟**:
- `od_add_overflow()`: 检测 a + b > UINT64_MAX
- `od_sub_underflow()`: 检测 b > a
- `od_mul_overflow()`: 检测 a * b > UINT64_MAX
- `od_div_safe()`: 检测除零

**特殊检测**:
- 时间戳溢出: uint256 时间戳赋值给 uint32 → 2106 年问题
- 区块号溢出: 类似时间戳
- 类型截断: uint256 → uint128/uint64/uint32
- 定点数小数点不匹配

**发现问题分类**:
- `OD_OVERFLOW`: 加法/乘法溢出
- `OD_UNDERFLOW`: 减法下溢
- `OD_DIV_ZERO`: 除零
- `OD_TRUNCATION`: 类型转换截断
- `OD_TIMESTAMP`: 时间戳 > uint32
- `OD_BLOCK_OVER`: 区块号溢出
- `OD_FIXED_POINT`: 定点数问题

### 4. 访问控制 (access_control)

**设计目标**: 检查和验证合约访问控制机制。

**Ownable 模式**:
- 单一 owner 地址
- `onlyOwner` 修饰符模拟
- 所有权转移检查

**RBAC (Role-Based Access Control)**:
- 基于 OpenZeppelin AccessControl
- 角色: 32 字节标识符 (如 `MINTER_ROLE`)
- `grantRole()` / `revokeRole()` 操作
- 权限验证: `hasRole()`

**EIP-712/EIP-2612**:
- 类型化数据签名 (EIP-712)
- Permit 签名 (EIP-2612)
- 签名结构: r(32B) + s(32B) + v(1B)

**安全检测**:
- `tx.origin` vs `msg.sender`: 检测钓鱼攻击 (phishing via tx.origin)
- Delegatecall 风险: 代理调用到不可信合约
- 初始化器漏洞: 重复初始化检测

### 5. 形式化验证 (formal_verify)

**设计目标**: 提供符号执行、污点分析、模糊测试。

**符号执行**:
- 符号变量: concrete/symbolic/constrained 三种类型
- 值域: [min_val, max_val] 约束
- 路径探索: DFS 遍历 CFG
- 路径最大深度: FV_MAX_PATHS (256)

**控制流图 (CFG)**:
- 基本块: label + line + succ[2]
- 块类型: 普通/条件/断言/revert/return
- 边: 条件分支 (true/false)

**断言检查**:
- 路径断言收集
- 不变量验证 (如 `totalSupply == sum(balances)`)
- 失败统计

**污点分析**:
- 污点源: 用户输入 (calldata, msg.sender, msg.value)
- 传播: 变量赋值追踪
- 汇点: 敏感操作 (SSTORE, CALL, DELEGATECALL, SELFDESTRUCT)
- 等级: NONE < USER_INPUT < LOW < MEDIUM < HIGH

**模糊测试**:
- LCG 伪随机数生成器
- 支持种子 (可重现)
- 边缘情况自动测试: 0, MAX, 相等
- 可注册目标函数

**Mythril/Slither 模拟**:
- SWC-101: 整数溢出
- SWC-107: 重入漏洞
- SWC-104: 未检查的调用
- SWC-106: 自毁风险

## 数据流

```
Solidity-like code → [手写分析输入]
    ↓
evm_sim:     字节码执行 → 状态变化跟踪
reentrancy:  事件序列 → CEI/调用图分析 → 漏洞报告
overflow:    算术操作 → 溢出检测 → 问题列表
access:      权限配置 → 角色检查 → 权限问题
formal:      CFG + 符号 → 路径探索 → 断言/污点/模糊报告
```

## 限制

1. `uint256_t` 使用 4×uint64_t，不支持除法和模运算的高精度实现
2. 存储限制为 256 个 slot（简化）
3. 不支持合约间调用的完整模拟（CALL/DELEGATECALL 返回空）
4. EIP-712 签名验证为占位（需要 secp256k1 库）
5. 符号执行仅遍历 CFG，不做 SMT 求解
6. 模糊测试使用 LCG 而非密码学随机数

## 编译要求

- C99 编译器 (GCC/Clang/MSVC)
- 标准库: stdio.h, string.h, stdlib.h, stdint.h, stdbool.h
- 可选: __uint128_t (GCC/Clang 扩展，用于乘法)

## 代码统计

| 文件 | 行数 | 说明 |
|------|------|------|
| evm_sim.h/c | ~420 | EVM 仿真 |
| reentrancy_check.h/c | ~280 | 重入检测 |
| overflow_detect.h/c | ~220 | 溢出检测 |
| access_control.h/c | ~270 | 访问控制 |
| formal_verify.h/c | ~340 | 形式化验证 |
| 示例/演示 | ~600 | 使用示例 |
| **总计** | ~2130 | |
