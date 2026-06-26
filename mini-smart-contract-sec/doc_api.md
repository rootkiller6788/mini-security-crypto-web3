# mini-smart-contract-sec API 参考

## 1. evm_sim.h — EVM 仿真引擎

### 类型

| 类型 | 说明 |
|------|------|
| `uint256_t` | 256-bit 无符号整数 (w[0..3]: uint64_t) |
| `evm_stack_t` | EVM 栈 (max 1024 words) |
| `evm_memory_t` | EVM 内存 (byte-addressable, max 1MB) |
| `evm_storage_t` | 持久化存储 (key-value, max 256 slots) |
| `evm_call_ctx_t` | 调用上下文 (caller, origin, value, balance) |
| `evm_t` | EVM 主状态结构体 |

### uint256_t 操作

```c
void uint256_zero(uint256_t *v);
void uint256_set64(uint256_t *v, uint64_t x);
int  uint256_cmp(const uint256_t *a, const uint256_t *b);
void uint256_add(uint256_t *r, const uint256_t *a, const uint256_t *b);
void uint256_sub(uint256_t *r, const uint256_t *a, const uint256_t *b);
void uint256_mul(uint256_t *r, const uint256_t *a, const uint256_t *b);
void uint256_from_bytes(uint256_t *v, const uint8_t *b, size_t len);
void uint256_to_bytes(const uint256_t *v, uint8_t *b, size_t len);
```

### EVM 生命周期

```c
void evm_init(evm_t *evm, const uint8_t *code, size_t code_len);
void evm_set_caller(evm_t *evm, const uint8_t caller[20]);
void evm_set_value(evm_t *evm, const uint256_t *value);
void evm_set_calldata(evm_t *evm, const uint8_t *data, size_t len);
int  evm_execute(evm_t *evm);          // 执行全部直到停止
bool evm_step(evm_t *evm);             // 单步执行
void evm_reset(evm_t *evm);            // 重置 PC/栈/revert
```

### 栈操作

```c
void stack_push(evm_stack_t *s, const uint256_t *v);
void stack_pop(evm_stack_t *s, uint256_t *v);
void stack_dup(evm_stack_t *s, int n);
void stack_swap(evm_stack_t *s, int n);
```

### 内存操作

```c
void memory_store(evm_memory_t *m, size_t offset, const uint8_t *data, size_t len);
void memory_load(const evm_memory_t *m, size_t offset, uint8_t *data, size_t len);
```

### 存储操作

```c
bool storage_get(const evm_storage_t *s, const uint256_t *key, uint256_t *value);
void storage_set(evm_storage_t *s, const uint256_t *key, const uint256_t *value);
```

### Gas 常量

| 常量 | 值 | 说明 |
|------|-----|------|
| `GAS_ZERO` | 0 | STOP/RETURN/REVERT |
| `GAS_BASE` | 2 | 基础操作 |
| `GAS_VERYLOW` | 3 | ADD/SUB/EQ |
| `GAS_LOW` | 5 | MUL/DIV |
| `GAS_MID` | 8 | JUMP |
| `GAS_HIGH` | 10 | JUMPI |
| `GAS_SLOAD` | 200 | 存储读取 |
| `GAS_SSTORE_SET` | 20000 | 存储写入 (新值) |
| `GAS_SELFDESTRUCT` | 5000 | 自毁 |
| `GAS_CREATE` | 32000 | 创建合约 |

### 支持的操作码

- **算术**: ADD, MUL, SUB, DIV, SDIV, MOD, SMOD, ADDMOD, MULMOD, EXP, SIGNEXTEND
- **比较**: LT, GT, SLT, SGT, EQ, ISZERO
- **逻辑**: AND, OR, XOR, NOT, BYTE, SHL, SHR, SAR, SHA3
- **上下文**: ADDRESS, BALANCE, ORIGIN, CALLER, CALLVALUE
- **数据**: CALLDATALOAD, CALLDATASIZE, CALLDATACOPY, CODESIZE, CODECOPY
- **存储**: SLOAD, SSTORE, MSTORE, MLOAD, MSTORE8
- **流控**: JUMP, JUMPI, JUMPDEST, PC, GAS
- **调用**: CALL, DELEGATECALL, CALLCODE, CREATE
- **PUSH/DUP/SWAP**: PUSH1..PUSH32, DUP1..DUP16, SWAP1..SWAP16
- **终止**: STOP, RETURN, REVERT, INVALID, SELFDESTRUCT

---

## 2. reentrancy_check.h — 重入检测

### 类型

```c
typedef enum { RC_PATTERN_SAFE, RC_PATTERN_CEI, RC_PATTERN_VULN,
               RC_PATTERN_GUARDED, RC_PATTERN_READONLY_REENT,
               RC_PATTERN_CROSS_FUNC } rc_pattern_t;
```

### API

```c
void rc_init(rc_analyzer_t *a);
int  rc_add_function(rc_analyzer_t *a, const char *name, bool has_guard, int guard_var);
int  rc_add_edge(rc_analyzer_t *a, int from, int to, rc_event_type_t type);
void rc_mark_external_call(rc_analyzer_t *a, int func_id);
void rc_mark_state_write(rc_analyzer_t *a, int func_id);

int  rc_detect_reentrancy(rc_analyzer_t *a);   // 返回漏洞数
int  rc_check_cei_pattern(rc_analyzer_t *a, int func_id);
int  rc_check_cross_func(rc_analyzer_t *a);
int  rc_check_readonly_reent(rc_analyzer_t *a);
void rc_simulate_attack(rc_analyzer_t *a, int entry_func, bool verbose);
void rc_print_report(const rc_analyzer_t *a);
```

---

## 3. overflow_detect.h — 溢出检测

### API

```c
void od_init(od_analyzer_t *a);

// SafeMath 模拟
bool od_add_overflow(uint64_t a, uint64_t b, uint64_t *result);
bool od_sub_underflow(uint64_t a, uint64_t b, uint64_t *result);
bool od_mul_overflow(uint64_t a, uint64_t b, uint64_t *result);
bool od_div_safe(uint64_t a, uint64_t b, uint64_t *result);

// 检测
od_result_t od_check_operation(od_analyzer_t *a, const char *op,
                                uint64_t a, uint64_t b, uint64_t result, int line);
od_result_t od_check_timestamp(od_analyzer_t *a, uint64_t ts, int line);
od_result_t od_check_truncation(od_analyzer_t *a, int from_bits, int to_bits, int line);

// 定点数
od_fixed_t od_fixed_add(od_fixed_t a, od_fixed_t b);
od_fixed_t od_fixed_sub(od_fixed_t a, od_fixed_t b);
od_fixed_t od_fixed_mul(od_fixed_t a, od_fixed_t b);

void od_print_report(const od_analyzer_t *a);
bool od_has_critical(const od_analyzer_t *a);
```

---

## 4. access_control.h — 访问控制

### API

```c
// Ownable
ac_result_t ac_set_owner(ac_analyzer_t *a, const uint8_t addr[20]);
ac_result_t ac_only_owner(const ac_analyzer_t *a, const uint8_t caller[20]);

// RBAC
ac_result_t ac_grant_role(ac_analyzer_t *a, const ac_role_t *role,
                           const uint8_t addr[20], const uint8_t caller[20]);
ac_result_t ac_revoke_role(ac_analyzer_t *a, const ac_role_t *role,
                            const uint8_t addr[20], const uint8_t caller[20]);
bool ac_has_role(const ac_analyzer_t *a, const ac_role_t *role,
                 const uint8_t addr[20]);

// EIP-712
void ac_eip712_init(ac_eip712_domain_t *d, const char *name, const char *version,
                    uint64_t chain_id, const uint8_t contract[20]);

// 安全检测
ac_result_t ac_check_tx_origin(const ac_analyzer_t *a);
ac_result_t ac_check_delegatecall_risk(const ac_analyzer_t *a,
                                        const uint8_t target[20], bool trusted);
ac_result_t ac_check_initializer(ac_analyzer_t *a, bool is_initializer);
```

---

## 5. formal_verify.h — 形式化验证

### API

```c
void fv_init(fv_analyzer_t *a);

// 符号执行
int  fv_sym_add_var(fv_symbolic_state_t *s, const char *name, fv_sym_type_t type);
int  fv_symbolic_execute(fv_analyzer_t *a);

// CFG
int  fv_cfg_add_block(fv_cfg_t *cfg, const char *label, int line);
void fv_cfg_set_conditional(fv_cfg_t *cfg, int id, int t_branch, int f_branch);
void fv_cfg_set_assert(fv_cfg_t *cfg, int id, const char *assertion);

// 污点
void fv_taint_mark_input(fv_taint_tracker_t *t, const char *var, const char *source);
void fv_taint_propagate(fv_taint_tracker_t *t, const char *src, const char *dst);
void fv_taint_check_sink(fv_taint_tracker_t *t, const char *var,
                          const char *sink, fv_taint_level_t min_level);

// 模糊测试
void fv_fuzz_run(fv_analyzer_t *a, void (*target)(uint64_t, uint64_t),
                 uint64_t iterations);
void fv_fuzz_run_seed(fv_analyzer_t *a, void (*target)(uint64_t, uint64_t),
                       uint64_t seed, uint64_t iterations);

// Mythril/Slither 模拟
int  fv_mythril_detect_overflow(const fv_analyzer_t *a);
int  fv_mythril_detect_reentrancy(const fv_analyzer_t *a);
int  fv_slither_detect_unchecked_call(const fv_analyzer_t *a);

void fv_print_report(const fv_analyzer_t *a);
void fv_print_cfg(const fv_cfg_t *cfg);
void fv_print_taint(const fv_taint_tracker_t *t);
```
