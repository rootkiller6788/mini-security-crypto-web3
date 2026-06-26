# mini-smart-contract-sec — 智能合约安全 (C 语言实现)

轻量级 C99 智能合约安全分析库，模拟 EVM 执行并检测常见漏洞。

## 模块

| 模块 | 头文件 | 功能 |
|------|--------|------|
| EVM 仿真 | `evm_sim.h` | 栈/内存/存储/调用/Gas 模型 |
| 重入检测 | `reentrancy_check.h` | 调用图/CEI 模式/重入防护 |
| 溢出检测 | `overflow_detect.h` | SafeMath/溢出/截断/时间戳 |
| 访问控制 | `access_control.h` | Ownable/RBAC/EIP-712/代理 |
| 形式化验证 | `formal_verify.h` | 符号执行/断言/污点/模糊 |

## 构建

```
make          # 构建库 + 示例 + 演示
make test     # 运行所有示例和演示
make clean    # 清理
```

## 使用

```c
#include "evm_sim.h"
#include "reentrancy_check.h"

evm_t evm;
evm_init(&evm, contract, GAS_LIMIT);
evm_execute(&evm, calldata, calldata_len);
if (evm.revert) printf("Reverted: %s\n", evm.revert_reason);
```

## 许可

MIT
