# mini-sec-governance — 安全治理 (C 语言实现)

安全治理与合规框架的轻量级 C99 实现库，覆盖 ISO 27001、SOC 2、NIST CSF、风险评估与合规自动化五大模块。

## 模块概览

| 模块 | 头文件 | 描述 |
|------|--------|------|
| ISO 27001 | `iso27001_mgr.h` | ISMS 管理体系：Annex A 控制集、风险评估、SoA、内部审计、管理评审、PDCA |
| SOC 2 | `soc2_audit.h` | 信任服务标准审计：Type I/II、控制活动、证据收集、审计报告 |
| NIST CSF | `nist_csf.h` | 网络安全框架：核心功能、实施层级、配置文件、差距分析、SP 800-53 |
| 风险评估 | `risk_assess.h` | 定量/定性评估、STRIDE 威胁建模、风险矩阵、风险处置、残余风险 |
| 合规自动化 | `compliance_auto.h` | 策略即代码、漂移检测、合规仪表盘、审计追踪、持续监控、GRC 模拟 |

## 构建

```sh
make
```

## 运行示例

```sh
make examples
```

## 运行演示

```sh
make demos
```

## 文件清单

```
mini-sec-governance/
├── README.md
├── Makefile
├── iso27001_mgr.h / .c        # ISO 27001 ISMS
├── soc2_audit.h / .c          # SOC 2 审计
├── nist_csf.h / .c            # NIST CSF 框架
├── risk_assess.h / .c         # 风险评估
├── compliance_auto.h / .c     # 合规自动化
├── example_iso27001.c         # ISO 27001 示例
├── example_soc2.c             # SOC 2 示例
├── example_nist.c             # NIST CSF 示例
├── demo_risk_assess.c         # 风险评估演示
├── demo_compliance_auto.c     # 合规自动化演示
├── doc_governance.md          # 治理框架文档
└── doc_compliance.md          # 合规自动化文档
```

## 许可证

MIT
