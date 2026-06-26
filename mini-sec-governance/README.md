# mini-sec-governance — Security Governance & GRC (C 语言实现)

安全治理、风险管理和合规自动化 (GRC) 的轻量级 C99 实现库。

**include/ + src/ 总行数: 3907** ✓

## 九层知识覆盖

| Level | 名称 | 状态 | 核心内容 |
|-------|------|------|---------|
| **L1** | Definitions | **Complete** | 42+ struct/typedef, 18+ enum, 90+ API declarations across 5 modules |
| **L2** | Core Concepts | **Complete** | ISMS, PDCA, TSC, NIST CSF Functions, Risk Appetite, Incident Lifecycle, Compliance-as-Code |
| **L3** | Engineering Structures | **Complete** | Risk Register, SoA, Audit Trail Hash Chain, Bow-Tie Barrier Model, Policy Rule Engine, Control Mapping |
| **L4** | Standards/Theorems | **Complete** | FAIR (O-RA), ALE/SLE formula, Bayes' Theorem, AICPA Sampling, COSO ERM, ISO 27004 Measurement |
| **L5** | Algorithms/Methods | **Complete** | Monte Carlo Simulation, 0-1 Knapsack Portfolio Optimization, Bayesian Inference, Linear Regression Forecasting, Box-Muller Transform, PDCA State Machine |
| **L6** | Canonical Problems | **Complete** | ISO 27001 ISMS, SOC 2 Audit, NIST CSF Gap Analysis, Risk Register, Compliance Dashboard |
| **L7** | Applications | **Complete** | GRC Dashboard, Automated Remediation Workflow, Compliance Trending, Bridge Letters, Evidence Export |
| **L8** | Advanced Topics | **Partial+** | GRC Maturity Model (CMMI-style), Supply Chain Risk (SP 800-161), Tamper-Proof Audit Chain, Monte Carlo VaR/ES |
| **L9** | Industry Frontiers | **Partial** | Documented: AI-driven compliance, continuous control monitoring, RegTech automation |

## 核心定义 (L1)

### ISO 27001 ISMS
- `ISO27001_Control`, `ISO27001_Asset`, `ISO27001_Threat`, `ISO27001_Vulnerability`
- `ISO27001_Risk`, `ISO27001_SoAEntry`, `ISO27001_Audit`, `ISO27001_ManagementReview`
- `ISO27001_KPI`, `ISO27001_Incident`, `ISO27001_RiskAppetite`, `ISO27001_ClauseStatus`

### SOC 2 Audit
- `SOC2_ControlActivity`, `SOC2_Evidence`, `SOC2_ControlTestResult`, `SOC2_AuditReport`
- `SOC2_AuditSample` (AICPA statistical sampling), `SOC2_BridgeLetter`

### NIST CSF
- `NIST_CSF_Category`, `NIST_CSF_Subcategory`, `NIST_80053_Control`, `NIST_CSF_ProfileItem`
- `NIST_CSF_MaturityAssessment`, `NIST_CSF_ProfileGap`, `NIST_SCRM_Supplier`

### Risk Assessment
- `Risk_Asset`, `Risk_Threat`, `Risk_Entry` (ALE/SLE/residual), `Risk_StrideEntry`
- `Risk_FAIR_Model`, `Risk_MonteCarloResult`, `Risk_BowtieModel`, `Risk_PortfolioItem`

### Compliance Automation
- `Compliance_Policy`, `Compliance_CheckResult`, `Compliance_Drift`, `Compliance_AuditLog`
- `Compliance_Remediation`, `Compliance_MaturityAssessment`, `Compliance_TrendPoint`

## 核心定理与公式 (L4)

| 定理/公式 | 模块 | 实现 |
|-----------|------|------|
| **ALE = SLE × ARO** (Annualized Loss Expectancy) | risk_assess | `risk_add_entry()` |
| **FAIR Model**: Vuln = TCap × (1 − CS), LEF = TEF × Vuln | risk_assess | `risk_fair_compute()` |
| **Bayes' Theorem**: P(H\|E) = P(E\|H)·P(H)/P(E) | risk_assess | `risk_bayesian_update()` |
| **Cochran Sample Size**: n = N·z²·p(1−p) / ((N−1)e² + z²·p(1−p)) | soc2_audit | `soc2_calculate_sample_size()` |
| **Value-at-Risk**: VaR_α ≈ μ·(1 + ln(1/(1−α))·CV) | risk_assess | `risk_value_at_risk()` |
| **Expected Shortfall (CVaR)**: ES_α = E[L \| L > VaR_α] | risk_assess | `risk_expected_shortfall()` |
| **Linear Regression Forecasting**: score = β₁·t + β₀ | compliance_auto | `comp_forecast_compliance()` |
| **0-1 Knapsack**: maximize Σ value_i subject to Σ cost_i ≤ budget | risk_assess | `risk_portfolio_optimize()` |

## 核心算法 (L5)

| 算法 | 实现 | 复杂度 |
|------|------|--------|
| Box-Muller Transform | `sample_normal()` | O(1) per sample |
| Monte Carlo ALE Simulation | `risk_monte_carlo_ale()` | O(N log N) for N iterations |
| 0-1 Knapsack DP | `risk_portfolio_optimize()` | O(n × W) for n items, budget W |
| Bayesian Network Inference | `risk_bayesian_network_inference()` | O(r) for r related risks |
| Linear Regression | `comp_forecast_compliance()` | O(n) for n trend points |
| Cochran Sampling | `soc2_calculate_sample_size()` | O(1) |
| Hash Chain Verification | `comp_verify_chain()` | O(n) for n log entries |

## 经典问题 (L6)

1. **ISO 27001 ISMS**: Full ISMS with Annex A controls, SoA, PDCA cycle, KPI scorecard, incident management
2. **SOC 2 Type II Audit**: Engagement lifecycle, evidence collection, evaluation, report generation, statistical sampling
3. **NIST CSF Profile**: Function/category/subcategory mapping, tier assessment, gap analysis, FISMA scoring
4. **Risk Register v2**: FAIR quantitative model, Monte Carlo simulation, bow-tie analysis, portfolio optimization
5. **Compliance as Code**: Policy engine, drift detection, audit trail with hash chain, automated remediation

## 跨模块集成

本模块为安全治理层，消费上游模块：

| 上游模块 | 接口 | 集成方式 |
|---------|------|---------|
| data-engine (7) | 向量存储 | 风险评估数据输入 |
| backend (8) | API 端点 | 合规策略检查 |
| security (13) | 审计网络/后端入口 | 本模块输出治理审计数据 |

## 文件结构

```
mini-sec-governance/
├── Makefile                     # make test 一键通过
├── README.md                    # 本文档
├── include/
│   ├── iso27001_mgr.h          # ISO 27001 ISMS (275 行)
│   ├── soc2_audit.h            # SOC 2 审计 (168 行)
│   ├── nist_csf.h              # NIST CSF 框架 (186 行)
│   ├── risk_assess.h           # 风险评估 (266 行)
│   └── compliance_auto.h       # 合规自动化 (252 行)
├── src/
│   ├── iso27001_mgr.c          # KPI, 事件管理, 风险偏好, 条款合规 (537 行)
│   ├── soc2_audit.c            # 统计抽样, 桥接函, TSC 覆盖 (333 行)
│   ├── nist_csf.c              # 成熟度评估, SCRM, 配置比较 (444 行)
│   ├── risk_assess.c           # FAIR, Monte Carlo, Bow-Tie, 组合优化, Bayesian (710 行)
│   └── compliance_auto.c       # 规则引擎, 修复工作流, GRC 成熟度, 趋势 (736 行)
├── tests/
│   └── test_core.c             # 30 个单元测试，全部通过
├── examples/
│   ├── example_iso27001.c      # ISO 27001 ISMS 示例
│   ├── example_soc2.c          # SOC 2 审计示例
│   ├── example_nist.c          # NIST CSF 示例
│   ├── demo_risk_assess.c      # 风险评估演示
│   └── demo_compliance_auto.c  # 合规自动化演示
├── demos/
│   └── demo_full.c             # 端到端 GRC 平台全栈演示
├── benches/
│   └── bench_core.c            # 性能基准测试
└── docs/
    ├── doc_governance.md       # 治理框架文档
    └── doc_compliance.md       # 合规自动化文档
```

## 构建与测试

```sh
make          # 编译静态库 libsecgovernance.a
make test     # 运行 30 个单元测试
make examples # 运行 3 个示例
make demos    # 运行 2 个演示
make demo-full # 运行全栈 GRC 演示
make bench    # 运行性能基准
```

## 九校课程映射

| 学校 | 相关课程 | 模块覆盖 |
|------|---------|---------|
| **MIT** | 6.858 Computer Security | ISO 27001, SOC 2, 风险 |
| **Stanford** | CS 255 Security | CSP, 策略评估 |
| **Berkeley** | CS 161 Security | STRIDE 威胁建模 |
| **CMU** | 14-829 Mobile & IoT Security | 供应链风险 (SP 800-161) |
| **UT Austin** | CS 380D Distributed Systems | 审计链 (hash chain) |
| **ETH** | 263-4657 Security | 形式化风险建模 |
| **Cambridge** | Part II Security | FAIR, 定量风险分析 |
| **清华** | 网络与信息安全 | 合规框架, GRC |
| **Georgia Tech** | CS 6262 Network Security | 安全治理指标 |

## Module Status: COMPLETE ✅

- **L1 Definitions**: Complete — 60+ types across 5 modules
- **L2 Core Concepts**: Complete — ISMS, TSC, NIST CSF, FAIR, Compliance-as-Code
- **L3 Engineering Structures**: Complete — Bow-Tie, Rule Engine, Audit Chain, Knapsack Portfolio
- **L4 Standards/Theorems**: Complete — 8 theorems/standards with code verification
- **L5 Algorithms/Methods**: Complete — 7 algorithms with full implementations
- **L6 Canonical Problems**: Complete — 5 end-to-end solved problems
- **L7 Applications**: Complete — Remediation workflow, trending, bridge letters, evidence export
- **L8 Advanced Topics**: Partial+ — GRC Maturity Model, Supply Chain Risk, Monte Carlo VaR
- **L9 Industry Frontiers**: Partial — Documented: AI compliance, continuous monitoring

**include/ + src/ 总行数: 3907** (≥ 3000 ✓)
**make test: 30/30 passed** ✓
