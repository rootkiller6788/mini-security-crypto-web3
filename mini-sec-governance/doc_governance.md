# 安全治理框架文档 (Security Governance Framework)

## 概述

`mini-sec-governance` 提供了五大安全治理模块的轻量级 C99 实现，覆盖企业安全治理的核心框架需求。

---

## 1. ISO 27001 — ISMS 管理体系

### 1.1 体系结构

```
ISO27001_ISMS
 ├── Annex A Controls (114 控制项 / 14 域)
 ├── Asset Inventory (资产清单)
 ├── Threat Register (威胁登记)
 ├── Risk Register (风险登记)
 ├── Statement of Applicability (适用性声明)
 ├── Internal Audit Schedule (内部审计计划)
 └── Management Reviews (管理评审)
```

### 1.2 Annex A 控制域

| 编号 | 域名 | 控制数 |
|------|------|--------|
| A.5  | 信息安全策略 | 2 |
| A.6  | 信息安全组织 | 5 |
| A.7  | 人力资源安全 | 2 |
| A.8  | 资产管理 | 5 |
| A.9  | 访问控制 | 4 |
| A.10 | 密码学 | 2 |
| A.11 | 物理与环境安全 | 2 |
| A.12 | 运行安全 | 3 |
| A.13 | 通信安全 | 2 |
| A.14 | 系统获取、开发与维护 | 2 |
| A.15 | 供应商关系 | 2 |
| A.16 | 信息安全事件管理 | 2 |
| A.17 | 业务持续性 | 2 |
| A.18 | 符合性 | 5 |

### 1.3 PDCA 周期

```
Plan  → 风险评估、控制定义、SoA 编制
Do    → 控制实施、培训、运行
Check → 内部审计、管理评审、监控测量
Act   → 纠正措施、持续改进、认证维护
```

### 1.4 认证生命周期

```
Stage 1 (文档审核) → Stage 2 (现场审核) → 认证颁发 → 监督审核 (每年) → 再认证 (3年)
```

---

## 2. SOC 2 — 服务组织控制

### 2.1 信任服务标准

| 标准 | 描述 | 控制示例 |
|------|------|----------|
| **Security** | 系统受保护防止未授权访问 | 访问控制、MFA、防火墙 |
| **Availability** | 系统可按 SLA 使用 | 备份恢复、冗余、监控 |
| **Confidentiality** | 机密信息受保护 | 加密、数据分类 |
| **Processing Integrity** | 处理完整、准确、及时 | 变更管理、QA测试 |
| **Privacy** | 个人信息按隐私声明处理 | 隐私通知、同意、数据主体权利 |

### 2.2 Type I vs Type II

| 特性 | Type I | Type II |
|------|--------|---------|
| 评估范围 | 控制在**某一时点**的设计 | 控制在**一段时期**的运行有效性 |
| 测试期间 | 快照（1天） | 通常 6-12 个月 |
| 证据需求 | 控制描述 + 设计证明 | 运行证据（多时间点采样） |
| 适用场景 | 首次审计、新服务 | 年度合规报告 |

### 2.3 评价等级

```
Designed Correctly → Operating Effectively → Deficiency → Significant Deficiency → Material Weakness
```

---

## 3. NIST CSF — 网络安全框架

### 3.1 框架核心 (Framework Core)

| 功能 | 描述 | 类别示例 |
|------|------|----------|
| **Identify** | 识别业务上下文、资产、风险 | 资产管理(AM)、风险评估(RA) |
| **Protect** | 制定和实施保护措施 | 访问控制(AC)、数据安全(DS) |
| **Detect** | 检测网络安全事件 | 异常检测(AE)、持续监控(CM) |
| **Respond** | 响应网络安全事件 | 响应规划(RP)、缓解(MI) |
| **Recover** | 恢复能力建设 | 恢复规划(RP)、改进(IM) |

### 3.2 实施层级 (Implementation Tiers)

```
Tier 1 (Partial)       → 临时、被动
Tier 2 (Risk Informed) → 风险意识、但非正式
Tier 3 (Repeatable)    → 正式化、可重复
Tier 4 (Adaptive)      → 自适应、持续改进
```

### 3.3 配置文件 (Profiles)

通过当前配置文件与目标配置文件的差距分析，识别改进路径。

### 3.4 NIST SP 800-53 参考

800-53 控制目录（18 个族）可直接映射到 CSF 子类别，提供具体的控制实施指南。

### 3.5 FedRAMP 概述

- FedRAMP Low: ~125 controls
- FedRAMP Moderate: ~325 controls
- FedRAMP High: ~421 controls

---

## 4. 风险评估方法论

### 4.1 定量 vs 定性

| 方法 | 输入 | 输出 | 公式 |
|------|------|------|------|
| **定量** | SLE, ARO | ALE (年预期损失) | `ALE = SLE × ARO` |
| **定性** | 可能性 1-5, 影响 1-5 | 风险得分 1-25 | `Score = Likelihood × Impact` |

### 4.2 STRIDE 威胁模型

| 威胁 | 违反属性 | 示例 |
|------|----------|------|
| **S**poofing | 身份验证 | 凭据窃取、会话劫持 |
| **T**ampering | 完整性 | 数据篡改、恶意注入 |
| **R**epudiation | 不可否认性 | 交易否认、日志删除 |
| **I**nfo Disclosure | 机密性 | 数据泄露、旁路攻击 |
| **D**enial of Service | 可用性 | DDoS、资源耗尽 |
| **E**levation of Privilege | 授权 | 权限提升、横向移动 |

### 4.3 风险处置策略

```
Accept  (接受)  → 风险在容忍范围内，接受
Mitigate (缓解) → 实施控制降低可能性或影响
Transfer (转移) → 保险、外包、合同转移
Avoid   (避免)  → 停止活动或变更架构消除风险
```

---

## 5. 合规自动化

### 5.1 策略即代码 (Policy-as-Code)

```c
// OPA/Rego 风格的规则表达
"config.db.encryption == AES256"
"config.access.review_period <= 90"
```

### 5.2 合规仪表盘

实时展示每个法规框架的合规状态、通过/失败率、整体合规评分。

### 5.3 审计追踪

哈希链式不可变日志：
```
Log[N].prev_hash = Log[N-1].hash
Log[N].hash = DJB2(timestamp + actor + action + resource + result + prev_hash)
```

### 5.4 法规映射

| 法规 | 域 | 关键控制 |
|------|------|----------|
| GDPR | 数据保护 | 加密、访问控制、数据最小化、同意管理 |
| HIPAA | 医疗保健 | 管理保障、物理保障、技术保障 |
| PCI-DSS | 支付卡 | 防火墙、加密、访问控制、监控、测试 |
| SOX | 财务报告 | IT 一般控制、变更管理、访问控制 |
| NIST | 联邦系统 | 18 个控制族，1000+ 控制项 |

---

## API 参考

### 通用模式

所有模块遵循一致的 API 设计：

1. `*_init()` — 初始化模块
2. `*_add_*()` — 添加实体
3. `*_report()` / `*_summary()` — 生成报告
4. `*_name()` — 枚举值转可读字符串

### 内存管理

所有结构体由调用方分配，库函数使用指针操作，不执行动态内存分配，适合嵌入式环境。
