# 合规自动化实现文档 (Compliance Automation)

## 模块架构

```
Compliance_Engine
 ├── Policy Management (政策管理)
 │   ├── Policy-as-Code Rules (OPA/Rego 风格规则)
 │   ├── Multi-Regulation Mapping (多法规映射)
 │   └── Severity Classification (严重性分级)
 ├── Check Engine (检查引擎)
 │   ├── Policy Evaluation (策略评估)
 │   ├── Batch Checking (批量检查)
 │   └── Pass/Fail/Warn Classification
 ├── Drift Detection (漂移检测)
 │   ├── Configuration vs Policy Comparison
 │   ├── Drift History Tracking
 │   └── Remediation Workflow
 ├── Audit Trail (审计追踪)
 │   ├── Immutable Hash-Chained Logs
 │   ├── Actor Attribution
 │   └── Temporal Ordering
 ├── Control Inventory (控制清单)
 │   ├── Regulation-Mapped Controls
 │   ├── Evidence Collection Status
 │   └── Pass/Fail Count Tracking
 └── Dashboard (仪表盘)
     ├── Compliance Score Calculation
     ├── Per-Regulation Status
     └── Remediation Report Generation
```

---

## 核心数据流

```
政策定义 → 策略即代码规则
    ↓
检查执行 → 当前配置 vs 期望值 → PASS / FAIL / WARN
    ↓
漂移检测 → FAIL 检查 → 漂移记录
    ↓
日志记录 → 不可变审计链
    ↓
控制更新 → 通过/失败计数 → 证据状态
    ↓
仪表盘 → 合规评分 → 报告生成
```

---

## Policy-as-Code 规则语法

### 支持的规则模式

```
// 相等比较
"config.db.encryption == AES256"

// 数值比较
"config.access.review_period <= 90"
"config.audit.retention_days >= 365"
"config.backup.frequency_hours <= 24"
"config.auth.password_min_length >= 12"
"config.auth.session_timeout_minutes <= 15"

// 布尔检查
"config.auth.mfa_enabled == true"

// 版本比较
"config.network.tls_version >= 1.2"
```

### 规则评估流程

```c
int comp_check_policy(Compliance_Engine *eng, int policy_id,
                      const char *current_value);
```

1. 获取策略定义（期望值）
2. 比较当前值 vs 期望值
3. 记录检查结果及时间戳
4. 返回检查 ID

---

## 漂移检测机制

### 漂移生命周期

```
检测 (Drift Detected)
  → 确认 (Acknowledged)
    → 修复 (Remediated)
      → 关闭 (Remediated timestamp set)
```

### 漂移结构

```c
typedef struct {
    int         drift_id;
    int         check_id;
    int         policy_id;
    const char *drifted_value;     // 实际值
    const char *expected_value;    // 期望值
    const char *resource_path;     // 资源配置路径
    time_t      detected_at;       // 检测时间
    int         acknowledged;      // 是否已确认
    const char *remediated_by;     // 修复者
    time_t      remediated_at;     // 修复时间
} Compliance_Drift;
```

---

## 审计追踪 — 不可变日志链

### 哈希链结构

```
Log[0]: hash = DJB2(ts0 + actor0 + action0 + resource0 + result0 + 0)
Log[1]: hash = DJB2(ts1 + actor1 + action1 + resource1 + result1 + Log[0].hash)
Log[2]: hash = DJB2(ts2 + actor2 + action2 + resource2 + result2 + Log[1].hash)
...
```

任何日志条目的修改都会破坏后续所有哈希值，确保审计追踪的不可变性。

### 日志条目

```c
typedef struct {
    int         log_id;
    time_t      timestamp;
    const char *actor;
    const char *action;
    const char *resource;
    const char *result;
    int         immutable;
    uint64_t    prev_hash;
    uint64_t    curr_hash;
} Compliance_AuditLog;
```

---

## GRC 工具模拟

### 法规注册

```
COMP_REG_GDPR    — 通用数据保护条例
COMP_REG_HIPAA   — 健康保险可携与责任法
COMP_REG_PCI_DSS — 支付卡行业数据安全标准
COMP_REG_SOX     — 萨班斯-奥克斯利法案
COMP_REG_NIST    — NIST 标准
COMP_REG_ISO27001— ISO 27001 标准
COMP_REG_CUSTOM  — 自定义法规
```

### 政策到法规映射

每个策略可以映射到一个或多个法规框架：

```c
Compliance_Regulation mappings[] = {COMP_REG_GDPR, COMP_REG_ISO27001, COMP_REG_HIPAA};
comp_add_policy(&eng, "Data Encryption", "...", "...", "AES256", 5, mappings, 3);
```

### 合规评分计算

```
Score = (Passing Policies / Total Policies) × 100%

其中:
  - Passing Policies: 最近一次检查状态为 PASS 的策略数
  - Total Policies: 已定义的策略总数
```

---

## 持续监控

### 监控循环

```
comp_continuous_monitor(engine, interval_seconds)
    ↓
  comp_check_all()        → 评估所有策略
    ↓
  comp_detect_drift()     → 检测新漂移
    ↓
  comp_update_dashboard() → 更新仪表盘
    ↓
  (等待 interval_seconds)
    ↓
  循环...
```

### 实时合规检查

```
comp_check_all(&eng);
// 立即对所有已注册策略执行合规检查
// 检查结果写入 eng.checks[]
```

---

## 仪表盘指标

| 指标 | 描述 | 计算 |
|------|------|------|
| 控制合规率 | 合规控制 / 总控制 | `compliant / total_controls × 100` |
| 策略通过率 | 通过策略 / 总策略 | `passing / total_policies × 100` |
| 合规评分 | 整体合规状态 | `passing / total × 100` |
| 漂移数 | 未修复的配置漂移 | 计数 `remediated_by == NULL` |
| 总体状态 | PASS / FAIL | 所有控制通过 & 所有策略通过 → PASS |

---

## 证据自动收集

`comp_generate_evidence()` 函数模拟了通过 API 集成自动收集合规证据的过程：

1. 检查控制关联的通过/失败计数
2. 根据计数比例确定控制状态
3. 更新控制最后一次检查时间戳
4. 记录证据到审计日志

实际生产环境中，证据收集可以通过集成 API 自动执行（如 AWS Config、Azure Policy、GCP SCC、SIEM 等）。

---

## 集成最佳实践

### 1. CI/CD 管道集成
```
构建 → 策略检查 → 漂移检测 → 合规评分 → 部署门禁
```

### 2. SIEM 集成
```
审计日志 → 哈希链导出 → SIEM → 告警规则
```

### 3. 仪表盘聚合
```
多引擎指标 → Prometheus → Grafana
```

### 4. 自动修复
```
漂移检测 → 告警 → 自动回滚 / 重新配置
```
