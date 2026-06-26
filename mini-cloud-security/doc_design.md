# mini-cloud-security 架构设计

## 概述

`mini-cloud-security` 是一个纯 C99 实现的 AWS 云安全核心模块库，模拟了五大安全子系统，提供策略评估、加密、检测、防护、合规等能力。

## 架构图

```
+------------------------------------------------------------------+
|                    mini-cloud-security (C99)                       |
+------------------------------------------------------------------+
|  IAM Engine    |  KMS Crypto    |  WAF Engine    |  DDoS Protect  |
|  (iam_policy.c)|  (kms_key.c)   |  (waf_rules.c) |  (ddos_protect)|
+------------------------------------------------------------------+
|              Container Security (container_security.c)            |
+------------------------------------------------------------------+
|              Shared: C99 stdlib (stdlib, string, time)            |
+------------------------------------------------------------------+
```

## 模块设计

### 1. IAM 策略引擎 (`iam_policy.c`)

**设计目标**: 实现 AWS IAM 策略评估逻辑。

**核心算法**:
```
eval(policy, action, resource, context):
  explicit_deny = false
  explicit_allow = false
  for each statement in policy:
    if action_match AND resource_match AND condition_match:
      if effect == DENY: explicit_deny = true
      if effect == ALLOW: explicit_allow = true
  if explicit_deny: return DENY
  if explicit_allow: return ALLOW
  return DENY  (implicit deny)
```

**策略类型**:
- **Identity-based**: 附着于 IAM 用户/组/角色
- **Resource-based**: 附着于 AWS 资源 (S3 Bucket Policy)
- **Permission Boundary**: 限制用户/角色的最高权限
- **SCP (Service Control Policy)**: 组织级别策略，约束所有成员账户

**评估顺序**: SCP → Permission Boundary → Identity/Resource Policies

**关键特性**:
- Explicit Deny 始终优先
- 通配符匹配 (`*`, `prefix*`)
- 上下文条件支持 (IP、日期、Arn、Bool、Numeric)
- AssumeRole 会话创建与过期管理

### 2. KMS 密钥管理 (`kms_key.c`)

**设计目标**: 模拟 AWS KMS 的密钥生命周期管理与信封加密。

**密钥层次结构**:
```
CMK (Customer Master Key)
  ├── 密钥材料 (AES-256)
  ├── 自动/手动轮换
  ├── 密钥策略 (JSON)
  └── 授权 (Grants)

Data Key
  ├── 明文密钥 (由 CMK 生成)
  └── 加密的密钥副本 (由 CMK 加密)
```

**信封加密流程**:
```
发送方:
  1. CMK.GenerateDataKey() → 明文 DK + 加密 DK
  2. 明文 DK 加密数据 → 密文数据
  3. 存储: 加密 DK + 密文数据

接收方:
  1. CMK.Decrypt(加密 DK) → 明文 DK
  2. 明文 DK 解密数据 → 明文数据
```

**安全属性**:
- 数据加密使用 AES-256-GCM (模拟)
- CMK 密钥材料不低于 256 位
- 轮换时生成新密钥材料，保留解密用旧材料的能力
- HSM-backed 密钥表示硬件安全模块保护
- Multi-region 密钥跨区域同步复制

**密钥生命周期**:
```
Enabled → Disabled → PendingDeletion → Deleted
   ↑         ↑            |
   └─────────┘            ↓
  Enable    Disable   CancelDeletion
```

### 3. WAF 规则引擎 (`waf_rules.c`)

**设计目标**: 实现 Web 应用防火墙的请求检测与规则匹配。

**规则匹配流程**:
```
HTTP Request
  → Parse (method, uri, headers, body, client_ip, country)
  → Rule Group 1: AWSManagedSQLi
    → Rule: Block if SQLi patterns detected
  → Rule Group 2: AWSManagedXSS
    → Rule: Block if XSS patterns detected
  → Rule Group 3: RateBased
    → Rule: Block if rate > 2000 req / 5 min / IP
  → Rule Group N: Custom
    → Rule: Match conditions → Apply action
  → Return final action (BLOCK > COUNT > ALLOW)
```

**SQL 注入检测** (部分模式):
- `UNION SELECT` / `' OR '1'='1` / `DROP TABLE`
- `INFORMATION_SCHEMA` / `SLEEP(` / `BENCHMARK(`
- `WAITFOR DELAY` / `xp_cmdshell`

**XSS 检测** (部分模式):
- `<script` / `</script>` / `javascript:`
- `onerror=` / `onload=` / `eval(`
- `<img` / `<iframe` / `document.cookie`

**速率限制**:
- 滑动窗口: 每个 IP 独立跟踪
- 默认: 2000 请求 / 300 秒
- 可自定义阈值和窗口

### 4. DDoS 防护 (`ddos_protect.c`)

**设计目标**: 检测和缓解分布式拒绝服务攻击。

**攻击检测流程**:
```
Traffic → Record (source_ip, size, protocol)
  → Aggregate (syn/udp/dns/http counts)
  → Analyze (threshold comparison)
  → Detect (attack type classification)
  → Decide (mitigation action selection)
  → Apply (rate limit / challenge / scrub / blackhole)
```

**攻击类型识别**:
| 类型 | 特征 | 阈值示例 |
|------|------|----------|
| SYN Flood | 大量 SYN 包 | >200 pps |
| UDP Flood | 大量 UDP 包 | >500 pps |
| DNS Amplification | DNS 查询 + 大响应包 | >100 pps + 平均包 >500B |
| HTTP Flood | 大量 HTTP 请求 | >300 pps |
| Slowloris | 低速持久连接 | >10 长时间连接 |

**缓解层级**:
```
Level 1: 速率限制 (per-source cap)
Level 2: JS/CAPTCHA 挑战 (人机验证)
Level 3: 流量清洗 (scrubbing center, 过滤恶意包)
Level 4: 黑洞路由 (blackhole, 完全丢弃)
```

**AWS Shield 集成**:
- **Standard**: 基础 DDoS 防护 (免费)
- **Advanced**: 增强防护 + 成本保护 + 24x7 专家支持

**CloudFront 边缘吸收**: 利用全球边缘节点分散攻击流量

### 5. 容器安全 (`container_security.c`)

**设计目标**: 容器镜像安全扫描与运行时策略验证。

**安全检查维度**:

**镜像扫描**:
- CVE 漏洞数据库查询
- 按严重性分类 (Critical / High / Medium / Low)
- CVSS 评分 (0-10)
- 恶意软件检测
- 修复状态跟踪

**运行时安全**:
- **Seccomp**: 系统调用过滤 (白名单/黑名单)
- **AppArmor**: 文件系统访问控制
- **SELinux**: 强制访问控制标签
- **Rootless**: 非 root 用户运行
- **Read-Only Rootfs**: 不可变文件系统

**Pod 安全标准**:
```
Privileged: 无限制，危险
  ↓ 移除特权 + host access
Baseline:   最小限制，防止已知提权
  ↓ 移除特权升级 + capabilities
Restricted: 强限制，最佳实践
```

**网络策略**:
```
Ingress 策略: 控制入站流量
Egress 策略:  控制出站流量
匹配规则:     命名空间 → 端口 → 协议 → CIDR
```

**密钥管理**:
- Kubernetes Secrets 挂载
- 外部 Vault 集成 (`vault:secret/...`)
- AWS Secrets Manager (`arn:aws:secretsmanager:...`)

**镜像签名 (Cosign)**:
- 签名类型: cosign / notary / GPG
- 签名验证: 部署前强制校验
- 公钥基础设施集成

## 安全模型总结

```
请求/操作 → [WAF 过滤] → [IAM 鉴权] → [KMS 加解密] → 业务处理
                                  ↑
流量/网络 → [DDoS 检测] → [缓解措施]

容器部署 → [镜像扫描] → [运行时策略] → 运行
```

## 编译要求

- **语言标准**: C99
- **编译器**: GCC 5+ / Clang 3.5+
- **依赖**: 标准 C 库 (libc)
- **平台**: Linux / macOS / Windows (MinGW)

## 限制与简化

1. **加密算法**: 使用简化的 XOR 循环模拟 AES-GCM (非生产级)
2. **JSON 解析**: 简单字符串搜索 (非完整 JSON 解析器)
3. **网络**: 纯数据结构模拟，无实际网络 I/O
4. **线程安全**: 单线程设计，全局状态无锁保护
5. **性能**: 针对教学/演示优化，非高吞吐场景
