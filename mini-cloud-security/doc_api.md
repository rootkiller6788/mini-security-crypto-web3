# mini-cloud-security API 参考

## IAM 策略引擎 (`iam_policy.h`)

### 数据结构

| 类型 | 说明 |
|------|------|
| `iam_policy_t` | IAM 策略文档，包含多个 Statement |
| `iam_statement_t` | 策略声明: Effect + Action + Resource + Conditions |
| `iam_condition_t` | 条件: key-value + 运算符 |
| `iam_user_t` | IAM 用户: 名称、ARN、附加策略、权限边界 |
| `iam_group_t` | IAM 组: 名称、成员列表、附加策略 |
| `iam_role_t` | IAM 角色: 信任策略、权限边界、最大会话时长 |
| `iam_session_t` | AssumeRole 会话: 角色 ARN、主体 ARN、过期时间 |

### 枚举

```c
iam_effect_t   IAM_EFFECT_ALLOW, IAM_EFFECT_DENY
iam_result_t   IAM_RESULT_ALLOW, IAM_RESULT_DENY, IAM_RESULT_ERROR
iam_policy_type_t  IAM_POLICY_IDENTITY, IAM_POLICY_RESOURCE,
                   IAM_POLICY_PERMISSION_BOUNDARY, IAM_POLICY_SCP
```

### 核心函数

| 函数 | 说明 |
|------|------|
| `iam_policy_create(name, type)` | 创建策略文档 |
| `iam_policy_add_statement(p, effect, action, resource)` | 添加 Statement |
| `iam_policy_add_condition(p, idx, key, value, op)` | 为 Statement 添加条件 |
| `iam_evaluate_policy(p, action, resource, context)` | 评估单个策略 |
| `iam_evaluate_all(policies, count, action, resource, context)` | 评估多个策略 (explicit deny 优先) |
| `iam_evaluate_scp(scp, action, resource, context)` | 评估 SCP |
| `iam_check_permission_boundary(base, boundary, ...)` | 应用权限边界 |

### 评估规则

1. **Explicit Deny 优先**: 任何 DENY 覆盖所有 ALLOW
2. **隐式拒绝**: 无匹配 Statement 时默认 DENY
3. **SCP 约束**: 即使身份策略允许，SCP 可拒绝
4. **权限边界**: 限制身份可获得的最高权限

---

## KMS 密钥管理 (`kms_key.h`)

### 数据结构

| 类型 | 说明 |
|------|------|
| `kms_key_t` | CMK: key_id, ARN, spec, state, key_material, rotation 配置 |
| `kms_data_key_t` | 数据密钥: 明文密钥 + 密文密钥 + 关联 CMK ID |
| `kms_grant_t` | 授权: grantee, operations, 约束, 回收主体 |
| `kms_encrypt_result_t` | 加密结果 |
| `kms_decrypt_result_t` | 解密结果 |

### 密钥规格

```c
KMS_KEY_SPEC_SYMMETRIC_DEFAULT   // AES-256-GCM
KMS_KEY_SPEC_RSA_2048            // RSA 2048
KMS_KEY_SPEC_RSA_3072            // RSA 3072
KMS_KEY_SPEC_RSA_4096            // RSA 4096
KMS_KEY_SPEC_ECC_NIST_P256       // ECC P-256
KMS_KEY_SPEC_ECC_NIST_P384       // ECC P-384
KMS_KEY_SPEC_ECC_NIST_P521       // ECC P-521
KMS_KEY_SPEC_HMAC_256            // HMAC SHA-256
```

### 核心函数

| 函数 | 说明 |
|------|------|
| `kms_create_key(...)` | 创建 CMK |
| `kms_encrypt(key, plaintext, len, result)` | 加密数据 |
| `kms_decrypt(key, ciphertext, len, result)` | 解密数据 |
| `kms_generate_data_key(key, dk, bits)` | 生成数据密钥 |
| `kms_envelope_encrypt(cmk, plain, len, dk, ct, ct_len)` | 信封加密 |
| `kms_envelope_decrypt(cmk, dk, ct, ct_len, plain, plen)` | 信封解密 |
| `kms_enable_rotation(key, days)` | 启用自动轮换 |
| `kms_rotate_key_on_demand(key)` | 手动轮换 |
| `kms_create_grant(key, grantee, ops, retiring)` | 创建授权 |
| `kms_retire_grant(grant)` | 回收授权 |

### 信封加密流程

```
明文数据 → [数据密钥(明文)] → 加密数据
               ↓
          [CMK 加密] → 加密的数据密钥
```

---

## WAF 规则引擎 (`waf_rules.h`)

### 数据结构

| 类型 | 说明 |
|------|------|
| `waf_rule_group_t` | 规则组: SQLi/XSS/Rate/Custom + 规则列表 |
| `waf_rule_t` | 单条规则: 优先级 + 条件列表 + 动作 |
| `waf_condition_t` | 匹配条件: 类型 + 目标字段 + 匹配值 |
| `waf_request_t` | HTTP 请求: method, uri, headers, body, ip, country |
| `waf_state_t` | WAF 全局状态: 流量统计、速率跟踪、检测计数 |

### 动作

```c
WAF_ACTION_ALLOW     // 放行
WAF_ACTION_BLOCK     // 拦截
WAF_ACTION_COUNT     // 计数
WAF_ACTION_CHALLENGE // JS 挑战
WAF_ACTION_CAPTCHA   // 验证码
```

### 条件类型

```c
WAF_COND_IP_MATCH      // IP/CIDR 匹配
WAF_COND_STRING_MATCH  // 字符串匹配 (body/uri/headers)
WAF_COND_REGEX_MATCH   // 正则匹配
WAF_COND_GEO_MATCH     // 地理位置匹配
WAF_COND_SQL_INJECTION // SQL 注入检测
WAF_COND_XSS           // XSS 检测
WAF_COND_RATE_LIMIT    // 速率限制
```

### 核心函数

| 函数 | 说明 |
|------|------|
| `waf_create_rule_group(name, type, default_action)` | 创建规则组 |
| `waf_add_rule(group, name, priority, action)` | 添加规则 |
| `waf_evaluate_all(state, req)` | 评估全部规则组 |
| `waf_check_sql_injection(input)` | SQLi 模式检测 |
| `waf_check_xss(input)` | XSS 模式检测 |
| `waf_check_path_traversal(input)` | 路径遍历检测 |
| `waf_rate_check(state, ip)` | 速率检查 |
| `waf_ip_in_cidr(ip, cidr)` | IP CIDR 匹配 |

### 速率限制

- 默认阈值: 2000 请求/5 分钟/IP
- 滑动窗口实现
- 每个 IP 独立跟踪

---

## DDoS 防护 (`ddos_protect.h`)

### 数据结构

| 类型 | 说明 |
|------|------|
| `ddos_protection_t` | 主防护引擎 |
| `ddos_source_t` | 流量来源跟踪 |
| `ddos_traffic_stats_t` | 流量统计 |
| `ddos_detection_rule_t` | 检测规则 |
| `ddos_mitigation_rule_t` | 缓解规则 |
| `ddos_target_t` | 保护目标 |

### 攻击类型

```c
DDOS_SYN_FLOOD, DDOS_UDP_FLOOD, DDOS_DNS_AMPLIFY,
DDOS_HTTP_FLOOD, DDOS_SLOWLORIS, DDOS_NTP_AMPLIFY,
DDOS_MEMCACHED, DDOS_CLDAP_AMPLIFY
```

### 缓解动作

```c
DDOS_ACTION_RATE_LIMIT  // 速率限制
DDOS_ACTION_CHALLENGE   // JS 挑战
DDOS_ACTION_SCRUB       // 流量清洗
DDOS_ACTION_BLACKHOLE   // 黑洞路由
DDOS_ACTION_BLOCK       // 完全阻断
```

### 核心函数

| 函数 | 说明 |
|------|------|
| `ddos_init(dp)` | 初始化防护引擎 |
| `ddos_record_traffic(dp, ip, port, size, protocol)` | 记录流量 |
| `ddos_detect_anomaly(dp)` | 异常检测 |
| `ddos_decide_action(dp, ip)` | 决策缓解动作 |
| `ddos_apply_action(dp, ip, action)` | 执行缓解动作 |
| `ddos_activate_blackhole(dp)` | 激活黑洞路由 |
| `ddos_update_mitigation(dp)` | 更新缓解状态 |

---

## 容器安全 (`container_security.h`)

### 数据结构

| 类型 | 说明 |
|------|------|
| `cs_image_t` | 容器镜像: 名称、漏洞列表、配置 |
| `cs_vulnerability_t` | CVE 漏洞: ID、包名、CVSS 评分 |
| `cs_container_t` | 运行容器: 安全配置、Pod 设置 |
| `cs_seccomp_profile_t` | Seccomp 配置文件 |
| `cs_apparmor_profile_t` | AppArmor 配置文件 |
| `cs_network_policy_t` | Kubernetes 网络策略 |

### Pod 安全级别

```c
CS_POD_PRIVILEGED   // 特权模式
CS_POD_BASELINE     // 基线安全
CS_POD_RESTRICTED   // 严格限制
```

### 核心函数

| 函数 | 说明 |
|------|------|
| `cs_scan_image(name, tag)` | 扫描镜像 |
| `cs_check_privileged(c)` | 检查特权容器 |
| `cs_validate_pod_security(c)` | 验证 Pod 安全级别 |
| `cs_create_seccomp_profile(name, action)` | 创建 Seccomp 配置 |
| `cs_create_apparmor_profile(name, mode)` | 创建 AppArmor 配置 |
| `cs_create_network_policy(name, dir, allow)` | 创建网络策略 |
| `cs_evaluate_network_policy(np, from, to, port, dir)` | 评估网络策略 |
| `cs_sign_image(img, type, signer)` | 镜像签名 |
| `cs_verify_image_signature(img, signer)` | 验证签名 |
