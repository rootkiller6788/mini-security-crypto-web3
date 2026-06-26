# mini-cloud-security — 云安全 (C 语言实现)

C99 实现的 AWS 云安全核心模块库。包含 IAM 策略引擎、KMS 密钥管理、WAF 规则引擎、DDoS 防护模拟、容器安全策略五大子系统。

## 模块

| 模块 | 头文件 | 功能 |
|------|--------|------|
| IAM | `iam_policy.h` | 用户/组/角色、策略文档解析、Effect 评估、AssumeRole、权限边界、SCP |
| KMS | `kms_key.h` | CMK 管理、密钥轮换、信封加密、数据密钥、授权、多区域、HSM |
| WAF | `waf_rules.h` | 规则组(SQLi/XSS/速率)、IP匹配、正则、地域匹配、CloudFront集成 |
| DDoS | `ddos_protect.h` | SYN Flood/UDP反射/DNS放大、黑洞路由、清洗中心、速率限制、Shield |
| Container | `container_security.h` | 镜像扫描(CVE/恶意软件)、seccomp/AppArmor/SELinux、Pod安全、密钥管理 |

## 构建

```
make all          # 编译全部 .o 和示例
make examples     # 编译示例程序
make demos        # 编译演示程序
make clean        # 清理编译产物
```

## 示例

- `example_iam` — IAM 策略创建与评估
- `example_kms` — KMS 信封加密流程
- `example_waf` — WAF 规则匹配演示

## 演示

- `demo_cloud_security` — 综合安全场景: IAM + KMS + WAF + DDoS + Container 联合演示
- `demo_security_sim` — 安全事件模拟器: 策略冲突、DoS 检测、密钥泄露、CVE 告警

## 文档

- `doc_api.md` — 完整 API 参考
- `doc_design.md` — 架构设计与安全模型

## 依赖

- C99 编译器 (gcc/clang)
- GNU Make

## License

MIT
