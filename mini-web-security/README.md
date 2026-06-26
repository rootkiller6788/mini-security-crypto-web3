# mini-web-security — Web安全 (C 语言实现)

## Module Status: COMPLETE ✅

纯 C99 实现的 Web 安全库，涵盖 OWASP Top 10、XSS/CSRF、SQL/NoSQL 注入、输入验证、认证与会话管理等核心安全机制。

## 目录结构

```
mini-web-security/
├── README.md
├── Makefile
├── xss_csrf.h / xss_csrf.c           # XSS 与 CSRF 防护
├── sqli_inject.h / sqli_inject.c     # SQL/NoSQL 注入防护
├── owasp_top10.h / owasp_top10.c     # OWASP Top 10 安全检测
├── input_validation.h / input_validation.c  # 输入验证
├── auth_session.h / auth_session.c   # 认证与会话管理
├── example_basic.c                   # 基础示例
├── example_intermediate.c            # 进阶示例
├── example_advanced.c                # 高级示例
├── demo_server.c                     # Web 安全演示服务器
├── demo_cli.c                        # 命令行安全测试工具
└── docs/
    ├── API.md                        # API 参考文档
    └── DESIGN.md                     # 设计文档
```

## 快速开始

```bash
# 编译所有目标

## Module Status: COMPLETE ✅
make

# 编译并运行基础示例
make run_basic

# 编译并运行演示服务器
make run_server

# 编译并运行 CLI 工具
make run_cli

# 编译并运行测试
make test

# 清理
make clean
```

## 模块概览

| 模块 | 功能 |
|------|------|
| **xss_csrf** | XSS 检测与编码、CSP 策略、CSRF Token、SameSite Cookie |
| **sqli_inject** | SQL 注入检测、预编译语句、NoSQL 注入防护、二阶注入 |
| **owasp_top10** | 越权访问、SSRF、文件包含、目录遍历、加密失败检测 |
| **input_validation** | 白名单/黑名单、格式验证、UTF-8 校验、规范化、参数污染 |
| **auth_session** | PBKDF2 密码哈希、TOTP MFA、会话管理、JWT 验证、速率限制 |

## 依赖

纯 C99 标准库 (stdlib.h, stdio.h, string.h, ctype.h, time.h, stdint.h, stdbool.h)，无外部依赖。

## 授权

MIT License
