# Mini Security Crypto Web3（迷你安全密码学 Web3）

**从零开始、零依赖的 C 语言实现**，涵盖密码学、区块链、Web3 和安全概念。每个模块以教学级精度实现安全原语、加密算法、区块链共识和 Web3 基础设施 — 从哈希函数、对称/非对称加密到零知识证明、智能合约安全和隐私计算。

## 模块总览

| 模块 | 主题 | 参考标准 |
|--------|--------|----------------|
| [mini-crypto-basic](mini-crypto-basic/) | 哈希（SHA256/MD5）、AES/DES、RSA/ECC、数字签名、PKI 公钥基础设施 | NIST FIPS, RFC 5280 |
| [mini-adv-crypto](mini-adv-crypto/) | zk-SNARKs、同态加密、安全多方计算（MPC）、后量子密码学、门限签名 | zk-SNARKs 论文, BGV/Paillier |
| [mini-blockchain-core](mini-blockchain-core/) | UTXO/账户模型、Merkle 树、PoW/PoS 共识、交易池、P2P 网络 | Bitcoin, Ethereum |
| [mini-defi-crosschain](mini-defi-crosschain/) | AMM 自动做市商（Uniswap）、借贷协议、稳定币、跨链桥、预言机 | Uniswap V3, Aave, Chainlink |
| [mini-smart-contract-sec](mini-smart-contract-sec/) | EVM 仿真、重入攻击、整数溢出、访问控制、形式化验证 | Ethereum Yellow Paper, OpenZeppelin |
| [mini-web-security](mini-web-security/) | XSS/SQLi/CSRF、CSP 内容安全策略、OWASP Top 10、输入验证、认证安全 | OWASP, MDN Security |
| [mini-binary-security](mini-binary-security/) | 缓冲区溢出、ROP 面向返回编程、ASLR/NX/Canary 防护、格式化字符串攻击、Fuzzing | MIT 6.858, Phrack |
| [mini-cloud-security](mini-cloud-security/) | IAM 身份访问管理、KMS 密钥管理、WAF Web 应用防火墙、DDoS 防护、容器安全、CSPM | AWS Security, GCP Security |
| [mini-ai-security](mini-ai-security/) | 对抗性机器学习、模型逆向攻击、提示注入、数据投毒 | OWASP ML Top 10, NIST AI RMF |
| [mini-trusted-compute](mini-trusted-compute/) | TEE 可信执行环境（SGX/TDX）、远程证明、机密计算 | Intel SGX, AMD SEV-SNP |
| [mini-privacy-compute](mini-privacy-compute/) | 差分隐私、联邦学习、安全多方计算、数据匿名化 | Dwork Differential Privacy, OpenMined |
| [mini-supply-chain-sec](mini-supply-chain-sec/) | SBOM 软件物料清单、SLSA 框架、Sigstore/Cosign 签名、依赖漏洞、来源证明 | SLSA.dev, Sigstore |
| [mini-sec-governance](mini-sec-governance/) | ISO 27001 信息安全管理、SOC2、NIST CSF 网络安全框架、风险评估、合规管理 | ISO 27001, SOC2, NIST CSF |

## 设计理念

- **零外部依赖** — 纯 C（C99/C11），仅使用 `libc` 和 `libm`
- **模块自包含** — 每个目录自带 `Makefile`、`include/`、`src/`、`examples/`、`demos/`、`tests/`
- **用户态安全仿真** — 对密码学原语、区块链共识和安全攻击/防护的教学级建模
- **理论到代码的映射** — 每个模块包含 `docs/` 目录，内有论文/标准对齐说明
- **实用演示程序** — 加密货币节点、EVM 仿真器、漏洞利用/防御演示、零知识证明验证器等

## 构建方式

每个模块相互独立。进入模块目录后运行：

```bash
cd mini-crypto-basic
make all    # 构建全部
make test   # 运行测试
```

需要 **GCC** 和 **GNU Make**。

## 项目结构

```
mini-security-crypto-web3/
├── mini-crypto-basic/           # 基础密码学
├── mini-adv-crypto/             # 高级密码学
├── mini-blockchain-core/        # 区块链核心
├── mini-defi-crosschain/        # DeFi 与跨链
├── mini-smart-contract-sec/     # 智能合约安全
├── mini-web-security/           # Web 安全
├── mini-binary-security/        # 二进制安全
├── mini-cloud-security/         # 云安全
├── mini-ai-security/            # AI 安全
├── mini-trusted-compute/        # 可信计算
├── mini-privacy-compute/        # 隐私计算
├── mini-supply-chain-sec/       # 供应链安全
└── mini-sec-governance/         # 安全治理与合规
```

## 许可证

MIT
