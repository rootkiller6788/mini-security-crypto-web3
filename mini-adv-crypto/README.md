# mini-adv-crypto — 高级密码学 (C 语言实现)

![C99](https://img.shields.io/badge/C-C99-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**mini-adv-crypto** 是一个轻量级、纯 C99 实现的高级密码学原语库，涵盖零知识证明、同态加密、安全多方计算、后量子密码学和门限签名五大核心领域。

---

## 模块概览

| 模块 | 头文件 | 核心功能 |
|------|--------|----------|
| **零知识证明** | `zk_proof.h` | R1CS 约束系统、QAP 多项式、Groth16/Pinocchio 协议、zk-STARK 基础 |
| **同态加密** | `homomorphic_enc.h` | Paillier 加法同态、BFV 全同态加密、密文运算与噪声管理 |
| **安全多方计算** | `mpc_proto.h` | Shamir 秘密共享、Yao 混淆电路、不经意传输 (OT)、SPDZ 协议 |
| **后量子密码** | `post_quantum.h` | Kyber KEM、Dilithium 签名、SPHINCS+、Module-LWE/LWR |
| **门限签名** | `threshold_sig.h` | Shamir 门限签名、FROST 协议、DKG 分布式密钥生成、主动安全刷新 |

---

## 快速开始

### 编译

```bash
make all
```

### 运行示例

```bash
make examples    # 编译所有示例
make run_zk      # 零知识证明演示
make run_he      # 同态加密演示
make run_mpc     # 安全多方计算演示
```

### 运行完整演示

```bash
make demos       # 编译所有演示
make run_full    # 全功能演示 (demo_full)
make run_bench   # 性能基准测试 (demo_bench)
```

### 运行测试

```bash
make test        # 编译并运行测试
make clean       # 清理构建文件
```

---

## 使用示例

### 零知识证明 (Groth16)

```c
#include "zk_proof.h"

int main(void) {
    zk_r1cs_t r1cs;
    zk_r1cs_init(&r1cs, 3, 2);

    int32_t a[] = {0, 1, 0, 0};
    int32_t b[] = {0, 0, 1, 0};
    int32_t c[] = {0, 0, 0, 1};
    zk_r1cs_add_constraint(&r1cs, 0, a, b, c);

    zk_proving_key_t pk;
    zk_verification_key_t vk;
    zk_setup_info_t info = {3, 1, {{0}}};
    zk_trusted_setup(&pk, &vk, &r1cs, &info);

    int32_t witness[] = {1, 3, 4, 12};
    zk_groth16_proof_t proof;
    zk_groth16_prove(&proof, &pk, witness, 1);

    int32_t pub[] = {12};
    int ret = zk_groth16_verify(&proof, &vk, pub, 1);
    printf("Verification: %s\n", ret ? "PASS" : "FAIL");

    return 0;
}
```

### 同态加密 (Paillier)

```c
#include "homomorphic_enc.h"

int main(void) {
    he_paillier_pub_t pub;
    he_paillier_prv_t prv;
    he_paillier_keygen(&pub, &prv, 512);

    he_bigint_t a, b;
    he_bigint_set_u64(&a, 15);
    he_bigint_set_u64(&b, 25);

    he_paillier_ct_t ca, cb, cr;
    he_paillier_encrypt(&ca, &a, &pub);
    he_paillier_encrypt(&cb, &b, &pub);
    he_paillier_add(&cr, &ca, &cb, &pub);

    he_bigint_t res;
    he_paillier_decrypt(&res, &cr, &prv);
    printf("15 + 25 = "); he_bigint_print("", &res);

    return 0;
}
```

### 安全多方计算

```c
#include "mpc_proto.h"

int main(void) {
    int64_t inputs[] = {10, 20, 30, 40, 50};
    int64_t result;
    mpc_multi_party_sum(&result, inputs, 5);
    printf("Sum (MPC): %lld\n", (long long)result);

    mpc_shamir_ctx_t ctx;
    mpc_shamir_split(&ctx, 12345, 3, 5);

    uint32_t indices[] = {0, 2, 4};
    int64_t secret;
    mpc_shamir_reconstruct(&secret, &ctx, indices, 3);
    printf("Recovered: %lld\n", (long long)secret);

    return 0;
}
```

---

## 项目结构

```
mini-adv-crypto/
├── README.md              # 本文件
├── Makefile               # 构建系统
├── zk_proof.h / .c        # 零知识证明模块
├── homomorphic_enc.h / .c # 同态加密模块
├── mpc_proto.h / .c       # 安全多方计算模块
├── post_quantum.h / .c    # 后量子密码模块
├── threshold_sig.h / .c   # 门限签名模块
├── example_zk.c           # ZK 示例
├── example_he.c           # 同态加密示例
├── example_mpc.c          # MPC 示例
├── demo_full.c            # 全功能演示
├── demo_bench.c           # 性能基准
├── doc_api.md             # API 参考
└── doc_design.md          # 设计文档
```

---

## 设计原则

- **纯 C99**：无外部依赖，可在嵌入式平台运行
- **教学导向**：每个算法附带注释说明原理
- **模块化**：每个头文件独立，不交叉引用
- **可审计**：代码清晰，便于安全审计

## 安全提示

本库为**教学演示**用途，未经过正式安全审计。生产环境请使用经过认证的密码学库。

## License

MIT
