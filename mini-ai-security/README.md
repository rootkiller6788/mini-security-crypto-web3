# mini-ai-security — AI安全 (C 语言实现)

C99 实现的 AI 安全库，涵盖对抗机器学习、模型逆向、提示注入、数据投毒和 AI 治理五大领域。

## 目录结构

```
mini-ai-security/
├── include/
│   ├── adversarial_ml.h     # 对抗机器学习
│   ├── model_inversion.h    # 模型逆向与隐私
│   ├── prompt_injection.h   # LLM 提示注入安全
│   ├── data_poison.h        # 数据投毒攻击与防御
│   └── ai_governance.h      # AI 治理与公平性
├── src/
│   ├── adversarial_ml.c
│   ├── model_inversion.c
│   ├── prompt_injection.c
│   ├── data_poison.c
│   └── ai_governance.c
├── examples/
│   ├── example_adversarial.c
│   ├── example_inversion.c
│   └── example_governance.c
├── demos/
│   ├── demo_adversarial_training.c
│   └── demo_data_poison.c
├── docs/
│   ├── ai_security_guide.md
│   └── api_reference.md
├── Makefile
└── README.md
```

## 构建

```sh
make all          # 构建所有库和示例
make lib          # 仅构建静态库 libai_security.a
make examples     # 构建示例程序
make demos        # 构建演示程序
make clean        # 清理构建产物
gcc -std=c99 -Wall -Wextra -pedantic ...
```

## 模块说明

| 模块 | 功能 |
|------|------|
| **adversarial_ml** | FGSM/PGD/CW 攻击, adversarial patch, 物理攻击, 对抗训练, 防御蒸馏, 输入变换 |
| **model_inversion** | 模型逆向, 成员推理(MIA), 属性推理, 差分隐私(DP-SGD), 模型萃取, 联邦学习梯度泄露 |
| **prompt_injection** | 直接/间接注入, jailbreak, prompt leaking, 防护: 指令层级, 输出过滤, Guard Model, RLHF |
| **data_poison** | 后门注入, clean-label 投毒, 可用性攻击, 数据清洗, 鲁棒训练, 异常检测, FL 恶意客户端 |
| **ai_governance** | 模型卡, 偏差检测(人口均等/均等化赔率), SHAP/LIME 可解释性, 红队审计, 内容安全, 模型溯源 |

## 许可证

MIT License
