# AI 安全指南 (AI Security Guide)

## 概述

mini-ai-security 是一个 C99 实现的 AI 安全库，涵盖五个关键领域的安全威胁和防御措施。

## 1. 对抗机器学习 (Adversarial ML)

### 威胁
- **FGSM** (Fast Gradient Sign Method): 白盒攻击，沿梯度符号方向添加微小扰动
- **PGD** (Projected Gradient Descent): 迭代式攻击，在 ε-ball 内多步优化
- **C&W Attack**: 基于优化的最小扰动攻击，支持 L0/L2/L∞ 范数
- **Adversarial Patch**: 在图像局部区域放置对抗性图案
- **Physical Attacks**: 现实世界中通过物理变换攻击（如修改路标）

### 防御
- **对抗训练 (Adversarial Training)**: 在训练中引入对抗样本
- **防御蒸馏 (Defensive Distillation)**: 使用高温度 softmax 平滑梯度
- **输入变换 (Input Transformation)**: 高斯噪声、JPEG 压缩、位深降低
- **特征压缩 (Feature Squeezing)**: 中值滤波、比特压缩
- **集成防御 (Ensemble)**: 多模型投票

## 2. 模型逆向与隐私 (Model Inversion & Privacy)

### 威胁
- **模型逆向 (Model Inversion)**: 从模型输出重建训练数据
- **成员推理 (Membership Inference)**: 判断某样本是否在训练集中
- **属性推理 (Attribute Inference)**: 从模型输出推断敏感属性
- **模型萃取 (Model Extraction)**: 通过查询复制模型功能
- **梯度泄露 (Gradient Leakage)**: 联邦学习中从梯度重建数据

### 防御
- **DP-SGD**: 差分隐私随机梯度下降
- **高斯机制 (Gaussian Mechanism)**: 添加高斯噪声
- **拉普拉斯机制 (Laplace Mechanism)**: 添加拉普拉斯噪声
- **梯度裁剪 (Gradient Clipping)**: 限制梯度范数
- **PATE**: 教师集成隐私聚合
- **隐私预算审计 (Privacy Budget Audit)**

## 3. LLM 提示注入安全 (Prompt Injection for LLMs)

### 威胁
- **直接注入 (Direct Injection)**: 覆盖系统提示词
- **间接注入 (Indirect Injection)**: 通过外部数据注入指令
- **越狱 (Jailbreak)**: 绕过安全限制
- **提示泄露 (Prompt Leaking)**: 提取系统提示词
- **数据泄露 (Data Exfiltration)**: 通过提示提取敏感信息
- **编码绕过 (Encoding Bypass)**: 使用编码混淆绕过检测
- **上下文溢出 (Context Overflow)**: 利用超长上下文

### 防御
- **指令层级 (Instruction Hierarchy)**: 系统提示 > 用户输入
- **输出过滤 (Output Filtering)**: 检测并过滤危险输出
- **约束检查 (Constraint Checking)**: 验证输出不违反约束
- **Guard Model**: 独立安全模型评估输入/输出
- **RLHF Safety Alignment**: 基于人类反馈的安全对齐
- **Sandwich Defense**: 系统提示包裹用户输入
- **Perplexity Check**: 检测异常文本复杂度

## 4. 数据投毒 (Data Poisoning)

### 威胁
- **后门注入 (Backdoor Injection)**: 插入触发模式映射到目标标签
- **Clean-label Poisoning**: 保持标签正确的特征空间投毒
- **可用性攻击 (Availability Attack)**: 降低模型整体性能
- **标签翻转 (Label Flipping)**: 随机或目标性翻转标签
- **联邦学习恶意客户端**: 上传恶意梯度更新

### 防御
- **数据清洗 (Data Sanitization)**: 异常检测移除可疑样本
- **鲁棒训练 (Robust Training)**: 裁剪梯度、修剪损失
- **异常检测 (Anomaly Detection)**: 基于离群分数检测
- **差分隐私 (Differential Privacy)**: 限制单个样本影响
- **谱签名防御 (Spectral Signature)**: 分析特征空间
- **KNN 过滤 (KNN Filter)**: 基于近邻一致性清洗
- **拜占庭容错聚合**: 抵抗恶意客户端

## 5. AI 治理 (AI Governance)

### 模型卡 (Model Cards)
记录模型用途、局限性、评估指标、伦理考量等信息。

### 偏差检测 (Bias Detection)
- **人口均等 (Demographic Parity)**: 不同群体正预测率相等
- **均等化赔率 (Equalized Odds)**: 不同群体 TPR 和 FPR 相等
- **均等机会 (Equal Opportunity)**: 不同群体 TPR 相等
- **差异影响 (Disparate Impact)**: 有利结果率的比率
- **校准 (Calibration)**: 预测概率与实际结果一致
- **个体公平 (Individual Fairness)**: 相似个体获得相似预测

### 可解释性 (Explainability)
- **SHAP**: Shapley 加法解释
- **LIME**: 局部可解释模型无关解释
- **Integrated Gradients**: 积分梯度
- **Saliency Map**: 显著性图
- **Permutation Importance**: 排列重要性

### AI 审计 (AI Audit)
- **红队测试 (Red Teaming)**: 对抗性测试
- **安全评估 (Safety Evaluation)**: 危险性内容检测
- **失败模式分析 (Failure Mode Analysis)**: 边缘案例测试
- **鲁棒性审计 (Robustness Audit)**: 扰动稳定性
- **公平性审计 (Fairness Audit)**: 多维度公平评估

### 内容安全 (Content Safety)
检测和过滤仇恨言论、暴力、色情、自残、骚扰、虚假信息等内容。

### 模型溯源 (Model Provenance)
验证模型哈希、训练数据版本、代码版本等溯源信息。

### 负责任 AI 原则 (Responsible AI)
- 透明性、可解释性、公平性、隐私保护、安全性、问责制

## 参考

- Goodfellow et al., "Explaining and Harnessing Adversarial Examples", 2015
- Madry et al., "Towards Deep Learning Models Resistant to Adversarial Attacks", 2018
- Carlini & Wagner, "Towards Evaluating the Robustness of Neural Networks", 2017
- Shokri et al., "Membership Inference Attacks Against Machine Learning Models", 2017
- Fredrikson et al., "Model Inversion Attacks that Exploit Confidence Information", 2015
- Dwork et al., "The Algorithmic Foundations of Differential Privacy", 2014
- Perez et al., "Ignore Previous Prompt: Attack Techniques For Language Models", 2022
- Gu et al., "BadNets: Identifying Vulnerabilities in the Machine Learning Model Supply Chain", 2017
- Papernot et al., "Distillation as a Defense to Adversarial Perturbations", 2016
- Mitchell et al., "Model Cards for Model Reporting", 2019
- Lundberg & Lee, "A Unified Approach to Interpreting Model Predictions", 2017 (SHAP)
- Ribeiro et al., "Why Should I Trust You?", 2016 (LIME)
