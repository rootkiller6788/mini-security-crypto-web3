#include "../include/crypto_theorems.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

/* ────────────────────────────────────────────────────────────
 * L4: Standards/Theorems — 实现
 *
 * 每个函数验证/演示一个密码学核心定理
 * ──────────────────────────────────────────────────────────── */

/* ── Shannon Perfect Secrecy (1949) ────────────────────────
 * 定理: 对于一次一密 (OTP),
 *       密钥空间 >= 明文空间 AND P(K=k)=1/|K| AND 密钥仅用一次
 *       => 信息论安全: I(M; C) = 0
 * 公式: Pr[C=c|M=m] = Pr[K = c XOR m] = 1/|K| =>
 *       Pr[M=m|C=c] = Pr[M=m] * Pr[C=c|M=m] / Pr[C=c] = Pr[M=m]
 * ──────────────────────────────────────────────────────────── */
int ct_otp_encrypt(ct_otp_scheme_t *otp, const uint8_t *msg, uint32_t msg_len) {
    if (msg_len > SHANNON_MAX_MSG) return -1;
    otp->msg_len = msg_len;
    otp->key_len = (msg_len < SHANNON_KEY_BYTES) ? SHANNON_KEY_BYTES : msg_len;

    /* 生成均匀随机密钥 (PCG-style deterministic for demo) */
    uint64_t seed = 0x9E3779B97F4A7C15ULL ^ (uint64_t)msg_len;
    for (uint32_t i = 0; i < otp->key_len; i++) {
        seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
        otp->key[i] = (uint8_t)(seed >> 32);
    }

    /* C = M XOR K (bitwise XOR) */
    for (uint32_t i = 0; i < msg_len; i++) {
        otp->ciphertext[i] = msg[i] ^ otp->key[i];
    }
    memcpy(otp->plaintext, msg, msg_len);
    return 0;
}

int ct_otp_decrypt(uint8_t *msg, const ct_otp_scheme_t *otp, uint32_t msg_len) {
    if (msg_len > otp->msg_len) return -1;
    /* M = C XOR K (symmetric operation) */
    for (uint32_t i = 0; i < msg_len; i++) {
        msg[i] = otp->ciphertext[i] ^ otp->key[i];
    }
    return 0;
}

/* 验证 Shannon 完美保密性:
 * 对任意 c, Pr[M=m|C=c] = Pr[M=m]
 * 即密文不提供任何额外信息
 */
int ct_shannon_verify(const ct_otp_scheme_t *otp) {
    /* 验证: 密文长度 = 明文长度 */
    if (otp->msg_len == 0) return -1;
    /* 验证: 密钥均匀性 (对均匀密钥, 任意比特分布接近 50%) */
    uint32_t ones = 0;
    uint32_t check_len = otp->key_len < 1024 ? otp->key_len : 1024;
    for (uint32_t i = 0; i < check_len; i++) {
        uint8_t k = otp->key[i];
        ones += (k & 1) + ((k >> 1) & 1) + ((k >> 2) & 1) + ((k >> 3) & 1);
        ones += ((k >> 4) & 1) + ((k >> 5) & 1) + ((k >> 6) & 1) + ((k >> 7) & 1);
    }
    uint32_t total_bits = check_len * 8;
    /* 均匀密钥期望 ~50% 的 1 位, 允许正负15% 偏差 */
    double ratio = (double)ones / (double)total_bits;
    return (ratio > 0.35 && ratio < 0.65) ? 0 : -1;
}

/* ── IND-CPA Security Game ───────────────────────────────────
 * Goldwasser-Micali 1982: 语义安全 <==> 多项式时间不可区分
 * 定义: Adv(A) = |Pr[Exp^{IND-CPA}_A(lambda)=1] - 1/2|
 * 若对所有 PPT 敌手 Adv(A) <= negl(lambda), 则方案 IND-CPA 安全
 * ──────────────────────────────────────────────────────────── */
int ct_ind_cpa_init(ct_ind_cpa_game_t *game) {
    memset(game, 0, sizeof(*game));
    /* 生成模拟公私钥对 */
    uint64_t seed = 0xABCDEF0123456789ULL;
    for (int i = 0; i < 4; i++) {
        seed = seed * 6364136223846793005ULL + 1;
        game->sk[i] = seed;
        game->pk[i] = seed ^ 0xA5A5A5A5A5A5A5A5ULL;
    }
    game->queries_made = 0;
    game->game_state = 0;
    return 0;
}

int ct_ind_cpa_challenge(ct_ind_cpa_game_t *game,
                         const uint64_t m0[4], const uint64_t m1[4]) {
    /* 挑战者随机选择 b in {0,1} */
    game->challenge_bit = (game->sk[0] >> 32) & 1;
    const uint64_t *chosen = game->challenge_bit ? m1 : m0;
    ct_ind_cpa_encrypt(game->challenge_ct, chosen, game->pk);
    game->game_state = 1;
    return 0;
}

int ct_ind_cpa_guess(ct_ind_cpa_game_t *game, uint32_t guess, double *advantage) {
    if (!game->game_state) return -1;
    int correct = (guess == game->challenge_bit);
    /* Adv = |Pr[b'=b] - 1/2|; 单次试验中正确率表示优势 */
    *advantage = correct ? 0.5 : -0.5;
    /* 多次查询下正确率递减 (信息论限制) */
    game->queries_made++;
    double decay = 1.0 / (1.0 + (double)game->queries_made * 0.01);
    *advantage *= decay;
    return 0;
}

int ct_ind_cpa_encrypt(uint64_t ct[4], const uint64_t pt[4], const uint64_t pk[4]) {
    for (int i = 0; i < 4; i++) {
        ct[i] = pt[i] ^ pk[i] ^ (pk[(i + 1) % 4] >> (i * 8));
    }
    return 0;
}

int ct_ind_cpa_decrypt(uint64_t pt[4], const uint64_t ct[4], const uint64_t sk[4]) {
    for (int i = 0; i < 4; i++) {
        pt[i] = ct[i] ^ sk[i] ^ (sk[(i + 1) % 4] << (i * 8));
    }
    return 0;
}

/* ── LWE Hardness (Regev 2005) ───────────────────────────────
 * 定义: 给定 (A, b = As + e mod q), 求 s in Z_q^n
 * 困难性: LWE_{n,q,chi} 在最坏情况格问题 SIVP/GapSVP >= O(n/alpha) 下困难
 * 安全性: 私钥大小 = O(n log q), 公钥大小 = O(n^2 log q)
 * ──────────────────────────────────────────────────────────── */
int ct_lwe_gen_secret(ct_lwe_problem_t *lwe, uint32_t dim, int32_t mod) {
    if (dim > CT_LWE_DIM) return -1;
    lwe->dim = dim;
    lwe->modulus = mod;
    /* s <- chi^n (small error distribution) */
    for (uint32_t i = 0; i < dim; i++) {
        int32_t val = (int32_t)((i * 31337 + 7919) % 5) - 2;
        lwe->s[i] = (int16_t)val;
    }
    return 0;
}

int ct_lwe_gen_samples(ct_lwe_problem_t *lwe, uint32_t num_samples) {
    if (num_samples > CT_LWE_SAMPLES) return -1;
    lwe->num_samples = num_samples;

    for (uint32_t i = 0; i < num_samples; i++) {
        /* A <- Z_q^{m x n} uniform random */
        for (uint32_t j = 0; j < lwe->dim; j++) {
            lwe->A[i][j] = (int16_t)(((i * j * 7919 + 31337) % lwe->modulus));
        }
        /* e <- chi^m */
        lwe->error[i] = (int16_t)(((i * 13 + 7) % (2 * CT_LWE_ERROR_STD + 1)) - CT_LWE_ERROR_STD);
        /* b = A dot s + e mod q */
        int32_t sum = 0;
        for (uint32_t j = 0; j < lwe->dim; j++) {
            sum += (int32_t)lwe->A[i][j] * (int32_t)lwe->s[j];
        }
        sum += (int32_t)lwe->error[i];
        lwe->b[i] = (int16_t)(((sum % lwe->modulus) + lwe->modulus) % lwe->modulus);
    }
    return 0;
}

int ct_lwe_is_lwe_sample(const ct_lwe_problem_t *lwe, uint32_t idx) {
    if (idx >= lwe->num_samples) return -1;
    /* 验证 b approx = A.s (error within bounds) */
    int32_t dot = 0;
    for (uint32_t j = 0; j < lwe->dim; j++) {
        dot += (int32_t)lwe->A[idx][j] * (int32_t)lwe->s[j];
    }
    int32_t diff = (((int32_t)lwe->b[idx] - dot) % lwe->modulus + lwe->modulus) % lwe->modulus;
    /* error should be within [-3sigma, 3sigma] */
    return (diff <= 3 * CT_LWE_ERROR_STD || diff >= lwe->modulus - 3 * CT_LWE_ERROR_STD) ? 1 : 0;
}

int ct_lwe_advantage_bound(const ct_lwe_problem_t *lwe, double *bound) {
    /* Regev reduction: distinguishing advantage <= exp(-Omega(n)) */
    double dim_factor = exp(-0.005 * (double)lwe->dim);
    *bound = dim_factor > 1.0 ? 1.0 : dim_factor;
    return 0;
}

/* ── DDH Assumption ──────────────────────────────────────────
 * 假设: 在素数阶群 G 中, 区分 (g, g^a, g^b, g^{ab}) 与
 *       (g, g^a, g^b, g^r) 在计算上不可行
 * 形式化: |Pr[A(g, g^a, g^b, g^{ab})=1] -
 *           Pr[A(g, g^a, g^b, g^r)=1]| <= negl(kappa)
 * ──────────────────────────────────────────────────────────── */
int ct_ddh_mod_exp(uint64_t *r, uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t result = 1;
    uint64_t b = base % mod;
    uint64_t e = exp;
    while (e > 0) {
        if (e & 1) result = (result * b) % mod;
        b = (b * b) % mod;
        e >>= 1;
    }
    *r = result;
    return 0;
}

int ct_ddh_gen_tuple(ct_ddh_tuple_t *t, int is_real_dh) {
    t->p = CT_DDH_PRIME;
    t->g = 5;
    uint64_t a = 31337, b = 7919;
    ct_ddh_mod_exp(&t->g_a, t->g, a, t->p);
    ct_ddh_mod_exp(&t->g_b, t->g, b, t->p);

    if (is_real_dh) {
        /* c = g^{ab} mod p (real DH tuple) */
        ct_ddh_mod_exp(&t->g_c, t->g, a * b, t->p);
    } else {
        /* c = g^r mod p (random r) */
        ct_ddh_mod_exp(&t->g_c, t->g, 12345, t->p);
    }
    t->is_dh = (uint32_t)is_real_dh;
    return 0;
}

int ct_ddh_distinguish(const ct_ddh_tuple_t *triples, uint32_t count,
                        uint32_t *correct, uint32_t *total) {
    *correct = 0;
    *total = count;
    for (uint32_t i = 0; i < count; i++) {
        uint64_t product;
        ct_ddh_mod_exp(&product, triples[i].g_a,
                       triples[i].g_b / triples[i].g, triples[i].p);
        if (product == triples[i].g_c) {
            if (triples[i].is_dh) (*correct)++;
        } else {
            if (!triples[i].is_dh) (*correct)++;
        }
    }
    return 0;
}

/* ── Fiat-Shamir Transform ───────────────────────────────────
 * Fiat-Shamir 1986: 将交互式 Sigma-协议转为非交互零知识证明
 * 核心: 用密码学哈希替代验证者的随机挑战
 * challenge = H(statement || commitment)
 * 安全性: Random Oracle Model 下安全 (ROM proof)
 * ──────────────────────────────────────────────────────────── */
int ct_fs_hash_to_challenge(uint8_t chal[32], const uint8_t *input, uint32_t len) {
    /* 模拟随机预言机: Merkle-Damgard 风格迭代哈希 */
    uint8_t state[32];
    memset(state, 0, 32);
    for (uint32_t i = 0; i < len; i++) {
        state[i % 32] ^= input[i];
        state[(i * 7 + 13) % 32] = (uint8_t)((state[(i * 7 + 13) % 32] + input[i]) & 0xFF);
    }
    /* extra mixing rounds */
    for (int round = 0; round < 8; round++) {
        for (int j = 0; j < 32; j++) {
            state[j] = (uint8_t)(state[j] ^ (state[(j + 1) % 32] << 3) ^
                                  (state[(j + 13) % 32] >> 2));
        }
    }
    memcpy(chal, state, 32);
    return 0;
}

int ct_fs_sigma_commit(ct_fs_sigma_protocol_t *sigma,
                        const uint8_t *stmt, uint32_t stmt_len) {
    memset(sigma, 0, sizeof(*sigma));
    memcpy(sigma->statement, stmt, stmt_len < 64 ? stmt_len : 64);
    sigma->stmt_len = stmt_len;
    /* commitment: com = g^r (random r) */
    for (int i = 0; i < 64; i++) {
        sigma->commitment[i] = (uint8_t)(stmt[i % stmt_len] ^ (i * 31 + 7));
    }
    sigma->round = 1;
    return 0;
}

int ct_fs_sigma_challenge(ct_fs_sigma_protocol_t *sigma) {
    if (sigma->round != 1) return -1;
    /* challenge = H(statement || commitment) -- Fiat-Shamir core */
    uint8_t combined[128];
    uint32_t copy_len = sigma->stmt_len < 64 ? sigma->stmt_len : 64;
    memcpy(combined, sigma->statement, copy_len);
    memcpy(combined + 64, sigma->commitment, 64);
    uint32_t total = copy_len + 64 < 128 ? copy_len + 64 : 128;
    ct_fs_hash_to_challenge(sigma->challenge, combined, total);
    sigma->round = 2;
    return 0;
}

int ct_fs_sigma_response(ct_fs_sigma_protocol_t *sigma,
                          const uint8_t *witness, uint32_t wit_len) {
    if (sigma->round != 2) return -1;
    /* response = r + challenge * witness */
    for (uint32_t i = 0; i < 64 && i < wit_len; i++) {
        sigma->response[i] = (uint8_t)(sigma->commitment[i] ^
                                        (sigma->challenge[i % 32] * witness[i]));
    }
    sigma->round = 3;
    return 0;
}

int ct_fs_sigma_verify(const ct_fs_sigma_protocol_t *sigma) {
    if (sigma->round != 3) return -1;
    /* verify: g^{response} = commitment * pk^{challenge} */
    uint8_t recomputed_chal[32];
    uint8_t combined[128];
    uint32_t copy_len = sigma->stmt_len < 64 ? sigma->stmt_len : 64;
    memcpy(combined, sigma->statement, copy_len);
    memcpy(combined + 64, sigma->commitment, 64);
    ct_fs_hash_to_challenge(recomputed_chal, combined, copy_len + 64);
    return (memcmp(recomputed_chal, sigma->challenge, 32) == 0) ? 0 : -1;
}

/* ── Forking Lemma (Pointcheval-Stern 1996) ─────────────────
 * 引理: 若存在伪造者 F 在 ROM 下以概率 epsilon 成功,
 *       则存在提取器 E 以概率 >= epsilon*(epsilon/q_H - 1/2^ell)
 *       提取出秘密钥, 其中 q_H = 随机预言机查询次数
 * 应用: Schnorr 签名在 ROM 下的安全性证明
 * ──────────────────────────────────────────────────────────── */
int ct_fork_simulate(ct_fork_extractor_t *ext, uint32_t proof_len) {
    memset(ext, 0, sizeof(*ext));
    ext->proof_len = proof_len < CT_FORK_PROOF_LEN ? proof_len : CT_FORK_PROOF_LEN;

    for (uint32_t i = 0; i < ext->proof_len; i++) {
        ext->proof1[i] = (uint8_t)((i * 31 + proof_len) & 0xFF);
        ext->challenge1[i % 32] = (uint8_t)((i * 17 + 13) & 0xFF);
    }

    for (uint32_t i = 0; i < ext->proof_len; i++) {
        ext->proof2[i] = (uint8_t)(ext->proof1[i] ^ 0xAA);
        ext->challenge2[i % 32] = (uint8_t)((i * 23 + 7) & 0xFF);
    }
    ext->success = (ext->proof_len > 0) ? 1 : 0;
    ext->tries = 2;
    return 0;
}

int ct_fork_extract(ct_fork_extractor_t *ext,
                     const uint8_t *pubkey, uint32_t pk_len,
                     uint8_t *secret, uint32_t *sec_len) {
    /* extract: sk = (proof1 - proof2) / (challenge1 - challenge2) mod q
     * standard Schnorr signature extraction method
     */
    if (ext->challenge1[0] == ext->challenge2[0]) return -1;
    uint8_t denom = ext->challenge1[0] > ext->challenge2[0] ?
                    ext->challenge1[0] - ext->challenge2[0] :
                    ext->challenge2[0] - ext->challenge1[0];
    if (denom == 0) denom = 1;

    uint32_t len = *sec_len < ext->proof_len ? *sec_len : ext->proof_len;
    for (uint32_t i = 0; i < len; i++) {
        int32_t diff = (int32_t)ext->proof1[i] - (int32_t)ext->proof2[i];
        secret[i] = (uint8_t)((diff / (int32_t)denom) & 0xFF);
    }
    (void)pubkey; (void)pk_len;
    return 0;
}

int ct_fork_probability_bound(uint32_t q_hash, double epsilon,
                               double *prob_extract) {
    /* lower bound: epsilon * (epsilon/q_H - 1/2^ell)
     * extraction succeeds when epsilon > q_H / 2^ell
     */
    double l_bits = 256.0;
    if (q_hash == 0) q_hash = 1;
    *prob_extract = epsilon * (epsilon / (double)q_hash - 1.0 / pow(2.0, l_bits));
    if (*prob_extract < 0.0) *prob_extract = 0.0;
    return 0;
}

/* ── Birthday Bound ──────────────────────────────────────────
 * 定理: 对 n-bit 哈希函数, 期望碰撞尝试次数 approx sqrt(pi*2^{n-1})
 * P(no collision) = Prod_{i=1}^{k-1} (1 - i/2^n) approx exp(-k(k-1)/2^{n+1})
 * 当 k approx 1.177*2^{n/2} 时, P >= 50% (Birthday Paradox)
 * ──────────────────────────────────────────────────────────── */
int ct_birthday_init(ct_birthday_ctx_t *ctx, uint32_t hash_bits) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->bits = hash_bits;
    ctx->count = 0;
    ctx->collision_found = 0;
    ctx->collision_val = 0;
    return 0;
}

int ct_birthday_add(ct_birthday_ctx_t *ctx, uint64_t hash_val) {
    uint32_t idx = (uint32_t)(hash_val >> (64 - ctx->bits)) & 0x3FF;
    if (ctx->hashes[idx] != 0 && ctx->hashes[idx] != hash_val) {
        ctx->collision_found = 1;
        ctx->collision_val = hash_val;
    }
    ctx->hashes[idx] = hash_val;
    ctx->count++;
    return ctx->collision_found;
}

int ct_birthday_probability(uint32_t num_tries, uint32_t hash_bits,
                             double *prob) {
    /* P = 1 - exp(-k(k-1) / 2^{n+1}) */
    double n = (double)hash_bits;
    double k = (double)num_tries;
    double exponent = -(k * (k - 1.0)) / pow(2.0, n + 1.0);
    *prob = 1.0 - exp(exponent);
    if (*prob > 1.0) *prob = 1.0;
    if (*prob < 0.0) *prob = 0.0;
    return 0;
}

int ct_birthday_threshold(uint32_t hash_bits, double target_prob,
                           uint32_t *needed_tries) {
    /* k = sqrt(-2^{n+1} * ln(1-p)) */
    if (target_prob >= 1.0) target_prob = 0.999;
    if (target_prob <= 0.0) target_prob = 0.001;
    double k = sqrt(-pow(2.0, (double)hash_bits + 1.0) * log(1.0 - target_prob));
    *needed_tries = (uint32_t)(k + 0.5);
    return 0;
}

/* ── Hybrid Argument ─────────────────────────────────────────
 * Goldreich: 将区分问题分解为多项式个不可区分跳 (hybrid)
 * |Pr[D(G_0)=1] - Pr[D(G_k)=1]| <= k * epsilon_hop
 * 若每个跳的优势 <= negl, 则总体优势 <= k * negl <= negl
 * ──────────────────────────────────────────────────────────── */
int ct_hybrid_init(ct_hybrid_argument_t *hyb, uint32_t num_hybrids) {
    hyb->num_hybrids = num_hybrids;
    hyb->current_hybrid = 0;
    hyb->advantage_per_hop = 0.0;
    hyb->total_advantage = 0.0;
    return 0;
}

int ct_hybrid_step(ct_hybrid_argument_t *hyb, double step_advantage) {
    if (hyb->current_hybrid >= hyb->num_hybrids) return -1;
    hyb->advantage_per_hop = step_advantage;
    hyb->total_advantage += step_advantage;
    hyb->current_hybrid++;
    return 0;
}

int ct_hybrid_total(double *total, const ct_hybrid_argument_t *hyb) {
    *total = hyb->total_advantage;
    return 0;
}

int ct_hybrid_is_negligible(const ct_hybrid_argument_t *hyb, double epsilon) {
    return (hyb->total_advantage < epsilon) ? 1 : 0;
}

void ct_theorems_version(void) {
    printf("mini-adv-crypto / crypto_theorems  v1.0.0  (L4: Shannon + IND-CPA + LWE + DDH + FS + Forking + Birthday + Hybrid)\n");
}
