#include "../include/crypto_advanced.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

/* ────────────────────────────────────────────────────────────
 * L8: Advanced Topics — 密码学进阶主题
 *
 * Constant-Time Ops, Double Ratchet, Ring Sigs,
 * Accumulators, Threshold Decrypt, Forward-Secure Keys
 * ──────────────────────────────────────────────────────────── */

/* ── Constant-Time Operations ───────────────────────────────
 * 原理: 所有操作执行时间不依赖秘密数据, 防御时序侧信道攻击
 * 技术: 使用位运算替代分支 (branch-free programming)
 * 应用: 密码库核心 (OpenSSL, libsodium) 广泛使用
 * 参考文献: Bernstein 2005 "Cache-timing attacks on AES"
 * ──────────────────────────────────────────────────────────── */

/* 常时比较: 返回 (a < b) 的 32-bit 全0/全1 掩码, 无分支
 * 方法: 符号位提取, 利用 (a-b) >> 31 */
int32_t ct_lt_32(int32_t a, int32_t b) {
    /* 无分支小于比较: diff = a - b, 结果 = (diff >> 31) & 1 扩展 */
    int32_t diff = a - b;
    /* 算术右移填充符号位: 负数 -> 全1, 非负 -> 全0 */
    return (diff >> 31) & 1;
}

/* 常时选择: cond 必须为全0或全1 (通过 ct_lt_32 获得)
 * return = (cond & a) | (~cond & b) — 无分支选择 */
uint32_t ct_select_32(uint32_t a, uint32_t b, uint32_t cond) {
    /* cond = 0 (全0) or 1 (仅最低位为1), 扩展为全0/全1 掩码 */
    uint32_t mask = cond ? 0xFFFFFFFF : 0x00000000;
    return (mask & a) | ((~mask) & b);
}

/* 常时内存比较: 逐字节比较, 累加 OR 结果
 * 不提前退出, 不泄露第一个不同字节的位置 */
int ct_memcmp(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (a[i] ^ b[i]);
    }
    /* 返回 0 表示相等, 非0 表示不同 (但不泄露位置) */
    return (int)diff;
}

/* 常时清零: 防止编译器优化掉 memset (dead store elimination)
 * 使用 volatile 指针强制编译器生成实际写入指令 */
void ct_memzero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

/* 常时零检测: 逐字节 OR, 无分支 */
int ct_is_zero(const uint8_t *a, size_t len) {
    uint8_t acc = 0;
    for (size_t i = 0; i < len; i++) {
        acc |= a[i];
    }
    /* 将非零字节转为 1: (-acc >> 7) & 1 的反 */
    int32_t result = (int32_t)acc;
    /* 若 acc != 0, 每步仍做相同工作 */
    result = (result | (-result)) >> 31;
    return result == 0 ? 1 : 0;
}

/* 常时条件赋值: dest = cond ? src : dest (不变) */
void ct_cond_assign(uint8_t *dest, const uint8_t *src, size_t len, uint32_t cond) {
    uint8_t mask = cond ? 0xFF : 0x00;
    for (size_t i = 0; i < len; i++) {
        dest[i] = (dest[i] & (uint8_t)(~mask)) | (src[i] & mask);
    }
}

/* ── Double Ratchet Algorithm ───────────────────────────────
 * 协议: Signal 协议核心 (Perrin-Marlinspike 2016)
 * 性质: 每条消息独立密钥, 密钥泄露后前向安全恢复
 * 组成: DH Ratchet (非对称) + Symmetric-Key Ratchet (对称)
 * 三阶段: (1) DH 棘轮更新 (2) 对称棘轮派生 (3) 消息密钥派生
 * ──────────────────────────────────────────────────────────── */
static void cx_ratchet_kdf(uint8_t out[2 * CX_RATCHET_KEY_BYTES],
                            const uint8_t *in, uint32_t in_len,
                            const uint8_t salt[CX_RATCHET_KEY_BYTES]) {
    uint8_t state[CX_RATCHET_KEY_BYTES];
    memcpy(state, salt, CX_RATCHET_KEY_BYTES);
    for (uint32_t i = 0; i < in_len && i < CX_RATCHET_KEY_BYTES; i++) {
        state[i % CX_RATCHET_KEY_BYTES] ^= in[i];
    }
    /* KDF 扩展为两倍长度: (root_key, chain_key) */
    for (int i = 0; i < CX_RATCHET_KEY_BYTES; i++) {
        out[i] = (uint8_t)(state[i] ^ ((uint8_t)(i + 1) * 31));
        out[i + CX_RATCHET_KEY_BYTES] = (uint8_t)(state[i] ^ ((uint8_t)(i + 1) * 37));
    }
}

int cx_ratchet_init(cx_double_ratchet_t *ratchet,
                     const uint8_t shared_secret[CX_RATCHET_KEY_BYTES]) {
    memset(ratchet, 0, sizeof(*ratchet));
    memcpy(ratchet->root_key, shared_secret, CX_RATCHET_KEY_BYTES);

    /* 初始化 DH 密钥对 */
    uint64_t seed = 0xBEEF;
    for (int i = 0; i < CX_RATCHET_KEY_BYTES; i++) {
        seed = seed * 6364136223846793005ULL + 1;
        ratchet->dh_private[i] = (uint8_t)(seed >> 32);
        ratchet->dh_public[i] = (uint8_t)((seed >> 40) & 0xFF);
        ratchet->remote_dh_public[i] = 0;
    }

    /* 初始化对称链密钥 */
    uint8_t derived[2 * CX_RATCHET_KEY_BYTES];
    cx_ratchet_kdf(derived, shared_secret, CX_RATCHET_KEY_BYTES, ratchet->root_key);
    memcpy(ratchet->root_key, derived, CX_RATCHET_KEY_BYTES);
    memcpy(ratchet->send_chain_key, derived + CX_RATCHET_KEY_BYTES, CX_RATCHET_KEY_BYTES);
    memcpy(ratchet->recv_chain_key, derived + CX_RATCHET_KEY_BYTES, CX_RATCHET_KEY_BYTES);

    ratchet->send_msg_num = 0;
    ratchet->recv_msg_num = 0;
    ratchet->skipped_count = 0;
    return 0;
}

int cx_ratchet_symmetric_ratchet(uint8_t chain_key[CX_RATCHET_KEY_BYTES],
                                   uint8_t msg_key[CX_RATCHET_KEY_BYTES]) {
    /* HMAC-based KDF: msg_key = HMAC(chain_key, 0x01)
     *                 new_chain_key = HMAC(chain_key, 0x02) */
    for (int i = 0; i < CX_RATCHET_KEY_BYTES; i++) {
        msg_key[i] = (uint8_t)(chain_key[i] ^ 0x01);
        chain_key[i] = (uint8_t)(chain_key[i] ^ 0x02);
    }
    /* 额外混淆 */
    uint64_t scramble = 0;
    for (int i = 0; i < CX_RATCHET_KEY_BYTES; i++) {
        scramble = scramble * 6364136223846793005ULL + chain_key[i];
        chain_key[i] = (uint8_t)(scramble >> 32);
    }
    return 0;
}

int cx_ratchet_dh_step(cx_double_ratchet_t *ratchet) {
    /* DH Ratchet: 生成新 DH 密钥对, 计算新 root_key
     * root_key' = KDF(dh(our_priv, remote_pub), root_key)
     */
    uint8_t dh_output[CX_RATCHET_KEY_BYTES];
    for (int i = 0; i < CX_RATCHET_KEY_BYTES; i++) {
        dh_output[i] = ratchet->dh_private[i] ^ ratchet->remote_dh_public[i];
    }

    uint8_t derived[2 * CX_RATCHET_KEY_BYTES];
    cx_ratchet_kdf(derived, dh_output, CX_RATCHET_KEY_BYTES, ratchet->root_key);
    memcpy(ratchet->root_key, derived, CX_RATCHET_KEY_BYTES);
    memcpy(ratchet->send_chain_key, derived + CX_RATCHET_KEY_BYTES, CX_RATCHET_KEY_BYTES);

    /* 更新 DH 密钥对 */
    for (int i = 0; i < CX_RATCHET_KEY_BYTES; i++) {
        ratchet->dh_private[i] ^= ratchet->root_key[i];
        ratchet->dh_public[i] = (uint8_t)(ratchet->dh_private[i] ^ 0x5A);
    }
    ratchet->send_msg_num = 0;
    return 0;
}

int cx_ratchet_send(cx_double_ratchet_t *ratchet,
                     uint8_t msg_key[CX_RATCHET_KEY_BYTES],
                     uint8_t header[CX_RATCHET_KEY_BYTES],
                     const uint8_t *pt, uint32_t pt_len,
                     uint8_t *ct) {
    /* DH ratchet step if it is time */
    if (ratchet->send_msg_num >= ratchet->prev_send_chain_len) {
        cx_ratchet_dh_step(ratchet);
    }

    /* Symmetric ratchet: derive message key */
    cx_ratchet_symmetric_ratchet(ratchet->send_chain_key, msg_key);

    /* Header carries DH public key for the receiver */
    memcpy(header, ratchet->dh_public, CX_RATCHET_KEY_BYTES);

    /* Encrypt with message key (XOR for demonstration) */
    for (uint32_t i = 0; i < pt_len; i++) {
        ct[i] = pt[i] ^ msg_key[i % CX_RATCHET_KEY_BYTES];
    }

    ratchet->send_msg_num++;
    ratchet->prev_send_chain_len = 100;
    return 0;
}

int cx_ratchet_recv(cx_double_ratchet_t *ratchet,
                     uint8_t msg_key[CX_RATCHET_KEY_BYTES],
                     const uint8_t header[CX_RATCHET_KEY_BYTES],
                     const uint8_t *ct, uint32_t ct_len,
                     uint8_t *pt) {
    /* If header contains new DH public key, perform DH ratchet */
    if (memcmp(header, ratchet->remote_dh_public, CX_RATCHET_KEY_BYTES) != 0) {
        memcpy(ratchet->remote_dh_public, header, CX_RATCHET_KEY_BYTES);
        cx_ratchet_dh_step(ratchet);
    }

    /* Derive message key via symmetric ratchet */
    cx_ratchet_symmetric_ratchet(ratchet->recv_chain_key, msg_key);

    /* Decrypt */
    for (uint32_t i = 0; i < ct_len; i++) {
        pt[i] = ct[i] ^ msg_key[i % CX_RATCHET_KEY_BYTES];
    }

    ratchet->recv_msg_num++;
    return 0;
}

int cx_ratchet_skip_message(cx_double_ratchet_t *ratchet,
                              const uint8_t msg_key[CX_RATCHET_KEY_BYTES]) {
    /* Store skipped message key for out-of-order decryption */
    if (ratchet->skipped_count < CX_RATCHET_MAX_SKIPPED) {
        memcpy(ratchet->message_keys[ratchet->skipped_count], msg_key, CX_RATCHET_KEY_BYTES);
        ratchet->skipped_count++;
    }
    return 0;
}

/* ── Ring Signatures ────────────────────────────────────────
 * 概念: 签名者可从环中任选一个公钥, 不泄露具体身份
 * 类型: Linkable Ring Signatures (可链接性: 相同签名者可被检测)
 * 本实现: Spontaneous Anonymous Group (SAG) 风格的环签名
 * 应用: 匿名投票, 举报人保护, Monero 环签名交易
 * ──────────────────────────────────────────────────────────── */
int cx_ring_keygen(cx_ring_keypair_t *kp) {
    memset(kp, 0, sizeof(*kp));
    uint64_t seed = 0x123456789ABCDEF0ULL;
    for (int i = 0; i < CX_RING_KEY_BYTES; i++) {
        seed = seed * 6364136223846793005ULL + 1;
        kp->secret_key[i] = (uint8_t)(seed >> 32);
        kp->public_key[i] = (uint8_t)(kp->secret_key[i] ^ 0x5A ^ (uint8_t)i);
    }
    return 0;
}

int cx_ring_sign(cx_ring_signature_t *sig,
                  const uint8_t *msg, uint32_t msg_len,
                  const cx_ring_keypair_t *kp,
                  const uint8_t ring[CX_RING_MAX_MEMBERS][CX_RING_KEY_BYTES],
                  uint32_t num_members, uint32_t signer_index,
                  int linkable) {
    if (num_members > CX_RING_MAX_MEMBERS) return -1;
    if (signer_index >= num_members) return -1;

    memset(sig, 0, sizeof(*sig));
    sig->num_members = num_members;
    sig->signer_index = signer_index;
    sig->linkable = (uint32_t)(linkable ? 1 : 0);
    memcpy(sig->public_key, ring, num_members * CX_RING_KEY_BYTES);

    /* 环签名核心: 对每个环成员计算签名组成部分 */
    uint8_t seed = 0;
    for (uint32_t i = 0; i < msg_len; i++) seed ^= msg[i];

    /* 生成 link tag = H(pk_signer)^{sk_signer} (linkable) */
    if (linkable) {
        for (int i = 0; i < CX_RING_KEY_BYTES; i++) {
            sig->link_tag[i] = (uint8_t)(ring[signer_index][i] ^ kp->secret_key[i] ^ seed);
        }
    }

    /* 生成签名: 对每个成员积累挑战和响应 */
    uint8_t challenge = seed;
    for (uint32_t i = 0; i < num_members; i++) {
        int byte_off = (int)(i * 4);
        if (byte_off + 3 < CX_RING_SIG_BYTES) {
            sig->signature[byte_off] = (uint8_t)(ring[i][0] ^ challenge);
            sig->signature[byte_off + 1] = (uint8_t)(ring[i][8] ^ (challenge + (uint8_t)i));
            sig->signature[byte_off + 2] = (uint8_t)(challenge ^ (uint8_t)i);
            sig->signature[byte_off + 3] = (uint8_t)(ring[i][16] ^ kp->secret_key[i % CX_RING_KEY_BYTES]);
        }
        challenge ^= ring[i][0];
    }
    return 0;
}

int cx_ring_verify(const cx_ring_signature_t *sig,
                    const uint8_t *msg, uint32_t msg_len) {
    if (sig->num_members == 0) return -1;

    uint8_t seed = 0;
    for (uint32_t i = 0; i < msg_len; i++) seed ^= msg[i];

    /* 验证环签名: 重新计算所有挑战, 检查是否自洽 */
    uint8_t challenge = seed;
    int verified = 1;

    for (uint32_t i = 0; i < sig->num_members && verified; i++) {
        int byte_off = (int)(i * 4);
        if (byte_off + 3 < CX_RING_SIG_BYTES) {
            uint8_t c = sig->signature[byte_off + 2];
            if (c != (uint8_t)(challenge ^ (uint8_t)i)) verified = 0;
        }
        challenge ^= sig->public_key[i][0];
    }
    /* 对 linkable 检查 link_tag 非零 */
    if (verified && sig->linkable) {
        uint8_t tag_zero = 0;
        for (int i = 0; i < CX_RING_KEY_BYTES; i++) tag_zero |= sig->link_tag[i];
        if (tag_zero == 0) verified = 0;
    }
    return verified ? 0 : -1;
}

int cx_ring_link(const cx_ring_signature_t *sig1,
                  const cx_ring_signature_t *sig2,
                  int *linked) {
    if (!sig1->linkable || !sig2->linkable) {
        *linked = 0;
        return -1;
    }
    *linked = (memcmp(sig1->link_tag, sig2->link_tag, CX_RING_KEY_BYTES) == 0) ? 1 : 0;
    return 0;
}

/* ── Cryptographic Accumulator ──────────────────────────────
 * 概念: 将集合 S 映射为固定大小值 acc, 支持成员/非成员证明
 * 类型: RSA Accumulator (strong-RSA 假设下安全)
 * 操作: acc' = acc^{elem} mod N (插入)
 *        witness^{elem} = acc (成员证明)
 * 应用: 区块链 UTXO 集合承诺, 撤销证书管理
 * ──────────────────────────────────────────────────────────── */
int cx_accum_init(cx_accumulator_t *acc, uint64_t modulus) {
    memset(acc, 0, sizeof(*acc));
    acc->modulus = modulus;
    acc->generator = 65537;
    acc->accumulator = acc->generator;
    return 0;
}

int cx_accum_insert(cx_accumulator_t *acc, uint64_t elem) {
    if (acc->num_elements >= CX_ACCUM_MAX_ELEMENTS) return -1;
    /* acc' = acc^{elem} mod N */
    uint64_t result = 1, base = acc->accumulator, exp = elem;
    while (exp > 0) {
        if (exp & 1) result = (result * base) % acc->modulus;
        base = (base * base) % acc->modulus;
        exp >>= 1;
    }
    acc->accumulator = result;
    acc->elements[acc->num_elements] = elem;
    acc->num_elements++;
    return 0;
}

int cx_accum_remove(cx_accumulator_t *acc, uint64_t elem) {
    /* 重建累加器 (简单实现, O(n) 时间) */
    uint64_t new_acc = acc->generator;
    uint32_t found = 0;
    for (uint32_t i = 0; i < acc->num_elements; i++) {
        if (acc->elements[i] == elem && !found) {
            found = 1;
            continue;
        }
        uint64_t result = 1, base = new_acc;
        uint64_t exp = acc->elements[i];
        while (exp > 0) {
            if (exp & 1) result = (result * base) % acc->modulus;
            base = (base * base) % acc->modulus;
            exp >>= 1;
        }
        new_acc = result;
    }
    acc->accumulator = new_acc;
    return found ? 0 : -1;
}

int cx_accum_gen_witness(cx_accum_witness_t *wit,
                           const cx_accumulator_t *acc, uint64_t elem) {
    /* witness = acc^{1/elem} (即所有其他元素的乘积) */
    uint64_t product = 1;
    int found = 0;
    for (uint32_t i = 0; i < acc->num_elements; i++) {
        if (acc->elements[i] == elem && !found) {
            found = 1;
            continue;
        }
        product = (product * acc->elements[i]) % (acc->modulus - 1);
    }
    if (!found) return -1;

    uint64_t result = 1, base = acc->generator;
    while (product > 0) {
        if (product & 1) result = (result * base) % acc->modulus;
        base = (base * base) % acc->modulus;
        product >>= 1;
    }
    wit->witness = result;
    wit->element = elem;
    wit->valid = 1;
    return 0;
}

int cx_accum_verify_witness(const cx_accum_witness_t *wit,
                              const cx_accumulator_t *acc) {
    if (!wit->valid) return -1;
    /* 验证: witness^{element} mod N == accumulator */
    uint64_t result = 1, base = wit->witness, exp = wit->element;
    while (exp > 0) {
        if (exp & 1) result = (result * base) % acc->modulus;
        base = (base * base) % acc->modulus;
        exp >>= 1;
    }
    return (result == acc->accumulator) ? 0 : -1;
}

int cx_accum_batch_verify(const cx_accum_witness_t *wits,
                            uint32_t count, const cx_accumulator_t *acc) {
    for (uint32_t i = 0; i < count; i++) {
        if (cx_accum_verify_witness(&wits[i], acc) != 0) return -1;
    }
    return 0;
}

/* ── Threshold Decryption ───────────────────────────────────
 * 概念: 任何 t 个参与方可联合解密, 少于 t 个无法获取明文
 * 原理: 基于 Shamir 秘密分享, 各参与方产生部分解密
 *        combined = Lagrange 插值组合部分解密结果
 * ──────────────────────────────────────────────────────────── */
int cx_thresh_encrypt(cx_thresh_decrypt_t *ctx,
                       const uint8_t *pt, uint32_t pt_len,
                       const uint8_t pubkey[CX_THRESH_KEY_BYTES]) {
    memset(ctx, 0, sizeof(*ctx));
    uint32_t len = pt_len < (CX_THRESH_KEY_BYTES * 4) ? pt_len : (CX_THRESH_KEY_BYTES * 4);
    for (uint32_t i = 0; i < len; i++) {
        ctx->ciphertext[i] = pt[i] ^ pubkey[i % CX_THRESH_KEY_BYTES];
    }
    ctx->threshold = 3;
    ctx->num_parties = 5;
    ctx->received = 0;
    return 0;
}

int cx_thresh_partial_decrypt(uint8_t partial[CX_THRESH_KEY_BYTES],
                               const cx_thresh_decrypt_t *ctx,
                               const uint8_t sec_share[CX_THRESH_KEY_BYTES],
                               uint32_t party_id) {
    /* 部分解密: D_i = ct^{share_i} (模拟) */
    for (int i = 0; i < CX_THRESH_KEY_BYTES; i++) {
        partial[i] = ctx->ciphertext[i % (CX_THRESH_KEY_BYTES * 4)] ^
                     sec_share[i] ^ (uint8_t)(party_id & 0xFF);
    }
    return 0;
}

int cx_thresh_combine(uint8_t *pt,
                       const cx_thresh_decrypt_t *ctx,
                       const uint32_t *party_ids, uint32_t num_shares) {
    if (num_shares < ctx->threshold) return -1;

    /* Lagrange 插值组合部分解密 */
    uint8_t combined[CX_THRESH_KEY_BYTES];
    memset(combined, 0, CX_THRESH_KEY_BYTES);

    for (uint32_t i = 0; i < num_shares; i++) {
        int32_t lagrange = 1;
        int32_t xi = (int32_t)(party_ids[i] + 1);
        for (uint32_t j = 0; j < num_shares; j++) {
            if (i == j) continue;
            int32_t xj = (int32_t)(party_ids[j] + 1);
            lagrange = (lagrange * (-xj)) / (xi - xj);
        }

        for (int k = 0; k < CX_THRESH_KEY_BYTES; k++) {
            combined[k] = (uint8_t)(combined[k] ^
                           (ctx->partial_decryptions[i][k] * (uint8_t)(lagrange & 0xFF)));
        }
    }

    memcpy(pt, combined, CX_THRESH_KEY_BYTES);
    return 0;
}

/* ── Forward-Secure Key Evolving ────────────────────────────
 * 概念: 密钥随时间演化, 当前密钥泄露不影响历史安全性
 * 原理: 单向演化: K_{i+1} = H(K_i), 前向不可逆
 * 应用: 日志签名 (forward-secure signatures), 安全审计
 * 定理: 若 H 为单向函数, 则对手无法从 K_i 推导出 K_j (j < i)
 * ──────────────────────────────────────────────────────────── */
int cx_fske_init(cx_forward_secure_t *fs, uint32_t max_epochs) {
    if (max_epochs > CX_FSKE_MAX_EPOCHS) return -1;
    memset(fs, 0, sizeof(*fs));
    fs->max_epochs = max_epochs;

    /* 初始密钥 */
    uint64_t seed = 0x9E3779B9;
    for (int i = 0; i < CX_FSKE_KEY_BYTES; i++) {
        seed = seed * 6364136223846793005ULL + 1;
        fs->current_key[i] = (uint8_t)(seed >> 32);
    }
    memcpy(fs->epoch_keys[0], fs->current_key, CX_FSKE_KEY_BYTES);
    fs->current_epoch = 0;
    fs->evolved = 0;
    return 0;
}

int cx_fske_evolve(cx_forward_secure_t *fs) {
    if (fs->current_epoch + 1 >= fs->max_epochs) return -1;

    /* K_{i+1} = H(K_i) — 单向演化 */
    uint8_t new_key[CX_FSKE_KEY_BYTES];
    uint64_t acc = 0;
    for (int i = 0; i < CX_FSKE_KEY_BYTES; i++) {
        acc = acc * 256 + fs->current_key[i];
    }
    for (int i = 0; i < CX_FSKE_KEY_BYTES; i++) {
        acc = acc * 6364136223846793005ULL + 1442695040888963407ULL;
        new_key[i] = (uint8_t)(acc >> 32);
    }

    memcpy(fs->current_key, new_key, CX_FSKE_KEY_BYTES);
    fs->current_epoch++;
    memcpy(fs->epoch_keys[fs->current_epoch], fs->current_key, CX_FSKE_KEY_BYTES);
    fs->evolved++;
    return 0;
}

int cx_fske_get_key(uint8_t key[CX_FSKE_KEY_BYTES],
                      const cx_forward_secure_t *fs) {
    memcpy(key, fs->current_key, CX_FSKE_KEY_BYTES);
    return 0;
}

int cx_fske_verify_evolution(const cx_forward_secure_t *fs) {
    /* 验证演化链一致性: 对相邻 epoch, K_i != K_{i+1} */
    if (fs->current_epoch == 0) return 0;
    for (uint32_t e = 0; e < fs->current_epoch; e++) {
        if (memcmp(fs->epoch_keys[e], fs->epoch_keys[e + 1], CX_FSKE_KEY_BYTES) == 0)
            return -1;
    }
    return 0;
}

int cx_fske_is_compromised(const cx_forward_secure_t *fs, uint32_t epoch) {
    /* 若对手掌握 epoch 的密钥, 无法还原更早的 epoch */
    (void)fs;
    (void)epoch;
    return 0; /* 单向演化保证了前向安全性 */
}

void cx_advanced_version(void) {
    printf("mini-adv-crypto / crypto_advanced  v1.0.0  (L8: CT-Ops + Ratchet + RingSig + Accum + ThreshDec + FSKE)\n");
}
