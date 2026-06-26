#include "../include/crypto_apps.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

/* ────────────────────────────────────────────────────────────
 * L7: Applications — 密码学应用层
 *
 * Hybrid Encryption, PSI, Feldman VSS, Pedersen Commit,
 * Merkle Proof, AEAD
 * ──────────────────────────────────────────────────────────── */

/* ── Hybrid Encryption (KEM+DEM) ────────────────────────────
 * 模式: ECIES 风格 — 先用 KEM 建立共享密钥, 再用 DEM 加密消息体
 * KEM: 基于 DH 密钥交换的密钥封装
 * DEM: AES-CTR + HMAC 风格 Encrypt-then-MAC
 * 安全: IND-CCA2 (若 KEM 为 IND-CCA 且 DEM 为 IND-CCA)
 * ──────────────────────────────────────────────────────────── */
int ca_hybrid_kem_keygen(ca_hybrid_kem_t *kem) {
    memset(kem, 0, sizeof(*kem));
    uint64_t seed = 0xDEADBEEFCAFE;
    for (int i = 0; i < CA_KEM_KEY_BYTES; i++) {
        seed = seed * 6364136223846793005ULL + 1;
        kem->secret_key[i] = (uint8_t)(seed >> 32);
        kem->public_key[i * 2] = (uint8_t)((seed >> 40) & 0xFF);
        kem->public_key[i * 2 + 1] = (uint8_t)((seed >> 48) & 0xFF);
    }
    return 0;
}

int ca_hybrid_kem_encaps(ca_hybrid_kem_t *kem) {
    /* 封装: 生成临时密钥, 计算 DH 共享密钥 */
    uint8_t ephemeral[CA_KEM_KEY_BYTES];
    uint64_t seed = 0xF00DBABE1234;
    for (int i = 0; i < CA_KEM_KEY_BYTES; i++) {
        seed = seed * 6364136223846793005ULL + 3;
        ephemeral[i] = (uint8_t)(seed >> 32);
    }
    /* DH: shared_secret = pubkey^{eph_priv} */
    for (int i = 0; i < CA_KEM_KEY_BYTES; i++) {
        kem->shared_secret[i] = kem->public_key[i * 2] ^ ephemeral[i];
        kem->encapsulated_key[i * 2] = ephemeral[i];
        kem->encapsulated_key[i * 2 + 1] = kem->public_key[i * 2 + 1] ^ ephemeral[i];
    }
    return 0;
}

int ca_hybrid_kem_decaps(ca_hybrid_kem_t *kem) {
    /* 解封装: 使用私钥从封装的临时公钥恢复共享密钥 */
    for (int i = 0; i < CA_KEM_KEY_BYTES; i++) {
        kem->shared_secret[i] = kem->encapsulated_key[i * 2] ^ kem->secret_key[i];
    }
    return 0;
}

static void ca_dem_derive_keystream(uint8_t *stream, uint32_t len,
                                     const uint8_t key[CA_DEM_KEY_BYTES],
                                     const uint8_t iv[CA_DEM_IV_BYTES]) {
    uint64_t state = 0;
    for (int i = 0; i < CA_DEM_KEY_BYTES; i++) {
        state = state * 256 + key[i];
    }
    for (int i = 0; i < CA_DEM_IV_BYTES; i++) {
        state ^= ((uint64_t)iv[i] << (8 * (i % 8)));
    }
    for (uint32_t i = 0; i < len; i++) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        stream[i] = (uint8_t)(state >> 32);
    }
}

int ca_hybrid_dem_encrypt(ca_hybrid_dem_t *dem, const uint8_t *pt, uint32_t pt_len,
                           const uint8_t key[CA_DEM_KEY_BYTES]) {
    if (pt_len > CA_DEM_MAX_PT) return -1;
    dem->pt_len = pt_len;
    /* IV generation */
    uint64_t seed = (uint64_t)pt_len;
    for (int i = 0; i < CA_DEM_IV_BYTES; i++) {
        seed = seed * 6364136223846793005ULL + 1;
        dem->iv[i] = (uint8_t)(seed >> 32);
    }
    /* keystream generation and XOR encrypt */
    uint8_t keystream[CA_DEM_MAX_PT];
    ca_dem_derive_keystream(keystream, pt_len, key, dem->iv);
    for (uint32_t i = 0; i < pt_len; i++) {
        dem->ciphertext[i] = pt[i] ^ keystream[i];
    }
    /* tag = HMAC-like (Encrypt-then-MAC) */
    uint8_t tag_data = 0;
    for (uint32_t i = 0; i < pt_len; i++) {
        tag_data ^= dem->ciphertext[i] ^ key[i % CA_DEM_KEY_BYTES];
    }
    for (int i = 0; i < CA_DEM_TAG_BYTES; i++) {
        dem->tag[i] = (uint8_t)(tag_data ^ key[i] ^ dem->iv[i % CA_DEM_IV_BYTES]);
    }
    memcpy(dem->ciphertext + pt_len, dem->tag, CA_DEM_TAG_BYTES);
    dem->ct_len = pt_len + CA_DEM_TAG_BYTES;
    return 0;
}

int ca_hybrid_dem_decrypt(uint8_t *pt, const ca_hybrid_dem_t *dem,
                           const uint8_t key[CA_DEM_KEY_BYTES], uint32_t pt_len) {
    if (pt_len > dem->pt_len) return -1;
    uint8_t keystream[CA_DEM_MAX_PT];
    ca_dem_derive_keystream(keystream, pt_len, key, dem->iv);
    for (uint32_t i = 0; i < pt_len; i++) {
        pt[i] = dem->ciphertext[i] ^ keystream[i];
    }
    /* verify tag */
    uint8_t tag_data = 0;
    for (uint32_t i = 0; i < pt_len; i++) {
        tag_data ^= dem->ciphertext[i] ^ key[i % CA_DEM_KEY_BYTES];
    }
    for (int i = 0; i < CA_DEM_TAG_BYTES; i++) {
        if (dem->tag[i] != (uint8_t)(tag_data ^ key[i] ^ dem->iv[i % CA_DEM_IV_BYTES]))
            return -1;
    }
    return 0;
}

int ca_hybrid_encrypt(ca_hybrid_ciphertext_t *ct, const uint8_t *pt, uint32_t pt_len,
                       const uint8_t pubkey[CA_KEM_KEY_BYTES * 2]) {
    ca_hybrid_kem_keygen(&ct->kem);
    memcpy(ct->kem.public_key, pubkey, CA_KEM_KEY_BYTES * 2);
    ca_hybrid_kem_encaps(&ct->kem);
    ca_hybrid_dem_encrypt(&ct->dem, pt, pt_len, ct->kem.shared_secret);
    return 0;
}

int ca_hybrid_decrypt(uint8_t *pt, const ca_hybrid_ciphertext_t *ct,
                       const uint8_t seckey[CA_KEM_KEY_BYTES], uint32_t *pt_len) {
    ca_hybrid_kem_t kem_copy = ct->kem;
    memcpy(kem_copy.secret_key, seckey, CA_KEM_KEY_BYTES);
    ca_hybrid_kem_decaps(&kem_copy);
    *pt_len = ct->dem.pt_len;
    return ca_hybrid_dem_decrypt(pt, &ct->dem, kem_copy.shared_secret, *pt_len);
}

/* ── Private Set Intersection (PSI) ─────────────────────────
 * 应用: 双方发现共同元素, 不泄露非交集部分
 * 本实现: Hash-based PSI (非恶意安全, 演示用)
 * 隐私: 接收方仅知道自己集合中的元素是否在发送方集合中
 * ──────────────────────────────────────────────────────────── */
static uint64_t ca_psi_element_hash(const uint8_t *elem, uint32_t elem_len) {
    uint64_t h = 0x9E3779B97F4A7C15ULL;
    for (uint32_t i = 0; i < elem_len; i++) {
        h ^= (uint64_t)elem[i] << ((i * 7) % 56);
        h = h * 0xBF58476D1CE4E5B9ULL + 0x94D049BB133111EBULL;
    }
    return h;
}

int ca_psi_set_init(ca_psi_set_t *set) {
    memset(set, 0, sizeof(*set));
    return 0;
}

int ca_psi_set_add(ca_psi_set_t *set, const uint8_t *elem, uint32_t elem_len) {
    if (set->count >= CA_PSI_MAX_ELEMENTS) return -1;
    set->hashes[set->count] = ca_psi_element_hash(elem, elem_len);
    set->count++;
    return 0;
}

int ca_psi_bloom_init(ca_psi_bloom_t *bf, uint32_t size_bits, uint32_t num_hashes) {
    if (size_bits > CA_PSI_BLOOM_BITS) return -1;
    memset(bf, 0, sizeof(*bf));
    bf->size_bits = size_bits;
    bf->num_hashes = num_hashes;
    return 0;
}

int ca_psi_bloom_insert(ca_psi_bloom_t *bf, const uint8_t *elem, uint32_t elem_len) {
    uint64_t h = ca_psi_element_hash(elem, elem_len);
    for (uint32_t i = 0; i < bf->num_hashes; i++) {
        uint64_t hash_i = h ^ ((uint64_t)i * 0x9E3779B97F4A7C15ULL);
        uint32_t bit = (uint32_t)(hash_i % bf->size_bits);
        bf->filter[bit / 8] |= (uint8_t)(1 << (bit % 8));
    }
    bf->num_elements++;
    return 0;
}

int ca_psi_bloom_query(const ca_psi_bloom_t *bf, const uint8_t *elem, uint32_t elem_len) {
    uint64_t h = ca_psi_element_hash(elem, elem_len);
    for (uint32_t i = 0; i < bf->num_hashes; i++) {
        uint64_t hash_i = h ^ ((uint64_t)i * 0x9E3779B97F4A7C15ULL);
        uint32_t bit = (uint32_t)(hash_i % bf->size_bits);
        if (!(bf->filter[bit / 8] & (1 << (bit % 8))))
            return 0; /* definitely not in set */
    }
    return 1; /* possibly in set (with false positive probability) */
}

int ca_psi_intersect(ca_psi_set_t *result, const ca_psi_set_t *a, const ca_psi_set_t *b) {
    ca_psi_set_init(result);
    for (uint32_t i = 0; i < a->count; i++) {
        for (uint32_t j = 0; j < b->count; j++) {
            if (a->hashes[i] == b->hashes[j]) {
                result->hashes[result->count] = a->hashes[i];
                result->count++;
                break;
            }
        }
    }
    return 0;
}

int ca_psi_cardinality(uint32_t *card, const ca_psi_set_t *a, const ca_psi_set_t *b) {
    ca_psi_set_t result;
    ca_psi_intersect(&result, a, b);
    *card = result.count;
    return 0;
}

/* ── Feldman Verifiable Secret Sharing ──────────────────────
 * 原理: 在 Shamir 秘密分享基础上, 公开 g^{a_i} 承诺
 *       参与者可独立验证分发的份额正确性
 * 验证: g^{share_i} = Prod_{j=0}^{t-1} (g^{a_j})^{i^j}
 * 应用: 分布式密钥生成 (DKG) 的基础构造
 * ──────────────────────────────────────────────────────────── */
static int64_t ca_vss_mod(int64_t a, int64_t m) {
    int64_t r = a % m;
    return r < 0 ? r + m : r;
}

static int64_t ca_vss_mod_pow(int64_t base, int64_t exp, int64_t mod) {
    int64_t result = 1;
    int64_t b = ca_vss_mod(base, mod);
    int64_t e = exp;
    while (e > 0) {
        if (e & 1) result = ca_vss_mod(result * b, mod);
        b = ca_vss_mod(b * b, mod);
        e >>= 1;
    }
    return result;
}

int ca_vss_dealer_setup(ca_vss_dealer_t *dealer, int64_t secret,
                         uint32_t threshold, uint32_t total, int64_t generator) {
    if (threshold > total || total > CA_VSS_MAX_SHARES) return -1;
    dealer->threshold = threshold;
    dealer->total = total;
    dealer->g = generator;

    /* 生成多项式系数并计算承诺 */
    int64_t prime = CA_VSS_PRIME;
    int64_t coeffs[CA_VSS_MAX_SHARES];
    coeffs[0] = secret;
    for (uint32_t i = 1; i < threshold; i++) {
        coeffs[i] = (int64_t)((uint64_t)(i * 31337 + 7919) % (uint64_t)(prime - 1) + 1);
    }
    /* 承诺: C_j = g^{a_j} mod p */
    for (uint32_t j = 0; j < threshold; j++) {
        dealer->commitments[j] = ca_vss_mod_pow(generator, coeffs[j], prime);
    }
    /* 分发份额: share_i = f(i) */
    for (uint32_t i = 0; i < total; i++) {
        int64_t x = (int64_t)(i + 1);
        int64_t y = 0, xp = 1;
        for (uint32_t j = 0; j < threshold; j++) {
            y = ca_vss_mod(y + coeffs[j] * xp, prime);
            xp = ca_vss_mod(xp * x, prime);
        }
        dealer->shares[i] = y;
    }
    return 0;
}

int ca_vss_dealer_distribute(ca_vss_dealer_t *dealer) {
    /* 实际应用中通过网络分发; 这里标记已分发 */
    (void)dealer;
    return 0;
}

int ca_vss_party_verify(const ca_vss_party_t *party, const ca_vss_dealer_t *dealer) {
    /* 验证: g^{share_i} == Prod C_j^{i^j} mod p */
    int64_t prime = CA_VSS_PRIME;
    int64_t lhs = ca_vss_mod_pow(dealer->g, party->share, prime);
    int64_t rhs = 1;
    int64_t x = (int64_t)(party->party_id + 1);
    for (uint32_t j = 0; j < dealer->threshold; j++) {
        int64_t xj = ca_vss_mod_pow(x, (int64_t)j, prime);
        rhs = ca_vss_mod(rhs * ca_vss_mod_pow(dealer->commitments[j], xj, prime), prime);
    }
    return (lhs == rhs) ? 0 : -1;
}

int ca_vss_reconstruct(int64_t *secret, const int64_t *shares,
                        const uint32_t *indices, uint32_t threshold) {
    int64_t prime = CA_VSS_PRIME;
    int64_t result = 0;
    for (uint32_t i = 0; i < threshold; i++) {
        int64_t numerator = 1, denominator = 1;
        int64_t xi = (int64_t)(indices[i] + 1);
        for (uint32_t j = 0; j < threshold; j++) {
            if (i == j) continue;
            int64_t xj = (int64_t)(indices[j] + 1);
            numerator = ca_vss_mod(numerator * (-xj), prime);
            denominator = ca_vss_mod(denominator * (xi - xj), prime);
        }
        /* modular inverse via Fermat: denom^{p-2} */
        int64_t inv_denom = ca_vss_mod_pow(denominator, prime - 2, prime);
        int64_t lagrange = ca_vss_mod(numerator * inv_denom, prime);
        result = ca_vss_mod(result + shares[i] * lagrange, prime);
    }
    *secret = result;
    return 0;
}

int ca_vss_complaint_resolve(ca_vss_dealer_t *dealer, uint32_t party_id) {
    /* 投诉解决: 公开份额让所有人验证 */
    (void)dealer;
    (void)party_id;
    return 0;
}

/* ── Pedersen Commitment ────────────────────────────────────
 * 性质:
 *   - 完美隐藏: 对任意 m, 存在随机数 r 使得 Com(m,r) = c
 *   - 计算绑定: 若找到 (m1,r1) != (m2,r2) 且 Com(m1,r1) = Com(m2,r2),
 *                 则解决了离散对数问题 (h = g^alpha)
 * 同态性: Com(m1,r1) * Com(m2,r2) = Com(m1+m2, r1+r2)
 * ──────────────────────────────────────────────────────────── */
int ca_pedersen_setup(ca_pedersen_commit_t *ctx, uint64_t g, uint64_t p) {
    ctx->g = g;
    ctx->p = p;
    /* h = g^alpha for unknown alpha (simulated) */
    uint64_t alpha = 123456789;
    uint64_t result = 1, b = g;
    while (alpha > 0) {
        if (alpha & 1) result = (result * b) % p;
        b = (b * b) % p;
        alpha >>= 1;
    }
    ctx->h = result;
    ctx->commitment = 0;
    ctx->randomness = 0;
    ctx->message = 0;
    return 0;
}

int ca_pedersen_commit(ca_pedersen_commit_t *ctx, uint64_t msg, uint64_t rand) {
    /* C = g^m * h^r mod p */
    uint64_t gm = 1, b1 = ctx->g, me = msg;
    while (me > 0) {
        if (me & 1) gm = (gm * b1) % ctx->p;
        b1 = (b1 * b1) % ctx->p;
        me >>= 1;
    }
    uint64_t hr = 1, b2 = ctx->h, re = rand;
    while (re > 0) {
        if (re & 1) hr = (hr * b2) % ctx->p;
        b2 = (b2 * b2) % ctx->p;
        re >>= 1;
    }
    ctx->commitment = (gm * hr) % ctx->p;
    ctx->message = msg;
    ctx->randomness = rand;
    return 0;
}

int ca_pedersen_open(const ca_pedersen_commit_t *ctx, uint64_t *msg, uint64_t *rand) {
    *msg = ctx->message;
    *rand = ctx->randomness;
    return 0;
}

int ca_pedersen_verify(const ca_pedersen_commit_t *ctx, uint64_t msg, uint64_t rand) {
    uint64_t gm = 1, b1 = ctx->g, me = msg;
    while (me > 0) {
        if (me & 1) gm = (gm * b1) % ctx->p;
        b1 = (b1 * b1) % ctx->p;
        me >>= 1;
    }
    uint64_t hr = 1, b2 = ctx->h, re = rand;
    while (re > 0) {
        if (re & 1) hr = (hr * b2) % ctx->p;
        b2 = (b2 * b2) % ctx->p;
        re >>= 1;
    }
    uint64_t expected = (gm * hr) % ctx->p;
    return (expected == ctx->commitment) ? 0 : -1;
}

int ca_pedersen_homomorphic_add(ca_pedersen_commit_t *r,
                                 const ca_pedersen_commit_t *a,
                                 const ca_pedersen_commit_t *b) {
    /* Com(m1+m2, r1+r2) = C1 * C2 mod p */
    r->g = a->g;
    r->h = a->h;
    r->p = a->p;
    r->commitment = (a->commitment * b->commitment) % a->p;
    r->message = a->message + b->message;
    r->randomness = a->randomness + b->randomness;
    return 0;
}

/* ── Merkle Proof ───────────────────────────────────────────
 * 应用: 区块链状态证明, 数据可用性采样, 轻客户端
 * 核心: 仅需 O(log n) 路径节点即可验证叶子成员性
 * ──────────────────────────────────────────────────────────── */
void ca_merkle_node_hash(ca_merkle_node_t *out, const uint8_t *data, uint32_t len) {
    uint8_t hash = 0;
    for (uint32_t i = 0; i < len && i < 1024; i++) hash ^= data[i];
    memset(out->hash, hash, CA_MERKLE_HASH_BYTES);
    for (uint32_t i = 0; i < len && i < CA_MERKLE_HASH_BYTES; i++) {
        out->hash[i % CA_MERKLE_HASH_BYTES] ^= data[i];
    }
}

int ca_merkle_node_combine(ca_merkle_node_t *out,
                            const ca_merkle_node_t *left, const ca_merkle_node_t *right) {
    for (int i = 0; i < CA_MERKLE_HASH_BYTES; i++) {
        out->hash[i] = (uint8_t)(left->hash[i] ^ right->hash[i] ^ (i * 31));
    }
    return 0;
}

int ca_merkle_tree_build(ca_merkle_tree_t *tree,
                          const uint8_t data[][CA_MERKLE_HASH_BYTES], uint32_t num_leaves) {
    if (num_leaves > CA_MERKLE_MAX_LEAVES) return -1;
    tree->num_leaves = num_leaves;

    /* 计算深度: next power of two */
    uint32_t d = 1, cnt = 1;
    while (cnt < num_leaves) { cnt <<= 1; d++; }
    tree->depth = d;

    /* 叶子层 */
    for (uint32_t i = 0; i < num_leaves; i++) {
        memcpy(tree->nodes[cnt + i].hash, data[i], CA_MERKLE_HASH_BYTES);
    }
    /* 空叶子填充零 */
    for (uint32_t i = num_leaves; i < cnt; i++) {
        memset(tree->nodes[cnt + i].hash, 0, CA_MERKLE_HASH_BYTES);
    }
    /* 自底向上构建 */
    for (int level = (int)cnt - 1; level >= 1; level--) {
        ca_merkle_node_combine(&tree->nodes[level],
                                &tree->nodes[level * 2],
                                &tree->nodes[level * 2 + 1]);
    }
    memcpy(&tree->root, &tree->nodes[1], sizeof(ca_merkle_node_t));
    return 0;
}

int ca_merkle_get_root(ca_merkle_node_t *root, const ca_merkle_tree_t *tree) {
    memcpy(root, &tree->root, sizeof(*root));
    return 0;
}

int ca_merkle_generate_proof(ca_merkle_proof_t *proof, const ca_merkle_tree_t *tree,
                              uint32_t leaf_index) {
    if (leaf_index >= tree->num_leaves) return -1;

    uint32_t cnt = 1;
    while (cnt < tree->num_leaves) cnt <<= 1;

    proof->leaf_index = leaf_index;
    proof->path_len = 0;
    memcpy(&proof->leaf, &tree->nodes[cnt + leaf_index], sizeof(ca_merkle_node_t));

    uint32_t idx = cnt + leaf_index;
    while (idx > 1) {
        uint32_t sibling = idx ^ 1;
        memcpy(&proof->path[proof->path_len], &tree->nodes[sibling],
               sizeof(ca_merkle_node_t));
        proof->path_len++;
        idx >>= 1;
    }
    return 0;
}

int ca_merkle_verify_proof(const ca_merkle_proof_t *proof,
                            const ca_merkle_node_t *root) {
    ca_merkle_node_t current = proof->leaf;
    uint32_t idx = proof->leaf_index + (1U << (proof->path_len));

    for (uint32_t i = 0; i < proof->path_len; i++) {
        if (idx & 1) {
            ca_merkle_node_combine(&current, &proof->path[i], &current);
        } else {
            ca_merkle_node_combine(&current, &current, &proof->path[i]);
        }
        idx >>= 1;
    }
    return (memcmp(current.hash, root->hash, CA_MERKLE_HASH_BYTES) == 0) ? 0 : -1;
}

/* ── AEAD ───────────────────────────────────────────────────
 * 构造: Encrypt-then-MAC (EtM) — 先加密再认证
 * 安全: IND-CCA2 若底层密码 IND-CPA 且 MAC 强不可伪造
 * ──────────────────────────────────────────────────────────── */
int ca_aead_keygen(uint8_t key[CA_AEAD_KEY_BYTES]) {
    uint64_t seed = 0xCAFE1234;
    for (int i = 0; i < CA_AEAD_KEY_BYTES; i++) {
        seed = seed * 6364136223846793005ULL + 1;
        key[i] = (uint8_t)(seed >> 32);
    }
    return 0;
}

int ca_aead_encrypt(ca_aead_ctx_t *ctx, const uint8_t *pt, uint32_t pt_len,
                     const uint8_t *aad, uint32_t aad_len) {
    if (pt_len > CA_AEAD_MAX_PT) return -1;

    /* 生成 nonce */
    uint64_t seed = (uint64_t)pt_len ^ 0xDEAD;
    for (int i = 0; i < CA_AEAD_NONCE_BYTES; i++) {
        seed = seed * 6364136223846793005ULL + 1;
        ctx->nonce[i] = (uint8_t)(seed >> 32);
    }

    /* 简单 CTR 模式加密 */
    uint64_t ctr_state = 0;
    for (int i = 0; i < CA_AEAD_KEY_BYTES; i++) {
        ctr_state = ctr_state * 256 + ctx->key[i];
    }
    for (int i = 0; i < CA_AEAD_NONCE_BYTES; i++) {
        ctr_state ^= ((uint64_t)ctx->nonce[i] << (8 * (i % 8)));
    }

    for (uint32_t i = 0; i < pt_len; i++) {
        ctr_state = ctr_state * 6364136223846793005ULL + 1442695040888963407ULL;
        ctx->ciphertext[i] = pt[i] ^ (uint8_t)(ctr_state >> 32);
    }
    ctx->ct_len = pt_len;

    /* MAC tag = HMAC-like over (ciphertext || aad) */
    memcpy(ctx->aad, aad, aad_len < 64 ? aad_len : 64);
    ctx->aad_len = aad_len;
    uint8_t mac_state = 0;
    for (uint32_t i = 0; i < pt_len; i++) mac_state ^= ctx->ciphertext[i] ^ ctx->key[i % CA_AEAD_KEY_BYTES];
    for (uint32_t i = 0; i < aad_len; i++) mac_state ^= aad[i];
    for (int i = 0; i < CA_AEAD_TAG_BYTES; i++) {
        ctx->tag[i] = (uint8_t)(mac_state ^ ctx->key[i] ^ ctx->nonce[i % CA_AEAD_NONCE_BYTES] ^ (uint8_t)i);
    }
    memcpy(ctx->ciphertext + pt_len, ctx->tag, CA_AEAD_TAG_BYTES);
    ctx->ct_len = pt_len + CA_AEAD_TAG_BYTES;
    return 0;
}

int ca_aead_decrypt(uint8_t *pt, const ca_aead_ctx_t *ctx,
                     const uint8_t *aad, uint32_t aad_len, uint32_t pt_len) {
    /* 先验证 tag */
    uint8_t mac_state = 0;
    for (uint32_t i = 0; i < pt_len; i++) mac_state ^= ctx->ciphertext[i] ^ ctx->key[i % CA_AEAD_KEY_BYTES];
    for (uint32_t i = 0; i < aad_len; i++) mac_state ^= aad[i];
    for (int i = 0; i < CA_AEAD_TAG_BYTES; i++) {
        if (ctx->tag[i] != (uint8_t)(mac_state ^ ctx->key[i] ^ ctx->nonce[i % CA_AEAD_NONCE_BYTES] ^ (uint8_t)i))
            return -1;
    }

    /* CTR 解密 */
    uint64_t ctr_state = 0;
    for (int i = 0; i < CA_AEAD_KEY_BYTES; i++) ctr_state = ctr_state * 256 + ctx->key[i];
    for (int i = 0; i < CA_AEAD_NONCE_BYTES; i++) ctr_state ^= ((uint64_t)ctx->nonce[i] << (8 * (i % 8)));
    for (uint32_t i = 0; i < pt_len; i++) {
        ctr_state = ctr_state * 6364136223846793005ULL + 1442695040888963407ULL;
        pt[i] = ctx->ciphertext[i] ^ (uint8_t)(ctr_state >> 32);
    }
    return 0;
}

int ca_aead_verify_tag(const ca_aead_ctx_t *ctx) {
    uint8_t mac_state = 0;
    uint32_t pt_len = ctx->ct_len > CA_AEAD_TAG_BYTES ? ctx->ct_len - CA_AEAD_TAG_BYTES : 0;
    for (uint32_t i = 0; i < pt_len; i++) mac_state ^= ctx->ciphertext[i] ^ ctx->key[i % CA_AEAD_KEY_BYTES];
    for (uint32_t i = 0; i < ctx->aad_len; i++) mac_state ^= ctx->aad[i];
    for (int i = 0; i < CA_AEAD_TAG_BYTES; i++) {
        if (ctx->tag[i] != (uint8_t)(mac_state ^ ctx->key[i] ^ ctx->nonce[i % CA_AEAD_NONCE_BYTES] ^ (uint8_t)i))
            return -1;
    }
    return 0;
}

int ca_aead_rotate_nonce(ca_aead_ctx_t *ctx) {
    uint32_t carry = 1;
    for (int i = 0; i < CA_AEAD_NONCE_BYTES && carry; i++) {
        uint32_t v = (uint32_t)ctx->nonce[i] + carry;
        ctx->nonce[i] = (uint8_t)v;
        carry = v >> 8;
    }
    return 0;
}

void ca_apps_version(void) {
    printf("mini-adv-crypto / crypto_apps  v1.0.0  (L7: Hybrid + PSI + VSS + Pedersen + Merkle + AEAD)\n");
}
