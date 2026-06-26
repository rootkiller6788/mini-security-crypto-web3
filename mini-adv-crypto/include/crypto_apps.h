#ifndef CRYPTO_APPS_H
#define CRYPTO_APPS_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ────────────────────────────────────────────────────────────
 * L7: Applications — 密码学应用层
 *
 * 应用:
 *   1. Hybrid Encryption (KEM + DEM): ECIES 风格结合公钥与对称密码
 *   2. Private Set Intersection (PSI): 基于散列的双方隐私交集
 *   3. Verifiable Secret Sharing (Feldman VSS): 可验证的秘密分享
 *   4. Pedersen Commitment: 完美隐藏·计算绑定的承诺方案
 *   5. Merkle Proof Verification: 成员证明与数据完整性
 *   6. Authenticated Encryption (AEAD): Encrypt-then-MAC 构造
 * ──────────────────────────────────────────────────────────── */

#define CA_KEM_KEY_BYTES     32
#define CA_DEM_KEY_BYTES     32
#define CA_DEM_IV_BYTES      16
#define CA_DEM_TAG_BYTES     16
#define CA_DEM_MAX_PT        1024

typedef struct {
    uint8_t  public_key[CA_KEM_KEY_BYTES * 2];
    uint8_t  secret_key[CA_KEM_KEY_BYTES];
    uint8_t  encapsulated_key[CA_KEM_KEY_BYTES * 2];
    uint8_t  shared_secret[CA_KEM_KEY_BYTES];
} ca_hybrid_kem_t;

typedef struct {
    uint8_t  ciphertext[CA_DEM_MAX_PT + CA_DEM_TAG_BYTES];
    uint8_t  iv[CA_DEM_IV_BYTES];
    uint8_t  tag[CA_DEM_TAG_BYTES];
    uint32_t ct_len;
    uint32_t pt_len;
} ca_hybrid_dem_t;

typedef struct {
    ca_hybrid_kem_t kem;
    ca_hybrid_dem_t dem;
    uint8_t         kem_ciphertext[CA_KEM_KEY_BYTES * 2];
} ca_hybrid_ciphertext_t;

int  ca_hybrid_kem_keygen(ca_hybrid_kem_t *kem);
int  ca_hybrid_kem_encaps(ca_hybrid_kem_t *kem);
int  ca_hybrid_kem_decaps(ca_hybrid_kem_t *kem);
int  ca_hybrid_dem_encrypt(ca_hybrid_dem_t *dem, const uint8_t *pt, uint32_t pt_len,
                           const uint8_t key[CA_DEM_KEY_BYTES]);
int  ca_hybrid_dem_decrypt(uint8_t *pt, const ca_hybrid_dem_t *dem,
                           const uint8_t key[CA_DEM_KEY_BYTES], uint32_t pt_len);
int  ca_hybrid_encrypt(ca_hybrid_ciphertext_t *ct, const uint8_t *pt, uint32_t pt_len,
                       const uint8_t pubkey[CA_KEM_KEY_BYTES * 2]);
int  ca_hybrid_decrypt(uint8_t *pt, const ca_hybrid_ciphertext_t *ct,
                       const uint8_t seckey[CA_KEM_KEY_BYTES], uint32_t *pt_len);

#define CA_PSI_MAX_ELEMENTS  256
#define CA_PSI_HASH_BYTES     32
#define CA_PSI_BLOOM_BITS    2048

typedef struct {
    uint64_t hashes[CA_PSI_MAX_ELEMENTS];
    uint32_t count;
} ca_psi_set_t;

typedef struct {
    uint8_t  filter[CA_PSI_BLOOM_BITS / 8];
    uint32_t num_elements;
    uint32_t num_hashes;
    uint32_t size_bits;
} ca_psi_bloom_t;

int  ca_psi_set_init(ca_psi_set_t *set);
int  ca_psi_set_add(ca_psi_set_t *set, const uint8_t *elem, uint32_t elem_len);
int  ca_psi_bloom_init(ca_psi_bloom_t *bf, uint32_t size_bits, uint32_t num_hashes);
int  ca_psi_bloom_insert(ca_psi_bloom_t *bf, const uint8_t *elem, uint32_t elem_len);
int  ca_psi_bloom_query(const ca_psi_bloom_t *bf, const uint8_t *elem, uint32_t elem_len);
int  ca_psi_intersect(ca_psi_set_t *result, const ca_psi_set_t *a, const ca_psi_set_t *b);
int  ca_psi_cardinality(uint32_t *card, const ca_psi_set_t *a, const ca_psi_set_t *b);

#define CA_VSS_MAX_SHARES     64
#define CA_VSS_PRIME          2147483647

typedef struct {
    int64_t  g;
    int64_t  commitments[CA_VSS_MAX_SHARES];
    int64_t  shares[CA_VSS_MAX_SHARES];
    uint32_t threshold;
    uint32_t total;
} ca_vss_dealer_t;

typedef struct {
    int64_t  share;
    int64_t  public_commitment;
    uint32_t party_id;
    uint32_t verified;
} ca_vss_party_t;

int  ca_vss_dealer_setup(ca_vss_dealer_t *dealer, int64_t secret,
                          uint32_t threshold, uint32_t total, int64_t generator);
int  ca_vss_dealer_distribute(ca_vss_dealer_t *dealer);
int  ca_vss_party_verify(const ca_vss_party_t *party, const ca_vss_dealer_t *dealer);
int  ca_vss_reconstruct(int64_t *secret, const int64_t *shares,
                         const uint32_t *indices, uint32_t threshold);
int  ca_vss_complaint_resolve(ca_vss_dealer_t *dealer, uint32_t party_id);

#define CA_PEDERSEN_BITS      256

typedef struct {
    uint64_t g;
    uint64_t h;
    uint64_t p;
    uint64_t commitment;
    uint64_t randomness;
    uint64_t message;
} ca_pedersen_commit_t;

int  ca_pedersen_setup(ca_pedersen_commit_t *ctx, uint64_t g, uint64_t p);
int  ca_pedersen_commit(ca_pedersen_commit_t *ctx, uint64_t msg, uint64_t rand);
int  ca_pedersen_open(const ca_pedersen_commit_t *ctx, uint64_t *msg, uint64_t *rand);
int  ca_pedersen_verify(const ca_pedersen_commit_t *ctx, uint64_t msg, uint64_t rand);
int  ca_pedersen_homomorphic_add(ca_pedersen_commit_t *r,
                                  const ca_pedersen_commit_t *a,
                                  const ca_pedersen_commit_t *b);

#define CA_MERKLE_MAX_LEAVES   128
#define CA_MERKLE_HASH_BYTES    32

typedef struct {
    uint8_t  hash[CA_MERKLE_HASH_BYTES];
} ca_merkle_node_t;

typedef struct {
    ca_merkle_node_t nodes[CA_MERKLE_MAX_LEAVES * 2];
    ca_merkle_node_t root;
    uint32_t num_leaves;
    uint32_t depth;
} ca_merkle_tree_t;

typedef struct {
    ca_merkle_node_t path[32];
    ca_merkle_node_t leaf;
    uint32_t leaf_index;
    uint32_t path_len;
} ca_merkle_proof_t;

int  ca_merkle_tree_build(ca_merkle_tree_t *tree,
                           const uint8_t data[][CA_MERKLE_HASH_BYTES], uint32_t num_leaves);
int  ca_merkle_get_root(ca_merkle_node_t *root, const ca_merkle_tree_t *tree);
int  ca_merkle_generate_proof(ca_merkle_proof_t *proof, const ca_merkle_tree_t *tree,
                               uint32_t leaf_index);
int  ca_merkle_verify_proof(const ca_merkle_proof_t *proof,
                              const ca_merkle_node_t *root);
void ca_merkle_node_hash(ca_merkle_node_t *out, const uint8_t *data, uint32_t len);
int  ca_merkle_node_combine(ca_merkle_node_t *out,
                              const ca_merkle_node_t *left, const ca_merkle_node_t *right);

#define CA_AEAD_KEY_BYTES     32
#define CA_AEAD_NONCE_BYTES   12
#define CA_AEAD_TAG_BYTES     16
#define CA_AEAD_MAX_PT        4096

typedef struct {
    uint8_t  key[CA_AEAD_KEY_BYTES];
    uint8_t  nonce[CA_AEAD_NONCE_BYTES];
    uint8_t  ciphertext[CA_AEAD_MAX_PT + CA_AEAD_TAG_BYTES];
    uint8_t  tag[CA_AEAD_TAG_BYTES];
    uint8_t  aad[64];
    uint32_t aad_len;
    uint32_t ct_len;
} ca_aead_ctx_t;

int  ca_aead_keygen(uint8_t key[CA_AEAD_KEY_BYTES]);
int  ca_aead_encrypt(ca_aead_ctx_t *ctx, const uint8_t *pt, uint32_t pt_len,
                      const uint8_t *aad, uint32_t aad_len);
int  ca_aead_decrypt(uint8_t *pt, const ca_aead_ctx_t *ctx,
                      const uint8_t *aad, uint32_t aad_len, uint32_t pt_len);
int  ca_aead_verify_tag(const ca_aead_ctx_t *ctx);
int  ca_aead_rotate_nonce(ca_aead_ctx_t *ctx);

void ca_apps_version(void);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_APPS_H */
