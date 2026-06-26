#ifndef CRYPTO_ADVANCED_H
#define CRYPTO_ADVANCED_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ────────────────────────────────────────────────────────────
 * L8: Advanced Topics — 密码学进阶主题
 *
 * 覆盖:
 *   1. Constant-Time Operations (抗侧信道攻击 / Side-Channel Resistance)
 *   2. Double Ratchet Algorithm (Signal Protocol 风格前向安全性)
 *   3. Ring Signatures (匿名签名 / Spontaneous Anonymous Group)
 *   4. Cryptographic Accumulators (RSA Accumulator, 成员证明)
 *   5. Threshold Decryption (分布式解密)
 *   6. Forward-Secure Key Evolving (密钥演化前向安全)
 * ──────────────────────────────────────────────────────────── */

/* ── Constant-Time Operations ─────────────────────────────── */
#define CX_CT_MIN(x, y) ct_select_32((y), (x), ct_lt_32((x), (y)))

int32_t ct_lt_32(int32_t a, int32_t b);
uint32_t ct_select_32(uint32_t a, uint32_t b, uint32_t cond);
int     ct_memcmp(const uint8_t *a, const uint8_t *b, size_t len);
void    ct_memzero(void *ptr, size_t len);
int     ct_is_zero(const uint8_t *a, size_t len);
void    ct_cond_assign(uint8_t *dest, const uint8_t *src, size_t len, uint32_t cond);

/* ── Double Ratchet ───────────────────────────────────────── */
#define CX_RATCHET_KEY_BYTES   32
#define CX_RATCHET_MAX_MSGS    1024
#define CX_RATCHET_MAX_SKIPPED  128

typedef struct {
    uint8_t  root_key[CX_RATCHET_KEY_BYTES];
    uint8_t  send_chain_key[CX_RATCHET_KEY_BYTES];
    uint8_t  recv_chain_key[CX_RATCHET_KEY_BYTES];
    uint8_t  dh_public[CX_RATCHET_KEY_BYTES];
    uint8_t  dh_private[CX_RATCHET_KEY_BYTES];
    uint8_t  remote_dh_public[CX_RATCHET_KEY_BYTES];
    uint8_t  message_keys[CX_RATCHET_MAX_SKIPPED][CX_RATCHET_KEY_BYTES];
    uint32_t send_msg_num;
    uint32_t recv_msg_num;
    uint32_t prev_send_chain_len;
    uint32_t skipped_count;
} cx_double_ratchet_t;

int  cx_ratchet_init(cx_double_ratchet_t *ratchet,
                      const uint8_t shared_secret[CX_RATCHET_KEY_BYTES]);
int  cx_ratchet_send(cx_double_ratchet_t *ratchet,
                      uint8_t msg_key[CX_RATCHET_KEY_BYTES],
                      uint8_t header[CX_RATCHET_KEY_BYTES],
                      const uint8_t *pt, uint32_t pt_len,
                      uint8_t *ct);
int  cx_ratchet_recv(cx_double_ratchet_t *ratchet,
                      uint8_t msg_key[CX_RATCHET_KEY_BYTES],
                      const uint8_t header[CX_RATCHET_KEY_BYTES],
                      const uint8_t *ct, uint32_t ct_len,
                      uint8_t *pt);
int  cx_ratchet_dh_step(cx_double_ratchet_t *ratchet);
int  cx_ratchet_symmetric_ratchet(uint8_t chain_key[CX_RATCHET_KEY_BYTES],
                                    uint8_t msg_key[CX_RATCHET_KEY_BYTES]);
int  cx_ratchet_skip_message(cx_double_ratchet_t *ratchet,
                               const uint8_t msg_key[CX_RATCHET_KEY_BYTES]);

/* ── Ring Signatures ──────────────────────────────────────── */
#define CX_RING_MAX_MEMBERS     32
#define CX_RING_SIG_BYTES       128
#define CX_RING_KEY_BYTES        32

typedef struct {
    uint8_t  public_key[CX_RING_MAX_MEMBERS][CX_RING_KEY_BYTES];
    uint8_t  signature[CX_RING_SIG_BYTES];
    uint8_t  link_tag[CX_RING_KEY_BYTES];
    uint32_t num_members;
    uint32_t signer_index;
    uint32_t linkable;
} cx_ring_signature_t;

typedef struct {
    uint8_t  public_key[CX_RING_KEY_BYTES];
    uint8_t  secret_key[CX_RING_KEY_BYTES];
} cx_ring_keypair_t;

int  cx_ring_keygen(cx_ring_keypair_t *kp);
int  cx_ring_sign(cx_ring_signature_t *sig,
                   const uint8_t *msg, uint32_t msg_len,
                   const cx_ring_keypair_t *kp,
                   const uint8_t ring[CX_RING_MAX_MEMBERS][CX_RING_KEY_BYTES],
                   uint32_t num_members, uint32_t signer_index,
                   int linkable);
int  cx_ring_verify(const cx_ring_signature_t *sig,
                     const uint8_t *msg, uint32_t msg_len);
int  cx_ring_link(const cx_ring_signature_t *sig1,
                   const cx_ring_signature_t *sig2,
                   int *linked);

/* ── Cryptographic Accumulator ────────────────────────────── */
#define CX_ACCUM_MAX_ELEMENTS   256
#define CX_ACCUM_MOD_BITS       256

typedef struct {
    uint64_t accumulator;
    uint64_t modulus;
    uint64_t generator;
    uint32_t num_elements;
    uint64_t elements[CX_ACCUM_MAX_ELEMENTS];
} cx_accumulator_t;

typedef struct {
    uint64_t witness;
    uint64_t element;
    uint32_t valid;
} cx_accum_witness_t;

int  cx_accum_init(cx_accumulator_t *acc, uint64_t modulus);
int  cx_accum_insert(cx_accumulator_t *acc, uint64_t elem);
int  cx_accum_remove(cx_accumulator_t *acc, uint64_t elem);
int  cx_accum_gen_witness(cx_accum_witness_t *wit,
                            const cx_accumulator_t *acc, uint64_t elem);
int  cx_accum_verify_witness(const cx_accum_witness_t *wit,
                               const cx_accumulator_t *acc);
int  cx_accum_batch_verify(const cx_accum_witness_t *wits,
                             uint32_t count, const cx_accumulator_t *acc);

/* ── Threshold Decryption ─────────────────────────────────── */
#define CX_THRESH_MAX_PARTIES    16
#define CX_THRESH_KEY_BYTES      32

typedef struct {
    uint8_t  ciphertext[CX_THRESH_KEY_BYTES * 4];
    uint8_t  partial_decryptions[CX_THRESH_MAX_PARTIES][CX_THRESH_KEY_BYTES];
    uint8_t  combined[CX_THRESH_KEY_BYTES];
    uint32_t num_parties;
    uint32_t threshold;
    uint32_t received;
} cx_thresh_decrypt_t;

int  cx_thresh_encrypt(cx_thresh_decrypt_t *ctx,
                        const uint8_t *pt, uint32_t pt_len,
                        const uint8_t pubkey[CX_THRESH_KEY_BYTES]);
int  cx_thresh_partial_decrypt(uint8_t partial[CX_THRESH_KEY_BYTES],
                                const cx_thresh_decrypt_t *ctx,
                                const uint8_t sec_share[CX_THRESH_KEY_BYTES],
                                uint32_t party_id);
int  cx_thresh_combine(uint8_t *pt,
                         const cx_thresh_decrypt_t *ctx,
                         const uint32_t *party_ids, uint32_t num_shares);

/* ── Forward-Secure Key Evolving ──────────────────────────── */
#define CX_FSKE_MAX_EPOCHS       256
#define CX_FSKE_KEY_BYTES         32

typedef struct {
    uint8_t  current_key[CX_FSKE_KEY_BYTES];
    uint8_t  epoch_keys[CX_FSKE_MAX_EPOCHS][CX_FSKE_KEY_BYTES];
    uint32_t current_epoch;
    uint32_t max_epochs;
    uint32_t evolved;
} cx_forward_secure_t;

int  cx_fske_init(cx_forward_secure_t *fs, uint32_t max_epochs);
int  cx_fske_evolve(cx_forward_secure_t *fs);
int  cx_fske_get_key(uint8_t key[CX_FSKE_KEY_BYTES],
                       const cx_forward_secure_t *fs);
int  cx_fske_verify_evolution(const cx_forward_secure_t *fs);
int  cx_fske_is_compromised(const cx_forward_secure_t *fs, uint32_t epoch);

void cx_advanced_version(void);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_ADVANCED_H */
