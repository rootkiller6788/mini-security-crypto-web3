#ifndef CRYPTO_THEOREMS_H
#define CRYPTO_THEOREMS_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ────────────────────────────────────────────────────────────
 * L4: Standards/Theorems — 密码学核心定理验证
 *
 * 覆盖定理:
 *   1. Shannon's Perfect Secrecy (1949)
 *   2. Goldwasser-Micali Semantic Security (1982)
 *   3. IND-CPA / IND-CCA Security Games
 *   4. Learning With Errors (LWE) Hardness (Regev 2005)
 *   5. Decision Diffie-Hellman (DDH) Assumption
 *   6. Fiat-Shamir Heuristic (1986)
 *   7. Forking Lemma (Pointcheval-Stern 1996)
 *   8. Birthday Paradox / Collision Bound
 *   9. Random Oracle Model (Bellare-Rogaway 1993)
 *  10. Hybrid Argument (Goldreich)
 * ──────────────────────────────────────────────────────────── */

/* ── Shannon's Perfect Secrecy ───────────────────────────── */
#define SHANNON_KEY_BITS    256
#define SHANNON_KEY_BYTES   (SHANNON_KEY_BITS / 8)
#define SHANNON_MAX_MSG     2048

typedef struct {
    uint8_t  key[SHANNON_KEY_BYTES];
    uint8_t  ciphertext[SHANNON_MAX_MSG];
    uint8_t  plaintext[SHANNON_MAX_MSG];
    uint32_t msg_len;
    uint32_t key_len;
} ct_otp_scheme_t;

int  ct_otp_encrypt(ct_otp_scheme_t *otp, const uint8_t *msg, uint32_t msg_len);
int  ct_otp_decrypt(uint8_t *msg, const ct_otp_scheme_t *otp, uint32_t msg_len);
int  ct_shannon_verify(const ct_otp_scheme_t *otp);

/* ── IND-CPA Security Game ───────────────────────────────── */
#define CT_IND_QUERIES      256
#define CT_IND_MSG_BITS     128

typedef struct {
    uint64_t pk[4];
    uint64_t sk[4];
    uint64_t challenge_ct[4];
    uint32_t challenge_bit;
    uint32_t queries_made;
    uint32_t game_state;
} ct_ind_cpa_game_t;

typedef struct {
    uint64_t pk[4];
    uint64_t ct[4];
    uint8_t  oracle_access;
    uint32_t advantage_numer;
    uint32_t advantage_denom;
} ct_ind_adversary_t;

int  ct_ind_cpa_init(ct_ind_cpa_game_t *game);
int  ct_ind_cpa_challenge(ct_ind_cpa_game_t *game,
                          const uint64_t m0[4], const uint64_t m1[4]);
int  ct_ind_cpa_guess(ct_ind_cpa_game_t *game, uint32_t guess, double *advantage);
int  ct_ind_cpa_encrypt(uint64_t ct[4], const uint64_t pt[4], const uint64_t pk[4]);
int  ct_ind_cpa_decrypt(uint64_t pt[4], const uint64_t ct[4], const uint64_t sk[4]);

/* ── LWE Hardness ────────────────────────────────────────── */
#define CT_LWE_DIM          256
#define CT_LWE_MODULUS      4093
#define CT_LWE_ERROR_STD    3
#define CT_LWE_SAMPLES      512

typedef struct {
    int16_t  A[CT_LWE_SAMPLES][CT_LWE_DIM];
    int16_t  b[CT_LWE_SAMPLES];
    int16_t  s[CT_LWE_DIM];
    int16_t  error[CT_LWE_SAMPLES];
    uint32_t dim;
    uint32_t num_samples;
    int32_t  modulus;
} ct_lwe_problem_t;

int  ct_lwe_gen_secret(ct_lwe_problem_t *lwe, uint32_t dim, int32_t mod);
int  ct_lwe_gen_samples(ct_lwe_problem_t *lwe, uint32_t num_samples);
int  ct_lwe_is_lwe_sample(const ct_lwe_problem_t *lwe, uint32_t idx);
int  ct_lwe_advantage_bound(const ct_lwe_problem_t *lwe, double *bound);

/* ── DDH Assumption ──────────────────────────────────────── */
#define CT_DDH_BITS         256
#define CT_DDH_PRIME        0xFFFFFFFFFFFFFFC5ULL

typedef struct {
    uint64_t g;
    uint64_t p;
    uint64_t g_a;
    uint64_t g_b;
    uint64_t g_c;
    uint32_t is_dh;
} ct_ddh_tuple_t;

int  ct_ddh_gen_tuple(ct_ddh_tuple_t *t, int is_real_dh);
int  ct_ddh_distinguish(const ct_ddh_tuple_t *triples, uint32_t count,
                        uint32_t *correct, uint32_t *total);
int  ct_ddh_mod_exp(uint64_t *r, uint64_t base, uint64_t exp, uint64_t mod);

/* ── Fiat-Shamir Transform ────────────────────────────────── */
#define CT_FS_CHALLENGE_BITS 256
#define CT_FS_PROOF_BYTES    128

typedef struct {
    uint8_t  statement[64];
    uint8_t  commitment[64];
    uint8_t  challenge[32];
    uint8_t  response[64];
    uint32_t stmt_len;
    uint32_t round;
} ct_fs_sigma_protocol_t;

int  ct_fs_sigma_commit(ct_fs_sigma_protocol_t *sigma,
                        const uint8_t *stmt, uint32_t stmt_len);
int  ct_fs_sigma_challenge(ct_fs_sigma_protocol_t *sigma);
int  ct_fs_sigma_response(ct_fs_sigma_protocol_t *sigma,
                          const uint8_t *witness, uint32_t wit_len);
int  ct_fs_sigma_verify(const ct_fs_sigma_protocol_t *sigma);
int  ct_fs_hash_to_challenge(uint8_t chal[32], const uint8_t *input, uint32_t len);

/* ── Forking Lemma ───────────────────────────────────────── */
#define CT_FORK_MAX_TRIES   1000
#define CT_FORK_PROOF_LEN   256

typedef struct {
    uint8_t  proof1[CT_FORK_PROOF_LEN];
    uint8_t  proof2[CT_FORK_PROOF_LEN];
    uint8_t  challenge1[32];
    uint8_t  challenge2[32];
    uint32_t proof_len;
    uint32_t success;
    uint32_t tries;
} ct_fork_extractor_t;

int  ct_fork_simulate(ct_fork_extractor_t *ext, uint32_t proof_len);
int  ct_fork_extract(ct_fork_extractor_t *ext,
                     const uint8_t *pubkey, uint32_t pk_len,
                     uint8_t *secret, uint32_t *sec_len);
int  ct_fork_probability_bound(uint32_t q_hash, double epsilon,
                               double *prob_extract);

/* ── Birthday Bound ──────────────────────────────────────── */
#define CT_BIRTHDAY_HASH_BITS 64
#define CT_BIRTHDAY_MAX_TRIES 0xFFFFFFFF

typedef struct {
    uint64_t hashes[CT_BIRTHDAY_MAX_TRIES / 64];
    uint32_t bits;
    uint32_t count;
    uint32_t collision_found;
    uint64_t collision_val;
} ct_birthday_ctx_t;

int  ct_birthday_init(ct_birthday_ctx_t *ctx, uint32_t hash_bits);
int  ct_birthday_add(ct_birthday_ctx_t *ctx, uint64_t hash_val);
int  ct_birthday_probability(uint32_t num_tries, uint32_t hash_bits,
                              double *prob);
int  ct_birthday_threshold(uint32_t hash_bits, double target_prob,
                            uint32_t *needed_tries);

/* ── Hybrid Argument ──────────────────────────────────────── */
typedef struct {
    uint32_t num_hybrids;
    uint32_t current_hybrid;
    double   advantage_per_hop;
    double   total_advantage;
} ct_hybrid_argument_t;

int  ct_hybrid_init(ct_hybrid_argument_t *hyb, uint32_t num_hybrids);
int  ct_hybrid_step(ct_hybrid_argument_t *hyb, double step_advantage);
int  ct_hybrid_total(double *total, const ct_hybrid_argument_t *hyb);
int  ct_hybrid_is_negligible(const ct_hybrid_argument_t *hyb, double epsilon);

void ct_theorems_version(void);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_THEOREMS_H */
