#ifndef HOMOMORPHIC_ENC_H
#define HOMOMORPHIC_ENC_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HE_PAILLIER_BITS  2048
#define HE_PAILLIER_LIMBS ((HE_PAILLIER_BITS + 63) / 64)
#define HE_BFV_DEGREE     1024
#define HE_BFV_MOD_BITS   60
#define HE_NOISE_WARN     40

typedef struct {
    uint64_t limbs[HE_PAILLIER_LIMBS * 2];
} he_bigint_t;

typedef struct {
    he_bigint_t n;
    he_bigint_t n_squared;
    he_bigint_t g;
    he_bigint_t lambda;
    he_bigint_t mu;
    uint32_t    bits;
} he_paillier_prv_t;

typedef struct {
    he_bigint_t n;
    he_bigint_t n_squared;
    he_bigint_t g;
    uint32_t    bits;
} he_paillier_pub_t;

typedef struct {
    he_bigint_t c;
    uint32_t    bits;
} he_paillier_ct_t;

typedef struct {
    uint64_t coeff[HE_BFV_DEGREE];
    uint32_t degree;
    uint32_t noise_budget;
} he_bfv_plain_t;

typedef struct {
    uint64_t c0[HE_BFV_DEGREE];
    uint64_t c1[HE_BFV_DEGREE];
    uint32_t degree;
    uint32_t noise_level;
    uint32_t noise_budget;
} he_bfv_cipher_t;

typedef struct {
    uint64_t modulus;
    uint32_t poly_degree;
    uint32_t noise_limit;
} he_bfv_params_t;

typedef struct {
    he_bfv_cipher_t ct;
    uint64_t        rand[8];
} he_bfv_secret_t;

typedef enum {
    HE_SCHEME_PAILLIER = 0,
    HE_SCHEME_BFV      = 1,
    HE_SCHEME_BGV      = 2,
    HE_SCHEME_CKKS     = 3
} he_scheme_t;

int  he_bigint_zero(he_bigint_t *a);
int  he_bigint_set_u64(he_bigint_t *a, uint64_t val);
int  he_bigint_add(he_bigint_t *r, const he_bigint_t *a, const he_bigint_t *b);
int  he_bigint_mul(he_bigint_t *r, const he_bigint_t *a, const he_bigint_t *b);
int  he_bigint_mod(he_bigint_t *r, const he_bigint_t *a, const he_bigint_t *m);
int  he_bigint_mod_exp(he_bigint_t *r, const he_bigint_t *base,
                       const he_bigint_t *exp, const he_bigint_t *mod);
int  he_bigint_gcd(he_bigint_t *r, const he_bigint_t *a, const he_bigint_t *b);
int  he_bigint_lcm(he_bigint_t *r, const he_bigint_t *a, const he_bigint_t *b);
int  he_bigint_cmp(const he_bigint_t *a, const he_bigint_t *b);
void he_bigint_print(const char *label, const he_bigint_t *a);

int  he_paillier_keygen(he_paillier_pub_t *pub, he_paillier_prv_t *prv, uint32_t bits);
int  he_paillier_encrypt(he_paillier_ct_t *ct, const he_bigint_t *msg,
                         const he_paillier_pub_t *pub);
int  he_paillier_decrypt(he_bigint_t *msg, const he_paillier_ct_t *ct,
                         const he_paillier_prv_t *prv);
int  he_paillier_add(he_paillier_ct_t *r, const he_paillier_ct_t *a,
                     const he_paillier_ct_t *b, const he_paillier_pub_t *pub);
int  he_paillier_scalar_mul(he_paillier_ct_t *r, const he_paillier_ct_t *a,
                            const he_bigint_t *scalar, const he_paillier_pub_t *pub);
int  he_paillier_zero_test(const he_paillier_ct_t *a, const he_paillier_ct_t *b,
                           const he_paillier_pub_t *pub, const he_paillier_prv_t *prv);
void he_paillier_print_ct(const char *label, const he_paillier_ct_t *ct);

int  he_bfv_params_init(he_bfv_params_t *params, uint32_t poly_degree, uint64_t modulus);
int  he_bfv_keygen(he_bfv_secret_t *sk, he_bfv_params_t *params);
int  he_bfv_encrypt(he_bfv_cipher_t *ct, const he_bfv_plain_t *pt,
                    const he_bfv_secret_t *sk, const he_bfv_params_t *params);
int  he_bfv_decrypt(he_bfv_plain_t *pt, const he_bfv_cipher_t *ct,
                    const he_bfv_secret_t *sk, const he_bfv_params_t *params);
int  he_bfv_add(he_bfv_cipher_t *r, const he_bfv_cipher_t *a,
                const he_bfv_cipher_t *b, const he_bfv_params_t *params);
int  he_bfv_mul(he_bfv_cipher_t *r, const he_bfv_cipher_t *a,
                const he_bfv_cipher_t *b, const he_bfv_params_t *params);
int  he_bfv_noise_budget(const he_bfv_cipher_t *ct);
int  he_bfv_relinearize(he_bfv_cipher_t *ct, const he_bfv_params_t *params);

void      he_module_version(void);

#ifdef __cplusplus
}
#endif

#endif
