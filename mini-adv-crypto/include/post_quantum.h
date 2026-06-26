#ifndef POST_QUANTUM_H
#define POST_QUANTUM_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQ_KYBER_N          256
#define PQ_KYBER_Q          3329
#define PQ_KYBER_ETA        2
#define PQ_KYBER_DU         10
#define PQ_KYBER_DV         4
#define PQ_KYBER_PK_BYTES   800
#define PQ_KYBER_SK_BYTES  1632
#define PQ_KYBER_CT_BYTES   768
#define PQ_KYBER_SS_BYTES   32
#define PQ_KYBER_SYMBYTES   32

#define PQ_DILITHIUM_N      256
#define PQ_DILITHIUM_Q      8380417
#define PQ_DILITHIUM_TAU    39
#define PQ_DILITHIUM_GAMMA1 131072
#define PQ_DILITHIUM_GAMMA2 95232
#define PQ_DILITHIUM_PK_BYTES 1312
#define PQ_DILITHIUM_SK_BYTES 2528
#define PQ_DILITHIUM_SIG_BYTES 2420

#define PQ_SPHINCS_H        64
#define PQ_SPHINCS_T        512
#define PQ_SPHINCS_K        32
#define PQ_SPHINCS_W        256
#define PQ_SPHINCS_H_BYTES  ((PQ_SPHINCS_H + 7) / 8)
#define PQ_SPHINCS_SIG_BYTES 7856
#define PQ_SPHINCS_PK_BYTES  32

typedef struct {
    int16_t coeffs[PQ_KYBER_N];
} pq_poly_t;

typedef struct {
    pq_poly_t vec[2];
} pq_polyvec2_t;

typedef struct {
    pq_poly_t vec[3];
} pq_polyvec3_t;

typedef struct {
    pq_polyvec2_t t;
    pq_polyvec3_t a;
    uint8_t       seed[PQ_KYBER_SYMBYTES];
    uint8_t       hpk[PQ_KYBER_PK_BYTES];
} pq_kyber_pk_t;

typedef struct {
    pq_polyvec2_t s;
    pq_polyvec3_t a;
    uint8_t       seed[PQ_KYBER_SYMBYTES];
    uint8_t       hpk[PQ_KYBER_SK_BYTES - PQ_KYBER_PK_BYTES];
} pq_kyber_sk_t;

typedef struct {
    pq_polyvec2_t u;
    pq_poly_t     v;
    uint32_t      mlwe_error;
} pq_kyber_ct_t;

typedef struct {
    pq_poly_t s1[5];
    pq_poly_t s2[5];
    pq_poly_t t0[5];
    pq_poly_t t1[5];
    uint8_t   seed[PQ_KYBER_SYMBYTES];
    uint8_t   tr[PQ_KYBER_SYMBYTES];
} pq_dilithium_sk_t;

typedef struct {
    pq_poly_t t1[5];
    uint8_t   seed[PQ_KYBER_SYMBYTES];
} pq_dilithium_pk_t;

typedef struct {
    pq_poly_t z[5];
    int32_t   c[PQ_KYBER_N];
    pq_poly_t h[5];
    uint32_t  hint_count;
} pq_dilithium_sig_t;

typedef struct {
    uint8_t leaf[PQ_SPHINCS_H_BYTES];
    uint8_t hash_state[64];
    uint32_t index;
    uint32_t height;
    uint32_t leaf_count;
} pq_sphincs_leaf_t;

typedef struct {
    uint8_t seed[PQ_SPHINCS_PK_BYTES];
    uint8_t root[PQ_SPHINCS_PK_BYTES];
    uint8_t path[PQ_SPHINCS_T][PQ_SPHINCS_H_BYTES];
    uint32_t num_leaves;
    uint32_t num_paths;
} pq_sphincs_sk_t;

typedef struct {
    uint8_t root[PQ_SPHINCS_PK_BYTES];
} pq_sphincs_pk_t;

typedef struct {
    uint8_t sig_data[PQ_SPHINCS_SIG_BYTES];
    uint32_t sig_len;
} pq_sphincs_sig_t;

typedef enum {
    PQ_KEM_KYBER512    = 0,
    PQ_KEM_KYBER768    = 1,
    PQ_KEM_KYBER1024   = 2,
    PQ_SIG_DILITHIUM2  = 3,
    PQ_SIG_DILITHIUM3  = 4,
    PQ_SIG_DILITHIUM5  = 5,
    PQ_SIG_SPHINCS128  = 6,
    PQ_SIG_SPHINCS192  = 7,
    PQ_SIG_SPHINCS256  = 8
} pq_algorithm_t;

void pq_poly_init(pq_poly_t *p);
int  pq_poly_ntt(pq_poly_t *p);
int  pq_poly_invntt(pq_poly_t *p);
int  pq_poly_add(pq_poly_t *r, const pq_poly_t *a, const pq_poly_t *b);
int  pq_poly_sub(pq_poly_t *r, const pq_poly_t *a, const pq_poly_t *b);
int  pq_poly_mul(pq_poly_t *r, const pq_poly_t *a, const pq_poly_t *b);
int  pq_poly_reduce(pq_poly_t *p);
void pq_poly_cbd(pq_poly_t *p, const uint8_t *seed, uint32_t eta);

int  pq_kyber_keygen(pq_kyber_pk_t *pk, pq_kyber_sk_t *sk);
int  pq_kyber_encaps(pq_kyber_ct_t *ct, uint8_t shared_secret[PQ_KYBER_SS_BYTES],
                     const pq_kyber_pk_t *pk);
int  pq_kyber_decaps(uint8_t shared_secret[PQ_KYBER_SS_BYTES],
                     const pq_kyber_ct_t *ct, const pq_kyber_sk_t *sk);
int  pq_kyber_indcpa_enc(pq_kyber_ct_t *ct, const pq_polyvec2_t *m,
                         const pq_kyber_pk_t *pk, const uint8_t coins[PQ_KYBER_SYMBYTES]);
int  pq_kyber_indcpa_dec(pq_polyvec2_t *m, const pq_kyber_ct_t *ct,
                         const pq_kyber_sk_t *sk);

int  pq_dilithium_keygen(pq_dilithium_pk_t *pk, pq_dilithium_sk_t *sk);
int  pq_dilithium_sign(pq_dilithium_sig_t *sig, uint32_t *siglen,
                       const uint8_t *msg, uint32_t msglen,
                       const pq_dilithium_sk_t *sk);
int  pq_dilithium_verify(const pq_dilithium_sig_t *sig,
                         const uint8_t *msg, uint32_t msglen,
                         const pq_dilithium_pk_t *pk);
void pq_dilithium_rej_sampling(pq_poly_t *y, uint32_t gamma);

int  pq_sphincs_keygen(pq_sphincs_pk_t *pk, pq_sphincs_sk_t *sk);
int  pq_sphincs_sign(pq_sphincs_sig_t *sig, const uint8_t *msg, uint32_t msglen,
                     const pq_sphincs_sk_t *sk);
int  pq_sphincs_verify(const pq_sphincs_sig_t *sig, const uint8_t *msg,
                       uint32_t msglen, const pq_sphincs_pk_t *pk);
int  pq_sphincs_ht_sign(uint8_t *sig, const pq_sphincs_sk_t *sk, uint32_t idx);
int  pq_sphincs_ht_verify(const uint8_t *sig, const pq_sphincs_pk_t *pk, uint32_t idx);

int  pq_mlwe_sample(pq_poly_t *s, const uint8_t seed[PQ_KYBER_SYMBYTES]);
int  pq_mlwr_round(pq_poly_t *r, const pq_poly_t *s);
int  pq_mlwe_encrypt(pq_polyvec2_t *u, pq_poly_t *v,
                     const pq_polyvec3_t *t, const pq_polyvec2_t *m,
                     const uint8_t coins[PQ_KYBER_SYMBYTES]);

void pq_module_version(void);

#ifdef __cplusplus
}
#endif

#endif
