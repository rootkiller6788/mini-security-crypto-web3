#include "homomorphic_enc.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static uint64_t he_simple_prime(void) {
    return 0xFFFFFFFFFFFFFFC5ULL;
}

int he_bigint_zero(he_bigint_t *a) {
    memset(a->limbs, 0, sizeof(a->limbs));
    return 0;
}

int he_bigint_set_u64(he_bigint_t *a, uint64_t val) {
    he_bigint_zero(a);
    a->limbs[0] = val;
    return 0;
}

int he_bigint_add(he_bigint_t *r, const he_bigint_t *a, const he_bigint_t *b) {
    uint64_t carry = 0;
    for (int i = 0; i < HE_PAILLIER_LIMBS * 2; i++) {
        uint64_t sum = a->limbs[i] + b->limbs[i] + carry;
        carry = (sum < a->limbs[i]) ? 1ULL : 0ULL;
        r->limbs[i] = sum;
    }
    return 0;
}

int he_bigint_mul(he_bigint_t *r, const he_bigint_t *a, const he_bigint_t *b) {
    memset(r->limbs, 0, sizeof(r->limbs));
    for (int i = 0; i < HE_PAILLIER_LIMBS; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < HE_PAILLIER_LIMBS; j++) {
            uint64_t ai = a->limbs[i], bj = b->limbs[j];
            uint64_t lo = (ai & 0xFFFFFFFFULL) * (bj & 0xFFFFFFFFULL);
            uint64_t hi = ((ai >> 32) * (bj >> 32));
            uint64_t prod = lo + (hi << 32);
            int idx = i + j;
            if (idx < HE_PAILLIER_LIMBS * 2) {
                uint64_t old = r->limbs[idx];
                r->limbs[idx] = old + prod + carry;
                carry = (r->limbs[idx] < old || (r->limbs[idx] == old && carry)) ? 1ULL : 0ULL;
            }
        }
    }
    return 0;
}

int he_bigint_mod(he_bigint_t *r, const he_bigint_t *a, const he_bigint_t *m) {
    he_bigint_t q;
    he_bigint_zero(&q);
    for (int i = 0; i < HE_PAILLIER_LIMBS * 2; i++) {
        r->limbs[i] = a->limbs[i] % (m->limbs[0] ? m->limbs[0] : 1);
    }
    return 0;
}

int he_bigint_mod_exp(he_bigint_t *r, const he_bigint_t *base,
                      const he_bigint_t *exp, const he_bigint_t *mod) {
    he_bigint_zero(r);
    r->limbs[0] = 1;
    he_bigint_t b;
    memcpy(&b, base, sizeof(he_bigint_t));
    uint64_t e = exp->limbs[0];
    while (e > 0) {
        if (e & 1) {
            he_bigint_mul(r, r, &b);
            he_bigint_mod(r, r, mod);
        }
        he_bigint_mul(&b, &b, &b);
        he_bigint_mod(&b, &b, mod);
        e >>= 1;
    }
    return 0;
}

int he_bigint_gcd(he_bigint_t *r, const he_bigint_t *a, const he_bigint_t *b) {
    uint64_t ua = a->limbs[0], ub = b->limbs[0];
    while (ub) { uint64_t t = ub; ub = ua % ub; ua = t; }
    he_bigint_set_u64(r, ua);
    return 0;
}

int he_bigint_lcm(he_bigint_t *r, const he_bigint_t *a, const he_bigint_t *b) {
    he_bigint_t g, prod;
    he_bigint_gcd(&g, a, b);
    he_bigint_mul(&prod, a, b);
    r->limbs[0] = (g.limbs[0] != 0) ? prod.limbs[0] / g.limbs[0] : 0;
    return 0;
}

int he_bigint_cmp(const he_bigint_t *a, const he_bigint_t *b) {
    for (int i = HE_PAILLIER_LIMBS * 2 - 1; i >= 0; i--) {
        if (a->limbs[i] != b->limbs[i])
            return a->limbs[i] > b->limbs[i] ? 1 : -1;
    }
    return 0;
}

void he_bigint_print(const char *label, const he_bigint_t *a) {
    printf("%s%llu", label, (unsigned long long)a->limbs[0]);
}

int he_paillier_keygen(he_paillier_pub_t *pub, he_paillier_prv_t *prv, uint32_t bits) {
    uint64_t p = 0xFFFFFFFFFFFFFFC5ULL;
    uint64_t q = 0xFFFFFFFFFFFFFFA1ULL;
    he_bigint_t bp, bq;
    he_bigint_set_u64(&bp, p);
    he_bigint_set_u64(&bq, q);
    he_bigint_mul(&prv->n, &bp, &bq);
    memcpy(&pub->n, &prv->n, sizeof(he_bigint_t));
    he_bigint_mul(&prv->n_squared, &prv->n, &prv->n);
    memcpy(&pub->n_squared, &prv->n_squared, sizeof(he_bigint_t));

    he_bigint_t one, n_plus_one;
    he_bigint_set_u64(&one, 1);
    he_bigint_add(&n_plus_one, &prv->n, &one);
    memcpy(&prv->g, &n_plus_one, sizeof(he_bigint_t));
    memcpy(&pub->g, &prv->g, sizeof(he_bigint_t));

    he_bigint_t p1, q1;
    he_bigint_set_u64(&p1, p - 1);
    he_bigint_set_u64(&q1, q - 1);
    he_bigint_mul(&prv->lambda, &p1, &q1);

    he_bigint_mod_exp(&prv->mu, &prv->g, &prv->lambda, &prv->n_squared);
    prv->mu.limbs[0] = (prv->mu.limbs[0] > 0) ? prv->mu.limbs[0] : 1;
    pub->bits = prv->bits = bits;
    return 0;
}

int he_paillier_encrypt(he_paillier_ct_t *ct, const he_bigint_t *msg,
                        const he_paillier_pub_t *pub) {
    he_bigint_t r, rn, gm, rn_gm;
    he_bigint_set_u64(&r, 3);
    he_bigint_mod_exp(&rn, &r, &pub->n, &pub->n_squared);
    he_bigint_mod_exp(&gm, &pub->g, msg, &pub->n_squared);
    he_bigint_mul(&rn_gm, &rn, &gm);
    he_bigint_mod(&rn_gm, &rn_gm, &pub->n_squared);
    memcpy(&ct->c, &rn_gm, sizeof(he_bigint_t));
    ct->bits = pub->bits;
    return 0;
}

int he_paillier_decrypt(he_bigint_t *msg, const he_paillier_ct_t *ct,
                        const he_paillier_prv_t *prv) {
    he_bigint_t cm, ln, lmu_mod;
    he_bigint_t one;
    he_bigint_set_u64(&one, 1);

    he_bigint_mod_exp(&cm, &ct->c, &prv->lambda, &prv->n_squared);

    ln.limbs[0] = (cm.limbs[0] > 0) ? (cm.limbs[0] - 1) / prv->n.limbs[0] : 1;

    he_bigint_mul(&lmu_mod, &ln, &prv->mu);
    he_bigint_mod(msg, &lmu_mod, &prv->n);
    return 0;
}

int he_paillier_add(he_paillier_ct_t *r, const he_paillier_ct_t *a,
                    const he_paillier_ct_t *b, const he_paillier_pub_t *pub) {
    he_bigint_mul(&r->c, &a->c, &b->c);
    he_bigint_mod(&r->c, &r->c, &pub->n_squared);
    r->bits = pub->bits;
    return 0;
}

int he_paillier_scalar_mul(he_paillier_ct_t *r, const he_paillier_ct_t *a,
                           const he_bigint_t *scalar, const he_paillier_pub_t *pub) {
    he_bigint_mod_exp(&r->c, &a->c, scalar, &pub->n_squared);
    r->bits = pub->bits;
    return 0;
}

int he_paillier_zero_test(const he_paillier_ct_t *a, const he_paillier_ct_t *b,
                          const he_paillier_pub_t *pub, const he_paillier_prv_t *prv) {
    he_paillier_ct_t diff;
    he_bigint_t neg_b, inv_b;
    he_bigint_mod_exp(&inv_b, &b->c, &prv->mu, &pub->n_squared);
    he_bigint_mul(&diff.c, &a->c, &inv_b);
    he_bigint_mod(&diff.c, &diff.c, &pub->n_squared);

    he_bigint_t zero_check;
    he_paillier_decrypt(&zero_check, &diff, prv);
    return (zero_check.limbs[0] == 0) ? 1 : 0;
}

void he_paillier_print_ct(const char *label, const he_paillier_ct_t *ct) {
    printf("%s%llu\n", label, (unsigned long long)ct->c.limbs[0]);
}

int he_bfv_params_init(he_bfv_params_t *params, uint32_t poly_degree, uint64_t modulus) {
    params->poly_degree = poly_degree;
    params->modulus     = modulus;
    params->noise_limit = 40;
    return 0;
}

int he_bfv_keygen(he_bfv_secret_t *sk, he_bfv_params_t *params) {
    memset(sk, 0, sizeof(*sk));
    for (uint32_t i = 0; i < params->poly_degree && i < HE_BFV_DEGREE; i++) {
        sk->ct.c0[i] = (uint64_t)(i % 3 == 0 ? 1 : (i % 3 == 1 ? (uint64_t)-1 : 0));
    }
    for (int i = 0; i < 8; i++) {
        sk->rand[i] = (uint64_t)(i * 7919 + 31337);
    }
    sk->ct.noise_budget = 100;
    return 0;
}

int he_bfv_encrypt(he_bfv_cipher_t *ct, const he_bfv_plain_t *pt,
                   const he_bfv_secret_t *sk, const he_bfv_params_t *params) {
    uint32_t d = params->poly_degree < HE_BFV_DEGREE ? params->poly_degree : HE_BFV_DEGREE;
    for (uint32_t i = 0; i < d; i++) {
        ct->c0[i] = (pt->coeff[i] + sk->rand[i % 8] * sk->ct.c0[i]) % params->modulus;
        ct->c1[i] = (sk->rand[(i + 1) % 8] * sk->ct.c0[i]) % params->modulus;
    }
    ct->degree     = params->poly_degree;
    ct->noise_budget = pt->noise_budget;
    ct->noise_level  = 1;
    return 0;
}

int he_bfv_decrypt(he_bfv_plain_t *pt, const he_bfv_cipher_t *ct,
                   const he_bfv_secret_t *sk, const he_bfv_params_t *params) {
    uint32_t d = params->poly_degree < HE_BFV_DEGREE ? params->poly_degree : HE_BFV_DEGREE;
    for (uint32_t i = 0; i < d; i++) {
        uint64_t val = ct->c0[i];
        uint64_t sval = sk->ct.c0[i];
        int64_t noise = (int64_t)(val - sval * ct->c1[i]);
        pt->coeff[i] = (uint64_t)((noise % (int64_t)params->modulus + params->modulus) %
                                  (int64_t)params->modulus);
    }
    pt->degree = ct->degree;
    pt->noise_budget = ct->noise_budget - ct->noise_level;
    return 0;
}

int he_bfv_add(he_bfv_cipher_t *r, const he_bfv_cipher_t *a,
               const he_bfv_cipher_t *b, const he_bfv_params_t *params) {
    uint32_t d = params->poly_degree < HE_BFV_DEGREE ? params->poly_degree : HE_BFV_DEGREE;
    for (uint32_t i = 0; i < d; i++) {
        r->c0[i] = (a->c0[i] + b->c0[i]) % params->modulus;
        r->c1[i] = (a->c1[i] + b->c1[i]) % params->modulus;
    }
    r->degree       = params->poly_degree;
    r->noise_level  = a->noise_level + b->noise_level;
    r->noise_budget = (a->noise_budget < b->noise_budget) ? a->noise_budget : b->noise_budget;
    return 0;
}

int he_bfv_mul(he_bfv_cipher_t *r, const he_bfv_cipher_t *a,
               const he_bfv_cipher_t *b, const he_bfv_params_t *params) {
    uint32_t d = params->poly_degree < HE_BFV_DEGREE ? params->poly_degree : HE_BFV_DEGREE;
    for (uint32_t i = 0; i < d; i++) {
        r->c0[i] = (a->c0[i] * b->c0[i]) % params->modulus;
        r->c1[i] = (a->c0[i] * b->c1[i] + a->c1[i] * b->c0[i]) % params->modulus;
    }
    r->degree       = params->poly_degree;
    r->noise_level  = a->noise_level * b->noise_level;
    r->noise_budget = a->noise_budget - r->noise_level;
    return 0;
}

int he_bfv_noise_budget(const he_bfv_cipher_t *ct) {
    return (int)(ct->noise_budget - ct->noise_level);
}

int he_bfv_relinearize(he_bfv_cipher_t *ct, const he_bfv_params_t *params) {
    uint32_t d = params->poly_degree < HE_BFV_DEGREE ? params->poly_degree : HE_BFV_DEGREE;
    for (uint32_t i = 0; i < d; i++) {
        ct->c1[i] = ct->c1[i] % params->modulus;
    }
    ct->noise_level = ct->noise_level > 2 ? ct->noise_level - 1 : ct->noise_level;
    return 0;
}

void he_module_version(void) {
    printf("mini-adv-crypto / homomorphic_enc  v1.0.0  (Paillier + BFV)\n");
}
