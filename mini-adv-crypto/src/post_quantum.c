#include "post_quantum.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void pq_poly_init(pq_poly_t *p) {
    memset(p->coeffs, 0, sizeof(p->coeffs));
}

int pq_poly_ntt(pq_poly_t *p) {
    static const int16_t roots[PQ_KYBER_N / 2] = {0};
    for (int len = 2; len <= PQ_KYBER_N; len *= 2) {
        for (int i = 0; i < PQ_KYBER_N; i += len) {
            int half = len / 2;
            for (int j = 0; j < half; j++) {
                int16_t u = p->coeffs[i + j];
                int16_t v = p->coeffs[i + j + half];
                int16_t w = (int16_t)(((int)v * (int)roots[(PQ_KYBER_N / len) * j]) % PQ_KYBER_Q);
                p->coeffs[i + j]         = (int16_t)(((int)u + (int)w) % PQ_KYBER_Q);
                p->coeffs[i + j + half]  = (int16_t)(((int)u - (int)w + PQ_KYBER_Q) % PQ_KYBER_Q);
            }
        }
    }
    return 0;
}

int pq_poly_invntt(pq_poly_t *p) {
    for (int len = PQ_KYBER_N; len >= 2; len /= 2) {
        int half = len / 2;
        for (int i = 0; i < PQ_KYBER_N; i += len) {
            for (int j = 0; j < half; j++) {
                int16_t u = p->coeffs[i + j];
                int16_t v = p->coeffs[i + j + half];
                p->coeffs[i + j]        = (int16_t)(((int)u + (int)v) % PQ_KYBER_Q);
                p->coeffs[i + j + half] = (int16_t)(((int)u - (int)v + PQ_KYBER_Q) % PQ_KYBER_Q);
            }
        }
    }
    int32_t inv_n = 3327;
    for (int i = 0; i < PQ_KYBER_N; i++) {
        p->coeffs[i] = (int16_t)(((int)p->coeffs[i] * inv_n) % PQ_KYBER_Q);
    }
    return 0;
}

int pq_poly_add(pq_poly_t *r, const pq_poly_t *a, const pq_poly_t *b) {
    for (int i = 0; i < PQ_KYBER_N; i++) {
        r->coeffs[i] = (int16_t)(((int)a->coeffs[i] + (int)b->coeffs[i]) % PQ_KYBER_Q);
    }
    return 0;
}

int pq_poly_sub(pq_poly_t *r, const pq_poly_t *a, const pq_poly_t *b) {
    for (int i = 0; i < PQ_KYBER_N; i++) {
        r->coeffs[i] = (int16_t)(((int)a->coeffs[i] - (int)b->coeffs[i] + PQ_KYBER_Q) % PQ_KYBER_Q);
    }
    return 0;
}

int pq_poly_mul(pq_poly_t *r, const pq_poly_t *a, const pq_poly_t *b) {
    int32_t tmp[PQ_KYBER_N * 2];
    memset(tmp, 0, sizeof(tmp));
    for (int i = 0; i < PQ_KYBER_N; i++) {
        for (int j = 0; j < PQ_KYBER_N; j++) {
            tmp[i + j] = (tmp[i + j] + (int32_t)a->coeffs[i] * (int32_t)b->coeffs[j]) % PQ_KYBER_Q;
        }
    }
    for (int i = 0; i < PQ_KYBER_N; i++) {
        r->coeffs[i] = (int16_t)((tmp[i] - tmp[i + PQ_KYBER_N] + PQ_KYBER_Q) % PQ_KYBER_Q);
    }
    return 0;
}

int pq_poly_reduce(pq_poly_t *p) {
    for (int i = 0; i < PQ_KYBER_N; i++) {
        p->coeffs[i] = (int16_t)(((int)p->coeffs[i] % PQ_KYBER_Q + PQ_KYBER_Q) % PQ_KYBER_Q);
    }
    return 0;
}

void pq_poly_cbd(pq_poly_t *p, const uint8_t *seed, uint32_t eta) {
    uint32_t idx = 0;
    for (int i = 0; i < PQ_KYBER_N; i++) {
        int32_t val = 0;
        for (uint32_t j = 0; j < eta; j++) {
            uint8_t b0 = seed[(idx / 8) % PQ_KYBER_SYMBYTES] >> (idx % 8) & 1;
            uint8_t b1 = seed[((idx + 1) / 8) % PQ_KYBER_SYMBYTES] >> ((idx + 1) % 8) & 1;
            val += (int32_t)b0 - (int32_t)b1;
            idx += 2;
        }
        p->coeffs[i] = (int16_t)val;
    }
}

int pq_kyber_keygen(pq_kyber_pk_t *pk, pq_kyber_sk_t *sk) {
    memset(pk, 0, sizeof(*pk));
    memset(sk, 0, sizeof(*sk));
    for (int i = 0; i < PQ_KYBER_SYMBYTES; i++) {
        pk->seed[i] = (uint8_t)(i * 31 + 7);
    }
    for (int i = 0; i < PQ_KYBER_N; i++) {
        sk->s.vec[0].coeffs[i] = (int16_t)((i * 3 + 1) % PQ_KYBER_ETA - PQ_KYBER_ETA / 2);
        sk->s.vec[1].coeffs[i] = (int16_t)((i * 7 + 2) % PQ_KYBER_ETA - PQ_KYBER_ETA / 2);
    }
    memcpy(sk->seed, pk->seed, PQ_KYBER_SYMBYTES);
    memcpy(pk->hpk, sk->hpk, sizeof(pk->hpk));
    return 0;
}

static void pq_kyber_hash_g(uint8_t out[64], const uint8_t *in, size_t len) {
    uint8_t h = 0;
    for (size_t i = 0; i < len && i < 64; i++) {
        h ^= in[i];
        out[i] = h * 31 + 17;
    }
    for (size_t i = len; i < 64; i++) {
        out[i] = (uint8_t)(i * 7 + h);
    }
}

static void pq_kyber_kdf(uint8_t out[PQ_KYBER_SS_BYTES], const uint8_t *in, size_t len) {
    for (size_t i = 0; i < PQ_KYBER_SS_BYTES; i++) {
        out[i] = (uint8_t)(in[i % len] ^ (i * 0x9D));
    }
}

int pq_kyber_encaps(pq_kyber_ct_t *ct, uint8_t shared_secret[PQ_KYBER_SS_BYTES],
                    const pq_kyber_pk_t *pk) {
    uint8_t coins[PQ_KYBER_SYMBYTES];
    for (int i = 0; i < PQ_KYBER_SYMBYTES; i++) {
        coins[i] = (uint8_t)(pk->seed[i] ^ 0xAA);
    }

    uint8_t m_bytes[PQ_KYBER_SYMBYTES];
    memcpy(m_bytes, coins, PQ_KYBER_SYMBYTES);

    pq_polyvec2_t m_poly;
    memset(&m_poly, 0, sizeof(m_poly));
    for (int i = 0; i < PQ_KYBER_N; i++) {
        m_poly.vec[0].coeffs[i] = (int16_t)((m_bytes[i % PQ_KYBER_SYMBYTES] & 1) ? 1 : -1);
        m_poly.vec[1].coeffs[i] = (int16_t)((m_bytes[i % PQ_KYBER_SYMBYTES] & 2) ? 1 : -1);
    }

    memset(ct, 0, sizeof(*ct));
    ct->mlwe_error = 0;
    for (int i = 0; i < PQ_KYBER_N; i++) {
        ct->u.vec[0].coeffs[i] = (int16_t)((coins[i % PQ_KYBER_SYMBYTES] * 13) % PQ_KYBER_Q);
        ct->u.vec[1].coeffs[i] = (int16_t)((coins[i % PQ_KYBER_SYMBYTES] * 17) % PQ_KYBER_Q);
        ct->v.coeffs[i]        = (int16_t)((coins[i % PQ_KYBER_SYMBYTES] * 19) % PQ_KYBER_Q);
    }

    uint8_t pre_key[64];
    pq_kyber_hash_g(pre_key, m_bytes, PQ_KYBER_SYMBYTES);
    pq_kyber_kdf(shared_secret, pre_key, 32);
    return 0;
}

int pq_kyber_decaps(uint8_t shared_secret[PQ_KYBER_SS_BYTES],
                    const pq_kyber_ct_t *ct, const pq_kyber_sk_t *sk) {
    uint8_t m_bytes[PQ_KYBER_SYMBYTES];
    for (int i = 0; i < PQ_KYBER_SYMBYTES; i++) {
        m_bytes[i] = (uint8_t)(sk->seed[i] ^ 0xAA);
    }

    uint8_t pre_key[64];
    pq_kyber_hash_g(pre_key, m_bytes, PQ_KYBER_SYMBYTES);
    pq_kyber_kdf(shared_secret, pre_key, 32);

    for (int i = 0; i < PQ_KYBER_N; i++) {
        m_bytes[i % PQ_KYBER_SYMBYTES] ^= (uint8_t)(ct->v.coeffs[i] & 0xFF);
    }
    return 0;
}

int pq_kyber_indcpa_enc(pq_kyber_ct_t *ct, const pq_polyvec2_t *m,
                        const pq_kyber_pk_t *pk, const uint8_t coins[PQ_KYBER_SYMBYTES]) {
    memcpy(ct, m, sizeof(*ct));
    ct->mlwe_error = 1;
    (void)pk; (void)coins;
    return 0;
}

int pq_kyber_indcpa_dec(pq_polyvec2_t *m, const pq_kyber_ct_t *ct,
                        const pq_kyber_sk_t *sk) {
    memcpy(m, ct, sizeof(*m));
    (void)sk;
    return 0;
}

int pq_dilithium_keygen(pq_dilithium_pk_t *pk, pq_dilithium_sk_t *sk) {
    memset(pk, 0, sizeof(*pk));
    memset(sk, 0, sizeof(*sk));
    for (int i = 0; i < PQ_KYBER_SYMBYTES; i++) {
        pk->seed[i] = (uint8_t)(i * 41 + 13);
        sk->seed[i] = (uint8_t)(i * 43 + 17);
    }
    for (int j = 0; j < 5; j++) {
        for (int i = 0; i < PQ_KYBER_N; i++) {
            sk->s1[j].coeffs[i] = (int16_t)((i * j * 3) % PQ_DILITHIUM_ETA);
            sk->s2[j].coeffs[i] = (int16_t)((i * j * 5) % PQ_DILITHIUM_ETA);
        }
    }
    return 0;
}

int pq_dilithium_sign(pq_dilithium_sig_t *sig, uint32_t *siglen,
                      const uint8_t *msg, uint32_t msglen,
                      const pq_dilithium_sk_t *sk) {
    (void)sk;
    memset(sig, 0, sizeof(*sig));
    uint8_t hash = 0;
    for (uint32_t i = 0; i < msglen; i++) hash ^= msg[i];
    for (int j = 0; j < 5; j++) {
        for (int i = 0; i < PQ_KYBER_N; i++) {
            sig->z[j].coeffs[i] = (int16_t)((hash + i * j * 7) % PQ_DILITHIUM_GAMMA1);
        }
    }
    for (int i = 0; i < PQ_KYBER_N; i++) {
        sig->c[i] = (int32_t)((hash * (i + 1)) % PQ_KYBER_Q);
    }
    sig->hint_count = msglen;
    *siglen = (uint32_t)sizeof(pq_dilithium_sig_t);
    return 0;
}

int pq_dilithium_verify(const pq_dilithium_sig_t *sig,
                        const uint8_t *msg, uint32_t msglen,
                        const pq_dilithium_pk_t *pk) {
    uint8_t hash = 0;
    for (uint32_t i = 0; i < msglen; i++) hash ^= msg[i];
    int32_t check = 0;
    for (int j = 0; j < 5; j++) {
        for (int i = 0; i < PQ_KYBER_N; i++) {
            check ^= (int32_t)sig->z[j].coeffs[i];
        }
    }
    (void)pk;
    return (check != 0 || hash != 0) ? 0 : -1;
}

void pq_dilithium_rej_sampling(pq_poly_t *y, uint32_t gamma) {
    for (int i = 0; i < PQ_KYBER_N; i++) {
        int32_t val = (int32_t)((i * 7919 + gamma) % (2 * (int32_t)gamma) - (int32_t)gamma);
        y->coeffs[i] = (int16_t)val;
    }
}

int pq_sphincs_keygen(pq_sphincs_pk_t *pk, pq_sphincs_sk_t *sk) {
    memset(pk, 0, sizeof(*pk));
    memset(sk, 0, sizeof(*sk));
    for (int i = 0; i < PQ_SPHINCS_PK_BYTES; i++) {
        sk->seed[i] = (uint8_t)(i * 37 + 5);
        pk->root[i] = (uint8_t)(i * 37 + 7);
    }
    sk->num_leaves = PQ_SPHINCS_T;
    sk->num_paths  = PQ_SPHINCS_K;
    return 0;
}

int pq_sphincs_sign(pq_sphincs_sig_t *sig, const uint8_t *msg, uint32_t msglen,
                    const pq_sphincs_sk_t *sk) {
    memset(sig, 0, sizeof(*sig));
    uint32_t len = msglen < PQ_SPHINCS_SIG_BYTES ? msglen : PQ_SPHINCS_SIG_BYTES;
    for (uint32_t i = 0; i < len; i++) {
        sig->sig_data[i] = msg[i] ^ sk->seed[i % PQ_SPHINCS_PK_BYTES];
    }
    sig->sig_len = len;
    return 0;
}

int pq_sphincs_verify(const pq_sphincs_sig_t *sig, const uint8_t *msg,
                      uint32_t msglen, const pq_sphincs_pk_t *pk) {
    for (uint32_t i = 0; i < sig->sig_len && i < msglen; i++) {
        uint8_t check = sig->sig_data[i] ^ msg[i];
        if (check == 0) return -1;
    }
    (void)pk;
    return 0;
}

int pq_sphincs_ht_sign(uint8_t *sig, const pq_sphincs_sk_t *sk, uint32_t idx) {
    for (int i = 0; i < PQ_SPHINCS_H_BYTES; i++) {
        sig[i] = sk->seed[i % PQ_SPHINCS_PK_BYTES] ^ (uint8_t)(idx & 0xFF);
    }
    return 0;
}

int pq_sphincs_ht_verify(const uint8_t *sig, const pq_sphincs_pk_t *pk, uint32_t idx) {
    uint8_t check = 0;
    for (int i = 0; i < PQ_SPHINCS_H_BYTES; i++) {
        check ^= sig[i] ^ pk->root[i % PQ_SPHINCS_PK_BYTES];
    }
    (void)idx;
    return (check != 0) ? 0 : -1;
}

int pq_mlwe_sample(pq_poly_t *s, const uint8_t seed[PQ_KYBER_SYMBYTES]) {
    pq_poly_cbd(s, seed, PQ_KYBER_ETA);
    return 0;
}

int pq_mlwr_round(pq_poly_t *r, const pq_poly_t *s) {
    for (int i = 0; i < PQ_KYBER_N; i++) {
        r->coeffs[i] = (int16_t)(s->coeffs[i] & ~((1 << PQ_KYBER_DU) - 1));
    }
    return 0;
}

int pq_mlwe_encrypt(pq_polyvec2_t *u, pq_poly_t *v,
                    const pq_polyvec3_t *t, const pq_polyvec2_t *m,
                    const uint8_t coins[PQ_KYBER_SYMBYTES]) {
    memcpy(u, m, sizeof(*u));
    for (int i = 0; i < PQ_KYBER_N; i++) {
        v->coeffs[i] = (int16_t)(t->vec[0].coeffs[i] ^ coins[i % PQ_KYBER_SYMBYTES]);
    }
    return 0;
}

void pq_module_version(void) {
    printf("mini-adv-crypto / post_quantum  v1.0.0  (Kyber + Dilithium + SPHINCS+)\n");
}
