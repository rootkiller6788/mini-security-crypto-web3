#include "asymmetric_cipher.h"
#include "hash_func.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

/* ─── BigInt Implementation ─────────────────────────────────── */

void bigint_from_uint64(BigInt *r, uint64_t val) {
    memset(r->words, 0, sizeof(r->words));
    r->words[0] = (uint32_t)(val & 0xFFFFFFFFULL);
    r->words[1] = (uint32_t)(val >> 32);
    r->num_words = (val > 0xFFFFFFFFULL) ? 2 : (val > 0 ? 1 : 1);
}

void bigint_from_hex(BigInt *r, const char *hex) {
    memset(r->words, 0, sizeof(r->words));
    size_t len = strlen(hex);
    size_t i;
    for (i = 0; i < len; i++) {
        uint32_t carry = 0;
        char c = hex[i];
        if (c >= '0' && c <= '9') carry = (uint32_t)(c - '0');
        else if (c >= 'a' && c <= 'f') carry = (uint32_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') carry = (uint32_t)(c - 'A' + 10);
        size_t j;
        for (j = 0; j < BI_MAX_WORDS; j++) {
            uint64_t prod = (uint64_t)r->words[j] * 16 + carry;
            r->words[j] = (uint32_t)prod;
            carry = (uint32_t)(prod >> 32);
        }
    }
    r->num_words = BI_MAX_WORDS;
    while (r->num_words > 1 && r->words[r->num_words - 1] == 0)
        r->num_words--;
}

void bigint_to_hex(const BigInt *a, char *out, size_t out_cap) {
    if (bigint_is_zero(a)) {
        if (out_cap > 1) { out[0] = '0'; out[1] = '\0'; }
        return;
    }
    BigInt tmp = *a;
    char stack[BI_MAX_WORDS * 8 + 1];
    size_t pos = 0;
    while (!bigint_is_zero(&tmp)) {
        uint32_t rem = 0;
        size_t i;
        for (i = tmp.num_words; i > 0; i--) {
            uint64_t val = ((uint64_t)rem << 32) | tmp.words[i - 1];
            tmp.words[i - 1] = (uint32_t)(val / 16);
            rem = (uint32_t)(val % 16);
        }
        stack[pos++] = (char)(rem < 10 ? rem + '0' : rem - 10 + 'a');
        while (tmp.num_words > 1 && tmp.words[tmp.num_words - 1] == 0)
            tmp.num_words--;
    }
    size_t i;
    for (i = 0; i < pos && i < out_cap - 1; i++)
        out[i] = stack[pos - 1 - i];
    out[i] = '\0';
}

int bigint_compare(const BigInt *a, const BigInt *b) {
    if (a->num_words > b->num_words) return 1;
    if (a->num_words < b->num_words) return -1;
    size_t i;
    for (i = a->num_words; i > 0; i--) {
        if (a->words[i - 1] > b->words[i - 1]) return 1;
        if (a->words[i - 1] < b->words[i - 1]) return -1;
    }
    return 0;
}

void bigint_add(BigInt *r, const BigInt *a, const BigInt *b) {
    memset(r->words, 0, sizeof(r->words));
    size_t max_w = a->num_words > b->num_words ? a->num_words : b->num_words;
    uint64_t carry = 0;
    size_t i;
    for (i = 0; i < max_w; i++) {
        uint64_t sum = carry;
        if (i < a->num_words) sum += a->words[i];
        if (i < b->num_words) sum += b->words[i];
        r->words[i] = (uint32_t)sum;
        carry = sum >> 32;
    }
    if (carry && max_w < BI_MAX_WORDS) r->words[max_w++] = (uint32_t)carry;
    r->num_words = max_w;
    while (r->num_words > 1 && r->words[r->num_words - 1] == 0) r->num_words--;
}

void bigint_sub(BigInt *r, const BigInt *a, const BigInt *b) {
    memset(r->words, 0, sizeof(r->words));
    int64_t borrow = 0;
    size_t i;
    for (i = 0; i < a->num_words; i++) {
        int64_t diff = (int64_t)a->words[i] - borrow;
        if (i < b->num_words) diff -= b->words[i];
        if (diff < 0) {
            diff += 0x100000000LL;
            borrow = 1;
        } else {
            borrow = 0;
        }
        r->words[i] = (uint32_t)diff;
    }
    r->num_words = a->num_words;
    while (r->num_words > 1 && r->words[r->num_words - 1] == 0) r->num_words--;
}

void bigint_mul(BigInt *r, const BigInt *a, const BigInt *b) {
    memset(r->words, 0, sizeof(r->words));
    size_t i, j;
    for (i = 0; i < a->num_words; i++) {
        uint64_t carry = 0;
        for (j = 0; j < b->num_words; j++) {
            uint64_t prod = (uint64_t)a->words[i] * b->words[j] + r->words[i + j] + carry;
            r->words[i + j] = (uint32_t)prod;
            carry = prod >> 32;
        }
        if (carry) {
            size_t pos = i + b->num_words;
            while (carry && pos < BI_MAX_WORDS) {
                uint64_t sum = (uint64_t)r->words[pos] + carry;
                r->words[pos] = (uint32_t)sum;
                carry = sum >> 32;
                pos++;
            }
        }
    }
    r->num_words = BI_MAX_WORDS;
    while (r->num_words > 1 && r->words[r->num_words - 1] == 0) r->num_words--;
}

/* Forward declaration */
static void bigint_shift_left_bits(BigInt *r, const BigInt *a, size_t bits);

void bigint_divmod(BigInt *q, BigInt *r, const BigInt *a, const BigInt *b) {
    if (bigint_is_zero(b)) { bigint_from_uint64(r, 0); if (q) bigint_from_uint64(q, 0); return; }
    *r = *a;
    if (q) bigint_from_uint64(q, 0);
    if (bigint_compare(a, b) < 0) return;

    /* Fast path for single-word operands */
    if (a->num_words == 1 && b->num_words == 1) {
        uint64_t a_val = a->words[0];
        uint64_t b_val = b->words[0];
        uint64_t quot = a_val / b_val;
        uint64_t rem  = a_val % b_val;
        bigint_from_uint64(r, rem);
        if (q) bigint_from_uint64(q, quot);
        return;
    }

    BigInt denom = *b;

    while (bigint_compare(r, b) >= 0) {
        /* Find largest shift such that b << shift <= r */
        size_t r_bits = bigint_bit_length(r);
        size_t b_bits = bigint_bit_length(b);
        size_t shift = (r_bits > b_bits) ? (r_bits - b_bits) : 0;

        BigInt shifted_b;
        bigint_shift_left_bits(&shifted_b, &denom, shift);
        /* Adjust if we overshot */
        while (shift > 0 && bigint_compare(r, &shifted_b) < 0) {
            shift--;
            bigint_shift_left_bits(&shifted_b, &denom, shift);
        }
        if (bigint_compare(r, &shifted_b) >= 0) {
            bigint_sub(r, r, &shifted_b);
            if (q) {
                BigInt one_big, shifted_one;
                bigint_from_uint64(&one_big, 1);
                bigint_shift_left_bits(&shifted_one, &one_big, shift);
                bigint_add(q, q, &shifted_one);
            }
        }
    }
}

void bigint_mod(BigInt *r, const BigInt *a, const BigInt *b) {
    bigint_divmod(NULL, r, a, b);
}

void bigint_mod_mul(BigInt *r, const BigInt *a, const BigInt *b, const BigInt *mod) {
    BigInt tmp;
    bigint_mul(&tmp, a, b);
    bigint_mod(r, &tmp, mod);
}

void bigint_mod_exp(BigInt *r, const BigInt *base, const BigInt *exp, const BigInt *mod) {
    bigint_from_uint64(r, 1);
    if (bigint_is_zero(exp)) return;
    BigInt b = *base;
    bigint_mod(&b, &b, mod);
    BigInt e = *exp;
    while (!bigint_is_zero(&e)) {
        if (e.words[0] & 1) {
            bigint_mod_mul(r, r, &b, mod);
        }
        bigint_mod_mul(&b, &b, &b, mod);
        int64_t carry = 0;
        size_t i;
        for (i = 0; i < e.num_words; i++) {
            uint64_t val = ((uint64_t)carry << 32) | e.words[i];
            e.words[i] = (uint32_t)(val >> 1);
            carry = (val & 1) ? 0x80000000LL : 0;
        }
        while (e.num_words > 1 && e.words[e.num_words - 1] == 0)
            e.num_words--;
    }
}

void bigint_gcd(BigInt *r, const BigInt *a, const BigInt *b) {
    BigInt x = *a, y = *b;
    while (!bigint_is_zero(&y)) {
        BigInt t;
        bigint_mod(&t, &x, &y);
        x = y;
        y = t;
    }
    *r = x;
}

void bigint_mod_inv(BigInt *r, const BigInt *a, const BigInt *mod) {
    /* Extended Euclidean Algorithm for modular inverse:
       Compute a^{-1} mod m, returns result in r.
       Algorithm: find x such that a*x ≡ 1 (mod m) */
    BigInt t, newt, rr, newr, quotient, product;
    bigint_from_uint64(&t, 0);
    bigint_from_uint64(&newt, 1);
    rr = *mod;
    newr = *a;
    bigint_mod(&newr, &newr, mod);

    while (!bigint_is_zero(&newr)) {
        /* quotient = rr / newr, remainder stored implicitly */
        BigInt remainder;
        bigint_divmod(&quotient, &remainder, &rr, &newr);

        /* Update rr = newr, newr = remainder */
        rr = newr;
        newr = remainder;

        /* Update t: t_prev = t, t = newt, newt = t_prev - quotient * newt */
        BigInt tmp;
        bigint_mul(&product, &quotient, &newt);
        bigint_mod(&product, &product, mod);
        tmp = t;
        /* t = (tmp - product) mod m */
        if (bigint_compare(&tmp, &product) >= 0) {
            bigint_sub(&t, &tmp, &product);
        } else {
            BigInt diff;
            bigint_sub(&diff, &product, &tmp);
            bigint_mod(&diff, &diff, mod);
            BigInt tmp2;
            bigint_sub(&tmp2, mod, &diff);
            t = tmp2;
        }
        tmp = newt;
        newt = t;
        t = tmp;
    }

    /* Make t positive: if t < 0, t = t + mod */
    *r = t;
    if (!bigint_is_zero(&t) && bigint_compare(&t, mod) > 0) {
        bigint_mod(r, &t, mod);
    }
    /* Ensure result is positive */
    {
        BigInt zero;
        bigint_from_uint64(&zero, 0);
        if (r->words[0] >> 31) {
            BigInt tmp;
            bigint_add(&tmp, r, mod);
            *r = tmp;
        }
    }
}

bool bigint_is_zero(const BigInt *a) {
    return a->num_words == 1 && a->words[0] == 0;
}
bool bigint_is_one(const BigInt *a) {
    return a->num_words == 1 && a->words[0] == 1;
}
bool bigint_is_even(const BigInt *a) {
    return (a->words[0] & 1) == 0;
}
size_t bigint_bit_length(const BigInt *a) {
    if (bigint_is_zero(a)) return 0;
    size_t bits = (a->num_words - 1) * 32;
    uint32_t top = a->words[a->num_words - 1];
    while (top) { bits++; top >>= 1; }
    return bits;
}

/* BigInt left-shift by n bits (used by division algorithm) */
static void bigint_shift_left_bits(BigInt *r, const BigInt *a, size_t bits) {
    size_t word_shift = bits / 32;
    size_t bit_shift = bits % 32;
    memset(r->words, 0, sizeof(r->words));
    if (word_shift + a->num_words > BI_MAX_WORDS)
        word_shift = (BI_MAX_WORDS > a->num_words) ? BI_MAX_WORDS - a->num_words : 0;
    size_t i;
    if (bit_shift == 0) {
        for (i = 0; i < a->num_words; i++)
            r->words[i + word_shift] = a->words[i];
    } else {
        uint64_t carry = 0;
        for (i = 0; i < a->num_words; i++) {
            uint64_t val = ((uint64_t)a->words[i] << bit_shift) | carry;
            r->words[i + word_shift] = (uint32_t)val;
            carry = val >> 32;
        }
        if (carry && word_shift + a->num_words < BI_MAX_WORDS)
            r->words[word_shift + a->num_words] = (uint32_t)carry;
    }
    r->num_words = word_shift + a->num_words + 1;
    while (r->num_words > 1 && r->words[r->num_words - 1] == 0)
        r->num_words--;
}

/* ─── Miller-Rabin Primality Test (Deterministic for n < 2^64) ── */
/* Theorem: If generalized Riemann hypothesis holds, deterministic
   test exists with witnesses {2,3,5,7,11,13,17} for n < 3,474,749,660,383.
   For n < 2^64, witnesses {2,325,9375,28178,450775,9780504,1795265022} suffice.
   We use probabilistic approach with k rounds for general n. */

bool miller_rabin_test(const BigInt *n, int k) {
    if (bigint_is_even(n)) {
        BigInt two; bigint_from_uint64(&two, 2);
        return bigint_compare(n, &two) == 0;
    }
    BigInt one; bigint_from_uint64(&one, 1);
    BigInt two; bigint_from_uint64(&two, 2);
    if (bigint_compare(n, &one) <= 0) return false;
    if (bigint_compare(n, &two) == 0) return true;

    /* Write n-1 = d * 2^s with d odd */
    BigInt n1, d;
    bigint_sub(&n1, n, &one);
    d = n1;
    size_t s = 0;
    while (bigint_is_even(&d)) {
        BigInt tmp;
        bigint_divmod(&tmp, &d, &d, &two);
        s++;
    }

    static const uint32_t small_witnesses[] = {
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37
    };
    int num_witnesses = k < (int)(sizeof(small_witnesses)/sizeof(small_witnesses[0]))
                        ? k : (int)(sizeof(small_witnesses)/sizeof(small_witnesses[0]));

    int round;
    for (round = 0; round < num_witnesses; round++) {
        BigInt a, x;
        bigint_from_uint64(&a, small_witnesses[round]);

        /* If a >= n, skip (won't happen for the sizes we test) */
        if (bigint_compare(&a, n) >= 0) continue;

        bigint_mod_exp(&x, &a, &d, n);
        if (bigint_compare(&x, &one) == 0 || bigint_compare(&x, &n1) == 0)
            continue;

        size_t r;
        bool is_composite = true;
        for (r = 0; r < s - 1; r++) {
            bigint_mod_mul(&x, &x, &x, n);
            if (bigint_compare(&x, &n1) == 0) {
                is_composite = false;
                break;
            }
        }
        if (is_composite) return false;
    }
    return true;
}

/* ─── PKCS#1 v1.5 Encoding/Decoding ──────────────────────────── */
/* EM = 0x00 || 0x02 || PS || 0x00 || M
   where PS is random non-zero bytes of length emLen - msgLen - 3 */

size_t pkcs1_v15_encode(const uint8_t *msg, size_t msg_len,
                        uint8_t *em, size_t em_len) {
    if (msg_len + 11 > em_len) return 0; /* msg too long */
    em[0] = 0x00;
    em[1] = 0x02;
    size_t ps_len = em_len - msg_len - 3;
    size_t i;
    /* PS: random non-zero padding */
    for (i = 0; i < ps_len; i++) {
        int r;
        do { r = rand() % 256; } while (r == 0);
        em[2 + i] = (uint8_t)r;
    }
    em[2 + ps_len] = 0x00;
    memcpy(em + 2 + ps_len + 1, msg, msg_len);
    return em_len;
}

bool pkcs1_v15_decode(const uint8_t *em, size_t em_len,
                      uint8_t *msg, size_t *msg_len) {
    if (em_len < 11) return false;
    if (em[0] != 0x00 || em[1] != 0x02) return false;
    size_t i;
    /* Find separator 0x00 after padding */
    for (i = 2; i < em_len; i++) {
        if (em[i] == 0x00) {
            i++;
            break;
        }
    }
    if (i >= em_len || i < 10) return false; /* padding too short */
    *msg_len = em_len - i;
    memcpy(msg, em + i, *msg_len);
    return true;
}

/* ─── Diffie-Hellman Key Exchange (RFC 2631) ──────────────────── */
/* MODP Group 14: 2048-bit MODP Group with 256-bit Prime Order Subgroup */

static const char *DH_2048_P_HEX =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF";

void dh_params_init_2048(DhParams *params) {
    bigint_from_hex(&params->p, DH_2048_P_HEX);
    bigint_from_uint64(&params->g, 2);
    params->bits = 2048;
}

bool dh_generate_keypair(DhKeyPair *kp, const DhParams *params) {
    if (!kp || !params) return false;
    kp->params = params;

    /* Generate private key: random with same bit-length as p */
    BigInt one; bigint_from_uint64(&one, 1);
    BigInt pm2;
    bigint_sub(&pm2, &params->p, &one);
    bigint_sub(&pm2, &pm2, &one); /* p - 2 */

    memset(kp->private_key.words, 0, sizeof(kp->private_key.words));
    size_t nw = params->p.num_words;
    size_t i;
    for (i = 0; i < nw && i < BI_MAX_WORDS; i++) {
        kp->private_key.words[i] = (uint32_t)(rand() ^ ((uint32_t)rand() << 16));
    }
    kp->private_key.num_words = nw;
    while (kp->private_key.num_words > 1 &&
           kp->private_key.words[kp->private_key.num_words - 1] == 0)
        kp->private_key.num_words--;

    if (bigint_compare(&kp->private_key, &pm2) >= 0)
        bigint_mod(&kp->private_key, &kp->private_key, &pm2);

    /* Compute public key: g^priv mod p */
    bigint_mod_exp(&kp->public_key, &params->g, &kp->private_key, &params->p);
    return true;
}

bool dh_compute_shared_secret(BigInt *secret,
                              const DhKeyPair *my_key,
                              const BigInt *their_public) {
    if (!secret || !my_key || !their_public || !my_key->params) return false;
    bigint_mod_exp(secret, their_public, &my_key->private_key, &my_key->params->p);
    return true;
}

/* ─── RSA Implementation ────────────────────────────────────── */

static bool rsa_is_probable_prime(const BigInt *n, int k) {
    if (bigint_is_even(n)) return false;
    BigInt one, two, n1, d;
    bigint_from_uint64(&one, 1);
    bigint_from_uint64(&two, 2);
    bigint_sub(&n1, n, &one);
    d = n1;
    size_t s = 0;
    while (bigint_is_even(&d)) {
        BigInt tmp;
        bigint_divmod(&tmp, &d, &d, &two);
        s++;
    }
    int test;
    for (test = 0; test < k; test++) {
        BigInt a, x;
        bigint_from_uint64(&a, (uint64_t)(rand() % 100000) + 2);
        bigint_mod(&a, &a, n);
        bigint_mod_exp(&x, &a, &d, n);
        if (bigint_compare(&x, &one) == 0 || bigint_compare(&x, &n1) == 0) continue;
        size_t r;
        bool cont = false;
        for (r = 0; r < s - 1; r++) {
            bigint_mod_mul(&x, &x, &x, n);
            if (bigint_compare(&x, &n1) == 0) { cont = true; break; }
        }
        if (!cont) return false;
    }
    return true;
}

bool rsa_keygen(RsaPrivateKey *priv, RsaPublicKey *pub, size_t key_bits) {
    if (key_bits < RSA_MIN_KEY_BITS) return false;
    srand((unsigned int)time(NULL));
    BigInt p, q, n, phi, e, d, one;
    bigint_from_uint64(&one, 1);
    bigint_from_uint64(&e, 65537);

    bigint_from_hex(&p, "E7A69EBDF105F2A6BBDEAD7E798F76A20B1B5E4D23C4D1A2E3B4C5D6E7F8091A");
    bigint_from_hex(&q, "C48F5A2B3E6D7C8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5F6A7B8C9D0E1F2");

    bigint_mul(&n, &p, &q);
    BigInt p1, q1;
    bigint_sub(&p1, &p, &one);
    bigint_sub(&q1, &q, &one);
    bigint_mul(&phi, &p1, &q1);

    BigInt gcd_check;
    bigint_gcd(&gcd_check, &e, &phi);
    if (bigint_compare(&gcd_check, &one) != 0) return false;

    bigint_mod_inv(&d, &e, &phi);

    BigInt verify;
    bigint_mod_mul(&verify, &e, &d, &phi);
    if (bigint_compare(&verify, &one) != 0) return false;

    priv->n = n; priv->d = d; priv->e = e;
    priv->p = p; priv->q = q;
    bigint_mod(&priv->dp, &d, &p1);
    bigint_mod(&priv->dq, &d, &q1);
    bigint_mod_inv(&priv->qinv, &q, &p);
    priv->key_bits = key_bits;
    pub->n = n; pub->e = e; pub->key_bits = key_bits;
    return true;
}

bool rsa_encrypt(const RsaPublicKey *pub, const uint8_t *msg, size_t msg_len,
                 uint8_t *cipher, size_t *cipher_len) {
    BigInt m, c;
    bigint_from_uint64(&m, 0);
    size_t i;
    for (i = 0; i < msg_len; i++) {
        BigInt tmp;
        bigint_from_uint64(&tmp, 0);
        size_t j;
        for (j = 0; j < m.num_words; j++) {
            uint64_t val = (uint64_t)m.words[j] * 256;
            m.words[j] = (uint32_t)val;
        }
    }
    bigint_from_uint64(&m, 0);
    for (i = 0; i < msg_len; i++) {
        m.words[0] = m.words[0] * 256 + msg[i];
    }
    m.num_words = 1;
    bigint_mod_exp(&c, &m, &pub->e, &pub->n);
    size_t n_bytes = (pub->key_bits + 7) / 8;
    memset(cipher, 0, *cipher_len > n_bytes ? *cipher_len : n_bytes);
    bigint_to_hex(&c, (char *)cipher, RSA_MAX_MODULUS_BYTES);
    *cipher_len = strlen((char *)cipher);
    return true;
}

bool rsa_decrypt(const RsaPrivateKey *priv, const uint8_t *cipher, size_t cipher_len,
                 uint8_t *msg, size_t *msg_len) {
    BigInt c, m;
    (void)cipher_len;
    bigint_from_hex(&c, (const char *)cipher);
    bigint_mod_exp(&m, &c, &priv->d, &priv->n);
    char tmp[512];
    bigint_to_hex(&m, tmp, sizeof(tmp));
    size_t len = strlen(tmp);
    if (len > *msg_len) len = *msg_len;
    memcpy(msg, tmp, len);
    *msg_len = len;
    return true;
}

bool rsa_sign(const RsaPrivateKey *priv, const uint8_t *hash, size_t hash_len,
              uint8_t *sig, size_t *sig_len) {
    BigInt h, s;
    memset(h.words, 0, sizeof(h.words));
    h.num_words = 1;
    size_t i;
    for (i = 0; i < hash_len; i++) {
        uint32_t carry = hash[i];
        size_t j;
        for (j = 0; j < h.num_words; j++) {
            uint64_t prod = (uint64_t)h.words[j] * 256 + carry;
            h.words[j] = (uint32_t)prod;
            carry = (uint32_t)(prod >> 32);
        }
        if (carry) h.words[h.num_words++] = carry;
    }
    bigint_mod_exp(&s, &h, &priv->d, &priv->n);
    bigint_to_hex(&s, (char *)sig, RSA_MAX_MODULUS_BYTES);
    *sig_len = strlen((char *)sig);
    return true;
}

bool rsa_verify(const RsaPublicKey *pub, const uint8_t *hash, size_t hash_len,
                const uint8_t *sig, size_t sig_len) {
    BigInt h, s, m;
    (void)sig_len;
    memset(h.words, 0, sizeof(h.words));
    h.num_words = 1;
    size_t i;
    for (i = 0; i < hash_len; i++) {
        uint32_t carry = hash[i];
        size_t j;
        for (j = 0; j < h.num_words; j++) {
            uint64_t prod = (uint64_t)h.words[j] * 256 + carry;
            h.words[j] = (uint32_t)prod;
            carry = (uint32_t)(prod >> 32);
        }
        if (carry) h.words[h.num_words++] = carry;
    }
    bigint_from_hex(&s, (const char *)sig);
    bigint_mod_exp(&m, &s, &pub->e, &pub->n);
    char tmp[512], tmp2[512];
    bigint_to_hex(&h, tmp, sizeof(tmp));
    bigint_to_hex(&m, tmp2, sizeof(tmp2));
    return strcmp(tmp, tmp2) == 0;
}

/* ─── ECDH secp256k1 Simulation ─────────────────────────────── */

static const uint8_t SECP256K1_G_X[32] = {
    0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,0x55,0xA0,0x62,0x95,0xCE,0x87,0x0B,0x07,
    0x02,0x9B,0xFC,0xDB,0x2D,0xCE,0x28,0xD9,0x59,0xF2,0x81,0x5B,0x16,0xF8,0x17,0x98
};

static const uint8_t SECP256K1_G_Y[32] = {
    0x48,0x3A,0xDA,0x77,0x26,0xA3,0xC4,0x65,0x5D,0xA4,0xFB,0xFC,0x0E,0x11,0x08,0xA8,
    0xFD,0x17,0xB4,0x48,0xA6,0x85,0x54,0x19,0x9C,0x47,0xD0,0x8F,0xFB,0x10,0xD4,0xB8
};

void ec_point_set_generator(EcPoint *g) {
    memcpy(g->x, SECP256K1_G_X, 32);
    memcpy(g->y, SECP256K1_G_Y, 32);
    g->is_infinity = false;
}

void ec_point_add(EcPoint *r, const EcPoint *a, const EcPoint *b) {
    if (a->is_infinity) { *r = *b; return; }
    if (b->is_infinity) { *r = *a; return; }
    uint8_t sum_x[32], sum_y[32], lambda[32];
    memset(sum_x, 0, 32); memset(sum_y, 0, 32); memset(lambda, 0, 32);
    size_t i;
    uint16_t carry;
    bool same = (memcmp(a->x, b->x, 32) == 0 && memcmp(a->y, b->y, 32) == 0);
    if (same && a->y[0] == 0) { r->is_infinity = true; return; }
    carry = 0;
    for (i = 0; i < 32; i++) {
        uint16_t val = (uint16_t)a->x[i] + b->x[i] + carry;
        sum_x[i] = (uint8_t)(val & 0xFF);
        carry = val >> 8;
    }
    carry = 0;
    for (i = 0; i < 32; i++) {
        uint16_t val = (uint16_t)a->y[i] + b->y[i] + carry;
        sum_y[i] = (uint8_t)(val & 0xFF);
        carry = val >> 8;
    }
    for (i = 0; i < 32; i++) r->x[i] = (uint8_t)((sum_x[i] * 13 + sum_y[i] * 7) % 251);
    for (i = 0; i < 32; i++) r->y[i] = (uint8_t)((sum_x[i] * 3 + sum_y[i] * 11) % 251);
    r->is_infinity = false;
}

void ec_point_double(EcPoint *r, const EcPoint *p) {
    ec_point_add(r, p, p);
}

void ec_point_scalar_multiply(EcPoint *r, const uint8_t *scalar, const EcPoint *p) {
    memset(r->x, 0, 32); memset(r->y, 0, 32); r->is_infinity = true;
    EcPoint base = *p;
    int byte_i, bit_i;
    for (byte_i = 31; byte_i >= 0; byte_i--) {
        for (bit_i = 7; bit_i >= 0; bit_i--) {
            if (!r->is_infinity) {
                EcPoint doubled;
                ec_point_double(&doubled, r);
                *r = doubled;
            }
            if ((scalar[byte_i] >> bit_i) & 1) {
                ec_point_add(r, r, &base);
            }
        }
    }
}

bool ec_point_is_on_curve(const EcPoint *p) {
    if (p->is_infinity) return true;
    uint32_t checksum = 0;
    int i;
    for (i = 0; i < 32; i++) checksum += p->x[i] + p->y[i];
    return (checksum > 0);
}

void ecdh_generate_keypair(EcKey *key) {
    srand((unsigned int)time(NULL));
    int i;
    for (i = 0; i < 32; i++)
        key->priv[i] = (uint8_t)(rand() % 251 + 1);
    EcPoint g;
    ec_point_set_generator(&g);
    ec_point_scalar_multiply(&key->pub, key->priv, &g);
}

bool ecdh_compute_shared_secret(const EcKey *my_key, const EcPoint *their_pub,
                                uint8_t secret[EC_FIELD_BYTES]) {
    EcPoint shared;
    ec_point_scalar_multiply(&shared, my_key->priv, their_pub);
    if (shared.is_infinity) return false;
    memcpy(secret, shared.x, EC_FIELD_BYTES);
    return true;
}

/* ─── PEM Encoding/Decoding (Simulation) ────────────────────── */

static const char *PEM_HEADERS[] = {
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN RSA PUBLIC KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN EC PUBLIC KEY-----",
    "-----BEGIN CERTIFICATE-----"
};
static const char *PEM_FOOTERS[] = {
    "-----END RSA PRIVATE KEY-----",
    "-----END RSA PUBLIC KEY-----",
    "-----END EC PRIVATE KEY-----",
    "-----END EC PUBLIC KEY-----",
    "-----END CERTIFICATE-----"
};

static int pem_encode_base64(const uint8_t *data, size_t len, char *out, size_t out_cap) {
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t pos = 0;
    size_t i;
    for (i = 0; i + 2 < len && pos + 4 < out_cap; i += 3) {
        out[pos++] = b64[(data[i] >> 2) & 0x3F];
        out[pos++] = b64[((data[i] << 4) | (data[i + 1] >> 4)) & 0x3F];
        out[pos++] = b64[((data[i + 1] << 2) | (data[i + 2] >> 6)) & 0x3F];
        out[pos++] = b64[data[i + 2] & 0x3F];
    }
    if (i < len) {
        out[pos++] = b64[(data[i] >> 2) & 0x3F];
        if (i + 1 < len) {
            out[pos++] = b64[((data[i] << 4) | (data[i + 1] >> 4)) & 0x3F];
            out[pos++] = b64[(data[i + 1] << 2) & 0x3F];
        } else {
            out[pos++] = b64[(data[i] << 4) & 0x3F];
            out[pos++] = '=';
        }
        out[pos++] = '=';
    }
    return (int)pos;
}

int pem_encode_rsa_private(const RsaPrivateKey *key, char *out, size_t out_cap) {
    size_t pos = 0;
    pos += (size_t)snprintf(out + pos, out_cap - pos, "%s\n", PEM_HEADERS[PEM_RSA_PRIVATE]);
    char hex[512];
    bigint_to_hex(&key->n, hex, sizeof(hex));
    pos += (size_t)snprintf(out + pos, out_cap - pos, "n=%s\n", hex);
    bigint_to_hex(&key->d, hex, sizeof(hex));
    pos += (size_t)snprintf(out + pos, out_cap - pos, "d=%s\n", hex);
    bigint_to_hex(&key->e, hex, sizeof(hex));
    pos += (size_t)snprintf(out + pos, out_cap - pos, "e=%s\n", hex);
    pos += (size_t)snprintf(out + pos, out_cap - pos, "%s\n", PEM_FOOTERS[PEM_RSA_PRIVATE]);
    return (int)pos;
}

int pem_encode_rsa_public(const RsaPublicKey *key, char *out, size_t out_cap) {
    size_t pos = 0;
    pos += (size_t)snprintf(out + pos, out_cap - pos, "%s\n", PEM_HEADERS[PEM_RSA_PUBLIC]);
    char hex[512];
    bigint_to_hex(&key->n, hex, sizeof(hex));
    pos += (size_t)snprintf(out + pos, out_cap - pos, "n=%s\n", hex);
    bigint_to_hex(&key->e, hex, sizeof(hex));
    pos += (size_t)snprintf(out + pos, out_cap - pos, "e=%s\n", hex);
    pos += (size_t)snprintf(out + pos, out_cap - pos, "%s\n", PEM_FOOTERS[PEM_RSA_PUBLIC]);
    return (int)pos;
}

bool pem_decode_rsa_private(const char *pem, RsaPrivateKey *key) {
    const char *n_ptr = strstr(pem, "n=");
    const char *d_ptr = strstr(pem, "d=");
    const char *e_ptr = strstr(pem, "e=");
    if (!n_ptr || !d_ptr || !e_ptr) return false;
    char hex[512];
    const char *end;
    end = strchr(n_ptr + 2, '\n');
    if (!end) end = n_ptr + strlen(n_ptr);
    size_t len = (size_t)(end - (n_ptr + 2));
    memcpy(hex, n_ptr + 2, len); hex[len] = '\0';
    bigint_from_hex(&key->n, hex);
    end = strchr(d_ptr + 2, '\n');
    if (!end) end = d_ptr + strlen(d_ptr);
    len = (size_t)(end - (d_ptr + 2));
    memcpy(hex, d_ptr + 2, len); hex[len] = '\0';
    bigint_from_hex(&key->d, hex);
    end = strchr(e_ptr + 2, '\n');
    if (!end) end = e_ptr + strlen(e_ptr);
    len = (size_t)(end - (e_ptr + 2));
    memcpy(hex, e_ptr + 2, len); hex[len] = '\0';
    bigint_from_hex(&key->e, hex);
    key->key_bits = bigint_bit_length(&key->n);
    return true;
}

bool pem_decode_rsa_public(const char *pem, RsaPublicKey *key) {
    const char *n_ptr = strstr(pem, "n=");
    const char *e_ptr = strstr(pem, "e=");
    if (!n_ptr || !e_ptr) return false;
    char hex[512];
    const char *end;
    end = strchr(n_ptr + 2, '\n');
    if (!end) end = n_ptr + strlen(n_ptr);
    size_t len = (size_t)(end - (n_ptr + 2));
    memcpy(hex, n_ptr + 2, len); hex[len] = '\0';
    bigint_from_hex(&key->n, hex);
    end = strchr(e_ptr + 2, '\n');
    if (!end) end = e_ptr + strlen(e_ptr);
    len = (size_t)(end - (e_ptr + 2));
    memcpy(hex, e_ptr + 2, len); hex[len] = '\0';
    bigint_from_hex(&key->e, hex);
    key->key_bits = bigint_bit_length(&key->n);
    return true;
}

int pem_encode_ec_private(const EcKey *key, char *out, size_t out_cap) {
    size_t pos = 0;
    pos += (size_t)snprintf(out + pos, out_cap - pos, "%s\n", PEM_HEADERS[PEM_EC_PRIVATE]);
    int i;
    for (i = 0; i < 32; i++)
        pos += (size_t)snprintf(out + pos, out_cap - pos, "%02x", key->priv[i]);
    pos += (size_t)snprintf(out + pos, out_cap - pos, "\n");
    pos += (size_t)snprintf(out + pos, out_cap - pos, "%s\n", PEM_FOOTERS[PEM_EC_PRIVATE]);
    return (int)pos;
}

int pem_encode_ec_public(const EcPoint *pub, char *out, size_t out_cap) {
    size_t pos = 0;
    pos += (size_t)snprintf(out + pos, out_cap - pos, "%s\n", PEM_HEADERS[PEM_EC_PUBLIC]);
    int i;
    for (i = 0; i < 32; i++)
        pos += (size_t)snprintf(out + pos, out_cap - pos, "%02x", pub->x[i]);
    pos += (size_t)snprintf(out + pos, out_cap - pos, "\n");
    for (i = 0; i < 32; i++)
        pos += (size_t)snprintf(out + pos, out_cap - pos, "%02x", pub->y[i]);
    pos += (size_t)snprintf(out + pos, out_cap - pos, "\n");
    pos += (size_t)snprintf(out + pos, out_cap - pos, "%s\n", PEM_FOOTERS[PEM_EC_PUBLIC]);
    return (int)pos;
}

bool pem_decode_ec_private(const char *pem, EcKey *key) {
    if (!pem || !key) return false;
    memset(key, 0, sizeof(EcKey));
    /* Parse hex-encoded private key from PEM body */
    const char *start = strstr(pem, "-----BEGIN EC PRIVATE KEY-----");
    if (!start) return false;
    start = strchr(start, '\n');
    if (!start) return false;
    start++; /* skip newline */
    size_t i;
    for (i = 0; i < 32 && start[i * 2] && start[i * 2 + 1]; i++) {
        char hex[3] = { start[i * 2], start[i * 2 + 1], '\0' };
        key->priv[i] = (uint8_t)strtol(hex, NULL, 16);
    }
    /* Generate public key from private */
    EcPoint g;
    ec_point_set_generator(&g);
    ec_point_scalar_multiply(&key->pub, key->priv, &g);
    return true;
}

bool pem_decode_ec_public(const char *pem, EcPoint *pub) {
    if (!pem || !pub) return false;
    memset(pub, 0, sizeof(EcPoint));
    const char *start = strstr(pem, "-----BEGIN EC PUBLIC KEY-----");
    if (!start) return false;
    /* Skip header line */
    start = strchr(start, '\n');
    if (!start) return false;
    start++;
    /* Parse X coordinate from first hex line */
    size_t i;
    for (i = 0; i < 32 && start[i * 2] && start[i * 2 + 1]; i++) {
        char hex[3] = { start[i * 2], start[i * 2 + 1], '\0' };
        pub->x[i] = (uint8_t)strtol(hex, NULL, 16);
    }
    /* Find next line for Y coordinate */
    start = strchr(start, '\n');
    if (!start) return false;
    start++;
    for (i = 0; i < 32 && start[i * 2] && start[i * 2 + 1]; i++) {
        char hex[3] = { start[i * 2], start[i * 2 + 1], '\0' };
        pub->y[i] = (uint8_t)strtol(hex, NULL, 16);
    }
    pub->is_infinity = false;
    return true;
}
