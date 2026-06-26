#ifndef ASYMMETRIC_CIPHER_H
#define ASYMMETRIC_CIPHER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ─── Big Integer (Simplified) ───────────────────────────────── */

#define BI_MAX_WORDS 64
#define BI_WORD_BITS 32

typedef struct BigInt {
    uint32_t words[BI_MAX_WORDS];
    size_t   num_words;
} BigInt;

void bigint_from_uint64(BigInt *r, uint64_t val);
void bigint_from_hex(BigInt *r, const char *hex);
void bigint_to_hex(const BigInt *a, char *out, size_t out_cap);
int  bigint_compare(const BigInt *a, const BigInt *b);
void bigint_add(BigInt *r, const BigInt *a, const BigInt *b);
void bigint_sub(BigInt *r, const BigInt *a, const BigInt *b);
void bigint_mul(BigInt *r, const BigInt *a, const BigInt *b);
void bigint_divmod(BigInt *q, BigInt *r, const BigInt *a, const BigInt *b);
void bigint_mod(BigInt *r, const BigInt *a, const BigInt *b);
void bigint_mod_exp(BigInt *r, const BigInt *base, const BigInt *exp, const BigInt *mod);
void bigint_mod_mul(BigInt *r, const BigInt *a, const BigInt *b, const BigInt *mod);
void bigint_gcd(BigInt *r, const BigInt *a, const BigInt *b);
void bigint_mod_inv(BigInt *r, const BigInt *a, const BigInt *mod);
bool bigint_is_zero(const BigInt *a);
bool bigint_is_one(const BigInt *a);
bool bigint_is_even(const BigInt *a);
size_t bigint_bit_length(const BigInt *a);

/* ─── Primality Testing (Miller-Rabin) ────────────────────────── */

#define MR_DEFAULT_ROUNDS 40

bool miller_rabin_test(const BigInt *n, int k);

/* ─── PKCS#1 v1.5 Padding ─────────────────────────────────────── */

#define PKCS1_MAX_MSG_LEN 256

size_t pkcs1_v15_encode(const uint8_t *msg, size_t msg_len,
                        uint8_t *em, size_t em_len);
bool pkcs1_v15_decode(const uint8_t *em, size_t em_len,
                      uint8_t *msg, size_t *msg_len);

/* ─── Diffie-Hellman Key Exchange ─────────────────────────────── */

typedef struct DhParams {
    BigInt p;  /* prime modulus */
    BigInt g;  /* generator */
    size_t bits;
} DhParams;

typedef struct DhKeyPair {
    BigInt private_key;
    BigInt public_key;
    const DhParams *params;
} DhKeyPair;

void dh_params_init_2048(DhParams *params);
bool dh_generate_keypair(DhKeyPair *kp, const DhParams *params);
bool dh_compute_shared_secret(BigInt *secret,
                              const DhKeyPair *my_key,
                              const BigInt *their_public);

/* ─── RSA ────────────────────────────────────────────────────── */

#define RSA_MIN_KEY_BITS 1024
#define RSA_MAX_MODULUS_BYTES ((RSA_MIN_KEY_BITS + 512) / 8)

typedef struct RsaPrivateKey {
    BigInt n;
    BigInt d;
    BigInt e;
    BigInt p;
    BigInt q;
    BigInt dp;  /* d mod (p-1) for CRT */
    BigInt dq;  /* d mod (q-1) for CRT */
    BigInt qinv; /* q^{-1} mod p */
    size_t  key_bits;
} RsaPrivateKey;

typedef struct RsaPublicKey {
    BigInt n;
    BigInt e;
    size_t key_bits;
} RsaPublicKey;

bool rsa_keygen(RsaPrivateKey *priv, RsaPublicKey *pub, size_t key_bits);
bool rsa_encrypt(const RsaPublicKey *pub, const uint8_t *msg, size_t msg_len,
                 uint8_t *cipher, size_t *cipher_len);
bool rsa_decrypt(const RsaPrivateKey *priv, const uint8_t *cipher, size_t cipher_len,
                 uint8_t *msg, size_t *msg_len);
bool rsa_sign(const RsaPrivateKey *priv, const uint8_t *hash, size_t hash_len,
              uint8_t *sig, size_t *sig_len);
bool rsa_verify(const RsaPublicKey *pub, const uint8_t *hash, size_t hash_len,
                const uint8_t *sig, size_t sig_len);

/* ─── ECDH (secp256k1, Simplified) ───────────────────────────── */

#define EC_FIELD_BYTES   32
#define EC_POINT_BYTES   65

typedef struct EcPoint {
    uint8_t x[EC_FIELD_BYTES];
    uint8_t y[EC_FIELD_BYTES];
    bool    is_infinity;
} EcPoint;

typedef struct EcKey {
    EcPoint pub;
    uint8_t priv[EC_FIELD_BYTES];
} EcKey;

void ecdh_generate_keypair(EcKey *key);
bool ecdh_compute_shared_secret(const EcKey *my_key, const EcPoint *their_pub,
                                uint8_t secret[EC_FIELD_BYTES]);
void ec_point_set_generator(EcPoint *g);
void ec_point_scalar_multiply(EcPoint *r, const uint8_t *scalar, const EcPoint *p);
void ec_point_add(EcPoint *r, const EcPoint *a, const EcPoint *b);
void ec_point_double(EcPoint *r, const EcPoint *p);
bool ec_point_is_on_curve(const EcPoint *p);

/* ─── PEM Simulation ─────────────────────────────────────────── */

typedef enum PemKeyType {
    PEM_RSA_PRIVATE,
    PEM_RSA_PUBLIC,
    PEM_EC_PRIVATE,
    PEM_EC_PUBLIC,
    PEM_CERTIFICATE
} PemKeyType;

#define PEM_MAX_SIZE 4096

int  pem_encode_rsa_private(const RsaPrivateKey *key, char *out, size_t out_cap);
int  pem_encode_rsa_public(const RsaPublicKey *key, char *out, size_t out_cap);
bool pem_decode_rsa_private(const char *pem, RsaPrivateKey *key);
bool pem_decode_rsa_public(const char *pem, RsaPublicKey *key);
int  pem_encode_ec_private(const EcKey *key, char *out, size_t out_cap);
int  pem_encode_ec_public(const EcPoint *pub, char *out, size_t out_cap);
bool pem_decode_ec_private(const char *pem, EcKey *key);
bool pem_decode_ec_public(const char *pem, EcPoint *pub);

#endif /* ASYMMETRIC_CIPHER_H */
