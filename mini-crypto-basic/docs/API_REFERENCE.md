# API Reference — mini-crypto-basic

Complete API reference for all 5 modules. All functions use C99 conventions: snake_case naming, PascalCase types, UPPER_SNAKE_CASE constants.

---

## Module 1: hash_func.h — Hash Functions

### Constants

| Name | Value | Description |
|------|-------|-------------|
| `SHA256_BLOCK_SIZE` | 64 | SHA-256 input block size (bytes) |
| `SHA256_DIGEST_SIZE` | 32 | SHA-256 output digest size (bytes) |
| `SHA256_HASH_COUNT` | 8 | Number of 32-bit words in SHA-256 state |
| `MD5_BLOCK_SIZE` | 64 | MD5 input block size (bytes) |
| `MD5_DIGEST_SIZE` | 16 | MD5 output digest size (bytes) |
| `MD5_STATE_COUNT` | 4 | Number of 32-bit words in MD5 state |
| `HMAC_BLOCK_SIZE` | 64 | HMAC key block size (bytes) |
| `HMAC_MAX_DIGEST` | 32 | Maximum HMAC digest size |

### Types

```c
typedef struct Sha256Context {
    uint8_t  buffer[SHA256_BLOCK_SIZE];
    uint32_t state[SHA256_HASH_COUNT];
    uint64_t bit_count;
    size_t   buffer_index;
} Sha256Context;
```

SHA-256 context holds the 8-word state vector, a 64-byte working buffer, total bit count, and current buffer filling position.

```c
typedef struct Md5Context {
    uint8_t  buffer[MD5_BLOCK_SIZE];
    uint32_t state[MD5_STATE_COUNT];
    uint64_t bit_count;
    size_t   buffer_index;
} Md5Context;
```

MD5 context holds the 4-word state, 64-byte buffer, bit count, and buffer index.

```c
typedef struct HmacContext {
    uint8_t ipad[HMAC_BLOCK_SIZE];
    uint8_t opad[HMAC_BLOCK_SIZE];
    Sha256Context inner;
    bool finalized;
} HmacContext;
```

HMAC context stores the inner/outer padded keys and the inner hash context.

```c
typedef struct MerkleDamgardConfig {
    size_t   block_size;
    size_t   state_size;
    size_t   digest_size;
    void   (*compress)(void *state, const uint8_t *block);
    void   (*init)(void *state);
} MerkleDamgardConfig;
```

Generic Merkle-Damgard construction configuration.

### Functions — SHA-256

```c
void sha256_init(Sha256Context *ctx);
```
Initialize SHA-256 context with standard IV values (6A09E667, BB67AE85, 3C6EF372, A54FF53A, 510E527F, 9B05688C, 1F83D9AB, 5BE0CD19).

```c
void sha256_update(Sha256Context *ctx, const uint8_t *data, size_t len);
```
Feed `len` bytes from `data` into the SHA-256 context. Partial blocks are buffered internally.

```c
void sha256_final(Sha256Context *ctx, uint8_t digest[SHA256_DIGEST_SIZE]);
```
Finalize hashing: apply padding, append length, process final block(s), output 32-byte digest.

```c
void sha256_hash(const uint8_t *data, size_t len, uint8_t digest[SHA256_DIGEST_SIZE]);
```
One-shot SHA-256 hash. Equivalent to `init + update + final`.

### Functions — MD5

```c
void md5_init(Md5Context *ctx);
void md5_update(Md5Context *ctx, const uint8_t *data, size_t len);
void md5_final(Md5Context *ctx, uint8_t digest[MD5_DIGEST_SIZE]);
void md5_hash(const uint8_t *data, size_t len, uint8_t digest[MD5_DIGEST_SIZE]);
```

Analogous to SHA-256 functions. MD5 uses 4 non-linear round functions (F, G, H, I) and 64 32-bit constant T-values.

### Macros — MD5 Round Functions

```c
#define MD5_F(x, y, z) (((x) & (y)) | ((~(x)) & (z)))
#define MD5_G(x, y, z) (((x) & (z)) | ((y) & (~(z))))
#define MD5_H(x, y, z) ((x) ^ (y) ^ (z))
#define MD5_I(x, y, z) ((y) ^ ((x) | (~(z))))
```

### Functions — HMAC

```c
void hmac_sha256_init(HmacContext *ctx, const uint8_t *key, size_t key_len);
```
Initialize HMAC-SHA256. If key > 64 bytes, it is first hashed with SHA-256, then padded. Inner and outer pad (ipad, opad) are computed.

```c
void hmac_sha256_update(HmacContext *ctx, const uint8_t *data, size_t len);
void hmac_sha256_final(HmacContext *ctx, uint8_t digest[SHA256_DIGEST_SIZE]);
void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t digest[SHA256_DIGEST_SIZE]);
```

### Functions — Merkle-Damgard

```c
bool merkle_damgard_hash(const MerkleDamgardConfig *config,
                         const uint8_t *data, size_t len,
                         uint8_t *digest);
```
Generic Merkle-Damgard iterative hash: init state, process blocks via compress function, apply padding, output digest. Returns `false` on invalid config or allocation failure.

---

## Module 2: symmetric_cipher.h — Symmetric Ciphers

### Constants

| Name | Value | Description |
|------|-------|-------------|
| `AES_BLOCK_SIZE` | 16 | AES block size (bytes) |
| `AES_KEY_SIZE` | 16 | AES-128 key size (bytes) |
| `AES_NUM_ROUNDS` | 10 | AES-128 rounds |
| `AES_KEY_WORDS` | 44 | Expanded key words (4 × 11) |
| `AES_SBOX_SIZE` | 256 | S-box entries |
| `DES_BLOCK_SIZE` | 8 | DES block size (bytes) |
| `DES_KEY_SIZE` | 8 | DES key size (bytes) |
| `DES_NUM_ROUNDS` | 16 | DES rounds |
| `PKCS7_MAX_PAD` | 16 | Maximum PKCS7 pad value |

### Types

```c
typedef struct AesContext {
    uint8_t round_keys[AES_KEY_WORDS * 4];
} AesContext;
```
AES context holding 11 round keys (176 bytes total).

```c
typedef struct DesContext {
    uint64_t round_keys[DES_NUM_ROUNDS];
} DesContext;
```
DES context holding 16 × 48-bit round subkeys.

```c
typedef enum CipherMode { CIPHER_MODE_CBC, CIPHER_MODE_CTR } CipherMode;
typedef enum CipherAlgo { CIPHER_ALGO_AES128, CIPHER_ALGO_DES } CipherAlgo;

typedef struct CbcContext { ... };
typedef struct CtrContext { ... };
```

### Functions — AES

```c
void aes128_key_schedule(AesContext *ctx, const uint8_t key[AES_KEY_SIZE]);
```
Expand 16-byte key into 44 words of round keys using Rcon values.

```c
void aes128_encrypt_block(const AesContext *ctx, const uint8_t plain[AES_BLOCK_SIZE],
                          uint8_t cipher[AES_BLOCK_SIZE]);
void aes128_decrypt_block(const AesContext *ctx, const uint8_t cipher[AES_BLOCK_SIZE],
                          uint8_t plain[AES_BLOCK_SIZE]);
```
Encrypt/decrypt a single 16-byte block.

```c
void aes_sub_bytes(uint8_t state[16]);
void aes_inv_sub_bytes(uint8_t state[16]);
void aes_shift_rows(uint8_t state[16]);
void aes_inv_shift_rows(uint8_t state[16]);
void aes_mix_columns(uint8_t state[16]);
void aes_inv_mix_columns(uint8_t state[16]);
void aes_add_round_key(uint8_t state[16], const uint8_t *rkey);
```
Individual AES transformation steps (SubBytes, ShiftRows, MixColumns, AddRoundKey) — exposed for educational use.

### Functions — DES

```c
void des_key_schedule(DesContext *ctx, const uint8_t key[DES_KEY_SIZE]);
void des_encrypt_block(const DesContext *ctx, const uint8_t plain[DES_BLOCK_SIZE],
                       uint8_t cipher[DES_BLOCK_SIZE]);
void des_decrypt_block(const DesContext *ctx, const uint8_t cipher[DES_BLOCK_SIZE],
                       uint8_t plain[DES_BLOCK_SIZE]);
```

### Functions — CBC Mode

```c
void cbc_encrypt_init(CbcContext *cbc, void *cipher_ctx, CipherAlgo algo,
                      const uint8_t iv[AES_BLOCK_SIZE]);
void cbc_encrypt_update(CbcContext *cbc, const uint8_t *plain, size_t len,
                        uint8_t *cipher, size_t *out_len);
void cbc_encrypt_final(CbcContext *cbc, uint8_t *cipher, size_t *out_len);
void cbc_decrypt_init(CbcContext *cbc, void *cipher_ctx, CipherAlgo algo,
                      const uint8_t iv[AES_BLOCK_SIZE]);
void cbc_decrypt_update(CbcContext *cbc, const uint8_t *cipher, size_t len,
                        uint8_t *plain, size_t *out_len);
void cbc_decrypt_final(CbcContext *cbc, uint8_t *plain, size_t *out_len);
```

### Functions — CTR Mode

```c
void ctr_crypt_init(CtrContext *ctr, void *cipher_ctx, CipherAlgo algo,
                    const uint8_t nonce_counter[AES_BLOCK_SIZE]);
void ctr_crypt_update(CtrContext *ctr, const uint8_t *in, size_t len,
                      uint8_t *out, size_t *out_len);
```
CTR mode encrypt/decrypt are identical (XOR with keystream).

### Functions — PKCS#7

```c
size_t pkcs7_pad(const uint8_t *data, size_t data_len, size_t block_size,
                 uint8_t *padded);
size_t pkcs7_unpad(const uint8_t *padded, size_t padded_len,
                   uint8_t *data);
```
Returns padded size and unpadded size respectively. Unpad validates all padding bytes.

---

## Module 3: asymmetric_cipher.h — Asymmetric Ciphers

### Types — BigInt

```c
#define BI_MAX_WORDS 64

typedef struct BigInt {
    uint32_t words[BI_MAX_WORDS];
    size_t   num_words;
} BigInt;
```

### Functions — BigInt Arithmetic

```c
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
```

### Types — RSA

```c
typedef struct RsaPrivateKey {
    BigInt n, d, e, p, q, dp, dq, qinv;
    size_t key_bits;
} RsaPrivateKey;

typedef struct RsaPublicKey {
    BigInt n, e;
    size_t key_bits;
} RsaPublicKey;
```

### Functions — RSA

```c
bool rsa_keygen(RsaPrivateKey *priv, RsaPublicKey *pub, size_t key_bits);
bool rsa_encrypt(const RsaPublicKey *pub, const uint8_t *msg, size_t msg_len,
                 uint8_t *cipher, size_t *cipher_len);
bool rsa_decrypt(const RsaPrivateKey *priv, const uint8_t *cipher, size_t cipher_len,
                 uint8_t *msg, size_t *msg_len);
bool rsa_sign(const RsaPrivateKey *priv, const uint8_t *hash, size_t hash_len,
              uint8_t *sig, size_t *sig_len);
bool rsa_verify(const RsaPublicKey *pub, const uint8_t *hash, size_t hash_len,
                const uint8_t *sig, size_t sig_len);
```

### Types — ECDH

```c
typedef struct EcPoint { uint8_t x[32]; uint8_t y[32]; bool is_infinity; } EcPoint;
typedef struct EcKey { EcPoint pub; uint8_t priv[32]; } EcKey;
```

### Functions — ECDH

```c
void ecdh_generate_keypair(EcKey *key);
bool ecdh_compute_shared_secret(const EcKey *my_key, const EcPoint *their_pub,
                                uint8_t secret[32]);
void ec_point_set_generator(EcPoint *g);
void ec_point_scalar_multiply(EcPoint *r, const uint8_t *scalar, const EcPoint *p);
void ec_point_add(EcPoint *r, const EcPoint *a, const EcPoint *b);
void ec_point_double(EcPoint *r, const EcPoint *p);
bool ec_point_is_on_curve(const EcPoint *p);
```

### Functions — PEM

```c
int  pem_encode_rsa_private(const RsaPrivateKey *key, char *out, size_t out_cap);
int  pem_encode_rsa_public(const RsaPublicKey *key, char *out, size_t out_cap);
bool pem_decode_rsa_private(const char *pem, RsaPrivateKey *key);
bool pem_decode_rsa_public(const char *pem, RsaPublicKey *key);
int  pem_encode_ec_private(const EcKey *key, char *out, size_t out_cap);
int  pem_encode_ec_public(const EcPoint *pub, char *out, size_t out_cap);
```

---

## Module 4: digital_sig.h — Digital Signatures

### Functions — RSA-PSS

```c
bool rsa_pss_sign(const void *rsa_priv, const uint8_t *msg, size_t msg_len,
                  PssHashAlgo algo, const uint8_t *salt, size_t salt_len,
                  uint8_t *sig, size_t *sig_len, size_t key_bits);
bool rsa_pss_verify(const void *rsa_pub, const uint8_t *msg, size_t msg_len,
                    PssHashAlgo algo, size_t salt_len,
                    const uint8_t *sig, size_t sig_len, size_t key_bits);
void pss_mgf1(uint8_t *mask, size_t mask_len, const uint8_t *seed, size_t seed_len,
              PssHashAlgo algo);
```

### Functions — ECDSA

```c
bool ecdsa_sign(const uint8_t *priv_key, const uint8_t *hash, size_t hash_len,
                EcdsaSignature *sig);
bool ecdsa_verify(const void *pub_point, const uint8_t *hash, size_t hash_len,
                  const EcdsaSignature *sig);
void ecdsa_sig_encode(const EcdsaSignature *sig, uint8_t *der, size_t *der_len);
```

### Functions — Hash-then-Sign

```c
bool hash_then_sign(const Signer *signer, const uint8_t *msg, size_t msg_len,
                    uint8_t *sig, size_t *sig_len);
bool hash_then_verify(const Verifier *verifier, const uint8_t *msg, size_t msg_len,
                      const uint8_t *sig, size_t sig_len);
```

### Functions — X.509

```c
bool x509_parse_der(const uint8_t *der, size_t der_len, X509Certificate *cert);
bool x509_verify_signature(const X509Certificate *cert, const X509Certificate *issuer);
bool x509_is_valid_at_time(const X509Certificate *cert, uint64_t timestamp);
void x509_print_certificate(const X509Certificate *cert);
```

### Functions — Certificate Chain

```c
bool cert_chain_verify(const CertChain *chain,
                       const X509Certificate *trust_root,
                       uint64_t verify_time);
```

### Functions — CRL

```c
bool crl_is_revoked(const CertificateRevocationList *crl,
                    const uint8_t *serial, size_t serial_len);
```

---

## Module 5: pki_model.h — PKI Model

### Functions — CSR

```c
void csr_init(CsrRequest *csr, const char *cn, const char *org, const char *country);
void csr_set_rsa_key(CsrRequest *csr, const uint8_t *pub_key, size_t pub_key_len);
void csr_set_ec_key(CsrRequest *csr, const uint8_t *pub_key, size_t pub_key_len);
bool csr_sign(CsrRequest *csr, const void *priv_key, size_t key_bits);
bool csr_verify(const CsrRequest *csr);
```

### Functions — CA

```c
bool ca_issue_certificate(const CaConfig *ca, const CsrRequest *csr,
                          X509Certificate *cert, uint64_t valid_days);
bool ca_self_sign_root(CaConfig *ca, X509Certificate *cert);
```

### Functions — Trust Store

```c
void trust_store_init(TrustStore *store);
bool trust_store_add(TrustStore *store, const X509Certificate *cert);
bool trust_store_remove(TrustStore *store, const uint8_t *serial, size_t serial_len);
const X509Certificate *trust_store_find_by_subject(const TrustStore *store, const char *cn);
bool trust_store_verify_chain(const TrustStore *store, const X509Certificate *cert,
                              const CertificateRevocationList *crl, uint64_t verify_time);
```

### Functions — ACME

```c
void acme_account_create(AcmeAccount *acc, const char *contact);
bool acme_new_order(AcmeOrder *order, const char *domain);
bool acme_submit_challenge_response(AcmeOrder *order, size_t chall_idx,
                                     const char *response);
bool acme_finalize_order(AcmeOrder *order, const CsrRequest *csr);
bool acme_download_certificate(AcmeOrder *order, uint8_t *der, size_t *der_len);
void acme_renew_certificate(AcmeOrder *order, uint8_t *der, size_t *der_len);
```

### Functions — OCSP

```c
bool ocsp_request_build(const uint8_t *serial, size_t serial_len,
                        uint8_t *der, size_t *der_len);
bool ocsp_response_parse(const uint8_t *der, size_t der_len, OcspResponse *resp);
bool ocsp_response_verify(const OcspResponse *resp, const X509Certificate *responder_cert);
OcspCertStatus ocsp_check_status(const OcspResponse *resp,
                                  const uint8_t *serial, size_t serial_len);
bool ocsp_staple_verify(const uint8_t *stapled_data, size_t data_len,
                         const X509Certificate *responder_cert, uint64_t current_time);
```

---

## Return Values

| Return Type | Meaning |
|-------------|---------|
| `void` | Function always succeeds |
| `bool` | `true` = success, `false` = failure/invalid input |
| `int` | PEM encode: output length; negative = error |
| `size_t` | PKCS7: padded/unpadded output length; 0 = error |
| `OcspCertStatus` | OCSP status enum (GOOD/REVOKED/UNKNOWN) |
| `const X509Certificate *` | NULL if not found, pointer otherwise |
