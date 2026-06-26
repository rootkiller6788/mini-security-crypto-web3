#ifndef HASH_FUNC_H
#define HASH_FUNC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ─── SHA256 ─────────────────────────────────────────────────── */

#define SHA256_BLOCK_SIZE  64
#define SHA256_DIGEST_SIZE 32
#define SHA256_HASH_COUNT   8

typedef struct Sha256Context {
    uint8_t  buffer[SHA256_BLOCK_SIZE];
    uint32_t state[SHA256_HASH_COUNT];
    uint64_t bit_count;
    size_t   buffer_index;
} Sha256Context;

void sha256_init(Sha256Context *ctx);
void sha256_update(Sha256Context *ctx, const uint8_t *data, size_t len);
void sha256_final(Sha256Context *ctx, uint8_t digest[SHA256_DIGEST_SIZE]);
void sha256_hash(const uint8_t *data, size_t len, uint8_t digest[SHA256_DIGEST_SIZE]);

/* ─── MD5 ────────────────────────────────────────────────────── */

#define MD5_BLOCK_SIZE  64
#define MD5_DIGEST_SIZE 16
#define MD5_STATE_COUNT  4

typedef struct Md5Context {
    uint8_t  buffer[MD5_BLOCK_SIZE];
    uint32_t state[MD5_STATE_COUNT];
    uint64_t bit_count;
    size_t   buffer_index;
} Md5Context;

#define MD5_F(x, y, z) (((x) & (y)) | ((~(x)) & (z)))
#define MD5_G(x, y, z) (((x) & (z)) | ((y) & (~(z))))
#define MD5_H(x, y, z) ((x) ^ (y) ^ (z))
#define MD5_I(x, y, z) ((y) ^ ((x) | (~(z))))

void md5_init(Md5Context *ctx);
void md5_update(Md5Context *ctx, const uint8_t *data, size_t len);
void md5_final(Md5Context *ctx, uint8_t digest[MD5_DIGEST_SIZE]);
void md5_hash(const uint8_t *data, size_t len, uint8_t digest[MD5_DIGEST_SIZE]);

/* ─── HMAC ───────────────────────────────────────────────────── */

#define HMAC_BLOCK_SIZE 64
#define HMAC_MAX_DIGEST  SHA256_DIGEST_SIZE

typedef struct HmacContext {
    uint8_t ipad[HMAC_BLOCK_SIZE];
    uint8_t opad[HMAC_BLOCK_SIZE];
    Sha256Context inner;
    bool finalized;
} HmacContext;

void hmac_sha256_init(HmacContext *ctx, const uint8_t *key, size_t key_len);
void hmac_sha256_update(HmacContext *ctx, const uint8_t *data, size_t len);
void hmac_sha256_final(HmacContext *ctx, uint8_t digest[SHA256_DIGEST_SIZE]);
void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t digest[SHA256_DIGEST_SIZE]);

/* ─── Merkle-Damgard ─────────────────────────────────────────── */

typedef struct MerkleDamgardConfig {
    size_t   block_size;
    size_t   state_size;
    size_t   digest_size;
    void   (*compress)(void *state, const uint8_t *block);
    void   (*init)(void *state);
} MerkleDamgardConfig;

bool merkle_damgard_hash(const MerkleDamgardConfig *config,
                         const uint8_t *data, size_t len,
                         uint8_t *digest);

#endif /* HASH_FUNC_H */
