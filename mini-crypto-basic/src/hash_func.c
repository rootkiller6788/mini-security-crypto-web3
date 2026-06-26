#include "hash_func.h"
#include <string.h>
#include <stdlib.h>

/* ─── SHA256 Constants ──────────────────────────────────────── */

static const uint32_t SHA256_K[64] = {
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};

static inline uint32_t sha256_rotr32(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

static void sha256_transform(uint32_t state[8], const uint8_t block[64]) {
    uint32_t w[64];
    int i;
    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (i = 16; i < 64; i++) {
        uint32_t s0 = sha256_rotr32(w[i - 15], 7) ^
                      sha256_rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = sha256_rotr32(w[i - 2], 17) ^
                      sha256_rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
    for (i = 0; i < 64; i++) {
        uint32_t S1 = sha256_rotr32(e, 6) ^ sha256_rotr32(e, 11) ^ sha256_rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + S1 + ch + SHA256_K[i] + w[i];
        uint32_t S0 = sha256_rotr32(a, 2) ^ sha256_rotr32(a, 13) ^ sha256_rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void sha256_init(Sha256Context *ctx) {
    ctx->state[0] = 0x6A09E667;
    ctx->state[1] = 0xBB67AE85;
    ctx->state[2] = 0x3C6EF372;
    ctx->state[3] = 0xA54FF53A;
    ctx->state[4] = 0x510E527F;
    ctx->state[5] = 0x9B05688C;
    ctx->state[6] = 0x1F83D9AB;
    ctx->state[7] = 0x5BE0CD19;
    ctx->bit_count = 0;
    ctx->buffer_index = 0;
    memset(ctx->buffer, 0, SHA256_BLOCK_SIZE);
}

void sha256_update(Sha256Context *ctx, const uint8_t *data, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        ctx->buffer[ctx->buffer_index++] = data[i];
        ctx->bit_count += 8;
        if (ctx->buffer_index == SHA256_BLOCK_SIZE) {
            sha256_transform(ctx->state, ctx->buffer);
            ctx->buffer_index = 0;
        }
    }
}

void sha256_final(Sha256Context *ctx, uint8_t digest[SHA256_DIGEST_SIZE]) {
    uint64_t total_bits = ctx->bit_count;
    ctx->buffer[ctx->buffer_index++] = 0x80;
    if (ctx->buffer_index > 56) {
        while (ctx->buffer_index < SHA256_BLOCK_SIZE)
            ctx->buffer[ctx->buffer_index++] = 0;
        sha256_transform(ctx->state, ctx->buffer);
        ctx->buffer_index = 0;
    }
    while (ctx->buffer_index < 56)
        ctx->buffer[ctx->buffer_index++] = 0;
    int i;
    for (i = 7; i >= 0; i--)
        ctx->buffer[56 + i] = (uint8_t)(total_bits >> ((7 - i) * 8));
    sha256_transform(ctx->state, ctx->buffer);
    for (i = 0; i < 8; i++) {
        digest[i * 4]     = (uint8_t)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}

void sha256_hash(const uint8_t *data, size_t len, uint8_t digest[SHA256_DIGEST_SIZE]) {
    Sha256Context ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, digest);
}

/* ─── MD5 ──────────────────────────────────────────────────── */

static const uint32_t MD5_T[64] = {
    0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE,
    0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
    0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
    0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
    0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA,
    0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
    0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED,
    0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
    0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
    0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
    0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05,
    0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
    0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039,
    0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
    0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
    0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391
};

static const int MD5_S[64] = {
    7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
    5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
    4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
    6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
};

static inline uint32_t md5_rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

static void md5_transform(uint32_t state[4], const uint8_t block[64]) {
    uint32_t M[16];
    int i;
    for (i = 0; i < 16; i++) {
        M[i] = (uint32_t)block[i * 4] |
               ((uint32_t)block[i * 4 + 1] << 8) |
               ((uint32_t)block[i * 4 + 2] << 16) |
               ((uint32_t)block[i * 4 + 3] << 24);
    }
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t (*round_funcs[4])(uint32_t, uint32_t, uint32_t) = {
        MD5_F, MD5_G, MD5_H, MD5_I
    };
    for (i = 0; i < 64; i++) {
        uint32_t f_val;
        int g;
        if (i < 16) {
            f_val = MD5_F(b, c, d);
            g = i;
        } else if (i < 32) {
            f_val = MD5_G(b, c, d);
            g = (5 * i + 1) % 16;
        } else if (i < 48) {
            f_val = MD5_H(b, c, d);
            g = (3 * i + 5) % 16;
        } else {
            f_val = MD5_I(b, c, d);
            g = (7 * i) % 16;
        }
        f_val = f_val + a + MD5_T[i] + M[g];
        a = d;
        d = c;
        c = b;
        b = b + md5_rotl32(f_val, MD5_S[i]);
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
}

void md5_init(Md5Context *ctx) {
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->bit_count = 0;
    ctx->buffer_index = 0;
    memset(ctx->buffer, 0, MD5_BLOCK_SIZE);
}

void md5_update(Md5Context *ctx, const uint8_t *data, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        ctx->buffer[ctx->buffer_index++] = data[i];
        ctx->bit_count += 8;
        if (ctx->buffer_index == MD5_BLOCK_SIZE) {
            md5_transform(ctx->state, ctx->buffer);
            ctx->buffer_index = 0;
        }
    }
}

void md5_final(Md5Context *ctx, uint8_t digest[MD5_DIGEST_SIZE]) {
    ctx->buffer[ctx->buffer_index++] = 0x80;
    if (ctx->buffer_index > 56) {
        while (ctx->buffer_index < MD5_BLOCK_SIZE)
            ctx->buffer[ctx->buffer_index++] = 0;
        md5_transform(ctx->state, ctx->buffer);
        ctx->buffer_index = 0;
    }
    while (ctx->buffer_index < 56)
        ctx->buffer[ctx->buffer_index++] = 0;
    int i;
    for (i = 0; i < 8; i++)
        ctx->buffer[56 + i] = (uint8_t)(ctx->bit_count >> (i * 8));
    md5_transform(ctx->state, ctx->buffer);
    for (i = 0; i < 4; i++) {
        digest[i]      = (uint8_t)(ctx->state[i]);
        digest[i + 4]  = (uint8_t)(ctx->state[i] >> 8);
        digest[i + 8]  = (uint8_t)(ctx->state[i] >> 16);
        digest[i + 12] = (uint8_t)(ctx->state[i] >> 24);
    }
}

void md5_hash(const uint8_t *data, size_t len, uint8_t digest[MD5_DIGEST_SIZE]) {
    Md5Context ctx;
    md5_init(&ctx);
    md5_update(&ctx, data, len);
    md5_final(&ctx, digest);
}

/* ─── HMAC-SHA256 ──────────────────────────────────────────── */

void hmac_sha256_init(HmacContext *ctx, const uint8_t *key, size_t key_len) {
    uint8_t norm_key[HMAC_BLOCK_SIZE];
    memset(norm_key, 0, HMAC_BLOCK_SIZE);
    if (key_len > HMAC_BLOCK_SIZE) {
        sha256_hash(key, key_len, norm_key);
        memcpy(norm_key + SHA256_DIGEST_SIZE, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", HMAC_BLOCK_SIZE - SHA256_DIGEST_SIZE);
    } else {
        memcpy(norm_key, key, key_len);
    }
    size_t i;
    for (i = 0; i < HMAC_BLOCK_SIZE; i++) {
        ctx->ipad[i] = norm_key[i] ^ 0x36;
        ctx->opad[i] = norm_key[i] ^ 0x5C;
    }
    sha256_init(&ctx->inner);
    sha256_update(&ctx->inner, ctx->ipad, HMAC_BLOCK_SIZE);
    ctx->finalized = false;
}

void hmac_sha256_update(HmacContext *ctx, const uint8_t *data, size_t len) {
    sha256_update(&ctx->inner, data, len);
}

void hmac_sha256_final(HmacContext *ctx, uint8_t digest[SHA256_DIGEST_SIZE]) {
    uint8_t inner_hash[SHA256_DIGEST_SIZE];
    sha256_final(&ctx->inner, inner_hash);
    Sha256Context outer;
    sha256_init(&outer);
    sha256_update(&outer, ctx->opad, HMAC_BLOCK_SIZE);
    sha256_update(&outer, inner_hash, SHA256_DIGEST_SIZE);
    sha256_final(&outer, digest);
    ctx->finalized = true;
}

void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t digest[SHA256_DIGEST_SIZE]) {
    HmacContext ctx;
    hmac_sha256_init(&ctx, key, key_len);
    hmac_sha256_update(&ctx, data, data_len);
    hmac_sha256_final(&ctx, digest);
}

/* ─── Merkle-Damgard ───────────────────────────────────────── */

bool merkle_damgard_hash(const MerkleDamgardConfig *config,
                         const uint8_t *data, size_t len,
                         uint8_t *digest) {
    if (!config || !data || !digest) return false;
    uint8_t *state_buf = (uint8_t *)calloc(1, config->state_size);
    if (!state_buf) return false;
    uint8_t *block_buf = (uint8_t *)calloc(1, config->block_size);
    if (!block_buf) { free(state_buf); return false; }

    config->init(state_buf);
    size_t i = 0, buf_idx = 0;
    for (i = 0; i < len; i++) {
        block_buf[buf_idx++] = data[i];
        if (buf_idx == config->block_size) {
            config->compress(state_buf, block_buf);
            buf_idx = 0;
        }
    }
    block_buf[buf_idx++] = 0x80;
    if (buf_idx > config->block_size - 8) {
        while (buf_idx < config->block_size) block_buf[buf_idx++] = 0;
        config->compress(state_buf, block_buf);
        buf_idx = 0;
    }
    while (buf_idx < config->block_size - 8) block_buf[buf_idx++] = 0;
    uint64_t bits = len * 8;
    int j;
    for (j = 7; j >= 0; j--)
        block_buf[config->block_size - 8 + j] = (uint8_t)(bits >> ((7 - j) * 8));
    config->compress(state_buf, block_buf);
    memcpy(digest, state_buf, config->digest_size);
    free(state_buf);
    free(block_buf);
    return true;
}
