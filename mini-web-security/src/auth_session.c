#include "auth_session.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <stdint.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#else
#include <unistd.h>
#endif

/* ── SHA-256 Implementation ──────────────────────────────────────── */

#define SHA256_BLOCK_SIZE 32

typedef struct {
    uint8_t  data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} sha256_ctx_t;

static const uint32_t sha256_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0xaba5c2db,0x19a6de76,0x9ab1c977,0x196c72fc,
    0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,
    0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49bbc69,0x48c8b1e0,0x283423a4,0x86abce9b,0x3edbe48d,
    0x421248f9,0x50b6a5e2,0x5af1150f,0x686bd24e,0x7626cf4b,0x716cd56d,0x701cef45,0x08b4f2b0,
    0xca3bf3b1,0x587f5b75,0x2c7e53f7,0x8ff8439e,0x5cee4cc1,0x2cd14098,0x9c91b6d7,0xcde9b449,
    0x9cb70bb4,0x9e3a2c05,0x748c671e,0x1033ac38,0xd18e7be4,0x60b666f1,0x0058bb2d,0x9c27ea4d,
    0xc17a77f5,0x6505b55b,0x6ca9da29,0x5717e18c,0xe9559bff,0x5d25dd34,0xd2f37c0b,0xc6be7af6,
    0x1ef29292,0x79d4da5d,0xd508fcaa,0x3e4e920b,0x0b72c0e8,0xbd23d5bb,0x12b7aa32,0xbd79237c,
    0x4b834400,0xf8c4e51e,0x6c1377f1,0x3c88e7ff,0x65f14bca,0x93c18cb4,0xc6b04517,0x8a3b243c,
    0xb8c4c91d,0x3c950623,0x9de23df4,0x9b3c85ca,0x044e5d2f,0xcdcc1f53,0x58aa7658,0x3c4af85d,
    0x8ffc2b65,0x3245e071,0x16cba8e0,0x2ef55e68,0x9a85ccae,0x3d93a00f,0x63e34803,0x0b7a9b2b,
    0x776f35f9,0xfb8b6a7c,0xa37b1741,0xbaa43fdc,0x5ab73e57,0x00000000,0x00000000,0x00000000
};

#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z)     (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z)    (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)        (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x)        (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x)       (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x)       (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

static void sha256_transform(sha256_ctx_t *ctx, const uint8_t data[]) {
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];
    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j+1] << 16)
             | ((uint32_t)data[j+2] << 8) | (uint32_t)data[j+3];
    for ( ; i < 64; ++i)
        m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e,f,g) + sha256_k[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(sha256_ctx_t *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

static void sha256_update(sha256_ctx_t *ctx, const uint8_t data[], size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(sha256_ctx_t *ctx, uint8_t hash[]) {
    uint32_t i = ctx->datalen;
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }
    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = (uint8_t)(ctx->bitlen);
    ctx->data[62] = (uint8_t)(ctx->bitlen >> 8);
    ctx->data[61] = (uint8_t)(ctx->bitlen >> 16);
    ctx->data[60] = (uint8_t)(ctx->bitlen >> 24);
    ctx->data[59] = (uint8_t)(ctx->bitlen >> 32);
    ctx->data[58] = (uint8_t)(ctx->bitlen >> 40);
    ctx->data[57] = (uint8_t)(ctx->bitlen >> 48);
    ctx->data[56] = (uint8_t)(ctx->bitlen >> 56);
    sha256_transform(ctx, ctx->data);
    for (i = 0; i < 4; ++i) {
        hash[i]      = (uint8_t)((ctx->state[0] >> (24 - i * 8)) & 0xff);
        hash[i + 4]  = (uint8_t)((ctx->state[1] >> (24 - i * 8)) & 0xff);
        hash[i + 8]  = (uint8_t)((ctx->state[2] >> (24 - i * 8)) & 0xff);
        hash[i + 12] = (uint8_t)((ctx->state[3] >> (24 - i * 8)) & 0xff);
        hash[i + 16] = (uint8_t)((ctx->state[4] >> (24 - i * 8)) & 0xff);
        hash[i + 20] = (uint8_t)((ctx->state[5] >> (24 - i * 8)) & 0xff);
        hash[i + 24] = (uint8_t)((ctx->state[6] >> (24 - i * 8)) & 0xff);
        hash[i + 28] = (uint8_t)((ctx->state[7] >> (24 - i * 8)) & 0xff);
    }
}

static void sha256_hash(const uint8_t* data, size_t len, uint8_t* hash_out) {
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, hash_out);
}

/* ── HMAC-SHA256 ─────────────────────────────────────────────────── */

static void hmac_sha256(const uint8_t* key, size_t key_len,
                        const uint8_t* data, size_t data_len,
                        uint8_t* result) {
    uint8_t k_ipad[64], k_opad[64], inner_key[64];
    uint8_t tk[32];
    if (key_len > 64) {
        sha256_hash(key, key_len, tk);
        key = tk;
        key_len = 32;
    }
    memset(k_ipad, 0x36, 64);
    memset(k_opad, 0x5c, 64);
    for (size_t i = 0; i < key_len; i++) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }
    uint8_t inner_hash[32];
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, k_ipad, 64);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, inner_hash);
    sha256_init(&ctx);
    sha256_update(&ctx, k_opad, 64);
    sha256_update(&ctx, inner_hash, 32);
    sha256_final(&ctx, result);
}

/* ── PBKDF2-SHA256 ───────────────────────────────────────────────── */

static void pbkdf2_sha256(const uint8_t* password, size_t pass_len,
                          const uint8_t* salt, size_t salt_len,
                          int iterations, uint8_t* dk, size_t dklen) {
    uint8_t u[32], t[32], salt_block[128];
    size_t salt_block_len = salt_len + 4;
    if (salt_block_len > sizeof(salt_block)) salt_block_len = sizeof(salt_block);
    memcpy(salt_block, salt, salt_len);
    for (size_t block = 1; dklen > 0; block++) {
        salt_block[salt_len]     = (uint8_t)(block >> 24);
        salt_block[salt_len + 1] = (uint8_t)(block >> 16);
        salt_block[salt_len + 2] = (uint8_t)(block >> 8);
        salt_block[salt_len + 3] = (uint8_t)(block);
        hmac_sha256(password, pass_len, salt_block, salt_block_len, u);
        memcpy(t, u, 32);
        for (int i = 1; i < iterations; i++) {
            hmac_sha256(password, pass_len, u, 32, u);
            for (int j = 0; j < 32; j++) t[j] ^= u[j];
        }
        size_t copy = dklen > 32 ? 32 : dklen;
        memcpy(dk + (block - 1) * 32, t, copy);
        if (dklen <= 32) break;
        dklen -= 32;
    }
}

/* ── Password Hashing ────────────────────────────────────────────── */

bool auth_password_hash(const char* password, auth_password_t* result) {
    if (!password || !result) return false;
    for (int i = 0; i < AUTH_SALT_SIZE; i++)
        result->salt[i] = (uint8_t)(rand() & 0xFF);
    result->iterations = AUTH_PBKDF2_ITERS;
    pbkdf2_sha256((const uint8_t*)password, strlen(password),
                  result->salt, AUTH_SALT_SIZE,
                  result->iterations, result->hash, AUTH_HASH_SIZE);
    return true;
}

bool auth_password_verify(const char* password, const auth_password_t* stored) {
    if (!password || !stored) return false;
    uint8_t computed[AUTH_HASH_SIZE];
    pbkdf2_sha256((const uint8_t*)password, strlen(password),
                  stored->salt, AUTH_SALT_SIZE,
                  stored->iterations, computed, AUTH_HASH_SIZE);
    uint8_t diff = 0;
    for (int i = 0; i < AUTH_HASH_SIZE; i++) diff |= computed[i] ^ stored->hash[i];
    return diff == 0;
}

void auth_password_to_base64(const auth_password_t* pw, char* output, size_t out_size) {
    if (!pw || !output || out_size < 128) return;
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t pos = 0;
    for (int i = 0; i < AUTH_SALT_SIZE && pos < out_size - 4; i += 3) {
        uint32_t v = (uint32_t)pw->salt[i] << 16;
        if (i+1 < AUTH_SALT_SIZE) v |= (uint32_t)pw->salt[i+1] << 8;
        if (i+2 < AUTH_SALT_SIZE) v |= pw->salt[i+2];
        for (int s = 18; s >= 0; s -= 6) output[pos++] = b64[(v >> s) & 0x3F];
    }
    for (int i = 0; i < AUTH_HASH_SIZE && pos < out_size - 4; i += 3) {
        uint32_t v = (uint32_t)pw->hash[i] << 16;
        if (i+1 < AUTH_HASH_SIZE) v |= (uint32_t)pw->hash[i+1] << 8;
        if (i+2 < AUTH_HASH_SIZE) v |= pw->hash[i+2];
        for (int s = 18; s >= 0; s -= 6) output[pos++] = b64[(v >> s) & 0x3F];
    }
    output[pos] = '\0';
}

bool auth_password_from_base64(const char* encoded, auth_password_t* pw) {
    (void)encoded; (void)pw;
    return false;
}

int auth_password_strength(const char* password) {
    if (!password) return 0;
    size_t len = strlen(password);
    int score = 0;
    if (len >= 8) score += 20; else if (len >= 6) score += 10;
    if (len >= 12) score += 20;
    bool has_upper = false, has_lower = false, has_digit = false, has_special = false;
    for (size_t i = 0; i < len; i++) {
        if (isupper((unsigned char)password[i])) has_upper = true;
        else if (islower((unsigned char)password[i])) has_lower = true;
        else if (isdigit((unsigned char)password[i])) has_digit = true;
        else has_special = true;
    }
    if (has_upper) score += 20; if (has_lower) score += 15;
    if (has_digit) score += 15; if (has_special) score += 15;
    return score > 100 ? 100 : score;
}

/* ── TOTP ────────────────────────────────────────────────────────── */

/* Base32 alphabet: RFC 4648 */
static const char base32_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

void totp_init(totp_config_t* cfg, int digits, int period) {
    if (!cfg) return;
    memset(cfg, 0, sizeof(*cfg));
    cfg->digits = digits > 0 ? digits : TOTP_DIGITS;
    cfg->period = period > 0 ? period : TOTP_PERIOD;
}

bool totp_generate_secret(char* output, size_t out_size) {
    if (!output || out_size < 17) return false;
    for (size_t i = 0; i < 16; i++)
        output[i] = base32_chars[rand() & 0x1F];
    output[16] = '\0';
    return true;
}

static int base32_decode(const char* encoded, uint8_t* decoded, size_t buf_size) {
    size_t count = 0, buffer = 0, bits_left = 0;
    size_t out_len = 0;
    while (*encoded && out_len < buf_size) {
        const char* p = strchr(base32_chars, toupper((unsigned char)*encoded));
        if (!p) { encoded++; continue; }
        buffer = (buffer << 5) | (size_t)(p - base32_chars);
        bits_left += 5;
        if (bits_left >= 8) {
            bits_left -= 8;
            decoded[out_len++] = (uint8_t)(buffer >> bits_left);
            buffer &= (1U << bits_left) - 1;
        }
        encoded++;
        count++;
    }
    return (int)out_len;
}

uint32_t totp_hotp(const uint8_t* key, size_t key_len, uint64_t counter, int digits) {
    uint8_t counter_bytes[8];
    for (int i = 7; i >= 0; i--) {
        counter_bytes[i] = (uint8_t)(counter & 0xFF);
        counter >>= 8;
    }
    uint8_t hash[32];
    hmac_sha256(key, key_len, counter_bytes, 8, hash);
    int offset = hash[31] & 0x0F;
    uint32_t binary = ((uint32_t)(hash[offset] & 0x7f) << 24)
                    | ((uint32_t)hash[offset+1] << 16)
                    | ((uint32_t)hash[offset+2] << 8)
                    | hash[offset+3];
    uint32_t mod = 1;
    for (int i = 0; i < digits; i++) mod *= 10;
    return binary % mod;
}

uint32_t totp_generate_code(const totp_config_t* cfg, time_t timestamp) {
    if (!cfg || !cfg->secret_base32[0]) return 0;
    uint8_t key[64];
    int key_len = base32_decode(cfg->secret_base32, key, sizeof(key));
    if (key_len <= 0) return 0;
    uint64_t counter = (uint64_t)(timestamp / cfg->period);
    return totp_hotp(key, (size_t)key_len, counter, cfg->digits);
}

bool totp_validate_code(const totp_config_t* cfg, time_t timestamp, uint32_t code) {
    return code == totp_generate_code(cfg, timestamp);
}

bool totp_validate_window(const totp_config_t* cfg, time_t timestamp,
                          uint32_t code, int window) {
    for (int i = -window; i <= window; i++) {
        if (totp_validate_code(cfg, timestamp + i * cfg->period, code)) return true;
    }
    return false;
}

/* ── Session Management ──────────────────────────────────────────── */

void session_init(session_t* sess) {
    if (!sess) return;
    memset(sess, 0, sizeof(*sess));
}

bool session_generate_id(session_t* sess) {
    if (!sess) return false;
    uint8_t rand_bytes[32];
    for (int i = 0; i < 32; i++) rand_bytes[i] = (uint8_t)(rand() & 0xFF);
    for (int i = 0; i < 32; i++)
        snprintf(sess->id + i * 2, 3, "%02x", rand_bytes[i]);
    sess->id[63] = '\0';
    sess->created_at = time(NULL);
    sess->is_active = true;
    return true;
}

bool session_is_expired(const session_t* sess) {
    if (!sess) return true;
    if (!sess->is_active) return true;
    if (sess->expires_at > 0 && time(NULL) > sess->expires_at) return true;
    return false;
}

int session_cookie_header(const session_t* sess, bool http_only,
                          bool secure, session_samesite_t same_site,
                          const char* path, char* output, size_t out_size) {
    if (!sess || !output) return 0;
    const char* site = "Lax";
    if (same_site == SAMESITE_STRICT) site = "Strict";
    else if (same_site == SAMESITE_NONE) site = "None";
    return snprintf(output, out_size,
                    "Set-Cookie: session_id=%s; Path=%s; HttpOnly=%s; Secure=%s; SameSite=%s",
                    sess->id, path ? path : "/",
                    http_only ? "true" : "false",
                    secure ? "true" : "false", site);
}

/* ── Session Fixation Prevention ─────────────────────────────────── */

void session_fix_init(session_fixation_t* sf) {
    if (!sf) return;
    memset(sf, 0, sizeof(*sf));
}

bool session_fix_prelogin(session_fixation_t* sf, const char* session_id) {
    if (!sf || !session_id) return false;
    strncpy(sf->original_id, session_id, 63);
    sf->original_id[63] = '\0';
    sf->is_rotated = false;
    return true;
}

bool session_fix_postlogin(session_fixation_t* sf) {
    if (!sf) return false;
    uint8_t rand_bytes[32];
    for (int i = 0; i < 32; i++) rand_bytes[i] = (uint8_t)(rand() & 0xFF);
    for (int i = 0; i < 32; i++)
        snprintf(sf->new_id + i * 2, 3, "%02x", rand_bytes[i]);
    sf->new_id[63] = '\0';
    sf->is_rotated = true;
    sf->rotated_at = time(NULL);
    sf->login_count++;
    return true;
}

bool session_fix_validate(const session_fixation_t* sf, const char* session_id) {
    if (!sf || !session_id) return false;
    if (!sf->is_rotated) return false;
    return strcmp(session_id, sf->new_id) == 0;
}

/* ── Rate Limiting ───────────────────────────────────────────────── */

void ratelimit_init(rate_limiter_t* rl, int max_attempts,
                    int window_seconds, int block_duration) {
    if (!rl) return;
    memset(rl, 0, sizeof(*rl));
    rl->max_attempts = max_attempts;
    rl->window_seconds = window_seconds;
    rl->block_duration = block_duration;
    rl->window_start = time(NULL);
    rl->current_attempts = 0;
    rl->block_until = 0;
}

bool ratelimit_check(rate_limiter_t* rl) {
    if (!rl) return false;
    time_t now = time(NULL);
    if (rl->block_until > 0 && now < rl->block_until) return false;
    if (rl->block_until > 0 && now >= rl->block_until) {
        rl->block_until = 0;
        rl->current_attempts = 0;
        rl->window_start = now;
    }
    if (now - rl->window_start > rl->window_seconds) {
        rl->window_start = now;
        rl->current_attempts = 0;
    }
    rl->current_attempts++;
    if (rl->current_attempts > rl->max_attempts) {
        rl->block_until = now + rl->block_duration;
        return false;
    }
    return true;
}

bool ratelimit_is_blocked(const rate_limiter_t* rl) {
    if (!rl) return false;
    return rl->block_until > 0 && time(NULL) < rl->block_until;
}

int ratelimit_remaining(const rate_limiter_t* rl) {
    if (!rl) return 0;
    if (ratelimit_is_blocked(rl)) return 0;
    time_t now = time(NULL);
    if (now - rl->window_start > rl->window_seconds) return rl->max_attempts;
    int remaining = rl->max_attempts - rl->current_attempts;
    return remaining > 0 ? remaining : 0;
}

void ratelimit_reset(rate_limiter_t* rl) {
    if (!rl) return;
    rl->window_start = time(NULL);
    rl->current_attempts = 0;
    rl->block_until = 0;
}

/* ── OAuth2 Implicit Flow Audit ──────────────────────────────────── */

void oauth2_audit_implicit_flow(const char* redirect_uri, const char* client_id,
                                const char* response_type, oauth2_audit_t* audit) {
    if (!audit) return;
    memset(audit, 0, sizeof(*audit));
    audit->valid = true;
    if (response_type && strcmp(response_type, "token") == 0) {
        audit->valid = false;
        audit->issues[audit->issue_count++] = 1;
    }
    if (redirect_uri) {
        if (strncmp(redirect_uri, "https://", 8) != 0) {
            audit->issues[audit->issue_count++] = 2;
            audit->valid = false;
        }
        if (strstr(redirect_uri, "localhost") || strstr(redirect_uri, "127.0.0.1"))
            audit->issues[audit->issue_count++] = 3;
    }
    if (!client_id || !redirect_uri) audit->valid = false;
    if (audit->issue_count >= 8) audit->issue_count = 8;
}

bool oauth2_validate_state(const char* state_param) {
    if (!state_param) return false;
    return strlen(state_param) >= 16;
}

bool oauth2_validate_redirect_uri(const char* registered, const char* received) {
    if (!registered || !received) return false;
    return strcmp(registered, received) == 0;
}

/* ── JWT ─────────────────────────────────────────────────────────── */

void jwt_init(jwt_token_t* token) {
    if (!token) return;
    memset(token, 0, sizeof(*token));
}

static int b64url_decode(const char* input, char* output, size_t out_size) {
    if (!input || !output || out_size == 0) return 0;
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t out_pos = 0;
    int vals[4];
    int vi = 0;
    for (size_t i = 0; input[i] && out_pos < out_size; i++) {
        if (input[i] == '-' || input[i] == '_') { char c = input[i] == '-' ? '+' : '/';
            const char* p = strchr(b64, c);
            vals[vi++] = p ? (int)(p - b64) : 0;
        } else { const char* p = strchr(b64, input[i]); if (!p) continue; vals[vi++] = (int)(p - b64); }
        if (vi == 4) {
            output[out_pos++] = (char)((vals[0] << 2) | (vals[1] >> 4));
            if (out_pos < out_size) output[out_pos++] = (char)((vals[1] << 4) | (vals[2] >> 2));
            if (out_pos < out_size) output[out_pos++] = (char)((vals[2] << 6) | vals[3]);
            vi = 0;
        }
    }
    if (vi >= 2) {
        output[out_pos++] = (char)((vals[0] << 2) | (vals[1] >> 4));
        if (vi == 3 && out_pos < out_size)
            output[out_pos++] = (char)((vals[1] << 4) | (vals[2] >> 2));
    }
    output[out_pos] = '\0';
    return (int)out_pos;
}

bool jwt_parse(const char* token_str, jwt_token_t* token) {
    if (!token_str || !token) return false;
    jwt_init(token);
    const char* dot1 = strchr(token_str, '.');
    const char* dot2 = dot1 ? strchr(dot1 + 1, '.') : NULL;
    if (!dot1 || !dot2) return false;
    size_t hlen = (size_t)(dot1 - token_str);
    size_t plen = (size_t)(dot2 - dot1 - 1);
    if (hlen >= 512 || plen >= 4096) return false;
    memcpy(token->header, token_str, hlen);
    token->header[hlen] = '\0';
    memcpy(token->payload, dot1 + 1, plen);
    token->payload[plen] = '\0';
    strncpy(token->signature, dot2 + 1, 511);
    token->signature[511] = '\0';
    token->parsed = true;
    if (strstr(token->header, "\"none\"") || strstr(token->header, "\"None\""))
        token->algorithm = JWT_ALG_NONE;
    else if (strstr(token->header, "\"HS256\"")) token->algorithm = JWT_ALG_HS256;
    else if (strstr(token->header, "\"HS384\"")) token->algorithm = JWT_ALG_HS384;
    else if (strstr(token->header, "\"HS512\"")) token->algorithm = JWT_ALG_HS512;
    else token->algorithm = JWT_ALG_HS256;
    return true;
}

bool jwt_sign(const jwt_token_t* token, const uint8_t* key, size_t key_len,
              char* output, size_t out_size) {
    if (!token || !key || !output) return false;
    char signing_input[4608];
    snprintf(signing_input, sizeof(signing_input), "%s.%s", token->header, token->payload);
    uint8_t sig[32];
    hmac_sha256(key, key_len, (const uint8_t*)signing_input, strlen(signing_input), sig);
    static const char b64url[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t pos = 0;
    for (int i = 0; i < 32 && pos + 4 < out_size; i += 3) {
        uint32_t v = ((uint32_t)sig[i] << 16)
                   | ((i+1 < 32 ? (uint32_t)sig[i+1] : 0) << 8)
                   | (i+2 < 32 ? (uint32_t)sig[i+2] : 0);
        output[pos++] = b64url[(v >> 18) & 0x3F];
        output[pos++] = b64url[(v >> 12) & 0x3F];
        if (pos < out_size) output[pos++] = (i+1 < 32) ? b64url[(v >> 6) & 0x3F] : '=';
        if (pos < out_size) output[pos++] = (i+2 < 32) ? b64url[v & 0x3F] : '=';
    }
    output[pos] = '\0';
    char encoded[1024];
    memcpy(encoded, signing_input, strlen(signing_input) + 1);
    if (strlen(encoded) + pos + 2 < out_size) {
        encoded[strlen(encoded)] = '.';
        memcpy(encoded + strlen(encoded), output, pos + 1);
    }
    strncpy(output, encoded, out_size);
    output[out_size - 1] = '\0';
    return true;
}

int jwt_validate(const jwt_token_t* token, const uint8_t* key, size_t key_len,
                 jwt_validation_t* result) {
    if (!token || !result) return -1;
    memset(result, 0, sizeof(*result));
    if (!token->parsed) return -1;
    result->none_attack = jwt_none_attack_check(token->header);
    result->weak_key = jwt_weak_key_check(key, key_len, token->algorithm);
    if (result->none_attack) {
        result->issues_found++;
        strncpy(result->issues_desc[0], "JWT 'none' algorithm attack possible", 127);
    }
    if (result->weak_key) {
        strncpy(result->issues_desc[result->issues_found],
                "JWT HMAC key is weak (too short)", 127);
        result->issues_found++;
    }
    if (result->none_attack || result->weak_key) result->valid = false;
    else result->valid = true;
    result->signature_match = true;
    return result->issues_found;
}

bool jwt_none_attack_check(const char* token_str) {
    if (!token_str) return false;
    char lower[512];
    for (size_t i = 0; token_str[i] && i < 511; i++)
        lower[i] = (char)tolower((unsigned char)token_str[i]);
    lower[strlen(token_str) < 511 ? strlen(token_str) : 511] = '\0';
    return strstr(lower, "\"alg\":\"none\"") != NULL
        || strstr(lower, "\"alg\": \"none\"") != NULL;
}

bool jwt_weak_key_check(const uint8_t* key, size_t key_len, jwt_algorithm_t alg) {
    if (!key && alg != JWT_ALG_NONE) return true;
    if (alg == JWT_ALG_HS256 && key_len < 32) return true;
    if (alg == JWT_ALG_HS384 && key_len < 48) return true;
    if (alg == JWT_ALG_HS512 && key_len < 64) return true;
    return false;
}

/* ── Password Reset ──────────────────────────────────────────────── */

bool pwd_reset_generate(password_reset_t* reset, const char* user_id,
                         int expiry_seconds) {
    if (!reset || !user_id) return false;
    strncpy(reset->user_id, user_id, 127);
    reset->user_id[127] = '\0';
    uint8_t rand_bytes[32];
    for (int i = 0; i < 32; i++) rand_bytes[i] = (uint8_t)(rand() & 0xFF);
    for (int i = 0; i < 32; i++)
        snprintf(reset->token + i * 2, 3, "%02x", rand_bytes[i]);
    reset->token[63] = '\0';
    reset->created_at = time(NULL);
    reset->expires_at = reset->created_at + expiry_seconds;
    reset->used = false;
    return true;
}

bool pwd_reset_validate(const password_reset_t* reset, const char* token) {
    if (!reset || !token) return false;
    if (reset->used) return false;
    if (time(NULL) > reset->expires_at) return false;
    return strcmp(reset->token, token) == 0;
}

bool pwd_reset_is_expired(const password_reset_t* reset) {
    if (!reset) return true;
    return time(NULL) > reset->expires_at;
}

int pwd_reset_entropy_bits(const char* token) {
    if (!token) return 0;
    int hex_chars = 0;
    for (size_t i = 0; token[i]; i++)
        if (isxdigit((unsigned char)token[i])) hex_chars++;
    return hex_chars * 4;
}
