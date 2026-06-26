#include "jwt_token.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

/*
 * L5: JWT HS256 Implementation (RFC 7519, RFC 7518)
 *
 * HMAC-SHA256 is a keyed-hash message authentication code built from SHA-256.
 * HMAC(K, m) = H((K' XOR opad) || H((K' XOR ipad) || m))
 * where K' = K if |K| <= block_size, else H(K)
 *
 * The signature over the JWT signing input (header.payload) uses:
 *   signature = HMAC-SHA256(base64url(header) + "." + base64url(payload), secret)
 *
 * Base64URL differs from standard Base64:
 *   - Replace '+' with '-', '/' with '_'
 *   - Strip trailing '=' padding
 *
 * L4: EUF-CMA Security Theorem (Goldwasser, Micali, Rivest, 1988)
 * If HMAC-SHA256 is a PRF, then JWT-HS256 is existentially unforgeable
 * under chosen-message attack (EUF-CMA) against adaptive adversaries
 * with advantage <= q_s * Adv_PRF + (q_s^2 / 2^{taglen}).
 *
 * Reference:
 * - RFC 7519 "JSON Web Token"
 * - RFC 7518 "JSON Web Algorithms"
 * - NIST FIPS 198-1 "The Keyed-Hash Message Authentication Code (HMAC)"
 * - Stanford CS 255 / MIT 6.858
 */

/* SHA-256 core (FIPS 180-4) */
typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buf[64];
} SHA256_CTX;

static const uint32_t SHA256_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTR32(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z)   (((x)&(y))^(~(x)&(z)))
#define MAJ(x,y,z)  (((x)&(y))^((x)&(z))^((y)&(z)))
#define EP0(x)      (ROTR32(x,2)^ROTR32(x,13)^ROTR32(x,22))
#define EP1(x)      (ROTR32(x,6)^ROTR32(x,11)^ROTR32(x,25))
#define SIG0(x)     (ROTR32(x,7)^ROTR32(x,18)^((x)>>3))
#define SIG1(x)     (ROTR32(x,17)^ROTR32(x,19)^((x)>>10))

static void sha256_transform(SHA256_CTX *ctx, const uint8_t *data) {
    uint32_t a, b, c, d, e, f, g, h, t1, t2, W[64];
    int j;
    for (j = 0; j < 16; j++)
        W[j] = ((uint32_t)data[j*4]<<24)|((uint32_t)data[j*4+1]<<16)|
               ((uint32_t)data[j*4+2]<<8)|(uint32_t)data[j*4+3];
    for (; j < 64; j++)
        W[j] = SIG1(W[j-2]) + W[j-7] + SIG0(W[j-15]) + W[j-16];
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
    for (j = 0; j < 64; j++) {
        t1 = h + EP1(e) + CH(e,f,g) + SHA256_K[j] + W[j];
        t2 = EP0(a) + MAJ(a,b,c);
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(SHA256_CTX *ctx) {
    ctx->state[0]=0x6a09e667;ctx->state[1]=0xbb67ae85;ctx->state[2]=0x3c6ef372;
    ctx->state[3]=0xa54ff53a;ctx->state[4]=0x510e527f;ctx->state[5]=0x9b05688c;
    ctx->state[6]=0x1f83d9ab;ctx->state[7]=0x5be0cd19;
    ctx->count = 0;
}

static void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        ctx->buf[ctx->count++ % 64] = data[i];
        if (ctx->count % 64 == 0) sha256_transform(ctx, ctx->buf);
    }
}

static void sha256_final(SHA256_CTX *ctx, uint8_t digest[32]) {
    uint64_t bits = ctx->count * 8;
    int padlen = (ctx->count % 64 < 56) ? (int)(56 - ctx->count % 64) : (int)(120 - ctx->count % 64);
    uint8_t pad[128]; size_t i;
    pad[0] = 0x80;
    for (i = 1; i < (size_t)padlen; i++) pad[i] = 0;
    sha256_update(ctx, pad, (size_t)padlen);
    uint8_t lenbuf[8];
    for (i = 0; i < 8; i++) lenbuf[7-i] = (uint8_t)(bits >> (i*8));
    sha256_update(ctx, lenbuf, 8);
    for (i = 0; i < 8; i++) {
        digest[i*4]   = (uint8_t)(ctx->state[i] >> 24);
        digest[i*4+1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i*4+2] = (uint8_t)(ctx->state[i] >> 8);
        digest[i*4+3] = (uint8_t)(ctx->state[i]);
    }
}

/* HMAC-SHA256 (FIPS 198-1) */
#define HMAC_BLOCK 64
static void hmac_sha256(const uint8_t *key, size_t key_len,
                         const uint8_t *msg, size_t msg_len,
                         uint8_t mac[32]) {
    uint8_t k_ipad[HMAC_BLOCK], k_opad[HMAC_BLOCK], tk[32];
    SHA256_CTX ctx; size_t i;
    if (key_len > HMAC_BLOCK) {
        sha256_init(&ctx); sha256_update(&ctx, key, key_len); sha256_final(&ctx, tk);
        key = tk; key_len = 32;
    }
    memset(k_ipad, 0x36, HMAC_BLOCK); memset(k_opad, 0x5c, HMAC_BLOCK);
    for (i = 0; i < key_len; i++) { k_ipad[i] ^= key[i]; k_opad[i] ^= key[i]; }
    sha256_init(&ctx); sha256_update(&ctx, k_ipad, HMAC_BLOCK);
    sha256_update(&ctx, msg, msg_len); sha256_final(&ctx, tk);
    sha256_init(&ctx); sha256_update(&ctx, k_opad, HMAC_BLOCK);
    sha256_update(&ctx, tk, 32); sha256_final(&ctx, mac);
}

/* Base64URL (RFC 4648 section 5) */
static const char b64url_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

int jwt_base64url_encode(const uint8_t *data, size_t len, char *out, size_t cap) {
    if (!data || !out) return -1;
    size_t i, j = 0;
    for (i = 0; i < len; i += 3) {
        uint32_t v = (uint32_t)data[i] << 16;
        if (i + 1 < len) v |= (uint32_t)data[i+1] << 8;
        if (i + 2 < len) v |= (uint32_t)data[i+2];
        if (j + 4 > cap) return -1;
        out[j++] = b64url_chars[(v >> 18) & 0x3F];
        out[j++] = b64url_chars[(v >> 12) & 0x3F];
        out[j++] = (i + 1 < len) ? b64url_chars[(v >> 6) & 0x3F] : '=';
        out[j++] = (i + 2 < len) ? b64url_chars[v & 0x3F] : '=';
    }
    while (j > 0 && out[j-1] == '=') j--;
    if (j < cap) out[j] = '\0';
    return (int)j;
}

int jwt_base64url_decode(const char *in, uint8_t *out, size_t cap) {
    if (!in || !out) return -1;
    (void)cap;
    size_t i = 0, j = 0, len = strlen(in);
    uint32_t v = 0; int bits = 0;
    for (i = 0; i < len; i++) {
        const char *p = strchr(b64url_chars, in[i]);
        if (!p) { if (in[i] == '=') break; continue; }
        v = (v << 6) | (uint32_t)(p - b64url_chars);
        bits += 6;
        if (bits >= 8) { bits -= 8; out[j++] = (uint8_t)(v >> bits); }
    }
    return (int)j;
}

void jwt_hs256_sign(const char *header_b64, const char *payload_b64,
                     const uint8_t *secret, size_t secret_len,
                     char *signature_b64, size_t sig_cap) {
    if (!header_b64 || !payload_b64 || !secret || !signature_b64) return;
    char input[6000];
    int ilen = snprintf(input, sizeof(input), "%s.%s", header_b64, payload_b64);
    if (ilen <= 0) return;
    uint8_t mac[32];
    hmac_sha256(secret, secret_len, (uint8_t*)input, (size_t)ilen, mac);
    jwt_base64url_encode(mac, 32, signature_b64, sig_cap);
}

bool jwt_hs256_verify(const char *header_b64, const char *payload_b64,
                       const char *signature_b64,
                       const uint8_t *secret, size_t secret_len) {
    if (!header_b64 || !payload_b64 || !signature_b64 || !secret) return false;
    char computed_sig[JWT_MAX_SIG];
    jwt_hs256_sign(header_b64, payload_b64, secret, secret_len,
                    computed_sig, sizeof(computed_sig));
    return strcmp(computed_sig, signature_b64) == 0;
}

static const char JWT_HEADER_HS256[] = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";

int jwt_create(JWTAlgorithm alg, const JWTClaims *claims,
                const uint8_t *secret, size_t secret_len,
                char *token, size_t token_cap) {
    if (!claims || !token || token_cap < 32) return -1;
    (void)alg;
    int hdr_len = (int)strlen(JWT_HEADER_HS256);
    char hdr_b64[512];
    jwt_base64url_encode((const uint8_t*)JWT_HEADER_HS256, (size_t)hdr_len, hdr_b64, sizeof(hdr_b64));
    char payload[JWT_MAX_PAYLOAD];
    int plen = snprintf(payload, sizeof(payload),
        "{\"iss\":\"%s\",\"sub\":\"%s\",\"aud\":\"%s\",\"exp\":%llu,"
        "\"iat\":%llu,\"nbf\":%llu,\"jti\":\"%s\",\"scope\":\"%s\"}",
        claims->iss, claims->sub, claims->aud,
        (unsigned long long)claims->exp, (unsigned long long)claims->iat,
        (unsigned long long)claims->nbf, claims->jti, claims->scope);
    if (plen <= 0 || plen >= (int)sizeof(payload)) return -1;
    char pay_b64[8192];
    jwt_base64url_encode((uint8_t*)payload, (size_t)plen, pay_b64, sizeof(pay_b64));
    char sig_b64[JWT_MAX_SIG];
    jwt_hs256_sign(hdr_b64, pay_b64, secret, secret_len, sig_b64, sizeof(sig_b64));
    return snprintf(token, token_cap, "%s.%s.%s", hdr_b64, pay_b64, sig_b64);
}

bool jwt_validate(const char *token, const uint8_t *secret, size_t secret_len,
                   JWTClaims *claims_out) {
    if (!token || !secret) return false;
    char tok_copy[JWT_MAX_TOKEN];
    strncpy(tok_copy, token, sizeof(tok_copy)-1);
    tok_copy[sizeof(tok_copy)-1] = '\0';
    char *hdr = tok_copy;
    char *pay = strchr(hdr, '.');
    if (!pay) return false; *pay++ = '\0';
    char *sig = strchr(pay, '.');
    if (!sig) return false; *sig++ = '\0';
    if (!jwt_hs256_verify(hdr, pay, sig, secret, secret_len)) return false;
    if (claims_out) {
        memset(claims_out, 0, sizeof(*claims_out));
        sscanf(pay, "{\"iss\":\"%127[^\"]\",\"sub\":\"%127[^\"]\","
               "\"aud\":\"%127[^\"]\",\"exp\":%llu,\"iat\":%llu,"
               "\"nbf\":%llu,\"jti\":\"%63[^\"]\",\"scope\":\"%255[^\"]\"}",
               claims_out->iss, claims_out->sub, claims_out->aud,
               (unsigned long long*)&claims_out->exp,
               (unsigned long long*)&claims_out->iat,
               (unsigned long long*)&claims_out->nbf,
               claims_out->jti, claims_out->scope);
    }
    return true;
}

bool jwt_is_expired(const JWTClaims *claims, uint64_t leeway_seconds) {
    if (!claims) return true;
    uint64_t now = (uint64_t)time(NULL);
    return now > (claims->exp + leeway_seconds);
}
