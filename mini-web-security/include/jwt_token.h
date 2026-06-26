#ifndef JWT_TOKEN_H
#define JWT_TOKEN_H
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#define JWT_MAX_HEADER  512
#define JWT_MAX_PAYLOAD 4096
#define JWT_MAX_SIG     256
#define JWT_MAX_TOKEN   (JWT_MAX_HEADER + JWT_MAX_PAYLOAD + JWT_MAX_SIG + 8)

/* L4: JWT (RFC 7519) — Stateless Authentication Token
 *
 * Structure: base64url(header).base64url(payload).base64url(signature)
 * Signing algorithms (RFC 7518): HS256 (HMAC-SHA256), RS256 (RSA-SHA256)
 *
 * Security guarantees (informally):
 * - Integrity: signature prevents tampering
 * - Authenticity: shared secret (HS) or PKI (RS) verifies issuer
 * - Stateless: all claims embedded in token
 *
 * Theorem: JWT is secure against chosen-message forgery iff the underlying
 * HMAC/RSA signature scheme is EUF-CMA secure (Bellare et al., 1996).
 * Reference: Stanford CS 255: Cryptography, MIT 6.858: Computer Security
 */

typedef enum { JWT_ALG_HS256, JWT_ALG_RS256, JWT_ALG_NONE } JWTAlgorithm;

typedef struct {
    char iss[128];    /* issuer */
    char sub[128];    /* subject */
    char aud[128];    /* audience */
    uint64_t exp;     /* expiration (unix timestamp) */
    uint64_t iat;     /* issued at */
    uint64_t nbf;     /* not before */
    char jti[64];     /* JWT ID (unique token identifier) */
    char scope[256];  /* OAuth 2.0 scopes */
    char extra[JWT_MAX_PAYLOAD]; /* custom claims JSON */
} JWTClaims;

/* L5: HS256 signing via HMAC-SHA256 (FIPS 198-1) */
void jwt_hs256_sign(const char *header_b64, const char *payload_b64,
                     const uint8_t *secret, size_t secret_len,
                     char *signature_b64, size_t sig_cap);
bool jwt_hs256_verify(const char *header_b64, const char *payload_b64,
                       const char *signature_b64,
                       const uint8_t *secret, size_t secret_len);

/* L5: Base64URL encode/decode (RFC 4648 §5) */
int  jwt_base64url_encode(const uint8_t *data, size_t len, char *out, size_t cap);
int  jwt_base64url_decode(const char *in, uint8_t *out, size_t cap);

/* L7: Full token creation and validation */
int  jwt_create(JWTAlgorithm alg, const JWTClaims *claims,
                const uint8_t *secret, size_t secret_len,
                char *token, size_t token_cap);
bool jwt_validate(const char *token, const uint8_t *secret, size_t secret_len,
                   JWTClaims *claims_out);

/* L4: Token expiry check */
bool jwt_is_expired(const JWTClaims *claims, uint64_t leeway_seconds);

#endif
