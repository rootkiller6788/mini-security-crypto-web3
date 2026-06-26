#ifndef AUTH_SESSION_H
#define AUTH_SESSION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Password Hashing (PBKDF2-SHA256) ────────────────────────────── */

#define AUTH_SALT_SIZE      16
#define AUTH_HASH_SIZE      32
#define AUTH_PBKDF2_ITERS   100000

typedef struct {
    uint8_t salt[AUTH_SALT_SIZE];
    uint8_t hash[AUTH_HASH_SIZE];
    int     iterations;
} auth_password_t;

bool auth_password_hash(const char* password, auth_password_t* result);

bool auth_password_verify(const char* password, const auth_password_t* stored);

void auth_password_to_base64(const auth_password_t* pw, char* output, size_t out_size);

bool auth_password_from_base64(const char* encoded, auth_password_t* pw);

int  auth_password_strength(const char* password);

/* ── MFA / TOTP (RFC 6238) ───────────────────────────────────────── */

#define TOTP_DIGITS       6
#define TOTP_PERIOD       30
#define TOTP_SECRET_MIN   16
#define TOTP_SECRET_MAX   64

typedef struct {
    char   secret_base32[64];
    size_t secret_len;
    int    digits;
    int    period;
} totp_config_t;

void totp_init(totp_config_t* cfg, int digits, int period);

bool totp_generate_secret(char* output, size_t out_size);

uint32_t totp_generate_code(const totp_config_t* cfg, time_t timestamp);

bool totp_validate_code(const totp_config_t* cfg, time_t timestamp, uint32_t code);

bool totp_validate_window(const totp_config_t* cfg, time_t timestamp,
                          uint32_t code, int window);

uint32_t totp_hotp(const uint8_t* key, size_t key_len, uint64_t counter, int digits);

/* ── Session Management ──────────────────────────────────────────── */

typedef enum {
    SAMESITE_STRICT,
    SAMESITE_LAX,
    SAMESITE_NONE
} session_samesite_t;

typedef struct {
    char     id[64];
    char     user_id[128];
    char     ip_addr[46];
    char     user_agent[256];
    time_t   created_at;
    time_t   expires_at;
    bool     is_active;
    uint32_t rotation_count;
} session_t;

void session_init(session_t* sess);

bool session_generate_id(session_t* sess);

bool session_is_expired(const session_t* sess);

int  session_cookie_header(const session_t* sess, bool http_only,
                           bool secure, session_samesite_t same_site,
                           const char* path, char* output, size_t out_size);

/* ── Session Fixation Prevention ─────────────────────────────────── */

typedef struct {
    char     original_id[64];
    char     new_id[64];
    time_t   rotated_at;
    bool     is_rotated;
    uint32_t login_count;
} session_fixation_t;

void session_fix_init(session_fixation_t* sf);

bool session_fix_prelogin(session_fixation_t* sf, const char* session_id);

bool session_fix_postlogin(session_fixation_t* sf);

bool session_fix_validate(const session_fixation_t* sf, const char* session_id);

/* ── Rate Limiting (Brute Force Protection) ──────────────────────── */

typedef struct {
    time_t window_start;
    int    max_attempts;
    int    current_attempts;
    time_t block_until;
    int    window_seconds;
    int    block_duration;
} rate_limiter_t;

void ratelimit_init(rate_limiter_t* rl, int max_attempts,
                    int window_seconds, int block_duration);

bool ratelimit_check(rate_limiter_t* rl);

bool ratelimit_is_blocked(const rate_limiter_t* rl);

int  ratelimit_remaining(const rate_limiter_t* rl);

void ratelimit_reset(rate_limiter_t* rl);

/* ── OAuth2 Implicit Flow Issues ─────────────────────────────────── */

typedef enum {
    OAUTH2_GRANT_IMPLICIT,
    OAUTH2_GRANT_AUTH_CODE,
    OAUTH2_GRANT_CLIENT_CREDENTIALS,
    OAUTH2_GRANT_PASSWORD,
    OAUTH2_GRANT_REFRESH_TOKEN
} oauth2_grant_t;

typedef struct {
    bool valid;
    int  issues[8];
    int  issue_count;
} oauth2_audit_t;

void oauth2_audit_implicit_flow(const char* redirect_uri, const char* client_id,
                                 const char* response_type, oauth2_audit_t* audit);

bool oauth2_validate_state(const char* state_param);

bool oauth2_validate_redirect_uri(const char* registered, const char* received);

/* ── JWT ─────────────────────────────────────────────────────────── */

typedef enum {
    JWT_ALG_NONE,
    JWT_ALG_HS256,
    JWT_ALG_HS384,
    JWT_ALG_HS512,
    JWT_ALG_RS256,
    JWT_ALG_ES256
} jwt_algorithm_t;

typedef struct {
    char header[512];
    char payload[4096];
    char signature[512];
    jwt_algorithm_t algorithm;
    bool parsed;
} jwt_token_t;

typedef struct {
    bool    valid;
    bool    none_attack;       /* alg=none attack detected */
    bool    weak_key;          /* HMAC key < 32 bytes */
    bool    expired;
    bool    signature_match;
    int     issues_found;
    char    issues_desc[4][128];
} jwt_validation_t;

void jwt_init(jwt_token_t* token);
bool jwt_parse(const char* token_str, jwt_token_t* token);
bool jwt_sign(const jwt_token_t* token, const uint8_t* key, size_t key_len,
              char* output, size_t out_size);

int  jwt_validate(const jwt_token_t* token, const uint8_t* key, size_t key_len,
                  jwt_validation_t* result);

bool jwt_none_attack_check(const char* token_str);

bool jwt_weak_key_check(const uint8_t* key, size_t key_len, jwt_algorithm_t alg);

/* ── Password Reset ──────────────────────────────────────────────── */

typedef struct {
    char   token[64];
    char   user_id[128];
    time_t created_at;
    time_t expires_at;
    bool   used;
} password_reset_t;

bool pwd_reset_generate(password_reset_t* reset, const char* user_id,
                         int expiry_seconds);

bool pwd_reset_validate(const password_reset_t* reset, const char* token);

bool pwd_reset_is_expired(const password_reset_t* reset);

int  pwd_reset_entropy_bits(const char* token);

#ifdef __cplusplus
}
#endif

#endif /* AUTH_SESSION_H */
