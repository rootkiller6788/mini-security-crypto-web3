#ifndef THRESHOLD_SIG_H
#define THRESHOLD_SIG_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TS_MAX_PARTIES      32
#define TS_MAX_SHARES       64
#define TS_SSS_PRIME        2147483647
#define TS_FROST_R_BYTES    32
#define TS_FROST_C_BYTES    32
#define TS_FROST_Z_BYTES    32
#define TS_FROST_CTX_BYTES  64
#define TS_DKG_ROUNDS       3
#define TS_REFRESH_INTERVAL 1024

typedef struct {
    int64_t  x;
    int64_t  y;
    uint32_t id;
} ts_share_t;

typedef struct {
    ts_share_t shares[TS_MAX_SHARES];
    uint32_t   threshold;
    uint32_t   total;
    int64_t    secret;
} ts_sss_ctx_t;

typedef struct {
    uint8_t  data[TS_FROST_R_BYTES];
    uint32_t party_id;
} ts_frost_nonce_t;

typedef struct {
    uint8_t data[TS_FROST_R_BYTES];
    uint8_t commitment[TS_FROST_R_BYTES];
    uint8_t binding[TS_FROST_CTX_BYTES];
} ts_frost_commit_t;

typedef struct {
    ts_frost_nonce_t  nonce;
    ts_frost_commit_t commit;
    uint8_t           secret_key_share[TS_FROST_R_BYTES];
    uint8_t           public_key[TS_FROST_R_BYTES];
    uint8_t           group_pubkey[TS_FROST_R_BYTES];
    uint32_t          party_id;
    uint32_t          threshold;
    uint32_t          num_signers;
} ts_frost_party_t;

typedef struct {
    uint8_t  sig_r[TS_FROST_R_BYTES];
    uint8_t  sig_z[TS_FROST_Z_BYTES];
    uint8_t  challenge[TS_FROST_C_BYTES];
    uint8_t  group_pubkey[TS_FROST_R_BYTES];
    uint32_t num_signers;
    uint32_t used_parties[TS_MAX_PARTIES];
    uint32_t used_count;
} ts_frost_signature_t;

typedef struct {
    uint8_t  coeff[TS_MAX_PARTIES][TS_FROST_R_BYTES];
    uint8_t  public_commit[TS_MAX_PARTIES][TS_FROST_R_BYTES];
    uint8_t  private_share[TS_MAX_PARTIES][TS_FROST_R_BYTES];
    uint32_t party_id;
    uint32_t threshold;
    uint32_t total;
    uint32_t round;
} ts_dkg_party_t;

typedef struct {
    ts_dkg_party_t  parties[TS_MAX_PARTIES];
    uint8_t         group_public_key[TS_FROST_R_BYTES];
    uint32_t        threshold;
    uint32_t        total;
    uint32_t        current_round;
} ts_dkg_ctx_t;

typedef enum {
    TS_PROTO_FROST    = 0,
    TS_PROTO_SSS      = 1,
    TS_PROTO_DKG      = 2,
    TS_PROTO_REFRESH  = 3,
    TS_PROTO_LINDSAY  = 4
} ts_protocol_t;

int  ts_sss_split(ts_sss_ctx_t *ctx, int64_t secret,
                  uint32_t threshold, uint32_t total);
int  ts_sss_reconstruct(int64_t *secret, const ts_share_t *shares,
                        uint32_t num_shares, uint32_t threshold);
int  ts_sss_add_share(ts_share_t *r, const ts_share_t *a, const ts_share_t *b,
                      const int64_t *prime);
int  ts_sss_mul_share(ts_share_t *r, const ts_share_t *a,
                      const ts_share_t *b, const int64_t *prime);
int  ts_sss_lagrange_coeff(int64_t *coeff, const uint32_t *indices,
                           uint32_t count, uint32_t target_idx, int64_t prime);

int  ts_frost_keygen_round1(ts_frost_party_t *party, uint32_t party_id,
                            uint32_t threshold, uint32_t num_signers);
int  ts_frost_sign_round1(ts_frost_nonce_t *nonce, ts_frost_commit_t *commit,
                          const ts_frost_party_t *party);
int  ts_frost_sign_round2(uint8_t sig_z[TS_FROST_Z_BYTES],
                          const ts_frost_party_t *party,
                          const ts_frost_nonce_t *nonce,
                          const uint8_t aggregate_r[TS_FROST_R_BYTES],
                          const uint8_t challenge[TS_FROST_C_BYTES],
                          const uint8_t *msg, uint32_t msglen);
int  ts_frost_aggregate_nonces(uint8_t aggregate_r[TS_FROST_R_BYTES],
                               const ts_frost_commit_t *commits, uint32_t count);
int  ts_frost_aggregate_sigs(ts_frost_signature_t *sig,
                             const uint8_t sig_shares[][TS_FROST_Z_BYTES],
                             const ts_frost_party_t *party, uint32_t count);
int  ts_frost_verify(const ts_frost_signature_t *sig,
                     const uint8_t *msg, uint32_t msglen,
                     const uint8_t group_pubkey[TS_FROST_R_BYTES]);

int  ts_dkg_init(ts_dkg_ctx_t *ctx, uint32_t threshold, uint32_t total);
int  ts_dkg_round1(ts_dkg_ctx_t *ctx, uint32_t party_id);
int  ts_dkg_round2(ts_dkg_ctx_t *ctx, uint32_t party_id);
int  ts_dkg_round3(ts_dkg_ctx_t *ctx, uint32_t party_id);
int  ts_dkg_finalize(uint8_t group_pk[TS_FROST_R_BYTES],
                     uint8_t secret_shares[][TS_FROST_R_BYTES],
                     const ts_dkg_ctx_t *ctx);

int  ts_refresh_share(ts_share_t *new_share, const ts_share_t *old_share,
                      uint32_t threshold, uint32_t total, uint32_t epoch);
int  ts_refresh_proactive(ts_sss_ctx_t *ctx, uint32_t epoch);
int  ts_refresh_verify(const ts_sss_ctx_t *old_ctx, const ts_sss_ctx_t *new_ctx,
                       uint32_t threshold);

void ts_module_version(void);

#ifdef __cplusplus
}
#endif

#endif
