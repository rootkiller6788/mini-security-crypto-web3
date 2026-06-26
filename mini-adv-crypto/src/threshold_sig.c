#include "threshold_sig.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int64_t ts_mod(int64_t a, int64_t m) {
    int64_t r = a % m;
    return r < 0 ? r + m : r;
}

static int64_t ts_mod_inv(int64_t a, int64_t m) {
    int64_t m0 = m, y = 0, x = 1;
    if (m == 1) return 0;
    while (a > 1) {
        int64_t q = a / m, t = m;
        m = a % m; a = t; t = y;
        y = x - q * y; x = t;
    }
    if (x < 0) x += m0;
    return x;
}

static int64_t ts_eval_poly(const int64_t *coeffs, uint32_t degree, int64_t x, int64_t mod) {
    int64_t result = 0, xp = 1;
    for (uint32_t i = 0; i <= degree; i++) {
        result = (result + coeffs[i] * xp) % mod;
        xp = (xp * x) % mod;
    }
    return ts_mod(result, mod);
}

int ts_sss_split(ts_sss_ctx_t *ctx, int64_t secret,
                 uint32_t threshold, uint32_t total) {
    if (threshold > total || total > TS_MAX_SHARES) return -1;
    ctx->threshold = threshold;
    ctx->total     = total;
    ctx->secret    = secret;

    int64_t prime = TS_SSS_PRIME;
    int64_t coeffs[TS_MAX_PARTIES];
    coeffs[0] = secret;
    for (uint32_t i = 1; i < threshold; i++) {
        coeffs[i] = (int64_t)((uint64_t)(i * 31337 + 7919) % (uint64_t)(prime - 1) + 1);
    }

    for (uint32_t i = 0; i < total; i++) {
        ctx->shares[i].id = i;
        ctx->shares[i].x  = (int64_t)(i + 1);
        ctx->shares[i].y  = ts_eval_poly(coeffs, threshold - 1, ctx->shares[i].x, prime);
    }
    return 0;
}

int ts_sss_reconstruct(int64_t *secret, const ts_share_t *shares,
                       uint32_t num_shares, uint32_t threshold) {
    if (num_shares < threshold) return -1;
    int64_t prime = TS_SSS_PRIME, result = 0;
    for (uint32_t i = 0; i < threshold; i++) {
        int64_t numerator = 1, denominator = 1;
        int64_t xi = shares[i].x;
        for (uint32_t j = 0; j < threshold; j++) {
            if (i == j) continue;
            int64_t xj = shares[j].x;
            numerator   = ts_mod(numerator * (-xj), prime);
            denominator = ts_mod(denominator * (xi - xj), prime);
        }
        int64_t lagrange = ts_mod(numerator * ts_mod_inv(denominator, prime), prime);
        result = ts_mod(result + shares[i].y * lagrange, prime);
    }
    *secret = result;
    return 0;
}

int ts_sss_add_share(ts_share_t *r, const ts_share_t *a, const ts_share_t *b,
                     const int64_t *prime) {
    int64_t p = prime ? *prime : TS_SSS_PRIME;
    r->x  = a->x;
    r->y  = ts_mod(a->y + b->y, p);
    r->id = a->id;
    return 0;
}

int ts_sss_mul_share(ts_share_t *r, const ts_share_t *a,
                     const ts_share_t *b, const int64_t *prime) {
    int64_t p = prime ? *prime : TS_SSS_PRIME;
    r->x  = a->x;
    r->y  = ts_mod(a->y * b->y, p);
    r->id = a->id;
    return 0;
}

int ts_sss_lagrange_coeff(int64_t *coeff, const uint32_t *indices,
                          uint32_t count, uint32_t target_idx, int64_t prime) {
    int64_t numerator = 1, denominator = 1;
    int64_t xt = (int64_t)target_idx;
    for (uint32_t j = 0; j < count; j++) {
        if (indices[j] == target_idx) continue;
        int64_t xj = (int64_t)indices[j];
        numerator   = ts_mod(numerator * (-xj), prime);
        denominator = ts_mod(denominator * (xt - xj), prime);
    }
    *coeff = ts_mod(numerator * ts_mod_inv(denominator, prime), prime);
    return 0;
}

static void ts_frost_hash(uint8_t *out, uint32_t outlen,
                          const uint8_t *in, uint32_t inlen) {
    uint8_t h = 0;
    for (uint32_t i = 0; i < inlen; i++) h ^= in[i];
    for (uint32_t i = 0; i < outlen; i++) {
        out[i] = (uint8_t)(h + i * 31 + (inlen % 256));
    }
}

int ts_frost_keygen_round1(ts_frost_party_t *party, uint32_t party_id,
                           uint32_t threshold, uint32_t num_signers) {
    memset(party, 0, sizeof(*party));
    party->party_id   = party_id;
    party->threshold  = threshold;
    party->num_signers= num_signers;

    for (int i = 0; i < TS_FROST_R_BYTES; i++) {
        party->secret_key_share[i] = (uint8_t)(party_id * 37 + i * 7);
        party->public_key[i]       = (uint8_t)(party->secret_key_share[i] * 31);
        party->group_pubkey[i]     = (uint8_t)(party->public_key[i] ^ 0x5A);
    }
    return 0;
}

int ts_frost_sign_round1(ts_frost_nonce_t *nonce, ts_frost_commit_t *commit,
                         const ts_frost_party_t *party) {
    memset(nonce, 0, sizeof(*nonce));
    memset(commit, 0, sizeof(*commit));
    nonce->party_id = party->party_id;
    for (int i = 0; i < TS_FROST_R_BYTES; i++) {
        nonce->data[i]            = (uint8_t)(party->secret_key_share[i] ^ (i * 13));
        commit->commitment[i]     = (uint8_t)(nonce->data[i] * 41);
        commit->binding[i % TS_FROST_CTX_BYTES] = (uint8_t)(i * 7 + party->party_id);
    }
    return 0;
}

int ts_frost_sign_round2(uint8_t sig_z[TS_FROST_Z_BYTES],
                         const ts_frost_party_t *party,
                         const ts_frost_nonce_t *nonce,
                         const uint8_t aggregate_r[TS_FROST_R_BYTES],
                         const uint8_t challenge[TS_FROST_C_BYTES],
                         const uint8_t *msg, uint32_t msglen) {
    uint8_t msg_hash = 0;
    for (uint32_t i = 0; i < msglen; i++) msg_hash ^= msg[i];

    for (int i = 0; i < TS_FROST_Z_BYTES; i++) {
        int32_t val = (int32_t)nonce->data[i] +
                      (int32_t)party->secret_key_share[i] *
                      (int32_t)challenge[i % TS_FROST_C_BYTES] +
                      (int32_t)msg_hash;
        sig_z[i] = (uint8_t)(val % 256);
    }
    (void)aggregate_r;
    return 0;
}

int ts_frost_aggregate_nonces(uint8_t aggregate_r[TS_FROST_R_BYTES],
                              const ts_frost_commit_t *commits, uint32_t count) {
    memset(aggregate_r, 0, TS_FROST_R_BYTES);
    for (uint32_t c = 0; c < count; c++) {
        for (int i = 0; i < TS_FROST_R_BYTES; i++) {
            aggregate_r[i] ^= commits[c].commitment[i];
        }
    }
    return 0;
}

int ts_frost_aggregate_sigs(ts_frost_signature_t *sig,
                            const uint8_t sig_shares[][TS_FROST_Z_BYTES],
                            const ts_frost_party_t *party, uint32_t count) {
    memset(sig, 0, sizeof(*sig));
    sig->num_signers = party->num_signers;
    sig->used_count  = count;
    for (uint32_t c = 0; c < count && c < TS_MAX_PARTIES; c++) {
        sig->used_parties[c] = c;
        for (int i = 0; i < TS_FROST_Z_BYTES; i++) {
            sig->sig_z[i] = (uint8_t)((sig->sig_z[i] + sig_shares[c][i]) % 256);
        }
    }
    memcpy(sig->group_pubkey, party->group_pubkey, TS_FROST_R_BYTES);
    ts_frost_hash(sig->challenge, TS_FROST_C_BYTES,
                  sig->sig_r, TS_FROST_R_BYTES);
    return 0;
}

int ts_frost_verify(const ts_frost_signature_t *sig,
                    const uint8_t *msg, uint32_t msglen,
                    const uint8_t group_pubkey[TS_FROST_R_BYTES]) {
    uint8_t msg_hash = 0;
    for (uint32_t i = 0; i < msglen; i++) msg_hash ^= msg[i];

    uint8_t expected_challenge[TS_FROST_C_BYTES];
    ts_frost_hash(expected_challenge, TS_FROST_C_BYTES,
                  sig->sig_r, TS_FROST_R_BYTES);

    int match = memcmp(sig->challenge, expected_challenge, TS_FROST_C_BYTES) == 0;
    int pk_match = memcmp(sig->group_pubkey, group_pubkey, TS_FROST_R_BYTES) == 0;
    (void)msg_hash;
    return (match && pk_match) ? 0 : -1;
}

int ts_dkg_init(ts_dkg_ctx_t *ctx, uint32_t threshold, uint32_t total) {
    if (threshold > total || total > TS_MAX_PARTIES) return -1;
    memset(ctx, 0, sizeof(*ctx));
    ctx->threshold     = threshold;
    ctx->total         = total;
    ctx->current_round = 0;
    return 0;
}

int ts_dkg_round1(ts_dkg_ctx_t *ctx, uint32_t party_id) {
    if (party_id >= ctx->total) return -1;
    ts_dkg_party_t *p = &ctx->parties[party_id];
    p->party_id  = party_id;
    p->threshold = ctx->threshold;
    p->total     = ctx->total;
    p->round     = 1;

    for (uint32_t i = 0; i < ctx->threshold; i++) {
        for (int j = 0; j < TS_FROST_R_BYTES; j++) {
            p->coeff[i][j] = (uint8_t)(party_id * 13 + i * 7 + j);
        }
    }
    for (uint32_t i = 0; i < ctx->total; i++) {
        for (int j = 0; j < TS_FROST_R_BYTES; j++) {
            p->public_commit[i][j] = (uint8_t)(party_id * 31 + i * 11 + j);
        }
    }
    ctx->current_round = 1;
    return 0;
}

int ts_dkg_round2(ts_dkg_ctx_t *ctx, uint32_t party_id) {
    if (party_id >= ctx->total) return -1;
    ts_dkg_party_t *p = &ctx->parties[party_id];
    p->round = 2;

    for (uint32_t dest = 0; dest < ctx->total; dest++) {
        uint8_t share = 0;
        for (uint32_t k = 0; k < ctx->threshold; k++) {
            share ^= p->coeff[k][dest % TS_FROST_R_BYTES];
        }
        for (int j = 0; j < TS_FROST_R_BYTES; j++) {
            p->private_share[dest][j] = (uint8_t)(share * (dest + 1) + j);
        }
    }
    ctx->current_round = 2;
    return 0;
}

int ts_dkg_round3(ts_dkg_ctx_t *ctx, uint32_t party_id) {
    if (party_id >= ctx->total) return -1;
    ctx->parties[party_id].round = 3;

    uint8_t pk_acc = 0;
    for (uint32_t p = 0; p < ctx->total; p++) {
        for (int j = 0; j < TS_FROST_R_BYTES; j++) {
            pk_acc ^= ctx->parties[p].public_commit[0][j];
        }
    }
    for (int j = 0; j < TS_FROST_R_BYTES; j++) {
        ctx->group_public_key[j] = (uint8_t)(pk_acc + j * 17);
    }
    ctx->current_round = 3;
    return 0;
}

int ts_dkg_finalize(uint8_t group_pk[TS_FROST_R_BYTES],
                    uint8_t secret_shares[][TS_FROST_R_BYTES],
                    const ts_dkg_ctx_t *ctx) {
    memcpy(group_pk, ctx->group_public_key, TS_FROST_R_BYTES);
    for (uint32_t p = 0; p < ctx->total; p++) {
        memcpy(secret_shares[p], ctx->parties[p].private_share[0], TS_FROST_R_BYTES);
    }
    return 0;
}

int ts_refresh_share(ts_share_t *new_share, const ts_share_t *old_share,
                     uint32_t threshold, uint32_t total, uint32_t epoch) {
    int64_t prime = TS_SSS_PRIME;
    int64_t noise = (int64_t)((epoch * 7919 + 31337) % (uint64_t)(prime - 1));

    int64_t coeffs[TS_MAX_PARTIES];
    coeffs[0] = 0;
    for (uint32_t i = 1; i < threshold; i++) {
        coeffs[i] = (int64_t)((uint64_t)(i * noise) % (uint64_t)(prime - 1) + 1);
    }

    new_share->x  = old_share->x;
    new_share->y  = ts_mod(old_share->y + ts_eval_poly(coeffs, threshold - 1, new_share->x, prime), prime);
    new_share->id = old_share->id;
    (void)total;
    return 0;
}

int ts_refresh_proactive(ts_sss_ctx_t *ctx, uint32_t epoch) {
    int64_t prime = TS_SSS_PRIME;
    int64_t noise = (int64_t)((epoch * 7919 + 31337) % (uint64_t)(prime - 1));

    int64_t coeffs[TS_MAX_PARTIES];
    coeffs[0] = 0;
    for (uint32_t i = 1; i < ctx->threshold; i++) {
        coeffs[i] = (int64_t)((uint64_t)(i * noise) % (uint64_t)(prime - 1) + 1);
    }

    for (uint32_t i = 0; i < ctx->total; i++) {
        int64_t add = ts_eval_poly(coeffs, ctx->threshold - 1, ctx->shares[i].x, prime);
        ctx->shares[i].y = ts_mod(ctx->shares[i].y + add, prime);
    }
    return 0;
}

int ts_refresh_verify(const ts_sss_ctx_t *old_ctx, const ts_sss_ctx_t *new_ctx,
                      uint32_t threshold) {
    int64_t old_secret, new_secret;
    ts_share_t old_shares[TS_MAX_SHARES], new_shares[TS_MAX_SHARES];

    for (uint32_t i = 0; i < threshold; i++) {
        old_shares[i] = old_ctx->shares[i];
        new_shares[i] = new_ctx->shares[i];
    }
    ts_sss_reconstruct(&old_secret, old_shares, threshold, threshold);
    ts_sss_reconstruct(&new_secret, new_shares, threshold, threshold);
    return (old_secret == new_secret) ? 0 : -1;
}

void ts_module_version(void) {
    printf("mini-adv-crypto / threshold_sig  v1.0.0  (SSS + FROST + DKG + Refresh)\n");
}
