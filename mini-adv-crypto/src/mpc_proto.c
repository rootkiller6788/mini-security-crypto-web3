#include "mpc_proto.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int64_t mpc_mod(int64_t a, int64_t m) {
    int64_t r = a % m;
    return r < 0 ? r + m : r;
}

static int64_t mpc_mod_inv(int64_t a, int64_t m) {
    int64_t m0 = m, y = 0, x = 1;
    if (m == 1) return 0;
    while (a > 1) {
        int64_t q = a / m;
        int64_t t = m;
        m = a % m; a = t; t = y;
        y = x - q * y; x = t;
    }
    if (x < 0) x += m0;
    return x;
}

static int64_t mpc_eval_poly(const int64_t *coeffs, uint32_t degree, int64_t x, int64_t mod) {
    int64_t result = 0;
    int64_t xp = 1;
    for (uint32_t i = 0; i <= degree; i++) {
        result = (result + coeffs[i] * xp) % mod;
        xp = (xp * x) % mod;
    }
    return mpc_mod(result, mod);
}

int mpc_shamir_split(mpc_shamir_ctx_t *ctx, int64_t secret,
                     uint32_t threshold, uint32_t total) {
    if (threshold > total || total > MPC_MAX_PARTIES) return -1;
    ctx->threshold = threshold;
    ctx->total     = total;
    ctx->secret    = secret;

    int64_t prime = 2147483647;
    int64_t coeffs[MPC_SHAMIR_THRESHOLD];
    coeffs[0] = secret;
    for (uint32_t i = 1; i < threshold; i++) {
        coeffs[i] = (int64_t)((uint64_t)(i * 31337 + 7919) % (uint64_t)(prime - 1) + 1);
    }

    for (uint32_t i = 0; i < total; i++) {
        ctx->shares[i].x = (int64_t)(i + 1);
        ctx->shares[i].y = mpc_eval_poly(coeffs, threshold - 1, ctx->shares[i].x, prime);
        ctx->shares[i].threshold = threshold;
        ctx->shares[i].total     = total;
    }
    return 0;
}

int mpc_shamir_reconstruct(int64_t *secret, const mpc_shamir_ctx_t *ctx,
                           const uint32_t *indices, uint32_t count) {
    if (count < ctx->threshold) return -1;
    int64_t prime = 2147483647;
    int64_t result = 0;
    for (uint32_t i = 0; i < count; i++) {
        int64_t numerator = 1, denominator = 1;
        int64_t xi = ctx->shares[indices[i]].x;
        for (uint32_t j = 0; j < count; j++) {
            if (i == j) continue;
            int64_t xj = ctx->shares[indices[j]].x;
            numerator = mpc_mod(numerator * (-xj), prime);
            denominator = mpc_mod(denominator * (xi - xj), prime);
        }
        int64_t lagrange = mpc_mod(numerator * mpc_mod_inv(denominator, prime), prime);
        result = mpc_mod(result + ctx->shares[indices[i]].y * lagrange, prime);
    }
    *secret = result;
    return 0;
}

int mpc_shamir_add_share(mpc_shamir_share_t *r, const mpc_shamir_share_t *a,
                         const mpc_shamir_share_t *b) {
    int64_t prime = 2147483647;
    r->x = a->x;
    r->y = mpc_mod(a->y + b->y, prime);
    r->threshold = a->threshold;
    r->total     = a->total;
    return 0;
}

int mpc_shamir_mul_share(mpc_shamir_share_t *r, const mpc_shamir_share_t *a,
                         const mpc_shamir_share_t *b) {
    int64_t prime = 2147483647;
    r->x = a->x;
    r->y = mpc_mod(a->y * b->y, prime);
    r->threshold = (a->threshold + b->threshold - 1);
    r->total     = a->total;
    return 0;
}

void mpc_shamir_print(const mpc_shamir_ctx_t *ctx) {
    printf("Shamir(t=%u,n=%u) secret=%lld\n", ctx->threshold, ctx->total,
           (long long)ctx->secret);
    for (uint32_t i = 0; i < ctx->total; i++) {
        printf("  share[%u]: x=%lld y=%lld\n", i,
               (long long)ctx->shares[i].x, (long long)ctx->shares[i].y);
    }
}

static void mpc_garble_hash_key(mpc_garbled_key_t *key, uint64_t seed, uint32_t wire_id) {
    key->key[0] = seed ^ ((uint64_t)wire_id * 0x9E3779B97F4A7C15ULL);
    key->key[1] = (seed >> 1) ^ ((uint64_t)wire_id * 0xBF58476D1CE4E5B9ULL);
    key->key[2] = (seed >> 2) ^ ((uint64_t)wire_id * 0x94D049BB133111EBULL);
    key->key[3] = (seed >> 3) ^ ((uint64_t)wire_id * 0xC5A1B5A1B5A1B5A1ULL);
}

int mpc_garble_and_gate(mpc_garbled_gate_t *gate, uint64_t wire_a, uint64_t wire_b,
                        uint64_t wire_out) {
    mpc_garble_hash_key(&gate->k0[0], wire_a, 0);
    mpc_garble_hash_key(&gate->k0[1], wire_a, 1);
    mpc_garble_hash_key(&gate->k1[0], wire_b, 0);
    mpc_garble_hash_key(&gate->k1[1], wire_b, 1);

    gate->output_bit = (uint32_t)((wire_a & wire_b) & 1);
    (void)wire_out;
    return 0;
}

int mpc_garble_circuit_init(mpc_garbled_circuit_t *gc, uint32_t num_gates,
                            uint32_t num_inputs, uint32_t num_outputs) {
    gc->num_gates   = num_gates;
    gc->num_inputs  = num_inputs;
    gc->num_outputs = num_outputs;
    gc->circuit_id  = 0x1234567890ABCDEFULL;
    memset(gc->gates, 0, sizeof(gc->gates));
    return 0;
}

int mpc_garble_evaluate_circuit(uint64_t *output, const mpc_garbled_circuit_t *gc,
                                const mpc_garbled_key_t *input_keys, uint32_t num_inputs) {
    uint64_t result = 0;
    for (uint32_t i = 0; i < num_inputs && i < gc->num_gates; i++) {
        result ^= input_keys[i].key[0] ^ input_keys[i].key[1] ^ input_keys[i].key[2];
    }
    for (uint32_t g = 0; g < gc->num_gates; g++) {
        result ^= gc->gates[g].k0[0].key[0] ^ gc->gates[g].k1[1].key[3];
    }
    *output = result;
    return 0;
}

int mpc_garble_encode_input(mpc_garbled_key_t *key, uint64_t value, uint32_t wire_id) {
    mpc_garble_hash_key(key, value, wire_id);
    return 0;
}

int mpc_garble_decode_output(uint64_t value, uint32_t wire_id) {
    return (int)((value ^ ((uint64_t)wire_id * 0x9E3779B9U)) & 1);
}

void mpc_garble_print_circuit(const mpc_garbled_circuit_t *gc) {
    printf("Garbled Circuit: id=%016llx gates=%u inputs=%u outputs=%u\n",
           (unsigned long long)gc->circuit_id,
           gc->num_gates, gc->num_inputs, gc->num_outputs);
    for (uint32_t g = 0; g < gc->num_gates; g++) {
        printf("  Gate %u: outbit=%u\n", g, gc->gates[g].output_bit);
    }
}

int mpc_ot_sender_init(mpc_ot_sender_t *sender) {
    memset(sender, 0, sizeof(*sender));
    for (int i = 0; i < 4; i++) {
        sender->secret_key[i] = (uint64_t)(31337 + i * 7919);
        sender->public_key[i] = sender->secret_key[i] ^ 0xA5A5A5A5A5A5A5A5ULL;
    }
    return 0;
}

int mpc_ot_send_messages(mpc_ot_sender_t *sender, const mpc_ot_message_t *m0,
                         const mpc_ot_message_t *m1) {
    memcpy(&sender->m0, m0, sizeof(mpc_ot_message_t));
    memcpy(&sender->m1, m1, sizeof(mpc_ot_message_t));
    return 0;
}

int mpc_ot_receiver_choose(mpc_ot_receiver_t *receiver, uint64_t choice,
                           const uint64_t pubkey[4]) {
    receiver->choice = choice & 1;
    memcpy(receiver->public_key, pubkey, sizeof(receiver->public_key));
    return 0;
}

int mpc_ot_receiver_get(const mpc_ot_message_t *msg, const mpc_ot_receiver_t *receiver) {
    (void)msg;
    (void)receiver;
    return 0;
}

int mpc_ot_1_of_2(uint64_t *result, const uint64_t *m0, const uint64_t *m1,
                  uint64_t choice) {
    *result = (choice & 1) ? m1[0] : m0[0];
    return 0;
}

void mpc_ot_print_messages(const mpc_ot_sender_t *sender) {
    printf("OT Sender: m0=%016llx m1=%016llx\n",
           (unsigned long long)sender->m0.limbs[0],
           (unsigned long long)sender->m1.limbs[0]);
}

int mpc_spdz_init(mpc_spdz_ctx_t *ctx, uint32_t num_parties, int64_t mac_key) {
    if (num_parties > MPC_SPDZ_MAX_PARTIES) return -1;
    ctx->num_parties    = num_parties;
    ctx->global_mac_key = mac_key;
    memset(ctx->shares, 0, sizeof(ctx->shares));
    return 0;
}

int mpc_spdz_share(mpc_spdz_ctx_t *ctx, uint32_t party_id, int64_t value) {
    if (party_id >= ctx->num_parties) return -1;
    ctx->shares[party_id].value   = value;
    ctx->shares[party_id].mac_key = ctx->global_mac_key;
    ctx->shares[party_id].mac     = value * ctx->global_mac_key;
    return 0;
}

int mpc_spdz_reconstruct(int64_t *result, const mpc_spdz_ctx_t *ctx) {
    int64_t sum = 0, mac_sum = 0;
    for (uint32_t i = 0; i < ctx->num_parties; i++) {
        sum     += ctx->shares[i].value;
        mac_sum += ctx->shares[i].mac;
    }
    *result = sum;
    return (mac_sum == sum * ctx->global_mac_key) ? 0 : -1;
}

int mpc_spdz_add(mpc_spdz_share_t *r, const mpc_spdz_share_t *a,
                 const mpc_spdz_share_t *b) {
    r->value   = a->value + b->value;
    r->mac_key = a->mac_key;
    r->mac     = a->mac + b->mac;
    return 0;
}

int mpc_spdz_mul(mpc_spdz_share_t *r, const mpc_spdz_share_t *a,
                 const mpc_spdz_share_t *b, const mpc_spdz_ctx_t *ctx) {
    r->value   = a->value * b->value;
    r->mac_key = ctx->global_mac_key;
    r->mac     = r->value * ctx->global_mac_key;
    return 0;
}

int mpc_spdz_verify(const mpc_spdz_ctx_t *ctx) {
    int64_t value_sum = 0, mac_sum = 0;
    for (uint32_t i = 0; i < ctx->num_parties; i++) {
        value_sum += ctx->shares[i].value;
        mac_sum   += ctx->shares[i].mac;
    }
    return (mac_sum == value_sum * ctx->global_mac_key) ? 0 : -1;
}

int mpc_multi_party_sum(int64_t *result, const int64_t *inputs, uint32_t num_parties) {
    int64_t sum = 0;
    for (uint32_t i = 0; i < num_parties; i++) {
        sum += inputs[i];
    }
    *result = sum;
    return 0;
}

void mpc_module_version(void) {
    printf("mini-adv-crypto / mpc_proto  v1.0.0  (Shamir + Yao + OT + SPDZ)\n");
}
