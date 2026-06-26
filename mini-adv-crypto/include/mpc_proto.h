#ifndef MPC_PROTO_H
#define MPC_PROTO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MPC_MAX_PARTIES        32
#define MPC_SHAMIR_THRESHOLD   16
#define MPC_OT_MESSAGE_BITS    128
#define MPC_OT_MESSAGE_LIMBS  ((MPC_OT_MESSAGE_BITS + 63) / 64)
#define MPC_GARBLE_KEY_BITS    128
#define MPC_GARBLE_KEY_LIMBS  ((MPC_GARBLE_KEY_BITS + 63) / 64)
#define MPC_SPDZ_MAX_PARTIES   8

typedef struct {
    int64_t value;
    int64_t mac_key;
    int64_t mac;
} mpc_spdz_share_t;

typedef struct {
    int64_t x;
    int64_t y;
    uint32_t threshold;
    uint32_t total;
} mpc_shamir_share_t;

typedef struct {
    mpc_shamir_share_t shares[MPC_MAX_PARTIES];
    uint32_t threshold;
    uint32_t total;
    int64_t  secret;
} mpc_shamir_ctx_t;

typedef struct {
    uint64_t key[4];
} mpc_garbled_key_t;

typedef struct {
    mpc_garbled_key_t k0[2];
    mpc_garbled_key_t k1[2];
    uint32_t          output_bit;
} mpc_garbled_gate_t;

typedef struct {
    mpc_garbled_gate_t gates[MPC_MAX_PARTIES * 4];
    uint32_t num_gates;
    uint32_t num_inputs;
    uint32_t num_outputs;
    uint64_t circuit_id;
} mpc_garbled_circuit_t;

typedef struct {
    uint64_t limbs[MPC_OT_MESSAGE_LIMBS];
} mpc_ot_message_t;

typedef struct {
    mpc_ot_message_t m0;
    mpc_ot_message_t m1;
    uint64_t         public_key[4];
    uint64_t         secret_key[4];
} mpc_ot_sender_t;

typedef struct {
    uint64_t choice;
    uint64_t public_key[4];
    mpc_ot_message_t received;
} mpc_ot_receiver_t;

typedef struct {
    mpc_spdz_share_t shares[MPC_SPDZ_MAX_PARTIES];
    int64_t          global_mac_key;
    uint32_t         num_parties;
} mpc_spdz_ctx_t;

typedef enum {
    MPC_PROTO_SHAMIR       = 0,
    MPC_PROTO_GARBLED      = 1,
    MPC_PROTO_OT           = 2,
    MPC_PROTO_SPDZ         = 3,
    MPC_PROTO_GMW          = 4,
    MPC_PROTO_BGW          = 5
} mpc_protocol_t;

int  mpc_shamir_split(mpc_shamir_ctx_t *ctx, int64_t secret,
                      uint32_t threshold, uint32_t total);
int  mpc_shamir_reconstruct(int64_t *secret, const mpc_shamir_ctx_t *ctx,
                            const uint32_t *indices, uint32_t count);
int  mpc_shamir_add_share(mpc_shamir_share_t *r, const mpc_shamir_share_t *a,
                          const mpc_shamir_share_t *b);
int  mpc_shamir_mul_share(mpc_shamir_share_t *r, const mpc_shamir_share_t *a,
                          const mpc_shamir_share_t *b);
void mpc_shamir_print(const mpc_shamir_ctx_t *ctx);

int  mpc_garble_and_gate(mpc_garbled_gate_t *gate, uint64_t wire_a, uint64_t wire_b,
                         uint64_t wire_out);
int  mpc_garble_circuit_init(mpc_garbled_circuit_t *gc, uint32_t num_gates,
                             uint32_t num_inputs, uint32_t num_outputs);
int  mpc_garble_evaluate_circuit(uint64_t *output, const mpc_garbled_circuit_t *gc,
                                 const mpc_garbled_key_t *input_keys, uint32_t num_inputs);
int  mpc_garble_encode_input(mpc_garbled_key_t *key, uint64_t value, uint32_t wire_id);
int  mpc_garble_decode_output(uint64_t value, uint32_t wire_id);
void mpc_garble_print_circuit(const mpc_garbled_circuit_t *gc);

int  mpc_ot_sender_init(mpc_ot_sender_t *sender);
int  mpc_ot_send_messages(mpc_ot_sender_t *sender, const mpc_ot_message_t *m0,
                          const mpc_ot_message_t *m1);
int  mpc_ot_receiver_choose(mpc_ot_receiver_t *receiver, uint64_t choice,
                            const uint64_t pubkey[4]);
int  mpc_ot_receiver_get(const mpc_ot_message_t *msg, const mpc_ot_receiver_t *receiver);
int  mpc_ot_1_of_2(uint64_t *result, const uint64_t *m0, const uint64_t *m1,
                   uint64_t choice);
void mpc_ot_print_messages(const mpc_ot_sender_t *sender);

int  mpc_spdz_init(mpc_spdz_ctx_t *ctx, uint32_t num_parties, int64_t mac_key);
int  mpc_spdz_share(mpc_spdz_ctx_t *ctx, uint32_t party_id, int64_t value);
int  mpc_spdz_reconstruct(int64_t *result, const mpc_spdz_ctx_t *ctx);
int  mpc_spdz_add(mpc_spdz_share_t *r, const mpc_spdz_share_t *a, const mpc_spdz_share_t *b);
int  mpc_spdz_mul(mpc_spdz_share_t *r, const mpc_spdz_share_t *a, const mpc_spdz_share_t *b,
                  const mpc_spdz_ctx_t *ctx);
int  mpc_spdz_verify(const mpc_spdz_ctx_t *ctx);

int  mpc_multi_party_sum(int64_t *result, const int64_t *inputs, uint32_t num_parties);

void mpc_module_version(void);

#ifdef __cplusplus
}
#endif

#endif
