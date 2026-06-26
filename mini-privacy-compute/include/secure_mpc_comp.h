#ifndef SECURE_MPC_COMP_H
#define SECURE_MPC_COMP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- secret sharing ---------- */

typedef struct {
    uint64_t  prime;          /* field modulus */
    uint64_t  *shares;        /* additive: x = sum(shares[i]) mod prime */
    size_t    num_parties;
} SecretSharing;

void ss_init(                SecretSharing *ss, size_t num_parties, uint64_t prime);
void ss_share(               const SecretSharing *ss, uint64_t secret,
                             uint64_t *shares_out);
void ss_reconstruct(         const SecretSharing *ss, const uint64_t *shares,
                             uint64_t *secret_out);
void ss_add(                 const SecretSharing *ss,
                             const uint64_t *shares_a, const uint64_t *shares_b,
                             uint64_t *shares_out);
void ss_scalar_mul(          const SecretSharing *ss, const uint64_t *shares,
                             uint64_t scalar, uint64_t *shares_out);
void ss_free(                SecretSharing *ss);

/* ---------- Beaver triples ---------- */

typedef struct {
    uint64_t a_share;        /* [a] */
    uint64_t b_share;        /* [b] */
    uint64_t c_share;        /* [c] where c = a * b mod prime */
    int      consumed;
} BeaverTriple;

typedef struct {
    BeaverTriple *triples;
    size_t        num_triples;
    size_t        used;
    uint64_t      prime;
    uint64_t      seed;
} BeaverTriplePool;

void bt_pool_init(           BeaverTriplePool *pool, size_t num_triples,
                             uint64_t prime, uint64_t seed);
int  bt_pool_generate(       BeaverTriplePool *pool);
int  bt_pool_consume(        BeaverTriplePool *pool, BeaverTriple *triple_out);
void bt_multiply(            const SecretSharing *ss, const BeaverTriple *triple,
                             const uint64_t *x_shares, const uint64_t *y_shares,
                             uint64_t *prod_shares);
void bt_pool_free(           BeaverTriplePool *pool);

/* ---------- SPDZ online phase ---------- */

typedef struct {
    uint64_t *mac_share;
    uint64_t *data_share;
    uint64_t  global_key;
    size_t    num_ops;
} SPDZState;

void spdz_init(              SPDZState *state, size_t data_size, uint64_t global_key);
void spdz_mac_check(         const SPDZState *state, int *valid);
void spdz_online_add(        SPDZState *state, const uint64_t *a, const uint64_t *b,
                             uint64_t *result, size_t n);
void spdz_online_multiply(   SPDZState *state, const uint64_t *a, const uint64_t *b,
                             uint64_t *result, size_t n, const BeaverTriplePool *pool);
void spdz_free(              SPDZState *state);

/* ---------- garbled circuit ---------- */

typedef struct {
    uint8_t *gates;
    size_t   num_gates;
    size_t   num_wires;
    size_t   num_inputs_a;
    size_t   num_inputs_b;
    size_t   num_outputs;
    uint8_t *input_labels_a;
    uint8_t *input_labels_b;
} GarbledCircuit;

void gc_init(                GarbledCircuit *gc, size_t num_inputs_a, size_t num_inputs_b,
                             size_t num_outputs);
void gc_set_gate(            GarbledCircuit *gc, size_t gate_idx,
                             size_t in1, size_t in2, size_t out, uint8_t op);
void gc_garble(              GarbledCircuit *gc, uint64_t seed);
void gc_evaluate(            GarbledCircuit *gc, const uint8_t *input_a,
                             const uint8_t *input_b, uint8_t *output);
void gc_free(                GarbledCircuit *gc);

/* ---------- ORAM ---------- */

typedef struct {
    uint8_t   *position_map;
    uint8_t   *stash;
    uint8_t   *buckets;
    size_t     block_size;
    size_t     num_blocks;
    size_t     bucket_capacity;
    uint64_t   seed;
    int        access_count;
} ORAMServer;

void oram_init(              ORAMServer *oram, size_t num_blocks, size_t block_size);
void oram_access(            ORAMServer *oram, int op_write, size_t block_id,
                             uint8_t *data, uint64_t seed);
void oram_free(              ORAMServer *oram);

/* ---------- PSI (ECDH-based) ---------- */

typedef struct {
    uint8_t *private_key;
    uint8_t *hashed_set;
    size_t   num_items;
    size_t   hash_len;
} PSIClient;

typedef struct {
    uint8_t *private_key;
    uint8_t *hashed_set;
    size_t   num_items;
} PSIServer;

void psi_client_init(        PSIClient *client, size_t num_items, size_t hash_len);
void psi_client_hash(        PSIClient *client, const uint8_t **items,
                             const size_t *item_lens);
void psi_server_init(        PSIServer *server, size_t num_items);
void psi_server_hash(        PSIServer *server, const uint8_t **items,
                             const size_t *item_lens);
int  psi_compute_intersection(const PSIClient *client, const PSIServer *server,
                              uint8_t **intersection, size_t *intersection_size);
void psi_client_free(        PSIClient *client);
void psi_server_free(        PSIServer *server);

/* ---------- PIR ---------- */

typedef struct {
    uint8_t *database;
    size_t   db_size;
    size_t   record_size;
    size_t   num_records;
    uint8_t *query;
    size_t   query_size;
} PIRDatabase;

void pir_db_init(            PIRDatabase *db, size_t num_records, size_t record_size);
void pir_db_set_record(      PIRDatabase *db, size_t index, const uint8_t *data);
void pir_query(              const PIRDatabase *db, size_t index,
                             uint8_t *query_out, size_t *query_len);
void pir_answer(             const PIRDatabase *db, const uint8_t *query,
                             uint8_t *answer);
void pir_db_free(            PIRDatabase *db);

/* ---------- utility ---------- */

uint64_t mpc_mod_exp(        uint64_t base, uint64_t exp, uint64_t mod);
uint64_t mpc_mod_inv(        uint64_t a, uint64_t mod);
void     mpc_hash_bytes(     const uint8_t *data, size_t len, uint8_t *hash_out,
                             size_t hash_len);
int      mpc_constant_time_cmp(const uint8_t *a, const uint8_t *b, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* SECURE_MPC_COMP_H */
