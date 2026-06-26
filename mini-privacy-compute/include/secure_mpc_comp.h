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
/*
 * Yao's Garbled Circuit (L5).
 * Gate definitions (in1, in2, out, op) are immutable after setup.
 * The garble table stores encrypted truth table entries, indexed by
 * input wire labels. Evaluation decrypts the appropriate row.
 * Reference: A. Yao, "How to Generate and Exchange Secrets", FOCS 1986.
 */

typedef struct {
    size_t  in1;   /* input wire 1 index */
    size_t  in2;   /* input wire 2 index */
    size_t  out;   /* output wire index */
    uint8_t op;    /* 0=AND, 1=OR, 2=XOR, 3=NAND */
} GCGate;

typedef struct {
    GCGate *gate_defs;       /* immutable gate definitions (never garbled) */
    uint8_t *garble_table;   /* garbled truth table: 4 rows per gate */
    size_t  num_gates;
    size_t  num_wires;
    size_t  num_inputs_a;
    size_t  num_inputs_b;
    size_t  num_outputs;
    uint8_t *wire_labels_0; /* label for wire value 0, [num_wires][16] */
    uint8_t *wire_labels_1; /* label for wire value 1, [num_wires][16] */
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

/* ---------- Shamir secret sharing ---------- */
/*
 * Shamir's threshold scheme (L5).
 * Theoretical basis: any t points uniquely determine a polynomial of degree t-1
 * over a finite field; fewer than t points give no information about the constant term.
 * Reference: Adi Shamir, "How to Share a Secret", CACM 1979.
 *
 * Complexity: O(t log^2 t) for share, O(t^2) for Lagrange reconstruction.
 */

typedef struct {
    uint64_t prime;
    size_t   threshold;   /* t: minimum shares to reconstruct */
    size_t   num_parties; /* n: total shares */
    uint64_t *x_coords;   /* public evaluation points x_i, i = 0..n-1 */
} ShamirSS;

void  shamir_ss_init(      ShamirSS *sss, size_t threshold, size_t num_parties,
                            uint64_t prime);
void  shamir_ss_share(     const ShamirSS *sss, uint64_t secret, uint64_t *shares_out,
                            uint64_t *seed);
int   shamir_ss_reconstruct(const ShamirSS *sss, const uint64_t *xi_indices,
                            const uint64_t *shares, size_t num_present,
                            uint64_t *secret_out);
void  shamir_ss_free(      ShamirSS *sss);

/* ---------- polynomial eval over finite field ---------- */
uint64_t mpc_poly_eval(   const uint64_t *coeffs, size_t degree, uint64_t x,
                           uint64_t mod);
uint64_t mpc_lagrange_interp(const uint64_t *xi, const uint64_t *yi, size_t n,
                              uint64_t x, uint64_t mod);

/* ---------- homomorphic encryption: Paillier (L8) ---------- */
/*
 * Paillier cryptosystem (Pascal Paillier, EUROCRYPT 1999).
 * Additively homomorphic: E(m1) * E(m2) mod n^2 = E(m1 + m2 mod n).
 * Security based on the Decisional Composite Residuosity Assumption (DCRA).
 * Self-blinding: E(m) * r^n = E(m) for random r.
 */

typedef struct {
    uint64_t n;          /* n = p * q */
    uint64_t n_sq;       /* n^2 */
    uint64_t g;          /* generator, typically n+1 */
    uint64_t lambda;     /* lcm(p-1, q-1) */
    uint64_t mu;         /* L(g^lambda mod n^2)^{-1} mod n */
} PaillierPubKey;

typedef struct {
    uint64_t p;          /* secret prime */
    uint64_t q;          /* secret prime */
} PaillierPrivKey;

int  paillier_keygen(    PaillierPubKey *pub, PaillierPrivKey *priv, int bits);
void paillier_encrypt(   const PaillierPubKey *pub, uint64_t plaintext,
                          uint64_t *ciphertext, uint64_t *seed);
uint64_t paillier_decrypt(const PaillierPubKey *pub, const PaillierPrivKey *priv,
                          uint64_t ciphertext);
uint64_t paillier_add(   const PaillierPubKey *pub, uint64_t ct1, uint64_t ct2);
uint64_t paillier_scalar_mul(const PaillierPubKey *pub, uint64_t ct,
                              uint64_t scalar);
uint64_t paillier_rerandomize(const PaillierPubKey *pub, uint64_t ct,
                               uint64_t *seed);

/* ---------- formal DP composition theorems (L4) ---------- */
/*
 * L4: Dwork-Roth theorems on privacy loss composition.
 * Theorem 3.14 (Basic Sequential Composition):
 *   If M_i is (epsilon_i, delta_i)-DP, then the composition of k mechanisms
 *   is (sum epsilon_i, sum delta_i)-DP.
 *
 * Theorem 3.20 (Advanced Composition, Dwork-Rothblum-Vadhan 2010):
 *   For epsilon_i <= epsilon <= 1, the k-fold adaptive composition is
 *   (epsilon', k*delta + delta')-DP where
 *   epsilon' = sqrt(2k ln(1/delta')) * epsilon + k * epsilon * (e^epsilon - 1).
 *
 * Moments Accountant (Abadi et al., CCS 2016):
 *   Provides tighter composition bounds using Renyi DP.
 */
void dp_print_composition_theorems(void);

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
