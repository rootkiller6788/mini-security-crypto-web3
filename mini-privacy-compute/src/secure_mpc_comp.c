#include "secure_mpc_comp.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <stdio.h>

/* ---------- secret sharing ---------- */

void ss_init(SecretSharing *ss, size_t num_parties, uint64_t prime) {
    ss->prime       = prime;
    ss->num_parties = num_parties;
    ss->shares      = NULL;
}

void ss_share(const SecretSharing *ss, uint64_t secret, uint64_t *shares_out) {
    if (!shares_out || ss->num_parties < 2) return;
    secret %= ss->prime;
    uint64_t seed = (uint64_t)time(NULL);
    uint64_t sum = 0;
    for (size_t i = 0; i < ss->num_parties - 1; i++) {
        seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
        shares_out[i] = seed % ss->prime;
        sum = (sum + shares_out[i]) % ss->prime;
    }
    shares_out[ss->num_parties - 1] = (secret + ss->prime - sum) % ss->prime;
}

void ss_reconstruct(const SecretSharing *ss, const uint64_t *shares, uint64_t *secret_out) {
    if (!shares || !secret_out || ss->num_parties < 2) return;
    uint64_t sum = 0;
    for (size_t i = 0; i < ss->num_parties; i++) {
        sum = (sum + shares[i]) % ss->prime;
    }
    *secret_out = sum;
}

void ss_add(const SecretSharing *ss, const uint64_t *shares_a, const uint64_t *shares_b,
            uint64_t *shares_out) {
    if (!shares_a || !shares_b || !shares_out) return;
    for (size_t i = 0; i < ss->num_parties; i++) {
        shares_out[i] = (shares_a[i] + shares_b[i]) % ss->prime;
    }
}

void ss_scalar_mul(const SecretSharing *ss, const uint64_t *shares, uint64_t scalar,
                   uint64_t *shares_out) {
    if (!shares || !shares_out) return;
    scalar %= ss->prime;
    for (size_t i = 0; i < ss->num_parties; i++) {
        shares_out[i] = (shares[i] * scalar) % ss->prime;
    }
}

void ss_free(SecretSharing *ss) {
    ss->shares = NULL;
}

/* ---------- Beaver triples ---------- */

void bt_pool_init(BeaverTriplePool *pool, size_t num_triples, uint64_t prime,
                  uint64_t seed) {
    pool->triples    = (BeaverTriple *)calloc(num_triples, sizeof(BeaverTriple));
    pool->num_triples = num_triples;
    pool->used        = 0;
    pool->prime       = prime;
    pool->seed        = seed;
}

int bt_pool_generate(BeaverTriplePool *pool) {
    if (!pool->triples || pool->num_triples == 0) return 0;
    for (size_t i = 0; i < pool->num_triples; i++) {
        pool->seed = pool->seed * 6364136223846793005ULL + 1442695040888963407ULL;
        uint64_t a = pool->seed % pool->prime;
        pool->seed = pool->seed * 6364136223846793005ULL + 1442695040888963407ULL;
        uint64_t b = pool->seed % pool->prime;
        uint64_t c = (a * b) % pool->prime;
        pool->triples[i].a_share  = a;
        pool->triples[i].b_share  = b;
        pool->triples[i].c_share  = c;
        pool->triples[i].consumed = 0;
    }
    return (int)pool->num_triples;
}

int bt_pool_consume(BeaverTriplePool *pool, BeaverTriple *triple_out) {
    if (!pool->triples || pool->used >= pool->num_triples) return 0;
    *triple_out = pool->triples[pool->used];
    pool->triples[pool->used].consumed = 1;
    pool->used++;
    return 1;
}

void bt_multiply(const SecretSharing *ss, const BeaverTriple *triple,
                 const uint64_t *x_shares, const uint64_t *y_shares,
                 uint64_t *prod_shares) {
    if (!ss || !triple || !x_shares || !y_shares || !prod_shares) return;
    /*
     * Beaver multiplication: (x*y) = (x-a + a)*(y-b + b)
     *   = c + (x-a)*b + (y-b)*a + (x-a)*(y-b)
     * where c = a*b (the triple).
     * All parties know full a, b, c (simplified single-process demo).
     * d = x - a mod p, e = y - b mod p (opened values).
     * Each party computes: [z] = c/n + d*b/n + e*a/n + (party 0 adds d*e)
     * Using modular inverse for division: /n ≡ *inv(n) mod p.
     */
    uint64_t n_inv = mpc_mod_inv(ss->num_parties, ss->prime);
    if (n_inv == 0) return; /* num_parties divides prime (impossible for reasonable n) */

    uint64_t a_n = (triple->a_share * n_inv) % ss->prime;
    uint64_t b_n = (triple->b_share * n_inv) % ss->prime;
    uint64_t c_n = (triple->c_share * n_inv) % ss->prime;

    uint64_t *d_share = (uint64_t *)malloc(ss->num_parties * sizeof(uint64_t));
    uint64_t *e_share = (uint64_t *)malloc(ss->num_parties * sizeof(uint64_t));
    if (!d_share || !e_share) { free(d_share); free(e_share); return; }

    for (size_t i = 0; i < ss->num_parties; i++) {
        d_share[i] = (x_shares[i] + ss->prime - a_n) % ss->prime;
        e_share[i] = (y_shares[i] + ss->prime - b_n) % ss->prime;
    }
    /* Open d and e (sum all shares mod p) */
    uint64_t d_open = 0, e_open = 0;
    for (size_t i = 0; i < ss->num_parties; i++) {
        d_open = (d_open + d_share[i]) % ss->prime;
        e_open = (e_open + e_share[i]) % ss->prime;
    }
    /* Each party computes output share */
    for (size_t i = 0; i < ss->num_parties; i++) {
        uint64_t term = (c_n + d_open * b_n % ss->prime + e_open * a_n % ss->prime) % ss->prime;
        if (i == 0) {
            term = (term + d_open * e_open % ss->prime) % ss->prime;
        }
        prod_shares[i] = term;
    }
    free(d_share);
    free(e_share);
}

void bt_pool_free(BeaverTriplePool *pool) {
    free(pool->triples);
    pool->triples = NULL;
}

/* ---------- SPDZ ---------- */

void spdz_init(SPDZState *state, size_t data_size, uint64_t global_key) {
    state->mac_share  = (uint64_t *)calloc(data_size, sizeof(uint64_t));
    state->data_share = (uint64_t *)calloc(data_size, sizeof(uint64_t));
    state->global_key = global_key;
    state->num_ops    = 0;
}

void spdz_mac_check(const SPDZState *state, int *valid) {
    if (!state || !valid) return;
    *valid = 1;
    for (size_t i = 0; i < state->num_ops && i < 128; i++) {
        uint64_t expected = (state->data_share[i] * state->global_key) % 0xFFFFFFFFFFFFFFC5ULL;
        if (state->mac_share[i] != expected) {
            *valid = 0;
            return;
        }
    }
}

void spdz_online_add(SPDZState *state, const uint64_t *a, const uint64_t *b,
                     uint64_t *result, size_t n) {
    if (!state || !a || !b || !result) return;
    uint64_t mod = 0xFFFFFFFFFFFFFFC5ULL;
    for (size_t i = 0; i < n; i++) {
        result[i] = (a[i] + b[i]) % mod;
    }
    state->num_ops += n;
}

void spdz_online_multiply(SPDZState *state, const uint64_t *a, const uint64_t *b,
                          uint64_t *result, size_t n, const BeaverTriplePool *pool) {
    if (!state || !a || !b || !result || !pool) return;
    uint64_t mod = 0xFFFFFFFFFFFFFFC5ULL;
    for (size_t i = 0; i < n; i++) {
        BeaverTriple bt;
        if (bt_pool_consume((BeaverTriplePool *)pool, &bt)) {
            result[i] = (bt.c_share + a[i] * bt.b_share + b[i] * bt.a_share) % mod;
        } else {
            result[i] = (a[i] * b[i]) % mod;
        }
    }
    state->num_ops += n;
}

void spdz_free(SPDZState *state) {
    free(state->mac_share);
    free(state->data_share);
    state->mac_share  = NULL;
    state->data_share = NULL;
}

/* ---------- garbled circuit ---------- */
/*
 * Yao's Garbled Circuit: gate_defs store the circuit topology (immutable).
 * garble_table stores encrypted truth table rows indexed by label bits.
 * Each wire has two 4-byte labels (0-label, 1-label).
 * Evaluation: given input labels, decrypt one row per gate to get output label.
 */

#define GC_LABEL_BYTES 4

void gc_init(GarbledCircuit *gc, size_t num_inputs_a, size_t num_inputs_b,
             size_t num_outputs) {
    gc->num_inputs_a = num_inputs_a;
    gc->num_inputs_b = num_inputs_b;
    gc->num_outputs  = num_outputs;
    gc->num_wires    = num_inputs_a + num_inputs_b + num_outputs + 64;
    gc->num_gates    = gc->num_wires;
    gc->gate_defs    = (GCGate *)calloc(gc->num_gates, sizeof(GCGate));
    gc->garble_table = (uint8_t *)calloc(gc->num_gates * 4 * GC_LABEL_BYTES, 1);
    gc->wire_labels_0 = (uint8_t *)calloc(gc->num_wires * GC_LABEL_BYTES, 1);
    gc->wire_labels_1 = (uint8_t *)calloc(gc->num_wires * GC_LABEL_BYTES, 1);
    gc->input_labels_a = (uint8_t *)calloc(num_inputs_a * GC_LABEL_BYTES, 1);
    gc->input_labels_b = (uint8_t *)calloc(num_inputs_b * GC_LABEL_BYTES, 1);
}

void gc_set_gate(GarbledCircuit *gc, size_t gate_idx, size_t in1, size_t in2,
                 size_t out, uint8_t op) {
    if (!gc->gate_defs || gate_idx >= gc->num_gates) return;
    gc->gate_defs[gate_idx].in1 = in1;
    gc->gate_defs[gate_idx].in2 = in2;
    gc->gate_defs[gate_idx].out = out;
    gc->gate_defs[gate_idx].op  = op;
}

static void gc_gen_label(uint8_t *label, uint64_t *seed) {
    *seed = (*seed * 6364136223846793005ULL + 1442695040888963407ULL);
    for (int i = 0; i < GC_LABEL_BYTES; i++) {
        label[i] = (uint8_t)((*seed >> (i * 8)) & 0xFF);
    }
    /* ensure each label has a distinct least-significant bit for point-and-permute */
    label[0] = (label[0] & 0xFE);  /* wire 0-label has LSB 0 */
}

void gc_garble(GarbledCircuit *gc, uint64_t seed) {
    if (!gc->gate_defs) return;

    /* Generate random labels for every wire */
    for (size_t w = 0; w < gc->num_wires; w++) {
        gc_gen_label(&gc->wire_labels_0[w * GC_LABEL_BYTES], &seed);
        uint8_t *l1 = &gc->wire_labels_1[w * GC_LABEL_BYTES];
        gc_gen_label(l1, &seed);
        l1[0] |= 0x01;  /* 1-label has LSB 1 */
    }

    /* Copy input labels for distribution to Alice and Bob */
    for (size_t i = 0; i < gc->num_inputs_a; i++) {
        memcpy(&gc->input_labels_a[i * GC_LABEL_BYTES],
               &gc->wire_labels_0[i * GC_LABEL_BYTES], GC_LABEL_BYTES);
        memcpy(&gc->input_labels_a[i * GC_LABEL_BYTES + 2 * gc->num_inputs_a],
               &gc->wire_labels_1[i * GC_LABEL_BYTES], GC_LABEL_BYTES);
    }
    for (size_t i = 0; i < gc->num_inputs_b; i++) {
        memcpy(&gc->input_labels_b[i * GC_LABEL_BYTES],
               &gc->wire_labels_0[(gc->num_inputs_a + i) * GC_LABEL_BYTES],
               GC_LABEL_BYTES);
    }

    /* For each gate, encrypt the output label under the input labels */
    for (size_t i = 0; i < gc->num_gates; i++) {
        GCGate *g = &gc->gate_defs[i];
        if (g->in1 >= gc->num_wires || g->in2 >= gc->num_wires ||
            g->out >= gc->num_wires) continue;

        uint8_t *row = &gc->garble_table[i * 4 * GC_LABEL_BYTES];
        /* Compute output for all 4 input combinations */
        for (int a = 0; a < 2; a++) {
            for (int b = 0; b < 2; b++) {
                int out_val;
                switch (g->op) {
                    case 0: out_val = a & b; break;  /* AND */
                    case 1: out_val = a | b; break;  /* OR */
                    case 2: out_val = a ^ b; break;  /* XOR */
                    case 3: out_val = !(a & b); break;  /* NAND */
                    default: out_val = a & b; break;
                }
                uint8_t *out_label = out_val ? &gc->wire_labels_1[g->out * GC_LABEL_BYTES]
                                             : &gc->wire_labels_0[g->out * GC_LABEL_BYTES];
                uint8_t *in1_label = a ? &gc->wire_labels_1[g->in1 * GC_LABEL_BYTES]
                                       : &gc->wire_labels_0[g->in1 * GC_LABEL_BYTES];
                uint8_t *in2_label = b ? &gc->wire_labels_1[g->in2 * GC_LABEL_BYTES]
                                       : &gc->wire_labels_0[g->in2 * GC_LABEL_BYTES];
                int row_idx = (a * 2 + b) * GC_LABEL_BYTES;
                for (int k = 0; k < GC_LABEL_BYTES; k++) {
                    row[row_idx + k] = out_label[k] ^ in1_label[k] ^ in2_label[k];
                }
            }
        }
    }
}

void gc_evaluate(GarbledCircuit *gc, const uint8_t *input_a, const uint8_t *input_b,
                 uint8_t *output) {
    if (!gc->gate_defs || !gc->garble_table || !input_a || !input_b || !output) return;

    /* Initialize known wire labels. -1 sentinel means unknown. */
    int *wire_known = (int *)calloc(gc->num_wires, sizeof(int));
    uint8_t *wire_labels = (uint8_t *)calloc(gc->num_wires * GC_LABEL_BYTES, 1);
    if (!wire_known || !wire_labels) { free(wire_known); free(wire_labels); return; }

    for (size_t i = 0; i < gc->num_wires; i++) wire_known[i] = 0;

    /* Alice's inputs */
    for (size_t i = 0; i < gc->num_inputs_a; i++) {
        wire_known[i] = 1;
        const uint8_t *label = input_a[i] ? &gc->wire_labels_1[i * GC_LABEL_BYTES]
                                          : &gc->wire_labels_0[i * GC_LABEL_BYTES];
        memcpy(&wire_labels[i * GC_LABEL_BYTES], label, GC_LABEL_BYTES);
    }
    /* Bob's inputs */
    for (size_t i = 0; i < gc->num_inputs_b; i++) {
        size_t widx = gc->num_inputs_a + i;
        wire_known[widx] = 1;
        const uint8_t *label = input_b[i] ? &gc->wire_labels_1[widx * GC_LABEL_BYTES]
                                          : &gc->wire_labels_0[widx * GC_LABEL_BYTES];
        memcpy(&wire_labels[widx * GC_LABEL_BYTES], label, GC_LABEL_BYTES);
    }

    /* Evaluate topologically: iterate until all gates are evaluated */
    int changed = 1;
    while (changed) {
        changed = 0;
        for (size_t i = 0; i < gc->num_gates; i++) {
            GCGate *g = &gc->gate_defs[i];
            if (g->in1 >= gc->num_wires || g->in2 >= gc->num_wires ||
                g->out >= gc->num_wires) continue;
            if (wire_known[g->out]) continue;       /* already computed */
            if (!wire_known[g->in1] || !wire_known[g->in2]) continue; /* need inputs */

            uint8_t *in1_l = &wire_labels[g->in1 * GC_LABEL_BYTES];
            uint8_t *in2_l = &wire_labels[g->in2 * GC_LABEL_BYTES];
            int a_lsb = in1_l[0] & 0x01;
            int b_lsb = in2_l[0] & 0x01;
            int row_idx = (a_lsb * 2 + b_lsb) * GC_LABEL_BYTES;

            uint8_t *enc_row = &gc->garble_table[i * 4 * GC_LABEL_BYTES + row_idx];
            uint8_t *out_l = &wire_labels[g->out * GC_LABEL_BYTES];

            for (int k = 0; k < GC_LABEL_BYTES; k++) {
                out_l[k] = enc_row[k] ^ in1_l[k] ^ in2_l[k];
            }
            wire_known[g->out] = 1;
            changed = 1;
        }
    }

    /* Read output wires: compare against wire_labels_0 to get actual bit */
    size_t off = gc->num_inputs_a + gc->num_inputs_b;
    for (size_t i = 0; i < gc->num_outputs; i++) {
        size_t widx = off + i;
        if (wire_known[widx]) {
            int is_zero = (memcmp(&wire_labels[widx * GC_LABEL_BYTES],
                                  &gc->wire_labels_0[widx * GC_LABEL_BYTES],
                                  GC_LABEL_BYTES) == 0);
            output[i] = is_zero ? 0 : 1;
        } else {
            output[i] = 0;
        }
    }
    free(wire_known);
    free(wire_labels);
}

void gc_free(GarbledCircuit *gc) {
    free(gc->gate_defs);
    free(gc->garble_table);
    free(gc->wire_labels_0);
    free(gc->wire_labels_1);
    free(gc->input_labels_a);
    free(gc->input_labels_b);
    gc->gate_defs       = NULL;
    gc->garble_table    = NULL;
    gc->wire_labels_0   = NULL;
    gc->wire_labels_1   = NULL;
    gc->input_labels_a  = NULL;
    gc->input_labels_b  = NULL;
}

/* ---------- ORAM ---------- */

void oram_init(ORAMServer *oram, size_t num_blocks, size_t block_size) {
    oram->block_size      = block_size;
    oram->num_blocks      = num_blocks;
    oram->bucket_capacity = 4;
    oram->access_count    = 0;
    oram->seed            = (uint64_t)time(NULL);
    size_t pmap_size = num_blocks * sizeof(uint8_t);
    oram->position_map = (uint8_t *)calloc(pmap_size, 1);
    size_t stash_size = num_blocks * block_size * 2;
    oram->stash        = (uint8_t *)calloc(stash_size, 1);
    size_t bucket_size = num_blocks * block_size * oram->bucket_capacity;
    oram->buckets      = (uint8_t *)calloc(bucket_size, 1);
    for (size_t i = 0; i < num_blocks; i++) {
        oram->position_map[i] = (uint8_t)(i % oram->bucket_capacity);
    }
}

void oram_access(ORAMServer *oram, int op_write, size_t block_id, uint8_t *data,
                 uint64_t seed) {
    if (!oram || block_id >= oram->num_blocks) return;
    size_t pos = oram->position_map[block_id] % oram->bucket_capacity;
    size_t offset = block_id * oram->block_size;
    if (op_write) {
        if (offset + oram->block_size <= oram->num_blocks * oram->block_size) {
            memcpy(&oram->stash[offset], data, oram->block_size);
        }
    } else {
        if (offset + oram->block_size <= oram->num_blocks * oram->block_size) {
            memcpy(data, &oram->stash[offset], oram->block_size);
        }
    }
    oram->position_map[block_id] = (uint8_t)((pos + 1 + (seed & 0x03)) % oram->bucket_capacity);
    oram->access_count++;
    (void)op_write;
}

void oram_free(ORAMServer *oram) {
    free(oram->position_map);
    free(oram->stash);
    free(oram->buckets);
    oram->position_map = NULL;
    oram->stash        = NULL;
    oram->buckets      = NULL;
}

/* ---------- PSI ---------- */

void psi_client_init(PSIClient *client, size_t num_items, size_t hash_len) {
    client->num_items = num_items;
    client->hash_len  = hash_len > 0 ? hash_len : 32;
    client->private_key = (uint8_t *)calloc(32, 1);
    client->hashed_set  = (uint8_t *)calloc(num_items * client->hash_len, 1);
    for (int i = 0; i < 32; i++) client->private_key[i] = (uint8_t)((i * 7 + 13) & 0xFF);
}

void psi_client_hash(PSIClient *client, const uint8_t **items, const size_t *item_lens) {
    if (!client || !items) return;
    for (size_t i = 0; i < client->num_items; i++) {
        size_t offset = i * client->hash_len;
        uint32_t hash = 0x811c9dc5;
        for (size_t j = 0; j < item_lens[i]; j++) {
            hash ^= (uint32_t)items[i][j];
            hash *= 0x01000193;
        }
        for (size_t j = 0; j < client->hash_len && j < 4; j++) {
            client->hashed_set[offset + j] = (uint8_t)((hash >> (8 * j)) & 0xFF);
        }
    }
}

void psi_server_init(PSIServer *server, size_t num_items) {
    server->num_items  = num_items;
    server->private_key = (uint8_t *)calloc(32, 1);
    server->hashed_set  = (uint8_t *)calloc(num_items * 32, 1);
    for (int i = 0; i < 32; i++) server->private_key[i] = (uint8_t)((i * 11 + 3) & 0xFF);
}

void psi_server_hash(PSIServer *server, const uint8_t **items, const size_t *item_lens) {
    if (!server || !items) return;
    for (size_t i = 0; i < server->num_items; i++) {
        size_t offset = i * 32;
        uint32_t hash = 0x811c9dc5;
        for (size_t j = 0; j < item_lens[i]; j++) {
            hash ^= (uint32_t)items[i][j];
            hash *= 0x01000193;
        }
        for (size_t j = 0; j < 32 && j < 4; j++) {
            server->hashed_set[offset + j] = (uint8_t)((hash >> (8 * j)) & 0xFF);
        }
    }
}

int psi_compute_intersection(const PSIClient *client, const PSIServer *server,
                             uint8_t **intersection, size_t *intersection_size) {
    if (!client || !server || !intersection || !intersection_size) return 0;
    *intersection_size = 0;
    if (client->num_items < server->num_items) {
        *intersection = (uint8_t *)calloc(client->num_items * client->hash_len, 1);
    } else {
        *intersection = (uint8_t *)calloc(server->num_items * client->hash_len, 1);
    }
    if (!*intersection) return 0;
    size_t count = 0;
    for (size_t i = 0; i < client->num_items; i++) {
        const uint8_t *ch = &client->hashed_set[i * client->hash_len];
        for (size_t j = 0; j < server->num_items; j++) {
            const uint8_t *sh = &server->hashed_set[j * 32];
            int match = 1;
            for (size_t k = 0; k < client->hash_len && k < 32; k++) {
                if (ch[k] != sh[k]) { match = 0; break; }
            }
            if (match) {
                memcpy(&(*intersection)[count * client->hash_len], ch, client->hash_len);
                count++;
                break;
            }
        }
    }
    *intersection_size = count;
    return count > 0 ? 1 : 0;
}

void psi_client_free(PSIClient *client) {
    free(client->private_key);
    free(client->hashed_set);
    client->private_key = NULL;
    client->hashed_set  = NULL;
}

void psi_server_free(PSIServer *server) {
    free(server->private_key);
    free(server->hashed_set);
    server->private_key = NULL;
    server->hashed_set  = NULL;
}

/* ---------- PIR ---------- */

void pir_db_init(PIRDatabase *db, size_t num_records, size_t record_size) {
    db->num_records = num_records;
    db->record_size = record_size;
    db->db_size     = num_records * record_size;
    db->database    = (uint8_t *)calloc(db->db_size, 1);
    db->query_size  = record_size + 64;
    db->query       = (uint8_t *)calloc(db->query_size, 1);
}

void pir_db_set_record(PIRDatabase *db, size_t index, const uint8_t *data) {
    if (!db || index >= db->num_records || !data) return;
    memcpy(&db->database[index * db->record_size], data, db->record_size);
}

void pir_query(const PIRDatabase *db, size_t index, uint8_t *query_out, size_t *query_len) {
    if (!db || !query_out || !query_len) return;
    *query_len = db->record_size + 64;
    memset(query_out, 0, *query_len);
    query_out[0] = (uint8_t)(index & 0xFF);
    query_out[1] = (uint8_t)((index >> 8) & 0xFF);
}

void pir_answer(const PIRDatabase *db, const uint8_t *query, uint8_t *answer) {
    if (!db || !query || !answer) return;
    size_t idx = (size_t)query[0] | ((size_t)query[1] << 8);
    if (idx >= db->num_records) idx = db->num_records - 1;
    memcpy(answer, &db->database[idx * db->record_size], db->record_size);
    for (size_t i = 0; i < db->num_records; i++) {
        if (i != idx) {
            for (size_t j = 0; j < db->record_size; j++) {
                answer[j] ^= db->database[i * db->record_size + j];
            }
        }
    }
}

void pir_db_free(PIRDatabase *db) {
    free(db->database);
    free(db->query);
    db->database = NULL;
    db->query    = NULL;
}

/* ---------- Shamir secret sharing ---------- */
/*
 * Shamir (t,n)-threshold scheme over GF(prime).
 * Dealer picks random polynomial f(x) = a_0 + a_1*x + ... + a_{t-1}*x^{t-1}
 * where a_0 = secret, a_i are random for i>0.
 * Share i: (x_i, f(x_i) mod prime). Reconstruction uses Lagrange interpolation.
 */

void shamir_ss_init(ShamirSS *sss, size_t threshold, size_t num_parties,
                    uint64_t prime) {
    sss->threshold   = threshold;
    sss->num_parties = num_parties;
    sss->prime       = prime;
    sss->x_coords    = (uint64_t *)malloc(num_parties * sizeof(uint64_t));
    if (sss->x_coords) {
        for (size_t i = 0; i < num_parties; i++) {
            sss->x_coords[i] = (uint64_t)(i + 1);
        }
    }
}

void shamir_ss_share(const ShamirSS *sss, uint64_t secret, uint64_t *shares_out,
                     uint64_t *seed) {
    if (!sss || !shares_out || !seed) return;
    uint64_t *coeffs = (uint64_t *)malloc(sss->threshold * sizeof(uint64_t));
    if (!coeffs) return;
    coeffs[0] = secret % sss->prime;
    for (size_t i = 1; i < sss->threshold; i++) {
        *seed = (*seed * 6364136223846793005ULL + 1442695040888963407ULL);
        coeffs[i] = *seed % sss->prime;
    }
    for (size_t i = 0; i < sss->num_parties; i++) {
        shares_out[i] = mpc_poly_eval(coeffs, sss->threshold - 1,
                                      sss->x_coords[i], sss->prime);
    }
    free(coeffs);
}

int shamir_ss_reconstruct(const ShamirSS *sss, const uint64_t *xi_indices,
                          const uint64_t *shares, size_t num_present,
                          uint64_t *secret_out) {
    if (!sss || !xi_indices || !shares || !secret_out) return 0;
    if (num_present < sss->threshold) return 0;
    uint64_t *xi = (uint64_t *)malloc(num_present * sizeof(uint64_t));
    if (!xi) return 0;
    for (size_t i = 0; i < num_present; i++) {
        xi[i] = sss->x_coords[xi_indices[i]];
    }
    *secret_out = mpc_lagrange_interp(xi, shares, num_present, 0, sss->prime);
    free(xi);
    return 1;
}

void shamir_ss_free(ShamirSS *sss) {
    free(sss->x_coords);
    sss->x_coords = NULL;
}

/* ---------- polynomial utilities ---------- */

uint64_t mpc_poly_eval(const uint64_t *coeffs, size_t degree, uint64_t x,
                       uint64_t mod) {
    uint64_t result = 0;
    uint64_t x_pow  = 1;
    for (size_t i = 0; i <= degree; i++) {
        uint64_t term = (coeffs[i] % mod) * (x_pow % mod);
        result = (result + term) % mod;
        x_pow  = (x_pow * (x % mod)) % mod;
    }
    return result;
}

uint64_t mpc_lagrange_interp(const uint64_t *xi, const uint64_t *yi, size_t n,
                              uint64_t x, uint64_t mod) {
    uint64_t result = 0;
    for (size_t i = 0; i < n; i++) {
        uint64_t numerator   = 1;
        uint64_t denominator = 1;
        for (size_t j = 0; j < n; j++) {
            if (i == j) continue;
            numerator   = (numerator * ((x + mod - xi[j]) % mod)) % mod;
            denominator = (denominator * ((xi[i] + mod - xi[j]) % mod)) % mod;
        }
        uint64_t denom_inv = mpc_mod_inv(denominator, mod);
        uint64_t term = (yi[i] % mod) * numerator % mod;
        term = (term * denom_inv) % mod;
        result = (result + term) % mod;
    }
    return result;
}

/* ---------- homomorphic encryption: Paillier (L8) ---------- */
/*
 * Paillier: n = p*q, lambda = lcm(p-1, q-1), g = n+1.
 * Enc(m, r) = g^m * r^n  mod n^2
 * Dec(c) = L(c^lambda mod n^2) / L(g^lambda mod n^2) mod n
 *   where L(u) = (u-1)/n
 */

static uint64_t gcd64(uint64_t a, uint64_t b) {
    while (b) { uint64_t t = b; b = a % b; a = t; }
    return a;
}

static uint64_t lcm64(uint64_t a, uint64_t b) {
    if (a == 0 || b == 0) return 0;
    return a / gcd64(a, b) * b;
}

static int is_prime_small(uint64_t n) {
    if (n < 2) return 0;
    if (n % 2 == 0) return n == 2;
    for (uint64_t i = 3; i * i <= n && i < 1000; i += 2) {
        if (n % i == 0) return 0;
    }
    return 1;
}

int paillier_keygen(PaillierPubKey *pub, PaillierPrivKey *priv, int bits) {
    if (!pub || !priv || bits > 15) return 0;
    /* Use small primes for demos (safe against 64-bit overflow in mpc_mod_exp) */
    uint64_t demo_primes[] = {251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313};
    int n_primes = (int)(sizeof(demo_primes) / sizeof(demo_primes[0]));
    uint64_t p = demo_primes[0];
    uint64_t q = demo_primes[1];
    /* Ensure n^2 < 2^32 so all intermediate products in modexp fit uint64 */
    /* n = p*q < 2^16, n^2 < 2^32, safe for (mod-1)^2 < 2^64 */
    for (int i = 0; i < n_primes; i++) {
        for (int j = 0; j < n_primes; j++) {
            if (i != j) {
                uint64_t pp = demo_primes[i];
                uint64_t qq = demo_primes[j];
                if ((pp * qq * pp * qq) < (1ULL << 32)) {
                    p = pp; q = qq; goto found_primes;
                }
            }
        }
    }
found_primes:
    (void)bits;
    if (p == q) return 0;
    if (!is_prime_small(p) || !is_prime_small(q)) return 0;
    priv->p = p;
    priv->q = q;
    pub->n    = p * q;
    pub->n_sq = pub->n * pub->n;
    pub->g    = pub->n + 1;
    pub->lambda = lcm64(p - 1, q - 1);
    uint64_t g_lambda = mpc_mod_exp(pub->g, pub->lambda, pub->n_sq);
    uint64_t L_val = (g_lambda - 1) / pub->n;
    pub->mu = mpc_mod_inv(L_val, pub->n);
    return 1;
}

void paillier_encrypt(const PaillierPubKey *pub, uint64_t plaintext,
                      uint64_t *ciphertext, uint64_t *seed) {
    if (!pub || !ciphertext || !seed) return;
    uint64_t m = plaintext % pub->n;
    *seed = (*seed * 6364136223846793005ULL + 1442695040888963407ULL);
    uint64_t r = (*seed % (pub->n - 1)) + 1;
    while (gcd64(r, pub->n) != 1) {
        *seed = (*seed * 6364136223846793005ULL + 1442695040888963407ULL);
        r = (*seed % (pub->n - 1)) + 1;
    }
    uint64_t g_m = mpc_mod_exp(pub->g, m, pub->n_sq);
    uint64_t r_n = mpc_mod_exp(r, pub->n, pub->n_sq);
    *ciphertext = (g_m * r_n) % pub->n_sq;
}

uint64_t paillier_decrypt(const PaillierPubKey *pub, const PaillierPrivKey *priv,
                          uint64_t ciphertext) {
    if (!pub || !priv) return 0;
    uint64_t c_lambda = mpc_mod_exp(ciphertext, pub->lambda, pub->n_sq);
    uint64_t L_val = (c_lambda - 1) / pub->n;
    return (L_val * pub->mu) % pub->n;
}

uint64_t paillier_add(const PaillierPubKey *pub, uint64_t ct1, uint64_t ct2) {
    if (!pub) return 0;
    return (ct1 * ct2) % pub->n_sq;
}

uint64_t paillier_scalar_mul(const PaillierPubKey *pub, uint64_t ct,
                              uint64_t scalar) {
    if (!pub) return 0;
    return mpc_mod_exp(ct, scalar, pub->n_sq);
}

uint64_t paillier_rerandomize(const PaillierPubKey *pub, uint64_t ct,
                               uint64_t *seed) {
    if (!pub || !seed) return 0;
    *seed = (*seed * 6364136223846793005ULL + 1442695040888963407ULL);
    uint64_t r = (*seed % (pub->n - 1)) + 1;
    while (gcd64(r, pub->n) != 1) {
        *seed = (*seed * 6364136223846793005ULL + 1442695040888963407ULL);
        r = (*seed % (pub->n - 1)) + 1;
    }
    uint64_t r_n = mpc_mod_exp(r, pub->n, pub->n_sq);
    return (ct * r_n) % pub->n_sq;
}

/* ---------- formal DP composition theorems (L4) ---------- */
/*
 * Prints the formal statements of the three core DP composition theorems
 * that underpin the entire differential privacy framework.
 */
void dp_print_composition_theorems(void) {
    printf("=== DP Composition Theorems (Dwork-Roth 2014) ===\n");
    printf("L4.1 Basic Sequential Composition:\n");
    printf("  If M_i is (eps_i, delta_i)-DP for i=1..k, then their\n");
    printf("  sequential composition is (sum eps_i, sum delta_i)-DP.\n\n");

    printf("L4.2 Parallel Composition:\n");
    printf("  If M_i operates on disjoint subsets D_i of dataset D,\n");
    printf("  and each M_i is eps-DP, then the combined mechanism is\n");
    printf("  (max_i eps_i)-DP (NOT the sum).\n\n");

    printf("L4.3 Advanced Composition (Dwork-Rothblum-Vadhan 2010):\n");
    printf("  For eps <= 1, k-fold adaptive composition yields\n");
    printf("  (eps', k*delta + delta')-DP where\n");
    printf("  eps' = sqrt(2k ln(1/delta')) * eps + k*eps*(e^eps - 1).\n\n");

    printf("L4.4 Moments Accountant (Abadi et al. 2016):\n");
    printf("  Uses Renyi DP: M is (alpha, eps)-RDP if\n");
    printf("  D_alpha(P||Q) <= eps for all adjacent datasets.\n");
    printf("  Tighter composition than advanced composition.\n");
    printf("=================================================\n");
}

/* ---------- utility ---------- */

uint64_t mpc_mod_exp(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t result = 1 % mod;
    base %= mod;
    while (exp > 0) {
        if (exp & 1) result = (result * base) % mod;
        base = (base * base) % mod;
        exp >>= 1;
    }
    return result;
}

uint64_t mpc_mod_inv(uint64_t a, uint64_t mod) {
    int64_t t = 0, newt = 1;
    int64_t r = (int64_t)mod, newr = (int64_t)(a % mod);
    while (newr != 0) {
        int64_t q = r / newr;
        int64_t tmp = newt;
        newt = t - q * newt;
        t = tmp;
        tmp = newr;
        newr = r - q * newr;
        r = tmp;
    }
    if (r > 1) return 0;
    if (t < 0) t += (int64_t)mod;
    return (uint64_t)t;
}

void mpc_hash_bytes(const uint8_t *data, size_t len, uint8_t *hash_out, size_t hash_len) {
    uint32_t hash = 0x811c9dc5;
    for (size_t i = 0; i < len; i++) {
        hash ^= (uint32_t)data[i];
        hash *= 0x01000193;
    }
    for (size_t i = 0; i < hash_len; i++) {
        hash_out[i] = (uint8_t)((hash >> (8 * (i % 4))) & 0xFF);
        hash = hash * 0x01000193 + i;
    }
}

int mpc_constant_time_cmp(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return (diff == 0) ? 1 : 0;
}
