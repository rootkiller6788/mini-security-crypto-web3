#include "secure_mpc_comp.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

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
    uint64_t *d = (uint64_t *)malloc(ss->num_parties * sizeof(uint64_t));
    uint64_t *e = (uint64_t *)malloc(ss->num_parties * sizeof(uint64_t));
    if (!d || !e) { free(d); free(e); return; }
    for (size_t i = 0; i < ss->num_parties; i++) {
        d[i] = (x_shares[i] + ss->prime - triple->a_share / ss->num_parties) % ss->prime;
        e[i] = (y_shares[i] + ss->prime - triple->b_share / ss->num_parties) % ss->prime;
    }
    uint64_t d_val = 0, e_val = 0;
    for (size_t i = 0; i < ss->num_parties; i++) {
        d_val = (d_val + d[i]) % ss->prime;
        e_val = (e_val + e[i]) % ss->prime;
    }
    for (size_t i = 0; i < ss->num_parties; i++) {
        uint64_t term = (triple->c_share / ss->num_parties +
                        d_val * (triple->b_share / ss->num_parties) +
                        e_val * (triple->a_share / ss->num_parties)) % ss->prime;
        if (i == 0) term = (term + d_val * e_val) % ss->prime;
        prod_shares[i] = term;
    }
    free(d); free(e);
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

void gc_init(GarbledCircuit *gc, size_t num_inputs_a, size_t num_inputs_b,
             size_t num_outputs) {
    gc->num_inputs_a = num_inputs_a;
    gc->num_inputs_b = num_inputs_b;
    gc->num_outputs  = num_outputs;
    gc->num_wires    = num_inputs_a + num_inputs_b + num_outputs + 64;
    gc->num_gates    = gc->num_wires;
    size_t gate_bytes = gc->num_gates * sizeof(uint8_t) * 4;
    gc->gates = (uint8_t *)calloc(gate_bytes, 1);
    gc->input_labels_a = (uint8_t *)calloc(num_inputs_a, 1);
    gc->input_labels_b = (uint8_t *)calloc(num_inputs_b, 1);
}

void gc_set_gate(GarbledCircuit *gc, size_t gate_idx, size_t in1, size_t in2,
                 size_t out, uint8_t op) {
    if (!gc->gates || gate_idx >= gc->num_gates) return;
    size_t base = gate_idx * 4;
    gc->gates[base]     = (uint8_t)(in1 & 0xFF);
    gc->gates[base + 1] = (uint8_t)(in2 & 0xFF);
    gc->gates[base + 2] = (uint8_t)(out & 0xFF);
    gc->gates[base + 3] = op;
}

void gc_garble(GarbledCircuit *gc, uint64_t seed) {
    if (!gc->gates) return;
    for (size_t i = 0; i < gc->num_gates; i++) {
        size_t base = i * 4;
        seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
        gc->gates[base]     ^= (uint8_t)(seed & 0xFF);
        gc->gates[base + 1] ^= (uint8_t)((seed >> 8) & 0xFF);
        gc->gates[base + 2] ^= (uint8_t)((seed >> 16) & 0xFF);
        gc->gates[base + 3] ^= (uint8_t)((seed >> 24) & 0xFF);
    }
}

void gc_evaluate(GarbledCircuit *gc, const uint8_t *input_a, const uint8_t *input_b,
                 uint8_t *output) {
    if (!gc->gates || !input_a || !input_b || !output) return;
    uint8_t *wire_values = (uint8_t *)calloc(gc->num_wires, 1);
    if (!wire_values) return;
    for (size_t i = 0; i < gc->num_inputs_a; i++) wire_values[i] = input_a[i];
    for (size_t i = 0; i < gc->num_inputs_b; i++) wire_values[gc->num_inputs_a + i] = input_b[i];
    for (size_t i = 0; i < gc->num_gates; i++) {
        size_t base = i * 4;
        uint8_t in1_val = wire_values[gc->gates[base]];
        uint8_t in2_val = wire_values[gc->gates[base + 1]];
        uint8_t out_wire = gc->gates[base + 2];
        uint8_t op       = gc->gates[base + 3];
        switch (op) {
            case 0: wire_values[out_wire] = in1_val & in2_val; break;
            case 1: wire_values[out_wire] = in1_val | in2_val; break;
            case 2: wire_values[out_wire] = in1_val ^ in2_val; break;
            case 3: wire_values[out_wire] = in1_val & !in2_val; break;
            default: wire_values[out_wire] = in1_val & in2_val; break;
        }
    }
    size_t offset = gc->num_inputs_a + gc->num_inputs_b;
    for (size_t i = 0; i < gc->num_outputs; i++) {
        output[i] = wire_values[offset + i];
    }
    free(wire_values);
}

void gc_free(GarbledCircuit *gc) {
    free(gc->gates);
    free(gc->input_labels_a);
    free(gc->input_labels_b);
    gc->gates          = NULL;
    gc->input_labels_a = NULL;
    gc->input_labels_b = NULL;
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
