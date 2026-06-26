#include "secure_mpc_comp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

int main(void) {
    printf("=== Secure MPC Example ===\n\n");

    /* 1. Secret sharing (additive) */
    {
        printf("--- Additive Secret Sharing ---\n");
        SecretSharing ss;
        uint64_t prime = 0xFFFFFFFFFFFFFFC5ULL;
        ss_init(&ss, 3, prime);

        uint64_t secret = 42;
        uint64_t shares[3];
        ss_share(&ss, secret, shares);
        printf("  Secret: %llu\n", (unsigned long long)secret);
        for (size_t i = 0; i < 3; i++) {
            printf("  Share[%zu] = %llu\n", i, (unsigned long long)shares[i]);
        }

        uint64_t reconstructed;
        ss_reconstruct(&ss, shares, &reconstructed);
        printf("  Reconstructed: %llu (match: %s)\n",
               (unsigned long long)reconstructed,
               reconstructed == secret ? "YES" : "NO");

        /* addition of shared values */
        uint64_t secret_b = 15;
        uint64_t shares_b[3];
        ss_share(&ss, secret_b, shares_b);
        uint64_t shares_sum[3];
        ss_add(&ss, shares, shares_b, shares_sum);
        uint64_t sum_reconstructed;
        ss_reconstruct(&ss, shares_sum, &sum_reconstructed);
        printf("  Shared add: 42 + 15 = %llu (match: %s)\n",
               (unsigned long long)sum_reconstructed,
               sum_reconstructed == (42 + 15) % prime ? "YES" : "NO");

        ss_free(&ss);
    }

    /* 2. Beaver triples */
    {
        printf("\n--- Beaver Triples for Multiplication ---\n");
        SecretSharing ss;
        uint64_t prime = 0xFFFFFFFFFFFFFFC5ULL;
        ss_init(&ss, 3, prime);

        BeaverTriplePool pool;
        bt_pool_init(&pool, 10, prime, 12345ULL);
        int gen_count = bt_pool_generate(&pool);
        printf("  Generated %d triples\n", gen_count);

        uint64_t x = 7, y = 13;
        uint64_t x_shares[3], y_shares[3];
        ss_share(&ss, x, x_shares);
        ss_share(&ss, y, y_shares);

        BeaverTriple bt;
        bt_pool_consume(&pool, &bt);
        printf("  Triple: a=%llu b=%llu c=%llu (c == a*b mod p: %s)\n",
               (unsigned long long)bt.a_share, (unsigned long long)bt.b_share,
               (unsigned long long)bt.c_share,
               bt.c_share == (bt.a_share * bt.b_share) % prime ? "YES" : "NO");

        uint64_t prod_shares[3];
        bt_multiply(&ss, &bt, x_shares, y_shares, prod_shares);
        uint64_t prod;
        ss_reconstruct(&ss, prod_shares, &prod);
        printf("  Beaver multiply: 7 * 13 = %llu (expected %llu)\n",
               (unsigned long long)prod, (unsigned long long)((7ULL * 13ULL) % prime));

        bt_pool_free(&pool);
        ss_free(&ss);
    }

    /* 3. SPDZ online phase */
    {
        printf("\n--- SPDZ Online Phase ---\n");
        SPDZState spdz;
        uint64_t global_key = 0xDEADBEEF12345678ULL;
        spdz_init(&spdz, 4, global_key);

        uint64_t a[4] = {10, 20, 30, 40};
        uint64_t b[4] = {5, 10, 15, 20};
        uint64_t result[4];
        spdz_online_add(&spdz, a, b, result, 4);
        printf("  SPDZ add: [%llu %llu %llu %llu]\n",
               (unsigned long long)result[0], (unsigned long long)result[1],
               (unsigned long long)result[2], (unsigned long long)result[3]);

        int mac_valid;
        spdz_mac_check(&spdz, &mac_valid);
        printf("  MAC check: %s\n", mac_valid ? "PASS" : "FAIL");

        spdz_free(&spdz);
    }

    /* 4. Garbled circuit */
    {
        printf("\n--- Garbled Circuit Evaluation ---\n");
        GarbledCircuit gc;
        gc_init(&gc, 2, 2, 1);

        gc_set_gate(&gc, 0, 0, 2, 4, 0);  /* AND gate: wire0 AND wire2 -> wire4 */
        gc_set_gate(&gc, 1, 1, 3, 5, 1);  /* OR gate:  wire1 OR wire3 -> wire5 */
        gc_set_gate(&gc, 2, 4, 5, 6, 2);  /* XOR gate: wire4 XOR wire5 -> wire6 (output) */

        gc_garble(&gc, 54321ULL);

        uint8_t input_a[2] = {1, 0};  /* Alice inputs: 1, 0 */
        uint8_t input_b[2] = {1, 1};  /* Bob inputs:   1, 1 */
        uint8_t output[1];
        gc_evaluate(&gc, input_a, input_b, output);
        printf("  GC(1&1)=%d (1&0)=%d  XOR result=%d (expected %d)\n",
               input_a[0] & input_b[0], input_a[1] & input_b[1],
               output[0], (1 & 1) ^ (0 | 1));

        input_a[0] = 0; input_a[1] = 1;
        input_b[0] = 0; input_b[1] = 0;
        gc_evaluate(&gc, input_a, input_b, output);
        printf("  GC(0&0)=%d (1&0)=%d  XOR result=%d (expected %d)\n",
               input_a[0] & input_b[0], input_a[1] & input_b[1],
               output[0], (0 & 0) ^ (1 | 0));

        gc_free(&gc);
    }

    /* 5. ORAM */
    {
        printf("\n--- Oblivious RAM (ORAM) ---\n");
        ORAMServer oram;
        oram_init(&oram, 32, 16);

        uint8_t write_data[16] = "hello_oram_test";
        oram_access(&oram, 1, 5, write_data, 777ULL);
        printf("  Wrote to block 5 via ORAM\n");

        uint8_t read_data[16] = {0};
        oram_access(&oram, 0, 5, read_data, 888ULL);
        printf("  Read block 5: '");
        for (int i = 0; i < 16 && read_data[i]; i++) putchar(read_data[i]);
        printf("'\n");
        printf("  Access count: %d (indistinguishable from random)\n", oram.access_count);

        oram_free(&oram);
    }

    /* 6. PSI (Private Set Intersection) */
    {
        printf("\n--- Private Set Intersection (ECDH-style PSI) ---\n");
        PSIClient client;
        psi_client_init(&client, 5, 4);

        const uint8_t *c_items[] = {
            (const uint8_t *)"alice", (const uint8_t *)"bob",
            (const uint8_t *)"carol", (const uint8_t *)"dave",
            (const uint8_t *)"eve"
        };
        size_t c_lens[] = {5, 3, 5, 4, 3};
        psi_client_hash(&client, c_items, c_lens);

        PSIServer server;
        psi_server_init(&server, 4);
        const uint8_t *s_items[] = {
            (const uint8_t *)"alice", (const uint8_t *)"bob",
            (const uint8_t *)"frank", (const uint8_t *)"carol"
        };
        size_t s_lens[] = {5, 3, 5, 5};
        psi_server_hash(&server, s_items, s_lens);

        uint8_t *intersection = NULL;
        size_t isect_size = 0;
        int found = psi_compute_intersection(&client, &server, &intersection, &isect_size);
        printf("  PSI result: %zu items in intersection (alice, bob, carol)\n", isect_size);
        printf("  Intersection found: %s\n", found ? "YES" : "NO");

        free(intersection);
        psi_client_free(&client);
        psi_server_free(&server);
    }

    /* 7. PIR (Private Information Retrieval) */
    {
        printf("\n--- Private Information Retrieval ---\n");
        PIRDatabase db;
        pir_db_init(&db, 10, 32);

        uint8_t records[10][32];
        for (int i = 0; i < 10; i++) {
            snprintf((char *)records[i], 32, "record_%02d_data_block", i);
            pir_db_set_record(&db, (size_t)i, records[i]);
        }

        uint8_t query[96];
        size_t query_len;
        pir_query(&db, 3, query, &query_len);
        printf("  Query for index 3, len=%zu\n", query_len);

        uint8_t answer[32];
        pir_answer(&db, query, answer);
        printf("  PIR answer: '");
        for (int i = 0; i < 32 && answer[i]; i++) putchar(answer[i]);
        printf("'\n");

        pir_db_free(&db);
    }

    /* 8. MPC utilities */
    {
        printf("\n--- MPC Utility Functions ---\n");
        uint64_t mod = 0xFFFFFFFFFFFFFFC5ULL;
        uint64_t base = 5, exp = 3;
        uint64_t pow_result = mpc_mod_exp(base, exp, mod);
        printf("  mod_exp(5^3 mod p) = %llu (expected 125)\n", (unsigned long long)pow_result);

        uint64_t inv_a = 7;
        uint64_t inv = mpc_mod_inv(inv_a, 97);
        printf("  mod_inv(7 mod 97) = %llu (7 * %llu mod 97 = %llu)\n",
               (unsigned long long)inv, (unsigned long long)inv,
               (unsigned long long)((7 * inv) % 97));

        const uint8_t data[] = "test_data_mpc";
        uint8_t hash[16];
        mpc_hash_bytes(data, strlen((const char *)data), hash, 16);
        printf("  hash(test_data_mpc) = ");
        for (int i = 0; i < 16; i++) printf("%02x", hash[i]);
        printf("\n");
    }

    printf("\n=== SMPC Example Complete ===\n");
    return 0;
}
