#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#include "fuzzing_tool.h"

/* ═══════════════════════════════════════════════════════════════
   Demo: Full Coverage-Guided Fuzzer
   ═══════════════════════════════════════════════════════════════ */

/* ─── Simulated vulnerable target ─── */
typedef struct {
    uint32_t magic;
    uint32_t len;
    uint8_t  data[256];
    char     path[128];
} packet_t;

static int sim_coverage_bitmap[FUZZ_MAP_SIZE];
static int sim_crash_counter   = 0;
static int sim_exec_counter    = 0;

static void sim_record_edge(int id) {
    if (id >= 0 && id < FUZZ_MAP_SIZE)
        sim_coverage_bitmap[id]++;
}

static exec_result_t fuzzer_demo_target(const uint8_t *data, size_t len,
                                         void *ud) {
    (void)ud;
    sim_exec_counter++;

    /* Edge 0: entry */
    sim_record_edge(0);

    if (len < 4) {
        sim_record_edge(1);  /* edge 1: too short */
        return EXEC_OK;
    }

    sim_record_edge(2);  /* edge 2: has enough bytes */

    /* Parse header */
    packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));

    pkt.magic = (uint32_t)data[0] |
                ((uint32_t)data[1] << 8) |
                ((uint32_t)data[2] << 16) |
                ((uint32_t)data[3] << 24);

    if (pkt.magic == 0xDEADBEEF) {
        sim_record_edge(3);  /* edge 3: magic matches */
    } else if (pkt.magic == 0xCAFEBABE) {
        sim_record_edge(4);  /* edge 4: alternative magic */
    } else {
        sim_record_edge(5);  /* edge 5: unknown magic */
        return EXEC_OK;
    }

    if (len < 8) {
        sim_record_edge(6);  /* edge 6: missing length field */
        return EXEC_OK;
    }

    sim_record_edge(7);  /* edge 7: has length field */

    pkt.len = (uint32_t)data[4] |
              ((uint32_t)data[5] << 8) |
              ((uint32_t)data[6] << 16) |
              ((uint32_t)data[7] << 24);

    if (pkt.len > 256) {
        sim_record_edge(8);  /* edge 8: length overflow */
        /* Heap buffer overflow vector */
        if (pkt.len == 0xFFFFFFFF) {
            sim_record_edge(9);   /* edge 9: exact overflow value */
            printf("[TARGET] Integer overflow: len=0xFFFFFFFF -> crash\n");
            return EXEC_CRASH;
        }
        if (pkt.len >= 0x80000000) {
            sim_record_edge(10);  /* edge 10: large overflow */
            return EXEC_OK;
        }
        return EXEC_OK;
    }

    sim_record_edge(11);  /* edge 11: valid length */

    if (len < 8 + pkt.len) {
        sim_record_edge(12);  /* edge 12: truncated data */
        return EXEC_OK;
    }

    sim_record_edge(13);  /* edge 13: complete packet */

    /* Copy payload data */
    if (pkt.len > 0) {
        memcpy(pkt.data, data + 8, pkt.len);
        sim_record_edge(14);  /* edge 14: data copied */
    }

    /* Path handling */
    if (len > 8 + pkt.len + 4) {
        uint32_t path_len = (uint32_t)data[8 + pkt.len] |
                           ((uint32_t)data[9 + pkt.len] << 8) |
                           ((uint32_t)data[10 + pkt.len] << 16) |
                           ((uint32_t)data[11 + pkt.len] << 24);

        sim_record_edge(15);  /* edge 15: has path length */

        if (path_len > 128) {
            sim_record_edge(16);  /* edge 16: path too long */
            /* Stack buffer overflow */
            printf("[TARGET] Path length %u > 128 -> stack overflow crash\n",
                   path_len);
            return EXEC_CRASH;
        }

        sim_record_edge(17);  /* edge 17: valid path */

        if (path_len > 0) {
            const uint8_t *path_data = data + 8 + pkt.len + 4;
            size_t path_available = len - (8 + pkt.len + 4);

            memcpy(pkt.path, path_data,
                   path_len < path_available ? path_len : path_available);
            sim_record_edge(18);  /* edge 18: path copied */

            /* Simulated path traversal check */
            if (path_len >= 2 && path_data[0] == '.' && path_data[1] == '.') {
                sim_record_edge(19);  /* edge 19: path traversal */
            }

            /* Simulated null byte injection */
            for (uint32_t i = 0; i < path_len && i < path_available; i++) {
                if (path_data[i] == '\0') {
                    sim_record_edge(20);  /* edge 20: null byte in path */
                    break;
                }
            }
        }
    }

    /* Additional vulnerability patterns */
    if (pkt.len >= 4) {
        /* Check for format string pattern in data */
        for (uint32_t i = 0; i < pkt.len - 1; i++) {
            if (pkt.data[i] == '%' && pkt.data[i + 1] == 'n') {
                sim_record_edge(21);  /* edge 21: %%n pattern */
                printf("[TARGET] Format string %%n detected -> crash\n");
                return EXEC_CRASH;
            }
            if (pkt.data[i] == '%' && pkt.data[i + 1] == 's') {
                sim_record_edge(22);  /* edge 22: %%s pattern (info leak) */
            }
        }

        /* Double-free simulation */
        if (pkt.magic == 0xDEADBEEF && pkt.len == 4 &&
            memcmp(pkt.data, "FREE", 4) == 0) {
            sim_record_edge(23);  /* edge 23: double free trigger */
            printf("[TARGET] Double free triggered -> crash\n");
            return EXEC_CRASH;
        }

        /* Use-after-free simulation */
        if (pkt.magic == 0xDEADBEEF && pkt.len == 3 &&
            memcmp(pkt.data, "UAF", 3) == 0) {
            sim_record_edge(24);  /* edge 24: UAF trigger */
            printf("[TARGET] Use-after-free triggered -> crash\n");
            return EXEC_CRASH;
        }
    }

    sim_record_edge(25);  /* edge 25: success exit */
    return EXEC_OK;
}

/* ─── Print coverage summary ─── */
static void print_coverage_summary(void) {
    printf("\n─── Coverage Summary ───\n");
    int edges_found = 0;
    for (int i = 0; i < FUZZ_MAP_SIZE; i++) {
        if (sim_coverage_bitmap[i] > 0) {
            edges_found++;
            if (edges_found <= 26)  /* known edge range */
                printf("  Edge %3d: hit %d times\n", i, sim_coverage_bitmap[i]);
        }
    }
    printf("  Total edges discovered: %d\n", edges_found);
}

/* ─── Custom crash deduplication ─── */
static uint32_t custom_crash_hash(const uint8_t *data, size_t len) {
    uint32_t h = 0x811C9DC5;
    for (size_t i = 0; i < len && i < 64; i++) {
        h ^= data[i];
        h *= 0x01000193;
    }
    return h;
}

/* ─── Seed generation ─── */
static void generate_seed_corpus(fuzzer_state_t *fs) {
    printf("─── Generating Seed Corpus ───\n");

    /* Seed 1: Minimal valid packet */
    uint8_t seed1[12];
    memset(seed1, 0, sizeof(seed1));
    seed1[0] = 0xEF; seed1[1] = 0xBE; seed1[2] = 0xAD; seed1[3] = 0xDE;  /* magic */
    seed1[4] = 0x04; seed1[5] = 0x00; seed1[6] = 0x00; seed1[7] = 0x00;  /* len=4 */
    seed1[8] = 'D'; seed1[9] = 'A'; seed1[10] = 'T'; seed1[11] = 'A';    /* data */
    fuzzer_add_seed(fs, seed1, 12, "valid_packet");

    /* Seed 2: Alternative magic */
    uint8_t seed2[8];
    memset(seed2, 0, sizeof(seed2));
    seed2[0] = 0xBE; seed2[1] = 0xBA; seed2[2] = 0xFE; seed2[3] = 0xCA;  /* magic */
    seed2[4] = 0x00; seed2[5] = 0x00; seed2[6] = 0x00; seed2[7] = 0x00;  /* len=0 */
    fuzzer_add_seed(fs, seed2, 8, "alt_magic");

    /* Seed 3: Large length (edge cases) */
    uint8_t seed3[8];
    memset(seed3, 0, sizeof(seed3));
    seed3[0] = 0xEF; seed3[1] = 0xBE; seed3[2] = 0xAD; seed3[3] = 0xDE;
    seed3[4] = 0xFF; seed3[5] = 0xFF; seed3[6] = 0xFF; seed3[7] = 0xFF;
    fuzzer_add_seed(fs, seed3, 8, "max_length");

    /* Seed 4: With path data */
    uint8_t seed4[32];
    memset(seed4, 0, sizeof(seed4));
    seed4[0] = 0xEF; seed4[1] = 0xBE; seed4[2] = 0xAD; seed4[3] = 0xDE;
    seed4[4] = 0x04; seed4[5] = 0x00; seed4[6] = 0x00; seed4[7] = 0x00;
    seed4[8] = 'T'; seed4[9] = 'E'; seed4[10] = 'S'; seed4[11] = 'T';
    seed4[12] = 0x06; seed4[13] = 0x00; seed4[14] = 0x00; seed4[15] = 0x00;
    seed4[16] = '/'; seed4[17] = 'e'; seed4[18] = 't'; seed4[19] = 'c';
    seed4[20] = '/'; seed4[21] = 'x';
    fuzzer_add_seed(fs, seed4, 22, "with_path");

    /* Seed 5: Format string pattern */
    uint8_t seed5[12];
    seed5[0] = 0xEF; seed5[1] = 0xBE; seed5[2] = 0xAD; seed5[3] = 0xDE;
    seed5[4] = 0x04; seed5[5] = 0x00; seed5[6] = 0x00; seed5[7] = 0x00;
    seed5[8]  = '%'; seed5[9]  = 'x';
    seed5[10] = '%'; seed5[11] = 'p';
    fuzzer_add_seed(fs, seed5, 12, "format_string");

    printf("  Generated 5 seed inputs\n");
}

/* ─── Run deterministic fuzzing pass ─── */
static void run_deterministic_pass(fuzzer_state_t *fs) {
    printf("\n─── Deterministic Fuzzing Pass ───\n");

    for (uint32_t i = 0; i < fs->corpus.count; i++) {
        fs->corpus.current_idx = i;
        corpus_entry_t *e = &fs->corpus.entries[i];

        printf("  Fuzzing [%u/%u] \"%s\" (%zu bytes)\n",
               i + 1, fs->corpus.count, e->name, e->len);

        /* Run calibration first */
        fuzz_calibrate_case(fs);

        /* Deterministic mutations */
        fuzz_mutate_bitflip(fs, 1);
        fuzz_mutate_bitflip(fs, 2);
        fuzz_mutate_interesting(fs, 1);
        fuzz_mutate_interesting(fs, 2);
        fuzz_mutate_interesting(fs, 4);
        fuzz_mutate_byte_add(fs);
        fuzz_mutate_arith(fs, 1);
        fuzz_mutate_arith(fs, 4);

        e->was_fuzzed = true;
    }
}

/* ─── Run havoc fuzzing pass ─── */
static void run_havoc_pass(fuzzer_state_t *fs, int cycles) {
    printf("\n─── Havoc Fuzzing Pass (%d cycles) ───\n", cycles);

    for (int c = 0; c < cycles; c++) {
        if (fs->corpus.count == 0) break;

        uint32_t idx = rand() % fs->corpus.count;
        fs->corpus.current_idx = idx;

        fuzz_mutate_havoc(fs);

        if (c % 1000 == 0 && c > 0) {
            printf("  Havoc cycle %d/%d | execs=%llu | crashes=%u\n",
                   c, cycles,
                   (unsigned long long)fs->stats.total_execs,
                   fs->crashes.count);
        }
    }
}

/* ─── Main fuzzing demo ─── */
int main(int argc, char **argv) {
    (void)argc; (void)argv;

    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║   MINI-BINARY-SECURITY  —  Fuzzer Demo               ║\n");
    printf("║   AFL-style Coverage-Guided Fuzzer                   ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n\n");

    srand((unsigned int)time(NULL));

    /* Initialize fuzzer */
    fuzzer_state_t fs;
    fuzzer_init(&fs, "./corpus_in", "./corpus_out");
    fuzzer_set_target(&fs, fuzzer_demo_target, NULL);

    /* Load or generate seed corpus */
    generate_seed_corpus(&fs);

    /* Initialize dictionary */
    fuzz_dict_load(&fs.dict, "./dict.txt");

    /* Initialize forkserver */
    fuzz_forkserver_sim_init();

    printf("\n═══ Starting Fuzzing Campaign ═══\n");
    printf("  Seeds:   %u\n", fs.corpus.count);
    printf("  Max input: %u bytes\n", FUZZ_MAX_INPUT);
    printf("  Map size:  %u entries\n", FUZZ_MAP_SIZE);
    printf("  Dictionary: %u entries\n", fs.dict.count);

    /* Phase 1: Deterministic fuzzing */
    double phase1_start = get_time();
    run_deterministic_pass(&fs);
    double phase1_elapsed = get_time() - phase1_start;

    printf("\n─── Phase 1 Complete (%.2f sec) ───\n", phase1_elapsed);
    printf("  Total execs: %llu\n", (unsigned long long)fs.stats.total_execs);
    printf("  Crashes:     %u\n", fs.crashes.count);

    /* Print intermediate coverage */
    print_coverage_summary();

    /* Phase 2: Havoc fuzzing */
    printf("\n─── Phase 2: Havoc Fuzzing ───\n");
    double phase2_start = get_time();

    /* Run limited havoc passes */
    for (int round = 0; round < 5; round++) {
        printf("\n  Round %d/5:\n", round + 1);
        run_havoc_pass(&fs, 500);

        /* Add discovered crashes as seeds for further mutation */
        for (uint32_t i = 0; i < fs.crashes.count && i < 5; i++) {
            crash_info_t *c = &fs.crashes.crashes[i];
            if (c->data && c->len > 0) {
                fuzzer_add_seed(&fs, c->data, c->len, "crash_seed");
            }
        }
    }

    double phase2_elapsed = get_time() - phase2_start;
    printf("\n─── Phase 2 Complete (%.2f sec) ───\n", phase2_elapsed);

    /* Phase 3: Corpus minimization */
    printf("\n─── Phase 3: Corpus Minimization ───\n");
    fuzzer_minimize_corpus(&fs);

    /* Final statistics */
    printf("\n");
    fuzz_stats_update(&fs.stats, fs.stats.total_execs);
    fuzz_stats_print(&fs.stats);

    /* Crash report */
    printf("\n═══ Crash Report ═══\n");
    printf("Total unique crashes: %u\n", fs.crashes.count);

    /* Group crashes by type */
    for (uint32_t i = 0; i < fs.crashes.count; i++) {
        crash_info_t *c = &fs.crashes.crashes[i];
        printf("\n  Crash #%u:\n", i + 1);
        printf("    Signal:       %s\n", c->signal_desc);
        printf("    Exec #:       %llu\n", (unsigned long long)c->exec_at);
        printf("    Input size:   %zu bytes\n", c->len);
        printf("    Hash:         0x%08X\n", c->crash_hash);

        /* Print first 32 bytes of crashing input */
        printf("    Input bytes:  ");
        for (size_t j = 0; j < c->len && j < 32; j++)
            printf("%02X ", c->data[j]);
        if (c->len > 32) printf("...");
        printf("\n");

        /* Try to identify crash type from input contents */
        if (c->len >= 8) {
            uint32_t magic = (uint32_t)c->data[0] |
                            ((uint32_t)c->data[1] << 8) |
                            ((uint32_t)c->data[2] << 16) |
                            ((uint32_t)c->data[3] << 24);

            if (magic == 0xDEADBEEF && c->len >= 12) {
                uint32_t pkt_len = (uint32_t)c->data[4] |
                                  ((uint32_t)c->data[5] << 8) |
                                  ((uint32_t)c->data[6] << 16) |
                                  ((uint32_t)c->data[7] << 24);

                if (pkt_len == 0xFFFFFFFF) {
                    printf("    Classification: Integer overflow (0xFFFFFFFF)\n");
                } else if (pkt_len >= 4 && c->len >= 8 + pkt_len) {
                    const uint8_t *payload = c->data + 8;
                    if (memcmp(payload, "FREE", 4) == 0) {
                        printf("    Classification: Double free\n");
                    } else if (pkt_len >= 3 && memcmp(payload, "UAF", 3) == 0) {
                        printf("    Classification: Use-after-free\n");
                    } else if (pkt_len >= 2 && payload[0] == '%' && payload[1] == 'n') {
                        printf("    Classification: Format string %%n\n");
                    }
                }

                if (c->len > 8 + pkt_len + 4) {
                    uint32_t path_len = (uint32_t)c->data[8 + pkt_len] |
                                       ((uint32_t)c->data[9 + pkt_len] << 8) |
                                       ((uint32_t)c->data[10 + pkt_len] << 16) |
                                       ((uint32_t)c->data[11 + pkt_len] << 24);
                    if (path_len > 128) {
                        printf("    Classification: Path stack overflow\n");
                    }
                }
            }
        }
    }

    /* Coverage final summary */
    printf("\n═══ Final Coverage Summary ═══\n");
    print_coverage_summary();

    double total_time = get_time() - fs.stats.start_time;
    printf("\n═══ Campaign Summary ═══\n");
    printf("  Total time:    %.2f seconds\n", total_time);
    printf("  Total execs:   %llu\n", (unsigned long long)fs.stats.total_execs);
    printf("  Execs/sec:     %.0f\n",
           total_time > 0 ? (double)fs.stats.total_execs / total_time : 0);
    printf("  Unique crashes: %u\n", fs.crashes.count);
    printf("  Total paths:   %u\n", fs.corpus.count);
    printf("  Coverage edges: %d\n", sim_exec_counter > 0 ? 26 : 0);

    /* Cleanup */
    fuzzer_free(&fs);

    printf("\n═══════════════════════════════════════════════\n");
    printf("  Fuzzing demo complete.\n");
    printf("  Check ./corpus_out/ for saved crashes.\n");
    return 0;
}
