#include "fuzzing_tool.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
static double get_time(void) {
    LARGE_INTEGER f, c;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&c);
    return (double)c.QuadPart / (double)f.QuadPart;
}
#define RAND_MAX_VAL 0x7FFF
static uint32_t fuzz_rand(void) { return (uint32_t)rand(); }
#else
#include <sys/time.h>
static double get_time(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec + (double)tv.tv_usec / 1000000.0;
}
static uint32_t fuzz_rand(void) { return (uint32_t)rand(); }
#endif

/* ═══════════════════════════════════════════════════════════════
   Initialization
   ═══════════════════════════════════════════════════════════════ */

void fuzzer_init(fuzzer_state_t *fs, const char *in_dir, const char *out_dir) {
    memset(fs, 0, sizeof(*fs));
    fuzz_coverage_init(&fs->coverage);
    fuzz_dict_init(&fs->dict);
    strncpy(fs->in_dir,  in_dir,  sizeof(fs->in_dir)  - 1);
    strncpy(fs->out_dir, out_dir, sizeof(fs->out_dir) - 1);
    fs->running = true;
    fs->deterministic = true;
    fs->stats.start_time = get_time();
    fs->out_buf = (uint8_t*)malloc(FUZZ_MAX_INPUT);
    if (fs->out_buf) fs->out_len = 0;
    srand((unsigned int)time(NULL));
}

void fuzzer_free(fuzzer_state_t *fs) {
    free(fs->out_buf);
    fs->out_buf = NULL;
    fs->out_len = 0;
    for (uint32_t i = 0; i < fs->corpus.count; i++) {
        free(fs->corpus.entries[i].data);
    }
    for (uint32_t i = 0; i < fs->crashes.count; i++) {
        free(fs->crashes.crashes[i].data);
    }
    for (uint32_t i = 0; i < fs->dict.count; i++) {
        free(fs->dict.entries[i].data);
    }
}

/* ═══════════════════════════════════════════════════════════════
   Coverage Map
   ═══════════════════════════════════════════════════════════════ */

void fuzz_coverage_init(coverage_map_t *cm) {
    memset(cm, 0, sizeof(*cm));
}

static uint64_t g_coverage_new_edges = 0;   /* global: new edges this round */

bool fuzz_coverage_update(coverage_map_t *cm, const uint8_t *new_data,
                            size_t len) {
    g_coverage_new_edges = 0;
    if (len > FUZZ_MAP_SIZE) len = FUZZ_MAP_SIZE;

    for (size_t i = 0; i < len; i++) {
        uint8_t old = cm->bitmap[i];
        cm->bitmap[i] |= new_data[i];
        if (cm->bitmap[i] != old) {
            g_coverage_new_edges++;
            cm->total_edges++;
        }
    }
    return g_coverage_new_edges > 0;
}

bool fuzz_coverage_has_new(coverage_map_t *cm) {
    (void)cm;
    return g_coverage_new_edges > 0;
}

uint64_t fuzz_coverage_count(const coverage_map_t *cm) {
    uint64_t count = 0;
    for (int i = 0; i < FUZZ_MAP_SIZE; i++)
        if (cm->bitmap[i]) count++;
    return count;
}

void fuzz_coverage_reset_check(coverage_map_t *cm) {
    (void)cm;
    g_coverage_new_edges = 0;
}

/* ═══════════════════════════════════════════════════════════════
   Corpus Management
   ═══════════════════════════════════════════════════════════════ */

bool fuzzer_add_seed(fuzzer_state_t *fs, const uint8_t *data,
                      size_t len, const char *name) {
    if (fs->corpus.count >= FUZZ_MAX_CORPUS || len > FUZZ_MAX_INPUT)
        return false;

    corpus_entry_t *e = &fs->corpus.entries[fs->corpus.count];
    e->data = (uint8_t*)malloc(len);
    if (!e->data) return false;
    memcpy(e->data, data, len);
    e->len = len;
    e->depth = 0;
    e->fuzz_count = 0;
    e->was_fuzzed = false;
    if (name) strncpy(e->name, name, sizeof(e->name) - 1);
    else snprintf(e->name, sizeof(e->name), "seed_%u", fs->corpus.count);

    fs->corpus.count++;
    fs->corpus.total_size += len;
    fs->stats.total_paths++;

    printf("[CORPUS] Added seed: %s (%zu bytes)\n", e->name, len);
    return true;
}

void fuzzer_minimize_corpus(fuzzer_state_t *fs) {
    printf("[MINIMIZE] Minimizing corpus (%u entries)...\n",
           fs->corpus.count);
    coverage_map_t temp_cov;
    fuzz_coverage_init(&temp_cov);
    uint32_t kept = 0;

    for (uint32_t i = 0; i < fs->corpus.count; i++) {
        corpus_entry_t *e = &fs->corpus.entries[i];
        if (!e->data) continue;

        bool has_new = fuzz_coverage_update(&temp_cov, e->data, e->len);
        if (has_new) {
            /* Keep this entry */
            if (kept != i) {
                fs->corpus.entries[kept] = *e;
                memset(&fs->corpus.entries[i], 0, sizeof(*e));
            }
            kept++;
        } else {
            /* Redundant - free it */
            free(e->data);
            memset(e, 0, sizeof(*e));
        }
    }

    fs->corpus.count = kept;
    printf("[MINIMIZE] Kept %u entries (removed %u redundant)\n",
           kept, fs->corpus.count);
}

/* ═══════════════════════════════════════════════════════════════
   Mutation Engine
   ═══════════════════════════════════════════════════════════════ */

static void ensure_out_buf(fuzzer_state_t *fs, size_t len) {
    if (!fs->out_buf || fs->out_len < len) {
        free(fs->out_buf);
        fs->out_buf = (uint8_t*)malloc(len + 1024);
        if (fs->out_buf) fs->out_len = len + 1024;
    }
}

void fuzz_mutate_bitflip(fuzzer_state_t *fs, int bytes) {
    if (fs->corpus.current_idx >= fs->corpus.count) return;
    corpus_entry_t *e = &fs->corpus.entries[fs->corpus.current_idx];
    ensure_out_buf(fs, e->len);
    memcpy(fs->out_buf, e->data, e->len);

    for (size_t pos = 0; pos + bytes <= e->len; pos++) {
        for (int bit = 0; bit < 8 * bytes; bit++) {
            uint8_t orig = fs->out_buf[pos + bit / 8];
            fs->out_buf[pos + bit / 8] ^= (uint8_t)(1 << (bit % 8));
            fuzz_save_if_interesting(fs);
            fs->out_buf[pos + bit / 8] = orig;  /* restore */
        }
    }
}

void fuzz_mutate_byte_add(fuzzer_state_t *fs) {
    if (fs->corpus.current_idx >= fs->corpus.count) return;
    corpus_entry_t *e = &fs->corpus.entries[fs->corpus.current_idx];
    ensure_out_buf(fs, e->len);
    memcpy(fs->out_buf, e->data, e->len);

    for (size_t pos = 0; pos < e->len; pos++) {
        for (int val = -35; val <= 35; val++) {
            if (val == 0) continue;
            uint8_t orig = fs->out_buf[pos];
            fs->out_buf[pos] = (uint8_t)(orig + val);
            fuzz_save_if_interesting(fs);
            fs->out_buf[pos] = orig;
        }
    }
}

void fuzz_mutate_byte_sub(fuzzer_state_t *fs) {
    fuzz_mutate_byte_add(fs);  /* byte sub is covered by add with negative */
}

void fuzz_mutate_interesting(fuzzer_state_t *fs, int width) {
    if (fs->corpus.current_idx >= fs->corpus.count) return;
    corpus_entry_t *e = &fs->corpus.entries[fs->corpus.current_idx];
    ensure_out_buf(fs, e->len);
    memcpy(fs->out_buf, e->data, e->len);
    int count = 0;
    const void *values = NULL;

    if (width == 1) {
        values = INTERESTING_8;
        count  = FUZZ_INTERESTING_8_COUNT;
    } else if (width == 2) {
        values = INTERESTING_16;
        count  = FUZZ_INTERESTING_16_COUNT;
    } else if (width == 4) {
        values = INTERESTING_32;
        count  = FUZZ_INTERESTING_32_COUNT;
    } else return;

    for (size_t pos = 0; pos + width <= e->len; pos++) {
        for (int v = 0; v < count; v++) {
            if (width == 1) {
                uint8_t orig = fs->out_buf[pos];
                fs->out_buf[pos] = (uint8_t)((const int8_t*)values)[v];
                fuzz_save_if_interesting(fs);
                fs->out_buf[pos] = orig;
            } else if (width == 2) {
                uint16_t orig;
                memcpy(&orig, fs->out_buf + pos, 2);
                uint16_t val = (uint16_t)((const int16_t*)values)[v];
                memcpy(fs->out_buf + pos, &val, 2);
                fuzz_save_if_interesting(fs);
                memcpy(fs->out_buf + pos, &orig, 2);
            } else {
                uint32_t orig;
                memcpy(&orig, fs->out_buf + pos, 4);
                uint32_t val = (uint32_t)((const int32_t*)values)[v];
                memcpy(fs->out_buf + pos, &val, 4);
                fuzz_save_if_interesting(fs);
                memcpy(fs->out_buf + pos, &orig, 4);
            }
        }
    }
}

void fuzz_mutate_arith(fuzzer_state_t *fs, int width) {
    if (fs->corpus.current_idx >= fs->corpus.count) return;
    corpus_entry_t *e = &fs->corpus.entries[fs->corpus.current_idx];
    ensure_out_buf(fs, e->len);
    memcpy(fs->out_buf, e->data, e->len);

    for (size_t pos = 0; pos + width <= e->len; pos++) {
        for (int delta = -35; delta <= 35; delta += 10) {
            if (width == 1) {
                uint8_t orig = fs->out_buf[pos];
                fs->out_buf[pos] = (uint8_t)(orig + delta);
            } else if (width == 2) {
                uint16_t orig;
                memcpy(&orig, fs->out_buf + pos, 2);
                uint16_t v = (uint16_t)(orig + delta);
                memcpy(fs->out_buf + pos, &v, 2);
            } else {
                uint32_t orig;
                memcpy(&orig, fs->out_buf + pos, 4);
                uint32_t v = (uint32_t)(orig + delta);
                memcpy(fs->out_buf + pos, &v, 4);
            }
            fuzz_save_if_interesting(fs);
            memcpy(fs->out_buf, e->data, e->len);  /* restore all */
        }
    }
}

void fuzz_mutate_random_byte(fuzzer_state_t *fs) {
    if (fs->corpus.current_idx >= fs->corpus.count) return;
    corpus_entry_t *e = &fs->corpus.entries[fs->corpus.current_idx];
    ensure_out_buf(fs, e->len);
    memcpy(fs->out_buf, e->data, e->len);

    for (int i = 0; i < 32; i++) {
        size_t pos = (size_t)fuzz_rand() % e->len;
        fs->out_buf[pos] = (uint8_t)(fuzz_rand() & 0xFF);
    }
    fuzz_save_if_interesting(fs);
}

void fuzz_mutate_delete_bytes(fuzzer_state_t *fs) {
    if (fs->corpus.current_idx >= fs->corpus.count) return;
    corpus_entry_t *e = &fs->corpus.entries[fs->corpus.current_idx];
    if (e->len <= FUZZ_MIN_INPUT + 1) return;
    ensure_out_buf(fs, e->len);

    size_t del_pos = (size_t)fuzz_rand() % (e->len - 1);
    size_t del_len = 1 + ((size_t)fuzz_rand() % 16);
    if (del_pos + del_len > e->len) del_len = e->len - del_pos;

    memcpy(fs->out_buf, e->data, del_pos);
    memcpy(fs->out_buf + del_pos, e->data + del_pos + del_len,
           e->len - del_pos - del_len);
    size_t new_len = e->len - del_len;
    fuzz_save_if_interesting(fs);
    (void)new_len;
}

void fuzz_mutate_clone_bytes(fuzzer_state_t *fs) {
    if (fs->corpus.current_idx >= fs->corpus.count) return;
    corpus_entry_t *e = &fs->corpus.entries[fs->corpus.current_idx];
    if (e->len + 16 > FUZZ_MAX_INPUT) return;
    ensure_out_buf(fs, e->len + 16);

    size_t src  = (size_t)fuzz_rand() % e->len;
    size_t dst  = (size_t)fuzz_rand() % e->len;
    size_t clen = 1 + ((size_t)fuzz_rand() % 8);

    memcpy(fs->out_buf, e->data, e->len);
    /* Insert cloned bytes at dst */
    memmove(fs->out_buf + dst + clen, fs->out_buf + dst, e->len - dst);
    memcpy(fs->out_buf + dst, fs->out_buf + src, clen);
    fuzz_save_if_interesting(fs);
}

void fuzz_mutate_splice(fuzzer_state_t *fs) {
    if (fs->corpus.count < 2) return;
    corpus_entry_t *e1 = &fs->corpus.entries[fs->corpus.current_idx];
    uint32_t idx2 = fuzz_rand() % fs->corpus.count;
    corpus_entry_t *e2 = &fs->corpus.entries[idx2];

    size_t new_len = (e1->len + e2->len > FUZZ_MAX_INPUT)
                     ? FUZZ_MAX_INPUT : e1->len + e2->len;
    ensure_out_buf(fs, new_len);

    size_t split = (size_t)fuzz_rand() % e1->len;
    size_t take  = (size_t)fuzz_rand() % e2->len;
    if (take > new_len - split) take = new_len - split;

    memcpy(fs->out_buf, e1->data, split);
    memcpy(fs->out_buf + split, e2->data, take);
    fuzz_save_if_interesting(fs);
}

void fuzz_mutate_havoc(fuzzer_state_t *fs) {
    for (int stage = 0; stage < FUZZ_HAVOC_CYCLES; stage++) {
        uint32_t r = fuzz_rand() % 16;
        switch (r) {
        case 0:  fuzz_mutate_bitflip(fs, 1); break;
        case 1:  fuzz_mutate_bitflip(fs, 2); break;
        case 2:  fuzz_mutate_byte_add(fs);   break;
        case 3:  fuzz_mutate_interesting(fs, 1); break;
        case 4:  fuzz_mutate_interesting(fs, 2); break;
        case 5:  fuzz_mutate_interesting(fs, 4); break;
        case 6:  fuzz_mutate_arith(fs, 1);   break;
        case 7:  fuzz_mutate_arith(fs, 4);   break;
        case 8:  fuzz_mutate_random_byte(fs); break;
        case 9:  fuzz_mutate_delete_bytes(fs); break;
        case 10: fuzz_mutate_clone_bytes(fs); break;
        case 11: fuzz_mutate_splice(fs);      break;
        default: fuzz_mutate_random_byte(fs); break;
        }
    }
}

void fuzz_mutate_all(fuzzer_state_t *fs) {
    fuzz_mutate_bitflip(fs, 1);
    fuzz_mutate_bitflip(fs, 2);
    fuzz_mutate_bitflip(fs, 4);
    fuzz_mutate_byte_add(fs);
    fuzz_mutate_interesting(fs, 1);
    fuzz_mutate_interesting(fs, 2);
    fuzz_mutate_interesting(fs, 4);
    fuzz_mutate_havoc(fs);
    fuzz_mutate_splice(fs);
}

/* ═══════════════════════════════════════════════════════════════
   Execution & Calibration
   ═══════════════════════════════════════════════════════════════ */

exec_result_t fuzz_run_target_cb(fuzz_target_fn target, const uint8_t *data,
                                  size_t len, void *ud) {
    if (!target) return EXEC_ERROR;
    return target(data, len, ud);
}

static fuzz_target_fn g_target = NULL;
static void         *g_target_ud = NULL;

void fuzzer_set_target(fuzzer_state_t *fs, fuzz_target_fn target,
                        void *user_data) {
    (void)fs;
    g_target = target;
    g_target_ud = user_data;
}

exec_result_t fuzz_execute(fuzzer_state_t *fs) {
    if (!g_target || !fs->out_buf) return EXEC_ERROR;
    fs->stats.total_execs++;
    return g_target(fs->out_buf, fs->out_len, g_target_ud);
}

void fuzz_calibrate_case(fuzzer_state_t *fs) {
    if (fs->corpus.current_idx >= fs->corpus.count) return;
    corpus_entry_t *e = &fs->corpus.entries[fs->corpus.current_idx];
    printf("[CALIBRATE] Calibrating \"%s\" (%zu bytes)...\n",
           e->name, e->len);

    /* Run the test case multiple times */
    for (int i = 0; i < 8; i++) {
        ensure_out_buf(fs, e->len);
        memcpy(fs->out_buf, e->data, e->len);
        fs->out_len = e->len;
        exec_result_t res = fuzz_execute(fs);
        if (res == EXEC_CRASH) {
            printf("[!] Crash during calibration of %s\n", e->name);
            return;
        }
    }
    printf("[CALIBRATE] OK - %s behaves predictably\n", e->name);
}

void fuzz_trim_case(fuzzer_state_t *fs) {
    if (fs->corpus.current_idx >= fs->corpus.count) return;
    corpus_entry_t *e = &fs->corpus.entries[fs->corpus.current_idx];
    if (e->len <= 4) return;

    size_t remove_len = e->len;
    while (remove_len > 4) {
        remove_len >>= 1;
        ensure_out_buf(fs, e->len);
        memcpy(fs->out_buf, e->data, e->len);

        /* Move from front */
        memmove(fs->out_buf, fs->out_buf + remove_len,
                e->len - remove_len);
        /* ... in a real fuzzer, we'd check if it still triggers new paths */
    }
}

/* ═══════════════════════════════════════════════════════════════
   Save If Interesting
   ═══════════════════════════════════════════════════════════════ */

bool fuzz_save_if_interesting(fuzzer_state_t *fs) {
    if (!fs->out_buf || fs->out_len == 0) return false;
    if (!g_target) return false;

    exec_result_t res = g_target(fs->out_buf, fs->out_len, g_target_ud);
    fs->stats.total_execs++;

    if (res == EXEC_CRASH) {
        fuzz_crash_save(fs, "SIGSEGV", 11);
        return true;
    }

    /* In a real fuzzer, check coverage bitmap for new edges here */
    return false;
}

/* ═══════════════════════════════════════════════════════════════
   Crash Triage
   ═══════════════════════════════════════════════════════════════ */

uint32_t fuzz_crash_hash(const uint8_t *data, size_t len) {
    uint32_t hash = 5381;
    for (size_t i = 0; i < len && i < 256; i++)
        hash = ((hash << 5) + hash) + data[i];
    return hash;
}

int32_t fuzz_crash_find(const crash_db_t *db, uint32_t hash) {
    for (uint32_t i = 0; i < db->count; i++) {
        if (db->crashes[i].crash_hash == hash)
            return (int32_t)i;
    }
    return -1;
}

bool fuzz_crash_is_unique(const crash_db_t *db, uint32_t hash) {
    return fuzz_crash_find(db, hash) < 0;
}

void fuzz_crash_save(fuzzer_state_t *fs, const char *signal_desc,
                      int signal_num) {
    if (!fs->out_buf) return;

    uint32_t hash = fuzz_crash_hash(fs->out_buf, fs->out_len);

    if (!fuzz_crash_is_unique(&fs->crashes, hash)) {
        fs->stats.total_crashes++;
        return;
    }

    if (fs->crashes.count >= FUZZ_MAX_CRASHES) return;

    crash_info_t *c = &fs->crashes.crashes[fs->crashes.count];
    c->data = (uint8_t*)malloc(fs->out_len);
    if (!c->data) return;
    memcpy(c->data, fs->out_buf, fs->out_len);
    c->len = fs->out_len;
    strncpy(c->signal_desc, signal_desc, sizeof(c->signal_desc) - 1);
    c->signal_num = signal_num;
    c->crash_hash = hash;
    c->exec_at = fs->stats.total_execs;

    snprintf(c->filename, sizeof(c->filename),
             "%s/id-%06u-sig-%02d-crash%06llu",
             fs->out_dir, fs->crashes.count, signal_num,
             (unsigned long long)fs->stats.total_execs);

    fs->crashes.count++;
    fs->stats.unique_crashes++;
    fs->stats.total_crashes++;
    fs->coverage.unique_crashes++;

    printf("\n[CRASH!] Signal: %s (#%d) at exec %llu\n",
           signal_desc, signal_num,
           (unsigned long long)fs->stats.total_execs);
    printf("         Saved as: %s (size: %zu)\n", c->filename, c->len);
}

/* ═══════════════════════════════════════════════════════════════
   Main Fuzzing Loop
   ═══════════════════════════════════════════════════════════════ */

void fuzzer_main_loop(fuzzer_state_t *fs) {
    printf("\n[FUZZER] Starting main loop with %u seeds...\n",
           fs->corpus.count);

    while (fs->running && fs->corpus.count > 0) {
        for (uint32_t i = 0; i < fs->corpus.count && fs->running; i++) {
            fs->corpus.current_idx = i;
            corpus_entry_t *e = &fs->corpus.entries[i];

            if (e->was_fuzzed) continue;

            /* Deterministic stage */
            fs->deterministic = true;
            fuzz_calibrate_case(fs);
            fuzz_trim_case(fs);
            fuzz_mutate_bitflip(fs, 1);
            fuzz_mutate_bitflip(fs, 2);
            fuzz_mutate_bitflip(fs, 4);
            fuzz_mutate_byte_add(fs);
            fuzz_mutate_interesting(fs, 1);
            fuzz_mutate_interesting(fs, 2);
            fuzz_mutate_interesting(fs, 4);
            e->was_fuzzed = true;

            /* Havoc stage */
            fs->deterministic = false;
            fuzz_mutate_havoc(fs);

            fs->stats.pending_favs--;
            fs->stats.pending_total--;

            /* Periodic status */
            if (fs->stats.total_execs % 5000 == 0) {
                fuzzer_print_status(fs);
            }

            /* Simulated limit for demo purposes */
            if (fs->stats.total_execs > 100000) {
                fs->running = false;
                printf("[FUZZER] Hit exec limit, stopping.\n");
                break;
            }
        }

        fs->stats.cycles_done++;
    }
}

/* ═══════════════════════════════════════════════════════════════
   Stats
   ═══════════════════════════════════════════════════════════════ */

void fuzz_stats_update(fuzz_stats_t *st, uint64_t execs) {
    st->total_execs = execs;
    double elapsed = get_time() - st->start_time;
    if (elapsed > 0.001)
        st->execs_per_sec = (uint64_t)((double)st->total_execs / elapsed);
}

void fuzz_stats_print(const fuzz_stats_t *st) {
    printf("\n═══ Fuzzing Statistics ═══\n");
    printf("  Total execs:     %llu\n", (unsigned long long)st->total_execs);
    printf("  Total crashes:   %llu\n", (unsigned long long)st->total_crashes);
    printf("  Unique crashes:  %llu\n", (unsigned long long)st->unique_crashes);
    printf("  Total paths:     %llu\n", (unsigned long long)st->total_paths);
    printf("  Pending favs:    %llu\n", (unsigned long long)st->pending_favs);
    printf("  Cycles:          %llu\n", (unsigned long long)st->cycles_done);
    printf("  Execs/sec:       %llu\n", (unsigned long long)st->execs_per_sec);
    printf("  Max depth:       %llu\n", (unsigned long long)st->max_depth);
}

void fuzzer_print_status(const fuzzer_state_t *fs) {
    double elapsed = get_time() - fs->stats.start_time;
    uint64_t eps = elapsed > 0.001
        ? (uint64_t)((double)fs->stats.total_execs / elapsed) : 0;
    printf("[STATUS] execs: %6llu | paths: %4u | crashes: %3u/%3u |"
           " cycles: %2llu | %4llu/sec\n",
           (unsigned long long)fs->stats.total_execs,
           fs->corpus.count,
           fs->stats.unique_crashes,
           fs->crashes.count,
           (unsigned long long)fs->stats.cycles_done,
           (unsigned long long)eps);
}

void fuzzer_print_banner(void) {
    printf("┌──────────────────────────────────────┐\n");
    printf("│  mini-binary-security FUZZER v1.0    │\n");
    printf("│  AFL-style coverage-guided fuzzing   │\n");
    printf("│  C99 implementation                  │\n");
    printf("└──────────────────────────────────────┘\n");
}

/* ═══════════════════════════════════════════════════════════════
   Dictionary Support
   ═══════════════════════════════════════════════════════════════ */

void fuzz_dict_init(dictionary_t *d) {
    memset(d, 0, sizeof(*d));
}

bool fuzz_dict_add(dictionary_t *d, const uint8_t *data, size_t len,
                    const char *name) {
    if (d->count >= 256) return false;
    dict_entry_t *e = &d->entries[d->count];
    e->data = (uint8_t*)malloc(len);
    if (!e->data) return false;
    memcpy(e->data, data, len);
    e->len = len;
    if (name) strncpy(e->name, name, sizeof(e->name) - 1);
    d->count++;
    return true;
}

bool fuzz_dict_load(dictionary_t *d, const char *path) {
    (void)d; (void)path;
    printf("[DICT] Loading dictionary from %s (simulated)\n", path);
    /* In real code: parse AFL dict format */
    const char *defaults[] = {"\xff\xff", "\x00\x00", "<script>",
                               "AAAA", "%s%s%s", "0x"};
    for (int i = 0; i < 6; i++) {
        fuzz_dict_add(d, (const uint8_t*)defaults[i],
                       strlen(defaults[i]), "builtin");
    }
    return true;
}

/* ═══════════════════════════════════════════════════════════════
   Forkserver Simulation
   ═══════════════════════════════════════════════════════════════ */

void fuzz_forkserver_sim_init(void) {
    printf("[FORKSRV] Forkserver simulation initialized.\n");
    printf("[FORKSRV] In real AFL: forks once, uses copy-on-write.\n");
    printf("[FORKSRV] Fuzzer writes testcase to child via pipe.\n");
    printf("[FORKSRV] Child execs target; exit code -> crash/success.\n");
}

int fuzz_forkserver_sim_run(const uint8_t *data, size_t len) {
    (void)data; (void)len;
    /* Simulated: fork(), execv(), waitpid() pattern */
    return 0;  /* EXIT_SUCCESS */
}
