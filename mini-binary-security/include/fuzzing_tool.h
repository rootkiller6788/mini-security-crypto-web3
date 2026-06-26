#ifndef FUZZING_TOOL_H
#define FUZZING_TOOL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Constants ── */
#define FUZZ_MAP_SIZE         65536   /* 64 KB coverage bitmap (AFL-style) */
#define FUZZ_MAX_INPUT        1048576 /* 1 MB max test case                 */
#define FUZZ_MAX_CRASHES      1024
#define FUZZ_MAX_CORPUS       4096
#define FUZZ_MIN_INPUT         2
#define FUZZ_BITFLIP_STEPS    2       /* 1-, 2-byte flips                   */
#define FUZZ_HAVOC_CYCLES      32
#define FUZZ_SPLICE_CYCLES     4
#define FUZZ_INTERESTING_8_COUNT 9
#define FUZZ_INTERESTING_16_COUNT 19
#define FUZZ_INTERESTING_32_COUNT 27

/* ── Mutation types ── */
typedef enum {
    MUT_BITFLIP_1   = 0,
    MUT_BITFLIP_2   = 1,
    MUT_BITFLIP_4   = 2,
    MUT_BYTE_ADD    = 3,
    MUT_BYTE_SUB    = 4,
    MUT_INTEREST_8  = 5,
    MUT_INTEREST_16 = 6,
    MUT_INTEREST_32 = 7,
    MUT_ARITH_8     = 8,
    MUT_ARITH_16    = 9,
    MUT_ARITH_32    = 10,
    MUT_RAND_BYTE   = 11,
    MUT_DELETE_BYTE = 12,
    MUT_CLONE_BYTE  = 13,
    MUT_OVERWRITE   = 14,
    MUT_DICT_INSERT = 15,
    MUT_SPLICE      = 16,
    MUT_HAVOC       = 17,
    MUT_TRIM        = 18,
    MUT_COUNT       = 19,
} mutation_type_t;

/* ── Interesting values dictionary ── */
static const int8_t   INTERESTING_8[] = {
    -128, -1, 0, 1, 16, 32, 64, 100, 127
};

static const int16_t  INTERESTING_16[] = {
    -32768, -129, 128, 255, 256, 512, 1000, 1024, 4096,
    32767, -128, -1, 0, 1, 16, 32, 64, 100, 127
};

static const int32_t  INTERESTING_32[] = {
    -2147483647-1, -100663046, -32769, 32768, 65535,
    65536, 100663045, 2147483647, -1, 0, 1, 16, 32,
    64, 100, 127, 128, 129, 255, 256, 512, 1000, 1024,
    4096, 32767, 65536, 100663046
};

/* ── Coverage bitmap ── */
typedef struct {
    uint8_t  bitmap[FUZZ_MAP_SIZE];
    uint64_t total_edges;
    uint64_t unique_crashes;
    uint64_t total_execs;
} coverage_map_t;

/* ── Corpus entry ── */
typedef struct {
    uint8_t  *data;
    size_t    len;
    size_t    trimmed_len;
    uint64_t  exec_us;
    uint64_t  bitmap_size;     /* unique edges from this input   */
    uint64_t  handicap;
    uint64_t  depth;
    uint64_t  fuzz_count;
    char      name[256];
    bool      was_fuzzed;
} corpus_entry_t;

/* ── Corpus ── */
typedef struct {
    corpus_entry_t entries[FUZZ_MAX_CORPUS];
    uint32_t       count;
    uint64_t       total_size;
    uint32_t       current_idx;
} corpus_t;

/* ── Crash info ── */
typedef struct {
    uint8_t   *data;
    size_t     len;
    char       signal_desc[64];
    int        signal_num;
    uint32_t   crash_hash;      /* dedup key */
    uint64_t   exec_at;
    char       filename[256];
    bool       saved;
} crash_info_t;

/* ── Crash database ── */
typedef struct {
    crash_info_t crashes[FUZZ_MAX_CRASHES];
    uint32_t     count;
} crash_db_t;

/* ── Execution result ── */
typedef enum {
    EXEC_OK       = 0,
    EXEC_CRASH    = 1,
    EXEC_TIMEOUT  = 2,
    EXEC_HANG     = 3,
    EXEC_ERROR    = 4,
} exec_result_t;

/* ── Dictionary entry ── */
typedef struct {
    uint8_t *data;
    size_t   len;
    char     name[64];
} dict_entry_t;

typedef struct {
    dict_entry_t entries[256];
    uint32_t     count;
} dictionary_t;

/* ── Fuzzer statistics ── */
typedef struct {
    uint64_t total_execs;
    uint64_t total_crashes;
    uint64_t unique_crashes;
    uint64_t total_paths;
    uint64_t pending_favs;
    uint64_t pending_total;
    uint64_t cycles_done;
    uint64_t execs_per_sec;
    uint64_t bitmap_cvg[FUZZ_MAP_SIZE / 256];
    uint64_t max_depth;
    double   start_time;
} fuzz_stats_t;

/* ── Fuzzer state ── */
typedef struct {
    coverage_map_t  coverage;
    corpus_t        corpus;
    crash_db_t      crashes;
    dictionary_t    dict;
    fuzz_stats_t    stats;
    uint8_t        *out_buf;
    size_t          out_len;
    bool            running;
    bool            deterministic;   /* phase 1: deterministic  */
    uint32_t        queue_cur;
    uint32_t        stage_cur;
    uint32_t        stage_max;
    const char     *stage_name;
    char            out_dir[256];
    char            in_dir[256];
} fuzzer_state_t;

/* ── Target callbacks ── */
typedef exec_result_t (*fuzz_target_fn)(const uint8_t *data, size_t len,
                                         void *user_data);

/* ── Coverage callback (called by instrumented target) ── */
typedef void (*fuzz_coverage_cb)(uint32_t edge_id);

/* ── API ── */

/* Initialization */
void        fuzzer_init(fuzzer_state_t *fs, const char *in_dir,
                         const char *out_dir);
void        fuzzer_set_target(fuzzer_state_t *fs, fuzz_target_fn target,
                               void *user_data);
void        fuzzer_free(fuzzer_state_t *fs);

/* Corpus management */
bool        fuzzer_add_seed(fuzzer_state_t *fs, const uint8_t *data,
                             size_t len, const char *name);
bool        fuzzer_load_seeds(fuzzer_state_t *fs);
void        fuzzer_minimize_corpus(fuzzer_state_t *fs);

/* Coverage */
void        fuzz_coverage_init(coverage_map_t *cm);
bool        fuzz_coverage_update(coverage_map_t *cm, const uint8_t *new_data,
                                  size_t len);
bool        fuzz_coverage_has_new(coverage_map_t *cm);
uint64_t    fuzz_coverage_count(const coverage_map_t *cm);
void        fuzz_coverage_reset_check(coverage_map_t *cm);

/* Mutation engine */
void        fuzz_mutate_bitflip(fuzzer_state_t *fs, int bytes);
void        fuzz_mutate_byte_add(fuzzer_state_t *fs);
void        fuzz_mutate_byte_sub(fuzzer_state_t *fs);
void        fuzz_mutate_interesting(fuzzer_state_t *fs, int width);
void        fuzz_mutate_arith(fuzzer_state_t *fs, int width);
void        fuzz_mutate_random_byte(fuzzer_state_t *fs);
void        fuzz_mutate_delete_bytes(fuzzer_state_t *fs);
void        fuzz_mutate_clone_bytes(fuzzer_state_t *fs);
void        fuzz_mutate_splice(fuzzer_state_t *fs);
void        fuzz_mutate_havoc(fuzzer_state_t *fs);
void        fuzz_mutate_all(fuzzer_state_t *fs);

/* Execution and crash handling */
exec_result_t fuzz_execute(fuzzer_state_t *fs);
exec_result_t fuzz_run_target_cb(fuzz_target_fn target, const uint8_t *data,
                                  size_t len, void *ud);
void          fuzz_trim_case(fuzzer_state_t *fs);
void          fuzz_calibrate_case(fuzzer_state_t *fs);
bool          fuzz_save_if_interesting(fuzzer_state_t *fs);

/* Crash triage */
uint32_t      fuzz_crash_hash(const uint8_t *data, size_t len);
int32_t       fuzz_crash_find(const crash_db_t *db, uint32_t hash);
bool          fuzz_crash_is_unique(const crash_db_t *db, uint32_t hash);
void          fuzz_crash_save(fuzzer_state_t *fs, const char *signal_desc,
                               int signal_num);

/* Main loop */
void          fuzzer_main_loop(fuzzer_state_t *fs);

/* Stats */
void          fuzz_stats_update(fuzz_stats_t *st, uint64_t execs);
void          fuzz_stats_print(const fuzz_stats_t *st);
void          fuzzer_print_banner(void);
void          fuzzer_print_status(const fuzzer_state_t *fs);

/* Dictionary support */
void          fuzz_dict_init(dictionary_t *d);
bool          fuzz_dict_add(dictionary_t *d, const uint8_t *data, size_t len,
                             const char *name);
bool          fuzz_dict_load(dictionary_t *d, const char *path);

/* Forkserver simulation */
void          fuzz_forkserver_sim_init(void);
int           fuzz_forkserver_sim_run(const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* FUZZING_TOOL_H */
