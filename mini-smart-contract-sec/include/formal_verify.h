#ifndef FORMAL_VERIFY_H
#define FORMAL_VERIFY_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define FV_MAX_PATHS      256
#define FV_MAX_CONSTRAINTS 64
#define FV_MAX_BLOCKS     128
#define FV_MAX_VARS       64
#define FV_FUZZ_ITER      1000

typedef enum {
    FV_SYM_CONCRETE = 0,
    FV_SYM_SYMBOLIC = 1,
    FV_SYM_CONSTRAINED = 2
} fv_sym_type_t;

typedef struct {
    fv_sym_type_t type;
    union {
        int64_t  concrete;
        int      sym_id;
    } val;
    char     constraint[256];
    uint64_t min_val;
    uint64_t max_val;
} fv_sym_value_t;

typedef struct {
    fv_sym_value_t vars[FV_MAX_VARS];
    char           var_names[FV_MAX_VARS][32];
    int            var_count;
} fv_symbolic_state_t;

typedef struct {
    char        condition[512];
    int         block_id;
    bool        reached;
    bool        reverted;
    bool        asserted;
    char        assertion[256];
    bool        assertion_holds;
} fv_path_t;

typedef struct {
    int  id;
    char label[128];
    int  succ[2];
    int  succ_count;
    bool is_conditional;
    bool is_assert;
    bool is_revert;
    bool is_return;
    int  line;
    char assertion[256];
} fv_block_t;

typedef struct {
    fv_block_t blocks[FV_MAX_BLOCKS];
    int        block_count;
    int        entry_block;
} fv_cfg_t;

typedef enum {
    FV_TAINT_NONE       = 0,
    FV_TAINT_USER_INPUT = 1,
    FV_TAINT_LOW        = 2,
    FV_TAINT_MEDIUM     = 3,
    FV_TAINT_HIGH       = 4
} fv_taint_level_t;

typedef struct {
    char  var_name[32];
    fv_taint_level_t level;
    char  source[128];
    bool  reaches_sensitive;
    int   sinks[16];
    int   sink_count;
} fv_taint_var_t;

typedef struct {
    fv_taint_var_t vars[FV_MAX_VARS];
    int            var_count;
} fv_taint_tracker_t;

typedef struct {
    fv_symbolic_state_t sym_state;
    fv_cfg_t            cfg;
    fv_path_t           paths[FV_MAX_PATHS];
    int                 path_count;
    fv_taint_tracker_t  taint;
    bool                invariants_hold;
    int                 assertion_failures;
    int                 total_assertions;
    int                 total_paths_explored;
    char                findings[64][512];
    int                 findings_count;
    uint64_t            fuzz_crashes;
    uint64_t            fuzz_iterations;
} fv_analyzer_t;

void fv_init(fv_analyzer_t *a);
void fv_reset(fv_analyzer_t *a);

void fv_sym_set_concrete(fv_symbolic_state_t *s, int id, int64_t val);
void fv_sym_set_symbolic(fv_symbolic_state_t *s, int id, const char *name,
                          uint64_t min_val, uint64_t max_val);
int  fv_sym_add_var(fv_symbolic_state_t *s, const char *name, fv_sym_type_t type);

int  fv_cfg_add_block(fv_cfg_t *cfg, const char *label, int line);
void fv_cfg_add_edge(fv_cfg_t *cfg, int from, int to);
void fv_cfg_set_conditional(fv_cfg_t *cfg, int id, int t_branch, int f_branch);
void fv_cfg_set_assert(fv_cfg_t *cfg, int id, const char *assertion);
void fv_cfg_set_revert(fv_cfg_t *cfg, int id);
void fv_cfg_set_return(fv_cfg_t *cfg, int id);

int  fv_symbolic_execute(fv_analyzer_t *a);
void fv_explore_all_paths(fv_analyzer_t *a);

int  fv_check_assertions(fv_analyzer_t *a);
bool fv_check_invariant(fv_analyzer_t *a, const char *invariant,
                         bool (*check_fn)(void));
void fv_add_invariant(fv_analyzer_t *a, const char *invariant, bool holds);

void fv_taint_init(fv_taint_tracker_t *t);
void fv_taint_mark_input(fv_taint_tracker_t *t, const char *var, const char *source);
void fv_taint_propagate(fv_taint_tracker_t *t, const char *src, const char *dst);
void fv_taint_check_sink(fv_taint_tracker_t *t, const char *var,
                          const char *sink_name, fv_taint_level_t min_level);
void fv_taint_analyze(fv_analyzer_t *a);

void fv_fuzz_init(fv_analyzer_t *a);
void fv_fuzz_run(fv_analyzer_t *a, void (*target_fn)(uint64_t, uint64_t),
                 uint64_t iterations);
void fv_fuzz_run_seed(fv_analyzer_t *a, void (*target_fn)(uint64_t, uint64_t),
                       uint64_t seed, uint64_t iterations);

void fv_print_report(const fv_analyzer_t *a);
void fv_print_cfg(const fv_cfg_t *cfg);
void fv_print_taint(const fv_taint_tracker_t *t);

int  fv_mythril_detect_overflow(const fv_analyzer_t *a);
int  fv_mythril_detect_reentrancy(const fv_analyzer_t *a);
int  fv_slither_detect_unchecked_call(const fv_analyzer_t *a);
int  fv_slither_detect_suicidal(const fv_analyzer_t *a);

#endif
