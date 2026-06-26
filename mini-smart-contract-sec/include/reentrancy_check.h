#ifndef REENTRANCY_CHECK_H
#define REENTRANCY_CHECK_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define RC_CALLGRAPH_MAX_NODES   128
#define RC_CALLGRAPH_MAX_EDGES   512
#define RC_FUNC_NAME_MAX         64
#define RC_PATH_MAX_DEPTH        32

typedef enum {
    RC_PATTERN_SAFE           = 0,
    RC_PATTERN_CEI            = 1,
    RC_PATTERN_VULN           = 2,
    RC_PATTERN_GUARDED        = 3,
    RC_PATTERN_READONLY_REENT = 4,
    RC_PATTERN_CROSS_FUNC     = 5
} rc_pattern_t;

typedef enum {
    RC_EVT_CALL           = 0,
    RC_EVT_SSTORE         = 1,
    RC_EVT_SLOAD          = 2,
    RC_EVT_TRANSFER       = 3,
    RC_EVT_RETURN         = 4,
    RC_EVT_SELFDESTRUCT   = 5,
    RC_EVT_DELEGATECALL   = 6
} rc_event_type_t;

typedef struct {
    rc_event_type_t type;
    int line;
    char target_func[RC_FUNC_NAME_MAX];
    char source_func[RC_FUNC_NAME_MAX];
} rc_event_t;

typedef struct {
    char name[RC_FUNC_NAME_MAX];
    bool has_external_call;
    bool has_state_write;
    bool has_guard;
    int  guard_var_id;
    int  state_var_id;
    rc_pattern_t pattern;
    int  id;
} rc_func_node_t;

typedef struct {
    int from;
    int to;
    rc_event_type_t edge_type;
} rc_call_edge_t;

typedef struct {
    rc_func_node_t nodes[RC_CALLGRAPH_MAX_NODES];
    rc_call_edge_t edges[RC_CALLGRAPH_MAX_EDGES];
    int node_count;
    int edge_count;
} rc_callgraph_t;

typedef struct {
    bool locked;
    int  lock_var_id;
} rc_guard_t;

typedef struct {
    rc_callgraph_t graph;
    rc_guard_t     guard;
    rc_event_t     events[256];
    int            event_count;
    bool           detected_reentrancy;
    char           vuln_desc[512];
    int            vuln_count;
    rc_pattern_t   vulnerabilities[32];
    char           vuln_details[32][256];
} rc_analyzer_t;

void rc_init(rc_analyzer_t *a);
int  rc_add_function(rc_analyzer_t *a, const char *name, bool has_guard, int guard_var);
int  rc_add_edge(rc_analyzer_t *a, int from, int to, rc_event_type_t type);
void rc_mark_external_call(rc_analyzer_t *a, int func_id);
void rc_mark_state_write(rc_analyzer_t *a, int func_id);
void rc_set_guard(rc_analyzer_t *a, int lock_var_id, bool locked);

void rc_add_event(rc_analyzer_t *a, rc_event_type_t type, int line,
                  const char *target, const char *source);

int  rc_detect_reentrancy(rc_analyzer_t *a);
int  rc_check_cei_pattern(rc_analyzer_t *a, int func_id);
int  rc_check_cross_func(rc_analyzer_t *a);
int  rc_check_readonly_reent(rc_analyzer_t *a);

void rc_simulate_attack(rc_analyzer_t *a, int entry_func, bool verbose);
void rc_print_report(const rc_analyzer_t *a);

void rc_guard_enter(rc_guard_t *g);
void rc_guard_exit(rc_guard_t *g);
bool rc_guard_is_locked(const rc_guard_t *g);

bool rc_detect_external_before_update(rc_analyzer_t *a, int func_id);
const char *rc_pattern_name(rc_pattern_t p);

#endif
