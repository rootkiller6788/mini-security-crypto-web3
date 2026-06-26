#include "reentrancy_check.h"
#include <stdio.h>
#include <string.h>

const char *rc_pattern_name(rc_pattern_t p) {
    switch (p) {
    case RC_PATTERN_SAFE:           return "Safe";
    case RC_PATTERN_CEI:            return "Checks-Effects-Interactions";
    case RC_PATTERN_VULN:           return "Reentrancy Vulnerable";
    case RC_PATTERN_GUARDED:        return "Guarded (nonReentrant)";
    case RC_PATTERN_READONLY_REENT: return "Read-Only Reentrancy Risk";
    case RC_PATTERN_CROSS_FUNC:     return "Cross-Function Reentrancy Risk";
    default:                        return "Unknown";
    }
}

void rc_init(rc_analyzer_t *a) {
    memset(a, 0, sizeof(rc_analyzer_t));
    a->guard.locked = false;
    a->guard.lock_var_id = -1;
}

int rc_add_function(rc_analyzer_t *a, const char *name, bool has_guard, int guard_var) {
    if (a->graph.node_count >= RC_CALLGRAPH_MAX_NODES) return -1;
    rc_func_node_t *n = &a->graph.nodes[a->graph.node_count];
    strncpy(n->name, name, RC_FUNC_NAME_MAX - 1);
    n->name[RC_FUNC_NAME_MAX - 1] = '\0';
    n->has_external_call = false;
    n->has_state_write = false;
    n->has_guard = has_guard;
    n->guard_var_id = guard_var;
    n->state_var_id = -1;
    n->pattern = RC_PATTERN_SAFE;
    n->id = a->graph.node_count;
    a->graph.node_count++;
    return n->id;
}

int rc_add_edge(rc_analyzer_t *a, int from, int to, rc_event_type_t type) {
    if (from < 0 || from >= a->graph.node_count) return -1;
    if (to < 0 || to >= a->graph.node_count) return -1;
    if (a->graph.edge_count >= RC_CALLGRAPH_MAX_EDGES) return -1;
    a->graph.edges[a->graph.edge_count].from = from;
    a->graph.edges[a->graph.edge_count].to = to;
    a->graph.edges[a->graph.edge_count].edge_type = type;
    a->graph.edge_count++;
    return 0;
}

void rc_mark_external_call(rc_analyzer_t *a, int func_id) {
    if (func_id >= 0 && func_id < a->graph.node_count)
        a->graph.nodes[func_id].has_external_call = true;
}

void rc_mark_state_write(rc_analyzer_t *a, int func_id) {
    if (func_id >= 0 && func_id < a->graph.node_count)
        a->graph.nodes[func_id].has_state_write = true;
}

void rc_set_guard(rc_analyzer_t *a, int lock_var_id, bool locked) {
    a->guard.lock_var_id = lock_var_id;
    a->guard.locked = locked;
}

void rc_add_event(rc_analyzer_t *a, rc_event_type_t type, int line,
                  const char *target, const char *source) {
    if (a->event_count >= 256) return;
    a->events[a->event_count].type = type;
    a->events[a->event_count].line = line;
    strncpy(a->events[a->event_count].target_func, target, RC_FUNC_NAME_MAX - 1);
    a->events[a->event_count].target_func[RC_FUNC_NAME_MAX - 1] = '\0';
    strncpy(a->events[a->event_count].source_func, source, RC_FUNC_NAME_MAX - 1);
    a->events[a->event_count].source_func[RC_FUNC_NAME_MAX - 1] = '\0';
    a->event_count++;
}

void rc_guard_enter(rc_guard_t *g) {
    g->locked = true;
}

void rc_guard_exit(rc_guard_t *g) {
    g->locked = false;
}

bool rc_guard_is_locked(const rc_guard_t *g) {
    return g->locked;
}

bool rc_detect_external_before_update(rc_analyzer_t *a, int func_id) {
    if (func_id < 0 || func_id >= a->graph.node_count) return false;

    bool saw_call = false;
    for (int i = 0; i < a->event_count; i++) {
        if (strcmp(a->events[i].source_func, a->graph.nodes[func_id].name) != 0)
            continue;
        if (a->events[i].type == RC_EVT_CALL ||
            a->events[i].type == RC_EVT_TRANSFER ||
            a->events[i].type == RC_EVT_DELEGATECALL) {
            saw_call = true;
        }
        if (saw_call && a->events[i].type == RC_EVT_SSTORE) {
            return true;
        }
    }
    return false;
}

int rc_check_cei_pattern(rc_analyzer_t *a, int func_id) {
    if (func_id < 0 || func_id >= a->graph.node_count) return 0;

    rc_func_node_t *fn = &a->graph.nodes[func_id];
    if (fn->has_guard) {
        fn->pattern = RC_PATTERN_GUARDED;
        return 0;
    }

    bool has_call = false, has_update = false;
    int last_call = -1, last_update = -1;

    for (int i = 0; i < a->event_count; i++) {
        if (strcmp(a->events[i].source_func, fn->name) != 0) continue;
        if (a->events[i].type == RC_EVT_CALL ||
            a->events[i].type == RC_EVT_TRANSFER) {
            has_call = true;
            last_call = i;
        }
        if (a->events[i].type == RC_EVT_SSTORE) {
            has_update = true;
            last_update = i;
        }
    }

    if (has_call && has_update && last_call < last_update) {
        fn->pattern = RC_PATTERN_CEI;
        return 0;
    }
    if (has_call && !has_update) {
        return 0;
    }
    if (has_call && has_update && last_call > last_update) {
        fn->pattern = RC_PATTERN_VULN;
        if (a->vuln_count < 32) {
            snprintf(a->vuln_details[a->vuln_count], 256,
                     "Function '%s': external call before state update - reentrancy risk",
                     fn->name);
            a->vulnerabilities[a->vuln_count] = RC_PATTERN_VULN;
            a->vuln_count++;
        }
        a->detected_reentrancy = true;
        return 1;
    }
    fn->pattern = RC_PATTERN_SAFE;
    return 0;
}

int rc_check_cross_func(rc_analyzer_t *a) {
    int found = 0;
    for (int i = 0; i < a->graph.edge_count; i++) {
        rc_call_edge_t *e = &a->graph.edges[i];
        rc_func_node_t *from = &a->graph.nodes[e->from];
        rc_func_node_t *to = &a->graph.nodes[e->to];

        if (from->has_external_call && to->has_state_write &&
            !from->has_guard && !to->has_guard) {
            if (a->vuln_count < 32) {
                snprintf(a->vuln_details[a->vuln_count], 256,
                         "Cross-function reentrancy: '%s' calls '%s' which writes state",
                         from->name, to->name);
                a->vulnerabilities[a->vuln_count] = RC_PATTERN_CROSS_FUNC;
                a->vuln_count++;
            }
            found++;
        }
    }
    if (found > 0) a->detected_reentrancy = true;
    return found;
}

int rc_check_readonly_reent(rc_analyzer_t *a) {
    int found = 0;
    for (int i = 0; i < a->graph.node_count; i++) {
        const rc_func_node_t *n = &a->graph.nodes[i];
        if (n->has_external_call && !n->has_guard) {
            for (int j = 0; j < a->graph.node_count; j++) {
                if (i == j) continue;
                rc_func_node_t *m = &a->graph.nodes[j];
                if (m->has_state_write) {
                    for (int k = 0; k < a->graph.edge_count; k++) {
                        if (a->graph.edges[k].from == i &&
                            a->graph.edges[k].to == j) {
                            found++;
                            if (a->vuln_count < 32) {
                                snprintf(a->vuln_details[a->vuln_count], 256,
                                         "Read-only reentrancy: '%s' (view) can observe stale state from '%s'",
                                         m->name, n->name);
                                a->vulnerabilities[a->vuln_count] = RC_PATTERN_READONLY_REENT;
                                a->vuln_count++;
                            }
                        }
                    }
                }
            }
        }
    }
    return found;
}

int rc_detect_reentrancy(rc_analyzer_t *a) {
    int total = 0;
    for (int i = 0; i < a->graph.node_count; i++) {
        total += rc_check_cei_pattern(a, i);
    }
    total += rc_check_cross_func(a);
    total += rc_check_readonly_reent(a);
    return total;
}

void rc_simulate_attack(rc_analyzer_t *a, int entry_func, bool verbose) {
    if (verbose) {
        printf("\n=== Reentrancy Attack Simulation ===\n");
        printf("Entry function: %s\n",
               a->graph.nodes[entry_func].name);
    }

    rc_func_node_t *fn = &a->graph.nodes[entry_func];

    if (fn->has_guard) {
        if (verbose) printf("  [OK] Guard detected: reentrant call blocked\n");
        return;
    }

    if (fn->has_external_call && fn->has_state_write) {
        bool call_before_update = rc_detect_external_before_update(a, entry_func);

        if (call_before_update) {
            if (verbose) {
                printf("  [VULN] Recursive withdrawal simulation:\n");
                printf("    Step 1: Contract calls external (e.g. transfer)\n");
                printf("    Step 2: External contract re-enters before state update\n");
                printf("    Step 3: State still shows old balance\n");
                printf("    Step 4: Attacker can withdraw multiple times\n");
            }

            if (!a->detected_reentrancy) {
                a->detected_reentrancy = true;
                if (a->vuln_count < 32) {
                    snprintf(a->vuln_details[a->vuln_count], 256,
                             "Simulated reentrancy: '%s' - recursive withdrawal possible",
                             fn->name);
                    a->vulnerabilities[a->vuln_count] = RC_PATTERN_VULN;
                    a->vuln_count++;
                }
            }
        } else {
            if (verbose) printf("  [SAFE] CEI pattern followed\n");
        }
    }
}

void rc_print_report(const rc_analyzer_t *a) {
    printf("\n========== Reentrancy Analysis Report ==========\n");
    printf("Functions analyzed: %d\n", a->graph.node_count);
    printf("Call edges:         %d\n", a->graph.edge_count);
    printf("Events logged:      %d\n", a->event_count);
    printf("Reentrancy found:   %s\n", a->detected_reentrancy ? "YES" : "NO");
    printf("Vulnerabilities:    %d\n", a->vuln_count);

    printf("\n--- Function Patterns ---\n");
    for (int i = 0; i < a->graph.node_count; i++) {
        const rc_func_node_t *n = &a->graph.nodes[i];
        printf("  [%d] %s", n->id, n->name);
        if (n->has_external_call) printf(" (external-call)");
        if (n->has_state_write) printf(" (state-write)");
        if (n->has_guard) printf(" (guarded)");
        printf(" -> %s\n", rc_pattern_name(n->pattern));
    }

    if (a->vuln_count > 0) {
        printf("\n--- Vulnerability Details ---\n");
        for (int i = 0; i < a->vuln_count; i++) {
            printf("  [%d] %s\n", i + 1, a->vuln_details[i]);
        }
    }

    printf("\n--- Call Graph Edges ---\n");
    for (int i = 0; i < a->graph.edge_count; i++) {
        const rc_call_edge_t *e = &a->graph.edges[i];
        printf("  %s --> %s\n",
               a->graph.nodes[e->from].name,
               a->graph.nodes[e->to].name);
    }

    printf("=================================================\n");
}
