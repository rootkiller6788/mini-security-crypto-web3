#include "gas_optimizer.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

uint64_t go_eip1559_effective_gas(const go_eip1559_fee_t *fee) {
    if (fee->base_fee_per_gas > fee->max_fee_per_gas) return 0;
    uint64_t effective = fee->base_fee_per_gas + fee->max_priority_fee;
    if (effective > fee->max_fee_per_gas) effective = fee->max_fee_per_gas;
    return effective;
}

void go_init(go_analyzer_t *g) {
    memset(g, 0, sizeof(go_analyzer_t));
    g->fee_model.base_fee_per_gas = 30;
    g->fee_model.max_priority_fee = 2;
    g->fee_model.max_fee_per_gas = 50;
}

void go_reset(go_analyzer_t *g) {
    memset(g, 0, sizeof(go_analyzer_t));
    go_init(g);
}

static int go_var_size(go_var_type_t t) {
    switch (t) {
    case GO_VAR_UINT8: case GO_VAR_INT8: case GO_VAR_BOOL:
    case GO_VAR_BYTES1: return 1;
    case GO_VAR_UINT16: case GO_VAR_INT16: return 2;
    case GO_VAR_UINT32: case GO_VAR_INT32: return 4;
    case GO_VAR_UINT64: case GO_VAR_INT64: return 8;
    case GO_VAR_UINT128: case GO_VAR_INT128: return 16;
    case GO_VAR_ADDRESS: return 20;
    case GO_VAR_BYTES32: return 32;
    case GO_VAR_UINT256: case GO_VAR_INT256:
    case GO_VAR_STRING: case GO_VAR_BYTES:
    case GO_VAR_ARRAY: case GO_VAR_MAPPING:
    case GO_VAR_STRUCT: return 32;
    default: return 32;
    }
}

int go_register_variable(go_analyzer_t *g, const char *name,
                          go_var_type_t type, int size_bytes) {
    if (g->all_var_count >= GO_MAX_VARS) return -1;
    go_storage_var_t *v = &g->all_vars[g->all_var_count];
    strncpy(v->name, name, GO_FUNC_NAME_MAX - 1);
    v->name[GO_FUNC_NAME_MAX - 1] = '\0';
    v->type = type;
    v->slot = -1;
    v->offset_bytes = 0;
    v->size_bytes = size_bytes > 0 ? size_bytes : go_var_size(type);
    v->is_packed = false;
    g->all_var_count++;
    return g->all_var_count - 1;
}

void go_analyze_storage_packing(go_analyzer_t *g) {
    if (g->all_var_count == 0) return;
    g->storage_slot_count = 0;
    int current_slot = 0;
    int current_offset = 0;
    go_storage_slot_t *slot = &g->storage_layout[0];
    memset(slot, 0, sizeof(go_storage_slot_t));
    slot->slot_id = 0;
    slot->is_fully_packed = true;
    g->storage_slot_count = 1;
    for (int i = 0; i < g->all_var_count; i++) {
        go_storage_var_t *v = &g->all_vars[i];
        int sz = v->size_bytes;
        bool needs_new_slot = false;
        if (sz >= 32 || v->type == GO_VAR_STRUCT ||
            v->type == GO_VAR_ARRAY || v->type == GO_VAR_MAPPING) {
            needs_new_slot = true;
        }
        if (!needs_new_slot && current_offset + sz <= 32) {
            v->slot = current_slot;
            v->offset_bytes = current_offset;
            v->is_packed = (current_offset > 0);
            if (slot->var_count < 8) {
                slot->vars[slot->var_count] = *v;
                slot->var_count++;
            }
            current_offset += sz;
        } else {
            slot->used_bytes = current_offset;
            slot->wasted_bytes = 32 - current_offset;
            slot->is_fully_packed = (slot->wasted_bytes == 0);
            current_slot++;
            if (current_slot >= GO_MAX_STORAGE_SLOTS) break;
            slot = &g->storage_layout[current_slot];
            memset(slot, 0, sizeof(go_storage_slot_t));
            slot->slot_id = current_slot;
            slot->is_fully_packed = true;
            g->storage_slot_count = current_slot + 1;
            v->slot = current_slot;
            v->offset_bytes = 0;
            v->is_packed = false;
            if (slot->var_count < 8) {
                slot->vars[slot->var_count] = *v;
                slot->var_count++;
            }
            current_offset = (needs_new_slot && sz >= 32) ? 32 : sz;
        }
    }
    if (slot && current_offset > 0) {
        slot->used_bytes = current_offset;
        slot->wasted_bytes = 32 - current_offset;
        slot->is_fully_packed = (slot->wasted_bytes == 0);
    }
    for (int i = 0; i < g->storage_slot_count; i++) {
        if (g->storage_layout[i].wasted_bytes > 0) {
            uint64_t gas_saved = (uint64_t)g->storage_layout[i].wasted_bytes * 20000ULL;
            char desc[256];
            snprintf(desc, sizeof(desc),
                     "Slot %d wastes %d bytes (%d/32 used). Reorder variables for tighter packing.",
                     i, g->storage_layout[i].wasted_bytes, g->storage_layout[i].used_bytes);
            go_add_suggestion(g, GO_SUGGEST_PACK_VARS, 0, desc, gas_saved, "loose slot", "packed slot");
        }
    }
}

int go_detect_redundant_sload(go_analyzer_t *g, const int *sload_slots,
                               int sload_count, const int *sstore_slots,
                               int sstore_count) {
    int redundant = 0;
    for (int i = 0; i < sload_count; i++) {
        for (int j = i + 1; j < sload_count; j++) {
            if (sload_slots[i] != sload_slots[j]) continue;
            bool stored = false;
            for (int k = 0; k < sstore_count; k++) {
                if (sstore_slots[k] == sload_slots[i]) { stored = true; break; }
            }
            if (!stored) {
                redundant++;
                if (g->suggestion_count < GO_MAX_SUGGESTIONS) {
                    char desc[256];
                    snprintf(desc, sizeof(desc),
                             "Redundant SLOAD at slot %d (load #%d repeats load #%d). Cache in local var.",
                             sload_slots[i], j + 1, i + 1);
                    go_add_suggestion(g, GO_SUGGEST_CACHE_SLOAD, 0, desc, 100, "sload x2", "sload x1+mload");
                }
            }
        }
    }
    return redundant;
}

int go_detect_loop_invariant_sload(go_analyzer_t *g, go_loop_info_t *loop,
                                    const int *body_sloads, int body_sload_count) {
    int invariant_count = 0;
    loop->has_invariant_sload = false;
    loop->invariant_count = 0;
    for (int i = 0; i < body_sload_count; i++) {
        int slot = body_sloads[i];
        bool already = false;
        for (int j = 0; j < invariant_count; j++) {
            if (loop->invariant_slots[j] == slot) { already = true; break; }
        }
        if (already) continue;
        if (invariant_count < 16) {
            loop->invariant_slots[invariant_count] = slot;
            invariant_count++;
        }
    }
    if (invariant_count > 0) {
        loop->has_invariant_sload = true;
        loop->invariant_count = invariant_count;
        uint64_t gas_saved = (uint64_t)invariant_count * 19000ULL;
        char desc[256];
        snprintf(desc, sizeof(desc),
                 "Loop has %d invariant SLOAD(s). Hoist outside loop. Saves ~%llu gas/10 iters.",
                 invariant_count, (unsigned long long)gas_saved);
        go_add_suggestion(g, GO_SUGGEST_HOIST_INVARIANT, loop->header_pc, desc, gas_saved,
                          "sload per iter", "load once + mload");
    }
    return invariant_count;
}

int go_detect_dead_code(go_analyzer_t *g, const uint8_t *bytecode,
                         size_t code_len, int entry_pc) {
    if (code_len == 0 || entry_pc < 0 || (size_t)entry_pc >= code_len) return 0;
    bool is_jumpdest[65536];
    bool reachable[65536];
    memset(is_jumpdest, 0, sizeof(is_jumpdest));
    memset(reachable, 0, sizeof(reachable));
    for (size_t i = 0; i < code_len && i < 65536; i++) {
        if (bytecode[i] == 0x5b) is_jumpdest[i] = true;
    }
    int queue[65536];
    int head = 0, tail = 0;
    if ((size_t)entry_pc < 65536) {
        queue[tail++] = entry_pc;
        reachable[entry_pc] = true;
    }
    while (head < tail) {
        int pc = queue[head++];
        if (pc < 0 || (size_t)pc >= code_len || (size_t)pc >= 65536) continue;
        uint8_t op = bytecode[pc];
        if (op == 0x00 || op == 0xf3 || op == 0xfd || op == 0xfe || op == 0xff) continue;
        if (op >= 0x60 && op <= 0x7f) {
            int skip = op - 0x60 + 1;
            int next = pc + 1 + skip;
            if (next < (int)code_len && (size_t)next < 65536 && !reachable[next]) {
                reachable[next] = true; queue[tail++] = next;
                if (tail >= 65536) tail = 0;
            }
            continue;
        }
        if (op == 0x56) {
            for (size_t k = 0; k < code_len && k < 65536; k++) {
                if (is_jumpdest[k] && !reachable[k]) {
                    reachable[k] = true; queue[tail++] = (int)k;
                    if (tail >= 65536) tail = 0;
                }
            }
            continue;
        }
        if (op == 0x57) {
            int next = pc + 1;
            if (next < (int)code_len && (size_t)next < 65536 && !reachable[next]) {
                reachable[next] = true; queue[tail++] = next;
                if (tail >= 65536) tail = 0;
            }
            continue;
        }
        int next = pc + 1;
        if (next < (int)code_len && (size_t)next < 65536 && !reachable[next]) {
            reachable[next] = true; queue[tail++] = next;
            if (tail >= 65536) tail = 0;
        }
    }
    int dead_count = 0;
    for (size_t i = 0; i < code_len && i < 65536; i++) {
        if (is_jumpdest[i] && !reachable[i]) {
            dead_count++;
            size_t dead_start = i;
            size_t dead_end = i + 1;
            while (dead_end < code_len && dead_end < 65536 && !is_jumpdest[dead_end]) dead_end++;
            uint64_t bytes = (uint64_t)(dead_end - dead_start);
            uint64_t gas_saved = bytes * 200ULL;
            if (g->suggestion_count < GO_MAX_SUGGESTIONS) {
                char desc[256];
                snprintf(desc, sizeof(desc),
                         "Dead code at PC=%zu: %zu unreachable bytes. Saves ~%llu deployment gas.",
                         dead_start, (size_t)bytes, (unsigned long long)gas_saved);
                go_add_suggestion(g, GO_SUGGEST_REMOVE_DEAD, (int)dead_start, desc, gas_saved,
                                  "dead bytes", "removed");
            }
        }
    }
    return dead_count;
}

uint64_t go_estimate_section_gas(go_analyzer_t *g, const uint8_t *code,
                                  int start_pc, int end_pc) {
    uint64_t total = 0;
    int sload_count = 0;
    for (int pc = start_pc; pc < end_pc; pc++) {
        uint8_t op = code[pc];
        switch (op) {
        case 0x01: case 0x03: case 0x10: case 0x11: case 0x12: case 0x13:
        case 0x14: case 0x15: case 0x16: case 0x17: case 0x18: case 0x19:
        case 0x1a: case 0x1b: case 0x1c: case 0x1d:
        case 0x30: case 0x32: case 0x33: case 0x34: case 0x35: case 0x36:
        case 0x37: case 0x38: case 0x39: case 0x3a:
        case 0x50: case 0x51: case 0x52: case 0x53:
        case 0x58: case 0x59: case 0x5a: case 0x5b:
            total += 3; break;
        case 0x02: case 0x04: case 0x05: case 0x06: case 0x07:
            total += 5; break;
        case 0x08: case 0x09: case 0x56:
            total += 8; break;
        case 0x0a: case 0x57:
            total += 10; break;
        case 0x20: total += 30; break;
        case 0x31: total += 400; break;
        case 0x3b: case 0x3c: total += 700; break;
        case 0x54:
            sload_count++;
            total += (sload_count <= 1) ? 2100 : 100;
            break;
        case 0x55: total += 22100; break;
        case 0xf0: total += 32000; break;
        case 0xf1: case 0xf2: case 0xf4: total += 700; break;
        case 0xff: total += 5000; break;
        case 0x00: case 0xf3: case 0xfd: case 0xfe: total += 0; break;
        default:
            if (op >= 0x60 && op <= 0x7f) { total += 3; pc += (op - 0x60 + 1); }
            else if (op >= 0x80 && op <= 0x8f) { total += 3; }
            else if (op >= 0x90 && op <= 0x9f) { total += 3; }
            else { total += 3; }
            break;
        }
    }
    (void)g;
    return total;
}

int go_detect_sstore_zero_opportunities(go_analyzer_t *g,
                                         const uint8_t *code, size_t code_len) {
    int count = 0;
    for (size_t i = 0; i + 1 < code_len; i++) {
        if (code[i] == 0x55) {
            if (i >= 2 && code[i - 2] == 0x60 && code[i - 1] == 0x00) count++;
            if (i >= 3 && code[i - 3] >= 0x61 && code[i - 3] <= 0x7f) {
                int pb = code[i - 3] - 0x60 + 1;
                if ((size_t)(1 + pb) == i - (i - 3)) {
                    bool az = true;
                    for (int b = 0; b < pb; b++) {
                        if (code[i - pb + b] != 0x00) { az = false; break; }
                    }
                    if (az) count++;
                }
            }
        }
    }
    if (count > 0 && g->suggestion_count < GO_MAX_SUGGESTIONS) {
        char desc[256];
        snprintf(desc, sizeof(desc),
                 "Found %d zero-SSTORE pattern(s). EIP-3529: ~4800 gas refund per zero sstore. Total: ~%llu gas.",
                 count, (unsigned long long)((uint64_t)count * 4800ULL));
        go_add_suggestion(g, GO_SUGGEST_AVOID_ZERO_SSTORE, 0, desc,
                          (uint64_t)count * 4800ULL, "sstore nonzero", "sstore zero+refund");
    }
    return count;
}

bool go_can_use_unchecked(uint64_t a, uint64_t b, char op) {
    switch (op) {
    case '+': return (a <= UINT64_MAX - b);
    case '-': return (a >= b);
    case '*': if (a == 0 || b == 0) return true; return (a <= UINT64_MAX / b);
    default: return false;
    }
}

bool go_check_upgrade_compatible(const go_analyzer_t *old_layout,
                                  const go_analyzer_t *new_layout,
                                  char *conflict_desc, size_t desc_len) {
    if (conflict_desc) conflict_desc[0] = '\0';
    for (int i = 0; i < old_layout->all_var_count; i++) {
        const go_storage_var_t *ov = &old_layout->all_vars[i];
        bool found = false;
        for (int j = 0; j < new_layout->all_var_count; j++) {
            const go_storage_var_t *nv = &new_layout->all_vars[j];
            if (strcmp(ov->name, nv->name) == 0) {
                if (ov->slot != nv->slot || ov->offset_bytes != nv->offset_bytes) {
                    if (conflict_desc) {
                        snprintf(conflict_desc, desc_len,
                                 "Storage collision: '%s' moved slot %d+%d -> %d+%d",
                                 ov->name, ov->slot, ov->offset_bytes, nv->slot, nv->offset_bytes);
                    }
                    return false;
                }
                if (ov->size_bytes != nv->size_bytes) {
                    if (conflict_desc) {
                        snprintf(conflict_desc, desc_len, "Type change: '%s' size %d -> %d bytes",
                                 ov->name, ov->size_bytes, nv->size_bytes);
                    }
                    return false;
                }
                found = true; break;
            }
        }
        if (!found) {
            if (conflict_desc) {
                snprintf(conflict_desc, desc_len, "Variable '%s' removed. Use gap slot instead.", ov->name);
            }
            return false;
        }
    }
    int max_old_slot = -1;
    for (int i = 0; i < old_layout->all_var_count; i++) {
        if (old_layout->all_vars[i].slot > max_old_slot) max_old_slot = old_layout->all_vars[i].slot;
    }
    for (int j = 0; j < new_layout->all_var_count; j++) {
        const go_storage_var_t *nv = &new_layout->all_vars[j];
        bool is_new = true;
        for (int i = 0; i < old_layout->all_var_count; i++) {
            if (strcmp(old_layout->all_vars[i].name, nv->name) == 0) { is_new = false; break; }
        }
        if (is_new && nv->slot <= max_old_slot && max_old_slot >= 0) {
            if (conflict_desc) {
                snprintf(conflict_desc, desc_len,
                         "New var '%s' at slot %d overlaps old layout (slots 0-%d). Append after slot %d.",
                         nv->name, nv->slot, max_old_slot, max_old_slot + 1);
            }
            return false;
        }
    }
    return true;
}

void go_add_suggestion(go_analyzer_t *g, go_suggestion_type_t type, int line,
                        const char *desc, uint64_t gas_saved,
                        const char *before, const char *after) {
    if (g->suggestion_count >= GO_MAX_SUGGESTIONS) return;
    go_suggestion_t *s = &g->suggestions[g->suggestion_count];
    s->type = type;
    s->line = line;
    strncpy(s->description, desc, 255);
    s->description[255] = '\0';
    s->estimated_gas_saved = gas_saved;
    strncpy(s->before_snippet, before, 127);
    s->before_snippet[127] = '\0';
    strncpy(s->after_snippet, after, 127);
    s->after_snippet[127] = '\0';
    g->suggestion_count++;
    g->total_gas_saved += gas_saved;
}

void go_print_report(const go_analyzer_t *g) {
    printf("\n========== Gas Optimization Report ==========\n");
    printf("Storage slots analyzed:  %d\n", g->storage_slot_count);
    printf("Variables registered:    %d\n", g->all_var_count);
    printf("Suggestions:             %d\n", g->suggestion_count);
    printf("Total gas saved (est):   %llu\n", (unsigned long long)g->total_gas_saved);
    printf("EIP-1559 base fee:       %llu gwei\n", (unsigned long long)g->fee_model.base_fee_per_gas);
    if (g->storage_slot_count > 0) {
        printf("\n--- Storage Layout ---\n");
        for (int i = 0; i < g->storage_slot_count; i++) {
            const go_storage_slot_t *sl = &g->storage_layout[i];
            printf("  Slot %d: %d/32 bytes used, %d wasted, %d var(s) [%s]\n",
                   sl->slot_id, sl->used_bytes, sl->wasted_bytes, sl->var_count,
                   sl->is_fully_packed ? "packed" : "sparse");
            for (int j = 0; j < sl->var_count; j++) {
                printf("    %-28s offset=%-2d size=%-2d %s\n",
                       sl->vars[j].name, sl->vars[j].offset_bytes, sl->vars[j].size_bytes,
                       sl->vars[j].is_packed ? "(packed)" : "");
            }
        }
    }
    if (g->suggestion_count > 0) {
        printf("\n--- Optimization Suggestions ---\n");
        static const char *type_names[] = {
            "PACK_VARS", "CACHE_SLOAD", "REMOVE_DEAD", "HOIST_INVARIANT",
            "REPLACE_OPCODE", "USE_IMMUTABLE", "USE_CONSTANT", "UNCHECKED_BLOCK",
            "SHORT_CIRCUIT", "BATCH_SSTORE", "INLINE_SMALL", "AVOID_ZERO_SSTORE",
            "USE_CALLDATA"
        };
        for (int i = 0; i < g->suggestion_count; i++) {
            const go_suggestion_t *s = &g->suggestions[i];
            printf("  [%d] %-18s L%d | saved:~%-8llu | %s -> %s\n",
                   i + 1, type_names[s->type], s->line,
                   (unsigned long long)s->estimated_gas_saved,
                   s->before_snippet, s->after_snippet);
            printf("       %s\n", s->description);
        }
    }
    if (g->loop_count > 0) {
        printf("\n--- Loop Analysis ---\n");
        for (int i = 0; i < g->loop_count; i++) {
            const go_loop_info_t *lp = &g->loops[i];
            printf("  Loop %d: header=%d latch=%d exit=%d body=%d sections gas/iter=%llu inv_sloads=%d\n",
                   lp->loop_id, lp->header_pc, lp->latch_pc, lp->exit_pc,
                   lp->body_count, (unsigned long long)lp->estimated_gas_per_iter, lp->invariant_count);
        }
    }
    printf("==============================================\n");
}

int go_total_gas_saved(const go_analyzer_t *g) {
    return (int)g->total_gas_saved;
}

bool go_is_fully_optimized(const go_analyzer_t *g) {
    for (int i = 0; i < g->storage_slot_count; i++) {
        if (!g->storage_layout[i].is_fully_packed) return false;
    }
    return g->suggestion_count == 0;
}
