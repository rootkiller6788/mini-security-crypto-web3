#ifndef GAS_OPTIMIZER_H
#define GAS_OPTIMIZER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define GO_MAX_VARS          128
#define GO_MAX_SUGGESTIONS    64
#define GO_MAX_STORAGE_SLOTS  64
#define GO_MAX_CODE_SECTIONS  256
#define GO_MAX_LOOPS          32
#define GO_FUNC_NAME_MAX      64

/* L4: EIP-1559 Fee Market Model
 * Introduced in Ethereum London Hard Fork (August 2021).
 * Replaces first-price auction with base fee + tip.
 * Reference: https://eips.ethereum.org/EIPS/eip-1559 */
typedef struct {
    uint64_t base_fee_per_gas;
    uint64_t max_priority_fee;
    uint64_t max_fee_per_gas;
} go_eip1559_fee_t;

/* L1: Variable types for storage layout analysis */
typedef enum {
    GO_VAR_UINT8     = 0,
    GO_VAR_UINT16    = 1,
    GO_VAR_UINT32    = 2,
    GO_VAR_UINT64    = 3,
    GO_VAR_UINT128   = 4,
    GO_VAR_UINT256   = 5,
    GO_VAR_INT8      = 6,
    GO_VAR_INT16     = 7,
    GO_VAR_INT32     = 8,
    GO_VAR_INT64     = 9,
    GO_VAR_INT128    = 10,
    GO_VAR_INT256    = 11,
    GO_VAR_BOOL      = 12,
    GO_VAR_ADDRESS   = 13,
    GO_VAR_BYTES1    = 14,
    GO_VAR_BYTES32   = 15,
    GO_VAR_STRING    = 16,
    GO_VAR_BYTES     = 17,
    GO_VAR_ARRAY     = 18,
    GO_VAR_MAPPING   = 19,
    GO_VAR_STRUCT    = 20
} go_var_type_t;

typedef struct {
    char            name[GO_FUNC_NAME_MAX];
    go_var_type_t   type;
    int             slot;
    int             offset_bytes;
    int             size_bytes;
    bool            is_packed;
} go_storage_var_t;

typedef struct {
    int             slot_id;
    go_storage_var_t vars[8];
    int             var_count;
    int             used_bytes;
    int             wasted_bytes;
    bool            is_fully_packed;
} go_storage_slot_t;

/* L5: Suggestion types - each maps to a specific optimization pattern */
typedef enum {
    GO_SUGGEST_PACK_VARS       = 0,
    GO_SUGGEST_CACHE_SLOAD     = 1,
    GO_SUGGEST_REMOVE_DEAD     = 2,
    GO_SUGGEST_HOIST_INVARIANT = 3,
    GO_SUGGEST_REPLACE_OPCODE  = 4,
    GO_SUGGEST_USE_IMMUTABLE   = 5,
    GO_SUGGEST_USE_CONSTANT    = 6,
    GO_SUGGEST_UNCHECKED_BLOCK = 7,
    GO_SUGGEST_SHORT_CIRCUIT   = 8,
    GO_SUGGEST_BATCH_SSTORE    = 9,
    GO_SUGGEST_INLINE_SMALL    = 10,
    GO_SUGGEST_AVOID_ZERO_SSTORE = 11,
    GO_SUGGEST_USE_CALLDATA    = 12
} go_suggestion_type_t;

typedef struct {
    go_suggestion_type_t type;
    int             line;
    char            description[256];
    uint64_t        estimated_gas_saved;
    char            before_snippet[128];
    char            after_snippet[128];
} go_suggestion_t;

typedef enum {
    GO_SECT_REACHABLE   = 0,
    GO_SECT_UNREACHABLE = 1,
    GO_SECT_RECURSIVE   = 2,
    GO_SECT_ENTRY       = 3,
    GO_SECT_REVERT_ONLY = 4
} go_sect_status_t;

typedef struct {
    int             section_id;
    int             start_pc;
    int             end_pc;
    go_sect_status_t status;
    int             predecessors[8];
    int             pred_count;
    int             successors[8];
    int             succ_count;
    uint64_t        gas_cost;
    int             sstore_count;
    int             sload_count;
} go_code_section_t;

typedef struct {
    int             loop_id;
    int             header_pc;
    int             latch_pc;
    int             exit_pc;
    int             body_sections[32];
    int             body_count;
    bool            has_invariant_sload;
    int             invariant_slots[16];
    int             invariant_count;
    uint64_t        estimated_gas_per_iter;
} go_loop_info_t;

typedef struct {
    go_storage_slot_t   storage_layout[GO_MAX_STORAGE_SLOTS];
    int                 storage_slot_count;
    go_storage_var_t    all_vars[GO_MAX_VARS];
    int                 all_var_count;
    go_suggestion_t     suggestions[GO_MAX_SUGGESTIONS];
    int                 suggestion_count;
    go_code_section_t   code_sections[GO_MAX_CODE_SECTIONS];
    int                 code_section_count;
    go_loop_info_t      loops[GO_MAX_LOOPS];
    int                 loop_count;
    go_eip1559_fee_t    fee_model;
    uint64_t            total_gas_estimated;
    uint64_t            total_gas_saved;
    bool                is_optimized;
} go_analyzer_t;

void go_init(go_analyzer_t *g);
void go_reset(go_analyzer_t *g);

uint64_t go_eip1559_effective_gas(const go_eip1559_fee_t *fee);

int  go_register_variable(go_analyzer_t *g, const char *name,
                           go_var_type_t type, int size_bytes);
void go_analyze_storage_packing(go_analyzer_t *g);

int  go_detect_redundant_sload(go_analyzer_t *g, const int *sload_slots,
                                int sload_count, const int *sstore_slots,
                                int sstore_count);
int  go_detect_loop_invariant_sload(go_analyzer_t *g, go_loop_info_t *loop,
                                     const int *body_sloads, int body_sload_count);
int  go_detect_dead_code(go_analyzer_t *g, const uint8_t *bytecode,
                          size_t code_len, int entry_pc);
uint64_t go_estimate_section_gas(go_analyzer_t *g, const uint8_t *code,
                                  int start_pc, int end_pc);
int  go_detect_sstore_zero_opportunities(go_analyzer_t *g,
                                          const uint8_t *code, size_t code_len);
bool go_can_use_unchecked(uint64_t a, uint64_t b, char op);

void go_add_suggestion(go_analyzer_t *g, go_suggestion_type_t type, int line,
                        const char *desc, uint64_t gas_saved,
                        const char *before, const char *after);
void go_print_report(const go_analyzer_t *g);
int  go_total_gas_saved(const go_analyzer_t *g);
bool go_is_fully_optimized(const go_analyzer_t *g);

bool go_check_upgrade_compatible(const go_analyzer_t *old_layout,
                                  const go_analyzer_t *new_layout,
                                  char *conflict_desc, size_t desc_len);

#endif
