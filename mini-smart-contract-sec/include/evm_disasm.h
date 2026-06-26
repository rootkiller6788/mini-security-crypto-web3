#ifndef EVM_DISASM_H
#define EVM_DISASM_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define DISASM_MAX_INSTRS   65536
#define DISASM_MAX_BLOCKS   4096
#define DISASM_MAX_EDGES    8192
#define DISASM_MNEMONIC_MAX 32
#define DISASM_MAX_BYTECODE 65536

/* L1: Disassembled instruction representation
 * Each EVM instruction decoded from bytecode with opcode, mnemonic,
 * and optional immediate data (for PUSH operations). */
typedef struct {
    int         offset;       /* PC offset in bytecode */
    uint8_t     opcode;       /* raw EVM opcode byte */
    char        mnemonic[DISASM_MNEMONIC_MAX];
    uint8_t     immediate[32];
    int         imm_len;      /* length of immediate data (PUSH1..PUSH32) */
    bool        is_jumpdest;  /* true if this position is a JUMPDEST */
    bool        is_terminator; /* STOP/RETURN/REVERT/INVALID/SELFDESTRUCT */
} disasm_instr_t;

/* L1: Basic block: a sequence of instructions with single entry, single exit.
 * Entry is either: function start, JUMPDEST target, or fallthrough from branch.
 * Exit is either: JUMP, JUMPI, STOP, RETURN, REVERT, INVALID, or SELFDESTRUCT. */
typedef struct {
    int         block_id;
    int         start_offset;
    int         end_offset;     /* inclusive */
    int         instr_count;
    int         instr_ids[DISASM_MAX_INSTRS];
    int         successors[4];
    int         succ_count;
    bool        is_entry_block;
    bool        is_exit_block;
    uint64_t    block_gas;
} disasm_block_t;

/* L1: Control flow graph edge */
typedef struct {
    int         from_block;
    int         to_block;
    bool        is_conditional;  /* true if JUMPI edge */
    bool        is_dynamic;      /* true if JUMP (dynamic target) */
} disasm_edge_t;

/* L1: Full disassembly output */
typedef struct {
    disasm_instr_t  instructions[DISASM_MAX_INSTRS];
    int             instr_count;
    disasm_block_t  blocks[DISASM_MAX_BLOCKS];
    int             block_count;
    disasm_edge_t   edges[DISASM_MAX_EDGES];
    int             edge_count;
    char            error[256];
    bool            valid;
} disasm_ctx_t;

/* L3: Decode a single EVM opcode at the given offset.
 * Returns the number of bytes consumed (1 for most opcodes, 1+N for PUSH).
 * Sets the mnemonic string and extracts immediate data. */
int  disasm_decode_one(const uint8_t *bytecode, size_t code_len,
                        int offset, disasm_instr_t *out);

/* L5: Full bytecode disassembly
 * Iterates over bytecode, decoding each instruction and tracking
 * JUMPDEST positions. Constructs a linear instruction list. */
int  disasm_full(const uint8_t *bytecode, size_t code_len,
                  disasm_ctx_t *ctx);

/* L5: Build basic blocks from linear instruction stream.
 * Algorithm:
 * 1. Identify block leaders: offset 0, JUMPDEST targets, and instructions
 *    after JUMP/JUMPI/terminators.
 * 2. Each block spans from its leader to the next leader (exclusive).
 * 3. Classify blocks by their exit type.
 *
 * Reference: Aho, Lam, Sethi, Ullman, Section 8.4 "Basic Blocks".
 * Complexity: O(n) where n = number of instructions. */
int  disasm_build_blocks(disasm_ctx_t *ctx);

/* L5: Build control flow edges between basic blocks.
 * For each block:
 * - If exit is JUMPI: edges to next block (false) and target (true).
 * - If exit is JUMP: edge to target (dynamic if not PUSH-immediate).
 * - If exit is fallthrough (non-terminator): edge to next block.
 * - Use the JUMPDEST attribute to resolve static jump targets.
 *
 * Complexity: O(n + e) where n = blocks, e = edges. */
int  disasm_build_edges(disasm_ctx_t *ctx);

/* L5: Compute gas cost for each basic block.
 * Sums per-opcode gas costs using the EVM gas schedule.
 * Accounts for PUSH immediate bytes. */
void disasm_compute_block_gas(disasm_ctx_t *ctx);

/* L7: Pretty-print disassembly output */
void disasm_print(const disasm_ctx_t *ctx);
void disasm_print_blocks(const disasm_ctx_t *ctx);
void disasm_print_summary(const disasm_ctx_t *ctx);

/* L8: Detect potential jump destinations that cannot be resolved
 * statically (dynamic jumps from user input). Reports them as
 * security concern since dynamic jumps make static analysis harder. */
int  disasm_find_dynamic_jumps(const disasm_ctx_t *ctx);

/* L8: Compute the code coverage profile: which blocks are guaranteed
 * to be reachable based on static analysis alone. Unreachable blocks
 * may indicate dead code or obfuscation. */
int  disasm_reachable_blocks(const disasm_ctx_t *ctx, bool *reachable);

/* EVM mnemonic table - maps opcode byte to human-readable string */
const char *disasm_mnemonic(uint8_t opcode);
/* Returns the number of immediate bytes for PUSH opcodes */
int disasm_push_bytes(uint8_t opcode);
/* Returns true if the opcode terminates execution */
bool disasm_is_terminator(uint8_t opcode);

#endif
