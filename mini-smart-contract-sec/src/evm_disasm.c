#include "evm_disasm.h"
#include <stdio.h>
#include <string.h>

/* ================================================================
 * L2: Complete EVM opcode mnemonic table
 *
 * Maps each EVM opcode byte to its human-readable mnemonic string.
 * Based on the Ethereum Yellow Paper (Berlin version), Appendix H.
 * Unused/undefined opcodes return "INVALID".
 * ================================================================ */
const char *disasm_mnemonic(uint8_t opcode) {
    switch (opcode) {
    case 0x00: return "STOP";
    case 0x01: return "ADD";
    case 0x02: return "MUL";
    case 0x03: return "SUB";
    case 0x04: return "DIV";
    case 0x05: return "SDIV";
    case 0x06: return "MOD";
    case 0x07: return "SMOD";
    case 0x08: return "ADDMOD";
    case 0x09: return "MULMOD";
    case 0x0a: return "EXP";
    case 0x0b: return "SIGNEXTEND";
    case 0x10: return "LT";
    case 0x11: return "GT";
    case 0x12: return "SLT";
    case 0x13: return "SGT";
    case 0x14: return "EQ";
    case 0x15: return "ISZERO";
    case 0x16: return "AND";
    case 0x17: return "OR";
    case 0x18: return "XOR";
    case 0x19: return "NOT";
    case 0x1a: return "BYTE";
    case 0x1b: return "SHL";
    case 0x1c: return "SHR";
    case 0x1d: return "SAR";
    case 0x20: return "SHA3";
    case 0x30: return "ADDRESS";
    case 0x31: return "BALANCE";
    case 0x32: return "ORIGIN";
    case 0x33: return "CALLER";
    case 0x34: return "CALLVALUE";
    case 0x35: return "CALLDATALOAD";
    case 0x36: return "CALLDATASIZE";
    case 0x37: return "CALLDATACOPY";
    case 0x38: return "CODESIZE";
    case 0x39: return "CODECOPY";
    case 0x3a: return "GASPRICE";
    case 0x3b: return "EXTCODESIZE";
    case 0x3c: return "EXTCODECOPY";
    case 0x3d: return "RETURNDATASIZE";
    case 0x3e: return "RETURNDATACOPY";
    case 0x3f: return "EXTCODEHASH";
    case 0x40: return "BLOCKHASH";
    case 0x41: return "COINBASE";
    case 0x42: return "TIMESTAMP";
    case 0x43: return "NUMBER";
    case 0x44: return "DIFFICULTY";
    case 0x45: return "GASLIMIT";
    case 0x46: return "CHAINID";
    case 0x47: return "SELFBALANCE";
    case 0x48: return "BASEFEE";
    case 0x50: return "POP";
    case 0x51: return "MLOAD";
    case 0x52: return "MSTORE";
    case 0x53: return "MSTORE8";
    case 0x54: return "SLOAD";
    case 0x55: return "SSTORE";
    case 0x56: return "JUMP";
    case 0x57: return "JUMPI";
    case 0x58: return "PC";
    case 0x59: return "MSIZE";
    case 0x5a: return "GAS";
    case 0x5b: return "JUMPDEST";
    case 0xf0: return "CREATE";
    case 0xf1: return "CALL";
    case 0xf2: return "CALLCODE";
    case 0xf3: return "RETURN";
    case 0xf4: return "DELEGATECALL";
    case 0xf5: return "CREATE2";
    case 0xfa: return "STATICCALL";
    case 0xfd: return "REVERT";
    case 0xfe: return "INVALID";
    case 0xff: return "SELFDESTRUCT";
    default:
        if (opcode >= 0x60 && opcode <= 0x7f) return "PUSH";
        if (opcode >= 0x80 && opcode <= 0x8f) return "DUP";
        if (opcode >= 0x90 && opcode <= 0x9f) return "SWAP";
        if (opcode >= 0xa0 && opcode <= 0xa4) return "LOG";
        return "INVALID";
    }
}

/* ================================================================
 * L5: PUSH immediate byte count
 * ================================================================ */
int disasm_push_bytes(uint8_t opcode) {
    if (opcode >= 0x60 && opcode <= 0x7f) {
        return opcode - 0x60 + 1;
    }
    return 0;
}

/* ================================================================
 * L5: Terminator detection
 * ================================================================ */
bool disasm_is_terminator(uint8_t opcode) {
    return (opcode == 0x00 || opcode == 0xf3 ||
            opcode == 0xfd || opcode == 0xfe || opcode == 0xff);
}

/* ================================================================
 * L3: Single instruction decoder
 *
 * Decodes one EVM instruction at bytecode[offset].
 * Handles:
 * - Normal opcodes (1 byte)
 * - PUSH1..PUSH32 (1 + N bytes, N=1..32)
 * - Determines mnemonic string
 * - Extracts immediate data for PUSH operations
 *
 * Returns the total number of bytes consumed by this instruction,
 * or 0 if the offset is invalid.
 * ================================================================ */
int disasm_decode_one(const uint8_t *bytecode, size_t code_len,
                       int offset, disasm_instr_t *out) {
    if (offset < 0 || (size_t)offset >= code_len || !out) return 0;

    memset(out, 0, sizeof(disasm_instr_t));
    out->offset = offset;
    out->opcode = bytecode[offset];

    const char *mnem = disasm_mnemonic(out->opcode);

    /* Format PUSH/DUP/SWAP with their number suffix */
    if (out->opcode >= 0x60 && out->opcode <= 0x7f) {
        snprintf(out->mnemonic, DISASM_MNEMONIC_MAX,
                 "PUSH%d", out->opcode - 0x60 + 1);
    } else if (out->opcode >= 0x80 && out->opcode <= 0x8f) {
        snprintf(out->mnemonic, DISASM_MNEMONIC_MAX,
                 "DUP%d", out->opcode - 0x80 + 1);
    } else if (out->opcode >= 0x90 && out->opcode <= 0x9f) {
        snprintf(out->mnemonic, DISASM_MNEMONIC_MAX,
                 "SWAP%d", out->opcode - 0x90 + 1);
    } else if (out->opcode >= 0xa0 && out->opcode <= 0xa4) {
        snprintf(out->mnemonic, DISASM_MNEMONIC_MAX,
                 "LOG%d", out->opcode - 0xa0);
    } else {
        strncpy(out->mnemonic, mnem, DISASM_MNEMONIC_MAX - 1);
        out->mnemonic[DISASM_MNEMONIC_MAX - 1] = '\0';
    }

    out->is_jumpdest = (out->opcode == 0x5b);
    out->is_terminator = disasm_is_terminator(out->opcode);

    /* Extract immediate data for PUSH opcodes */
    int push_len = disasm_push_bytes(out->opcode);
    out->imm_len = push_len;
    if (push_len > 0) {
        int available = (int)code_len - offset - 1;
        int to_copy = push_len < available ? push_len : available;
        if (to_copy > 0) {
            memcpy(out->immediate, bytecode + offset + 1, (size_t)to_copy);
        }
    }

    return 1 + push_len;
}

/* ================================================================
 * L5: Full bytecode disassembly
 *
 * Walks through bytecode linearly, decoding each instruction.
 * Tracks JUMPDEST positions for later CFG construction.
 *
 * Complexity: O(n) where n = code length in bytes.
 * ================================================================ */
int disasm_full(const uint8_t *bytecode, size_t code_len,
                 disasm_ctx_t *ctx) {
    memset(ctx, 0, sizeof(disasm_ctx_t));
    ctx->valid = false;

    if (!bytecode || code_len == 0) {
        snprintf(ctx->error, sizeof(ctx->error), "empty bytecode");
        return 0;
    }

    int offset = 0;
    while (offset < (int)code_len && ctx->instr_count < DISASM_MAX_INSTRS) {
        disasm_instr_t instr;
        int consumed = disasm_decode_one(bytecode, code_len, offset, &instr);
        if (consumed <= 0) {
            snprintf(ctx->error, sizeof(ctx->error),
                     "decode error at offset %d", offset);
            break;
        }

        /* Check for opcode straddling end of bytecode (truncated PUSH) */
        if (consumed > 1 && offset + consumed > (int)code_len) {
            snprintf(ctx->error, sizeof(ctx->error),
                     "truncated PUSH at offset %d (need %d, have %d)",
                     offset, consumed, (int)(code_len - offset));
            /* Still record the partial instruction */
            ctx->instructions[ctx->instr_count] = instr;
            ctx->instr_count++;
            break;
        }

        ctx->instructions[ctx->instr_count] = instr;
        ctx->instr_count++;
        offset += consumed;
    }

    ctx->valid = (ctx->instr_count > 0);
    return ctx->instr_count;
}

/* ================================================================
 * L5: Basic block construction
 *
 * Algorithm (classic compiler construction):
 * 1. Identify block leaders:
 *    a. The first instruction (offset 0) is always a leader.
 *    b. Any instruction that is the target of a JUMP/JUMPI is a leader.
 *    c. Any instruction immediately following a JUMP/JUMPI/terminator
 *       is a leader (unless it is also a JUMPDEST target).
 *
 * 2. Each basic block consists of a leader and all subsequent
 *    instructions up to (but not including) the next leader.
 *
 * 3. The exit type of a block is determined by its last instruction.
 *
 * Reference: Aho, Sethi, Ullman, "Compilers" (1986), Chapter 9.
 * ================================================================ */
int disasm_build_blocks(disasm_ctx_t *ctx) {
    if (!ctx->valid || ctx->instr_count == 0) return 0;

    ctx->block_count = 0;
    ctx->edge_count = 0;

    /* Pass 1: Mark block leaders */
    bool is_leader[DISASM_MAX_INSTRS];
    memset(is_leader, 0, sizeof(is_leader));

    is_leader[0] = true; /* First instruction is always a leader */

    /* First pass: scan for JUMPDEST targets and terminator followers */
    for (int i = 0; i < ctx->instr_count; i++) {
        disasm_instr_t *instr = &ctx->instructions[i];

        /* JUMPDEST is always a leader (potential jump target) */
        if (instr->is_jumpdest) {
            is_leader[i] = true;
        }

        /* Instruction after a terminator is a leader */
        if (instr->is_terminator && i + 1 < ctx->instr_count) {
            /* Only if the next is reachable by someone */
            if (ctx->instructions[i + 1].is_jumpdest ||
                i + 1 < ctx->instr_count) {
                is_leader[i + 1] = true;
            }
        }

        /* After JUMP, next instruction is leader (reachable via JUMPI false) */
        if (instr->opcode == 0x56 && i + 1 < ctx->instr_count) {
            is_leader[i + 1] = true;
        }
    }

    /* Pass 2: Build blocks from leaders */
    int block_start = -1;
    for (int i = 0; i < ctx->instr_count; i++) {
        if (is_leader[i]) {
            /* Finish previous block */
            if (block_start >= 0 && ctx->block_count < DISASM_MAX_BLOCKS) {
                disasm_block_t *blk = &ctx->blocks[ctx->block_count - 1];
                blk->end_offset = ctx->instructions[i - 1].offset;
                blk->instr_count = i - block_start;
                for (int j = block_start; j < i; j++) {
                    blk->instr_ids[j - block_start] = j;
                }
            }
            /* Start new block */
            if (ctx->block_count >= DISASM_MAX_BLOCKS) break;
            disasm_block_t *blk = &ctx->blocks[ctx->block_count];
            blk->block_id = ctx->block_count;
            blk->start_offset = ctx->instructions[i].offset;
            blk->succ_count = 0;
            blk->is_entry_block = (ctx->block_count == 0);
            blk->is_exit_block = false;
            blk->block_gas = 0;
            ctx->block_count++;
            block_start = i;
        }
    }

    /* Finish the last block */
    if (block_start >= 0 && ctx->block_count > 0) {
        disasm_block_t *blk = &ctx->blocks[ctx->block_count - 1];
        int last = ctx->instr_count - 1;
        blk->end_offset = ctx->instructions[last].offset;
        blk->instr_count = ctx->instr_count - block_start;
        for (int j = block_start; j < ctx->instr_count; j++) {
            blk->instr_ids[j - block_start] = j;
        }
        /* Check if last instruction is a terminator */
        if (ctx->instructions[last].is_terminator) {
            blk->is_exit_block = true;
        }
    }

    return ctx->block_count;
}

/* ================================================================
 * L5: Control flow edge construction
 *
 * For each basic block, determine its outgoing edges:
 * - If the last instruction is JUMPI: edge to next block (false branch)
 *   and edge to jump target (true branch) if statically resolvable.
 * - If the last instruction is JUMP: dynamic edge (conservative).
 * - If the last instruction falls through (non-terminator, non-JUMP):
 *   edge to the next sequential block.
 * - For terminators (STOP/RETURN/REVERT/INVALID/SELFDESTRUCT): no edges.
 * ================================================================ */
int disasm_build_edges(disasm_ctx_t *ctx) {
    if (ctx->block_count == 0) return 0;

    ctx->edge_count = 0;

    for (int i = 0; i < ctx->block_count; i++) {
        disasm_block_t *blk = &ctx->blocks[i];
        if (blk->instr_count == 0) continue;

        /* Get last instruction of this block */
        int last_id = blk->instr_ids[blk->instr_count - 1];
        disasm_instr_t *last = &ctx->instructions[last_id];
        uint8_t last_op = last->opcode;

        /* Terminators: no outgoing edges */
        if (last->is_terminator) continue;

        /* JUMPI: conditional edge to next block (false) + target (true) */
        if (last_op == 0x57) {
            /* False branch: next sequential block */
            if (i + 1 < ctx->block_count && ctx->edge_count < DISASM_MAX_EDGES) {
                ctx->edges[ctx->edge_count].from_block = i;
                ctx->edges[ctx->edge_count].to_block = i + 1;
                ctx->edges[ctx->edge_count].is_conditional = false;
                ctx->edges[ctx->edge_count].is_dynamic = false;
                ctx->edge_count++;
                blk->succ_count++;
            }

            /* True branch: try to resolve static jump target */
            if (last->imm_len >= 1 && ctx->edge_count < DISASM_MAX_EDGES) {
                /* PUSH value is the target PC (stored in immediate) */
                int target_pc = 0;
                for (int b = 0; b < last->imm_len && b < 4; b++) {
                    target_pc = (target_pc << 8) | last->immediate[b];
                }
                /* Find which block contains this target offset */
                for (int j = 0; j < ctx->block_count; j++) {
                    if (ctx->blocks[j].start_offset == target_pc) {
                        ctx->edges[ctx->edge_count].from_block = i;
                        ctx->edges[ctx->edge_count].to_block = j;
                        ctx->edges[ctx->edge_count].is_conditional = true;
                        ctx->edges[ctx->edge_count].is_dynamic = false;
                        ctx->edge_count++;
                        blk->succ_count++;
                        break;
                    }
                }
            }
            continue;
        }

        /* JUMP: dynamic edge (conservative) */
        if (last_op == 0x56) {
            /* Mark as dynamic; no static edges possible */
            continue;
        }

        /* Fallthrough: edge to next sequential block */
        if (i + 1 < ctx->block_count && ctx->edge_count < DISASM_MAX_EDGES) {
            ctx->edges[ctx->edge_count].from_block = i;
            ctx->edges[ctx->edge_count].to_block = i + 1;
            ctx->edges[ctx->edge_count].is_conditional = false;
            ctx->edges[ctx->edge_count].is_dynamic = false;
            ctx->edge_count++;
            blk->succ_count++;
        }
    }

    return ctx->edge_count;
}

/* ================================================================
 * L5: Block gas computation using EVM gas schedule
 *
 * Sums the gas cost for each instruction in each block.
 * Uses the Berlin hard fork gas schedule.
 * ================================================================ */
void disasm_compute_block_gas(disasm_ctx_t *ctx) {
    static const uint64_t gas_table[256] = {
        [0x00]=0, [0x01]=3, [0x02]=5, [0x03]=3, [0x04]=5, [0x05]=5,
        [0x06]=5, [0x07]=5, [0x08]=8, [0x09]=8, [0x0a]=10, [0x0b]=5,
        [0x10]=3, [0x11]=3, [0x12]=3, [0x13]=3, [0x14]=3, [0x15]=3,
        [0x16]=3, [0x17]=3, [0x18]=3, [0x19]=3, [0x1a]=3,
        [0x1b]=3, [0x1c]=3, [0x1d]=3, [0x20]=30,
        [0x30]=2, [0x31]=400, [0x32]=2, [0x33]=2, [0x34]=2,
        [0x35]=3, [0x36]=2, [0x37]=3, [0x38]=2, [0x39]=3,
        [0x3a]=2, [0x3b]=700, [0x3c]=700, [0x3d]=2, [0x3e]=3,
        [0x3f]=700, [0x40]=20, [0x41]=2, [0x42]=2, [0x43]=2,
        [0x44]=2, [0x45]=2, [0x46]=2, [0x47]=5, [0x48]=2,
        [0x50]=2, [0x51]=3, [0x52]=3, [0x53]=3,
        [0x54]=2100, [0x55]=22100, [0x56]=8, [0x57]=10,
        [0x58]=2, [0x59]=2, [0x5a]=2, [0x5b]=1,
        [0xf0]=32000, [0xf1]=700, [0xf2]=700, [0xf3]=0,
        [0xf4]=700, [0xf5]=32000, [0xfa]=40,
        [0xfd]=0, [0xfe]=0, [0xff]=5000
    };

    for (int i = 0; i < ctx->block_count; i++) {
        disasm_block_t *blk = &ctx->blocks[i];
        blk->block_gas = 0;
        for (int j = 0; j < blk->instr_count; j++) {
            int instr_id = blk->instr_ids[j];
            uint8_t op = ctx->instructions[instr_id].opcode;
            uint64_t g = gas_table[op];
            if (g == 0 && op != 0x00 && op != 0xf3 && op != 0xfd && op != 0xfe) {
                g = 3; /* default for PUSH/DUP/SWAP/LOG/etc */
            }
            blk->block_gas += g;
        }
    }
}

/* ================================================================
 * L8: Dynamic jump detection
 *
 * Dynamic jumps (where the target is computed at runtime, not from
 * a PUSH immediate) make static analysis harder. They can be used
 * for obfuscation or to hide control flow from analyzers.
 *
 * Returns count of blocks ending with unresolved dynamic JUMP.
 * ================================================================ */
int disasm_find_dynamic_jumps(const disasm_ctx_t *ctx) {
    int count = 0;
    for (int i = 0; i < ctx->block_count; i++) {
        const disasm_block_t *blk = &ctx->blocks[i];
        if (blk->instr_count == 0) continue;
        int last_id = blk->instr_ids[blk->instr_count - 1];
        if (ctx->instructions[last_id].opcode == 0x56 &&
            ctx->instructions[last_id].imm_len == 0) {
            count++;
        }
    }
    return count;
}

/* ================================================================
 * L8: Reachable blocks analysis
 *
 * BFS from entry block to determine which blocks are statically
 * reachable. Unreachable blocks may indicate dead code.
 *
 * Writes true/false to reachable[] array.
 * Returns the number of reachable blocks.
 * ================================================================ */
int disasm_reachable_blocks(const disasm_ctx_t *ctx, bool *reachable) {
    if (ctx->block_count == 0) return 0;

    memset(reachable, 0, (size_t)ctx->block_count * sizeof(bool));
    int queue[DISASM_MAX_BLOCKS];
    int head = 0, tail = 0;

    queue[tail++] = 0; /* Start from entry block */
    reachable[0] = true;
    int count = 1;

    while (head < tail) {
        int b = queue[head++];

        for (int e = 0; e < ctx->edge_count; e++) {
            if (ctx->edges[e].from_block == b) {
                int to = ctx->edges[e].to_block;
                if (!reachable[to]) {
                    reachable[to] = true;
                    queue[tail++] = to;
                    if (tail >= DISASM_MAX_BLOCKS) tail = 0;
                    count++;
                }
            }
        }
    }

    return count;
}

/* ================================================================
 * L7: Disassembly pretty-printing
 * ================================================================ */
void disasm_print(const disasm_ctx_t *ctx) {
    printf("\n========== EVM Disassembly (%d instructions) ==========\n",
           ctx->instr_count);
    if (!ctx->valid) {
        printf("ERROR: %s\n", ctx->error);
        return;
    }
    for (int i = 0; i < ctx->instr_count; i++) {
        const disasm_instr_t *in = &ctx->instructions[i];
        printf("  %04x: %02x %-16s", in->offset, in->opcode, in->mnemonic);
        if (in->imm_len > 0) {
            printf(" 0x");
            for (int j = 0; j < in->imm_len && j < 8; j++) {
                printf("%02x", in->immediate[j]);
            }
            if (in->imm_len > 8) printf("...");
        }
        if (in->is_jumpdest) printf("  <= JUMPDEST");
        if (in->is_terminator) printf("  *");
        printf("\n");
    }
    printf("=========================================================\n");
}

void disasm_print_blocks(const disasm_ctx_t *ctx) {
    printf("\n========== Basic Blocks (%d blocks) ==========\n",
           ctx->block_count);
    for (int i = 0; i < ctx->block_count; i++) {
        const disasm_block_t *blk = &ctx->blocks[i];
        printf("  B%-3d: %04x-%04x  %d instrs  gas=%llu",
               blk->block_id, blk->start_offset, blk->end_offset,
               blk->instr_count, (unsigned long long)blk->block_gas);
        if (blk->is_entry_block) printf(" [ENTRY]");
        if (blk->is_exit_block) printf(" [EXIT]");
        printf("\n");
        /* Print edges */
        for (int e = 0; e < ctx->edge_count; e++) {
            if (ctx->edges[e].from_block == i) {
                printf("    -> B%d%s\n",
                       ctx->edges[e].to_block,
                       ctx->edges[e].is_conditional ? " (cond)" : "");
            }
        }
    }
    printf("==================================================\n");
}

void disasm_print_summary(const disasm_ctx_t *ctx) {
    printf("\n========== Disassembly Summary ==========\n");
    printf("Total instructions:    %d\n", ctx->instr_count);
    printf("Basic blocks:          %d\n", ctx->block_count);
    printf("Control flow edges:    %d\n", ctx->edge_count);
    printf("Dynamic jumps:         %d\n", disasm_find_dynamic_jumps(ctx));

    int push_count = 0, term_count = 0, jumpdest_count = 0;
    for (int i = 0; i < ctx->instr_count; i++) {
        uint8_t op = ctx->instructions[i].opcode;
        if (op >= 0x60 && op <= 0x7f) push_count++;
        if (disasm_is_terminator(op)) term_count++;
        if (op == 0x5b) jumpdest_count++;
    }
    printf("PUSH instructions:     %d\n", push_count);
    printf("Terminators:           %d\n", term_count);
    printf("JUMPDEST markers:      %d\n", jumpdest_count);

    /* Reachability analysis */
    bool reachable[DISASM_MAX_BLOCKS];
    int reached = disasm_reachable_blocks(ctx, reachable);
    int unreachable = ctx->block_count - reached;
    if (unreachable > 0) {
        printf("Unreachable blocks:    %d (potentially dead code)\n", unreachable);
    }
    printf("==========================================\n");
}
