#include "evm_sim.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

const uint64_t GAS_COST[256] = {
    [OP_STOP]         = GAS_ZERO,
    [OP_ADD]          = GAS_VERYLOW,
    [OP_MUL]          = GAS_LOW,
    [OP_SUB]          = GAS_VERYLOW,
    [OP_DIV]          = GAS_LOW,
    [OP_SDIV]         = GAS_LOW,
    [OP_MOD]          = GAS_LOW,
    [OP_SMOD]         = GAS_LOW,
    [OP_ADDMOD]       = GAS_MID,
    [OP_MULMOD]       = GAS_MID,
    [OP_EXP]          = GAS_HIGH,
    [OP_LT]           = GAS_VERYLOW,
    [OP_GT]           = GAS_VERYLOW,
    [OP_SLT]          = GAS_VERYLOW,
    [OP_SGT]          = GAS_VERYLOW,
    [OP_EQ]           = GAS_VERYLOW,
    [OP_ISZERO]       = GAS_VERYLOW,
    [OP_AND]          = GAS_VERYLOW,
    [OP_OR]           = GAS_VERYLOW,
    [OP_XOR]          = GAS_VERYLOW,
    [OP_NOT]          = GAS_VERYLOW,
    [OP_SHL]          = GAS_VERYLOW,
    [OP_SHR]          = GAS_VERYLOW,
    [OP_SHA3]         = 30,
    [OP_ADDRESS]      = GAS_BASE,
    [OP_BALANCE]      = 400,
    [OP_ORIGIN]       = GAS_BASE,
    [OP_CALLER]       = GAS_BASE,
    [OP_CALLVALUE]    = GAS_BASE,
    [OP_CALLDATALOAD] = GAS_VERYLOW,
    [OP_CALLDATASIZE] = GAS_BASE,
    [OP_CALLDATACOPY] = GAS_VERYLOW,
    [OP_CODESIZE]     = GAS_BASE,
    [OP_CODECOPY]     = GAS_VERYLOW,
    [OP_EXTCODESIZE]  = 700,
    [OP_EXTCODECOPY]  = 700,
    [OP_MLOAD]        = GAS_VERYLOW,
    [OP_MSTORE]       = GAS_VERYLOW,
    [OP_MSTORE8]      = GAS_VERYLOW,
    [OP_SLOAD]        = GAS_SLOAD,
    [OP_SSTORE]       = GAS_SSTORE_SET,
    [OP_JUMP]         = GAS_MID,
    [OP_JUMPI]        = GAS_HIGH,
    [OP_PC]           = GAS_BASE,
    [OP_MSIZE]        = GAS_BASE,
    [OP_GAS]          = GAS_BASE,
    [OP_JUMPDEST]     = GAS_BASE,
    [OP_RETURN]       = GAS_ZERO,
    [OP_DELEGATECALL] = 700,
    [OP_CREATE]       = GAS_CREATE,
    [OP_CALL]         = GAS_CALL,
    [OP_CALLCODE]     = 700,
    [OP_REVERT]       = GAS_ZERO,
    [OP_SELFDESTRUCT] = GAS_SELFDESTRUCT
};

void uint256_zero(uint256_t *v) {
    v->w[0] = v->w[1] = v->w[2] = v->w[3] = 0;
}

void uint256_set64(uint256_t *v, uint64_t x) {
    v->w[0] = x;
    v->w[1] = v->w[2] = v->w[3] = 0;
}

int uint256_cmp(const uint256_t *a, const uint256_t *b) {
    for (int i = 3; i >= 0; i--) {
        if (a->w[i] > b->w[i]) return 1;
        if (a->w[i] < b->w[i]) return -1;
    }
    return 0;
}

bool uint256_is_zero(const uint256_t *v) {
    return v->w[0] == 0 && v->w[1] == 0 && v->w[2] == 0 && v->w[3] == 0;
}

void uint256_add(uint256_t *r, const uint256_t *a, const uint256_t *b) {
    uint64_t carry = 0;
    for (int i = 0; i < 4; i++) {
        uint64_t sum = a->w[i] + b->w[i] + carry;
        carry = (sum < a->w[i] || (carry && sum == a->w[i])) ? 1 : 0;
        r->w[i] = sum;
    }
}

void uint256_sub(uint256_t *r, const uint256_t *a, const uint256_t *b) {
    uint64_t borrow = 0;
    for (int i = 0; i < 4; i++) {
        uint64_t diff = a->w[i] - b->w[i] - borrow;
        borrow = (a->w[i] < b->w[i] + borrow) ? 1 : 0;
        r->w[i] = diff;
    }
}

void uint256_mul(uint256_t *r, const uint256_t *a, const uint256_t *b) {
    uint64_t result[8] = {0};
    for (int i = 0; i < 4; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < 4; j++) {
            __uint128_t product = (__uint128_t)a->w[j] * b->w[i] + result[i + j] + carry;
            result[i + j] = (uint64_t)product;
            carry = (uint64_t)(product >> 64);
        }
        result[i + 4] = carry;
    }
    for (int i = 0; i < 4; i++) r->w[i] = result[i];
}

void uint256_from_bytes(uint256_t *v, const uint8_t *b, size_t len) {
    uint256_zero(v);
    size_t n = len > 32 ? 32 : len;
    for (size_t i = 0; i < n; i++) {
        int byte_pos = (int)(31 - i);
        int word = byte_pos / 8;
        int shift = (byte_pos % 8) * 8;
        v->w[word] |= ((uint64_t)b[i]) << shift;
    }
}

void uint256_to_bytes(const uint256_t *v, uint8_t *b, size_t len) {
    for (size_t i = 0; i < 32 && i < len; i++) {
        int byte_pos = (int)(31 - i);
        int word = byte_pos / 8;
        int shift = (byte_pos % 8) * 8;
        b[i] = (uint8_t)((v->w[word] >> shift) & 0xFF);
    }
}

void uint256_print(const uint256_t *v) {
    printf("0x%016llx%016llx%016llx%016llx",
           (unsigned long long)v->w[3], (unsigned long long)v->w[2],
           (unsigned long long)v->w[1], (unsigned long long)v->w[0]);
}

void stack_push(evm_stack_t *s, const uint256_t *v) {
    if (s->sp >= EVM_STACK_MAX) {
        fprintf(stderr, "EVM: stack overflow\n");
        return;
    }
    s->data[s->sp] = *v;
    s->sp++;
}

void stack_pop(evm_stack_t *s, uint256_t *v) {
    if (s->sp <= 0) {
        fprintf(stderr, "EVM: stack underflow\n");
        uint256_zero(v);
        return;
    }
    s->sp--;
    *v = s->data[s->sp];
}

void stack_dup(evm_stack_t *s, int n) {
    if (s->sp < n) {
        fprintf(stderr, "EVM: DUP underflow (need %d, have %d)\n", n, s->sp);
        return;
    }
    stack_push(s, &s->data[s->sp - n]);
}

void stack_swap(evm_stack_t *s, int n) {
    if (s->sp < n + 1) return;
    uint256_t tmp = s->data[s->sp - 1];
    s->data[s->sp - 1] = s->data[s->sp - 1 - n];
    s->data[s->sp - 1 - n] = tmp;
}

void memory_store(evm_memory_t *m, size_t offset, const uint8_t *data, size_t len) {
    if (offset + len > EVM_MEM_MAX) {
        fprintf(stderr, "EVM: memory overflow\n");
        return;
    }
    if (offset + len > m->size) {
        m->size = offset + len;
    }
    memcpy(m->data + offset, data, len);
}

void memory_load(const evm_memory_t *m, size_t offset, uint8_t *data, size_t len) {
    if (offset + len > m->size) {
        memset(data, 0, len);
        return;
    }
    memcpy(data, m->data + offset, len);
}

void memory_expand(evm_memory_t *m, size_t new_size) {
    if (new_size > EVM_MEM_MAX) {
        fprintf(stderr, "EVM: memory expansion exceeds limit\n");
        return;
    }
    if (new_size > m->size) {
        memset(m->data + m->size, 0, new_size - m->size);
        m->size = new_size;
    }
}

bool storage_get(const evm_storage_t *s, const uint256_t *key, uint256_t *value) {
    for (int i = 0; i < s->count; i++) {
        if (uint256_cmp(&s->slots[i].key, key) == 0) {
            *value = s->slots[i].value;
            return true;
        }
    }
    uint256_zero(value);
    return false;
}

void storage_set(evm_storage_t *s, const uint256_t *key, const uint256_t *value) {
    for (int i = 0; i < s->count; i++) {
        if (uint256_cmp(&s->slots[i].key, key) == 0) {
            s->slots[i].value = *value;
            return;
        }
    }
    if (s->count >= EVM_STORAGE_MAX) return;
    s->slots[s->count].key = *key;
    s->slots[s->count].value = *value;
    s->count++;
}

void storage_clear(evm_storage_t *s) {
    s->count = 0;
}

void address_copy(uint8_t dst[EVM_ADDR_LEN], const uint8_t src[EVM_ADDR_LEN]) {
    memcpy(dst, src, EVM_ADDR_LEN);
}

bool address_eq(const uint8_t a[EVM_ADDR_LEN], const uint8_t b[EVM_ADDR_LEN]) {
    return memcmp(a, b, EVM_ADDR_LEN) == 0;
}

void evm_init(evm_t *evm, const uint8_t *code, size_t code_len) {
    memset(evm, 0, sizeof(evm_t));
    memcpy(evm->code, code, code_len < 65536 ? code_len : 65536);
    evm->code_len = code_len < 65536 ? code_len : 65536;
    evm->pc = 0;
    evm->stack.sp = 0;
    evm->memory.size = 0;
    evm->storage.count = 0;
    evm->gas = 30000000;
    evm->gas_limit = 30000000;
    evm->reverted = false;
    evm->selfdestructed = false;
    evm->depth = 0;
    evm->gas_used = 0;
}

void evm_set_caller(evm_t *evm, const uint8_t caller[EVM_ADDR_LEN]) {
    memcpy(evm->ctx.caller, caller, EVM_ADDR_LEN);
}

void evm_set_value(evm_t *evm, const uint256_t *value) {
    evm->ctx.value = *value;
}

void evm_set_calldata(evm_t *evm, const uint8_t *data, size_t len) {
    memcpy(evm->calldata, data, len < 65536 ? len : 65536);
    evm->calldata_len = len < 65536 ? len : 65536;
}

void evm_reset(evm_t *evm) {
    evm->pc = 0;
    evm->stack.sp = 0;
    evm->reverted = false;
    evm->selfdestructed = false;
    evm->revert_reason[0] = '\0';
}

static bool evm_charge_gas(evm_t *evm, uint64_t cost) {
    if (evm->gas < cost) {
        evm->reverted = true;
        snprintf(evm->revert_reason, sizeof(evm->revert_reason), "out of gas");
        return false;
    }
    evm->gas -= cost;
    evm->gas_used += cost;
    return true;
}

bool evm_step(evm_t *evm) {
    if (evm->reverted || evm->selfdestructed) return false;
    if ((size_t)evm->pc >= evm->code_len) return false;

    uint8_t op = evm->code[evm->pc];
    uint64_t gas_cost = GAS_COST[op];
    if (gas_cost == 0 && op != OP_STOP && op != OP_RETURN && op != OP_REVERT) {
        gas_cost = GAS_BASE;
    }
    if (!evm_charge_gas(evm, gas_cost)) return false;

    uint256_t a, b, result;

    switch (op) {
    case OP_STOP:
        return false;

    case OP_ADD:
        stack_pop(&evm->stack, &b);
        stack_pop(&evm->stack, &a);
        uint256_add(&result, &a, &b);
        stack_push(&evm->stack, &result);
        break;

    case OP_MUL:
        stack_pop(&evm->stack, &b);
        stack_pop(&evm->stack, &a);
        uint256_mul(&result, &a, &b);
        stack_push(&evm->stack, &result);
        break;

    case OP_SUB:
        stack_pop(&evm->stack, &b);
        stack_pop(&evm->stack, &a);
        uint256_sub(&result, &a, &b);
        stack_push(&evm->stack, &result);
        break;

    case OP_CALLER:
        uint256_zero(&result);
        uint256_from_bytes(&result, evm->ctx.caller, EVM_ADDR_LEN);
        stack_push(&evm->stack, &result);
        break;

    case OP_CALLVALUE:
        stack_push(&evm->stack, &evm->ctx.value);
        break;

    case OP_CALLDATALOAD: {
        stack_pop(&evm->stack, &a);
        size_t off = (size_t)(a.w[0]);
        uint256_t loaded;
        uint256_zero(&loaded);
        if (off < evm->calldata_len) {
            uint256_from_bytes(&loaded, evm->calldata + off,
                               evm->calldata_len - off);
        }
        stack_push(&evm->stack, &loaded);
        break;
    }

    case OP_CALLDATASIZE: {
        uint256_t s;
        uint256_set64(&s, (uint64_t)evm->calldata_len);
        stack_push(&evm->stack, &s);
        break;
    }

    case OP_SLOAD:
        stack_pop(&evm->stack, &a);
        storage_get(&evm->storage, &a, &result);
        stack_push(&evm->stack, &result);
        evm->sload_count++;
        break;

    case OP_SSTORE:
        stack_pop(&evm->stack, &a);
        stack_pop(&evm->stack, &b);
        storage_set(&evm->storage, &a, &b);
        evm->sstore_count++;
        break;

    case OP_MSTORE: {
        stack_pop(&evm->stack, &a);
        stack_pop(&evm->stack, &b);
        uint8_t word[32];
        uint256_to_bytes(&b, word, 32);
        memory_store(&evm->memory, (size_t)(a.w[0]), word, 32);
        break;
    }

    case OP_MLOAD: {
        stack_pop(&evm->stack, &a);
        uint8_t word[32];
        memory_load(&evm->memory, (size_t)(a.w[0]), word, 32);
        uint256_from_bytes(&result, word, 32);
        stack_push(&evm->stack, &result);
        break;
    }

    case OP_RETURN:
        evm->returndata_len = 0;
        return false;

    case OP_REVERT:
        evm->reverted = true;
        snprintf(evm->revert_reason, sizeof(evm->revert_reason),
                 "execution reverted at pc=%d", evm->pc);
        return false;

    case OP_SELFDESTRUCT: {
        stack_pop(&evm->stack, &a);
        uint8_t tmp[32];
        uint256_to_bytes(&a, tmp, 32);
        memcpy(evm->beneficiary, tmp + 12, EVM_ADDR_LEN);
        evm->selfdestructed = true;
        return false;
    }

    case OP_JUMP: {
        stack_pop(&evm->stack, &a);
        evm->pc = (int)(a.w[0] & 0xFFFF);
        return true;
    }

    case OP_JUMPI: {
        stack_pop(&evm->stack, &a);
        stack_pop(&evm->stack, &b);
        if (!uint256_is_zero(&b)) {
            evm->pc = (int)(a.w[0] & 0xFFFF);
            return true;
        }
        break;
    }

    case OP_JUMPDEST:
        break;

    case OP_EQ:
        stack_pop(&evm->stack, &b);
        stack_pop(&evm->stack, &a);
        uint256_set64(&result, uint256_cmp(&a, &b) == 0 ? 1 : 0);
        stack_push(&evm->stack, &result);
        break;

    case OP_ISZERO:
        stack_pop(&evm->stack, &a);
        uint256_set64(&result, uint256_is_zero(&a) ? 1 : 0);
        stack_push(&evm->stack, &result);
        break;

    case OP_CALL: {
        stack_pop(&evm->stack, &a);
        stack_pop(&evm->stack, &b);
        uint256_set64(&result, 1);
        stack_push(&evm->stack, &result);
        break;
    }

    case OP_DELEGATECALL: {
        stack_pop(&evm->stack, &a);
        stack_pop(&evm->stack, &b);
        uint256_set64(&result, 1);
        stack_push(&evm->stack, &result);
        break;
    }

    case OP_PUSH1: case OP_PUSH2: case OP_PUSH3: case OP_PUSH4:
    case OP_PUSH5: case OP_PUSH6: case OP_PUSH7: case OP_PUSH8:
    case OP_PUSH9: case OP_PUSH10: case OP_PUSH11: case OP_PUSH12:
    case OP_PUSH13: case OP_PUSH14: case OP_PUSH15: case OP_PUSH16:
    case OP_PUSH17: case OP_PUSH18: case OP_PUSH19: case OP_PUSH20:
    case OP_PUSH21: case OP_PUSH22: case OP_PUSH23: case OP_PUSH24:
    case OP_PUSH25: case OP_PUSH26: case OP_PUSH27: case OP_PUSH28:
    case OP_PUSH29: case OP_PUSH30: case OP_PUSH31: case OP_PUSH32: {
        int push_bytes = op - OP_PUSH1 + 1;
        uint256_zero(&a);
        if (evm->pc + 1 + push_bytes <= (int)evm->code_len) {
            uint256_from_bytes(&a, evm->code + evm->pc + 1, (size_t)push_bytes);
        }
        stack_push(&evm->stack, &a);
        evm->pc += push_bytes;
        return true;
    }

    case OP_DUP1: case OP_DUP2: case OP_DUP3: case OP_DUP4:
    case OP_DUP5: case OP_DUP6: case OP_DUP7: case OP_DUP8:
    case OP_DUP9: case OP_DUP10: case OP_DUP11: case OP_DUP12:
    case OP_DUP13: case OP_DUP14: case OP_DUP15: case OP_DUP16:
        stack_dup(&evm->stack, op - OP_DUP1 + 1);
        break;

    case OP_SWAP1: case OP_SWAP2: case OP_SWAP3: case OP_SWAP4:
    case OP_SWAP5: case OP_SWAP6: case OP_SWAP7: case OP_SWAP8:
    case OP_SWAP9: case OP_SWAP10: case OP_SWAP11: case OP_SWAP12:
    case OP_SWAP13: case OP_SWAP14: case OP_SWAP15: case OP_SWAP16:
        stack_swap(&evm->stack, op - OP_SWAP1 + 1);
        break;

    case OP_GAS: {
        uint256_set64(&result, evm->gas);
        stack_push(&evm->stack, &result);
        break;
    }

    case OP_PC: {
        uint256_set64(&result, (uint64_t)evm->pc);
        stack_push(&evm->stack, &result);
        break;
    }

    default:
        evm->reverted = true;
        snprintf(evm->revert_reason, sizeof(evm->revert_reason),
                 "invalid opcode 0x%02x at pc=%d", op, evm->pc);
        return false;
    }

    evm->pc++;
    return true;
}

int evm_execute(evm_t *evm) {
    int steps = 0;
    while (evm_step(evm)) {
        steps++;
        if (steps > 1000000) {
            evm->reverted = true;
            snprintf(evm->revert_reason, sizeof(evm->revert_reason),
                     "max steps exceeded");
            break;
        }
    }
    return steps;
}
