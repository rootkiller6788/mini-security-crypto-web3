#ifndef EVM_SIM_H
#define EVM_SIM_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define EVM_STACK_MAX   1024
#define EVM_MEM_MAX     (1024 * 1024)
#define EVM_STORAGE_MAX 256
#define EVM_ADDR_LEN    20
#define EVM_WORD_SIZE   32
#define EVM_KEY_LEN     32

typedef struct {
    uint64_t w[4];
} uint256_t;

typedef enum {
    OP_STOP           = 0x00,
    OP_ADD            = 0x01,
    OP_MUL            = 0x02,
    OP_SUB            = 0x03,
    OP_DIV            = 0x04,
    OP_SDIV           = 0x05,
    OP_MOD            = 0x06,
    OP_SMOD           = 0x07,
    OP_ADDMOD         = 0x08,
    OP_MULMOD         = 0x09,
    OP_EXP            = 0x0a,
    OP_SIGNEXTEND     = 0x0b,
    OP_LT             = 0x10,
    OP_GT             = 0x11,
    OP_SLT            = 0x12,
    OP_SGT            = 0x13,
    OP_EQ             = 0x14,
    OP_ISZERO         = 0x15,
    OP_AND            = 0x16,
    OP_OR             = 0x17,
    OP_XOR            = 0x18,
    OP_NOT            = 0x19,
    OP_BYTE           = 0x1a,
    OP_SHL            = 0x1b,
    OP_SHR            = 0x1c,
    OP_SAR            = 0x1d,
    OP_SHA3           = 0x20,
    OP_ADDRESS        = 0x30,
    OP_BALANCE        = 0x31,
    OP_ORIGIN         = 0x32,
    OP_CALLER         = 0x33,
    OP_CALLVALUE      = 0x34,
    OP_CALLDATALOAD   = 0x35,
    OP_CALLDATASIZE   = 0x36,
    OP_CALLDATACOPY   = 0x37,
    OP_CODESIZE       = 0x38,
    OP_CODECOPY       = 0x39,
    OP_GASPRICE       = 0x3a,
    OP_EXTCODESIZE    = 0x3b,
    OP_EXTCODECOPY    = 0x3c,
    OP_PUSH1          = 0x60,
    OP_PUSH32         = 0x7f,
    OP_DUP1           = 0x80,
    OP_DUP16          = 0x8f,
    OP_SWAP1          = 0x90,
    OP_SWAP16         = 0x9f,
    OP_MLOAD          = 0x51,
    OP_MSTORE         = 0x52,
    OP_MSTORE8        = 0x53,
    OP_SLOAD          = 0x54,
    OP_SSTORE         = 0x55,
    OP_JUMP           = 0x56,
    OP_JUMPI          = 0x57,
    OP_PC             = 0x58,
    OP_MSIZE          = 0x59,
    OP_GAS            = 0x5a,
    OP_JUMPDEST       = 0x5b,
    OP_RETURN         = 0xf3,
    OP_DELEGATECALL   = 0xf4,
    OP_CREATE         = 0xf0,
    OP_CALL           = 0xf1,
    OP_CALLCODE       = 0xf2,
    OP_REVERT         = 0xfd,
    OP_INVALID        = 0xfe,
    OP_SELFDESTRUCT   = 0xff
} evm_opcode_t;

typedef struct {
    uint256_t data[EVM_STACK_MAX];
    int sp;
} evm_stack_t;

typedef struct {
    uint8_t data[EVM_MEM_MAX];
    size_t size;
} evm_memory_t;

typedef struct {
    uint256_t key;
    uint256_t value;
} evm_storage_slot_t;

typedef struct {
    evm_storage_slot_t slots[EVM_STORAGE_MAX];
    int count;
} evm_storage_t;

typedef struct {
    uint8_t addr[EVM_ADDR_LEN];
    uint8_t caller[EVM_ADDR_LEN];
    uint8_t origin[EVM_ADDR_LEN];
    uint256_t value;
    uint256_t balance;
} evm_call_ctx_t;

typedef struct {
    uint8_t code[65536];
    size_t code_len;
    int pc;
    evm_stack_t stack;
    evm_memory_t memory;
    evm_storage_t storage;
    evm_call_ctx_t ctx;
    uint64_t gas;
    uint64_t gas_limit;
    uint8_t calldata[65536];
    size_t calldata_len;
    uint8_t returndata[65536];
    size_t returndata_len;
    bool reverted;
    char revert_reason[256];
    bool selfdestructed;
    uint8_t beneficiary[EVM_ADDR_LEN];
    int depth;
    uint64_t gas_used;
    int sstore_count;
    int sload_count;
} evm_t;

extern const uint64_t GAS_COST[];
#define GAS_ZERO      0
#define GAS_BASE      2
#define GAS_VERYLOW   3
#define GAS_LOW       5
#define GAS_MID       8
#define GAS_HIGH      10
#define GAS_SLOAD     200
#define GAS_SSTORE_SET    20000
#define GAS_SSTORE_RESET  5000
#define GAS_SSTORE_CLEAR  15000
#define GAS_SELFDESTRUCT  5000
#define GAS_CREATE    32000
#define GAS_CALL      700
#define GAS_MEMORY    3

void evm_init(evm_t *evm, const uint8_t *code, size_t code_len);
void evm_set_caller(evm_t *evm, const uint8_t caller[EVM_ADDR_LEN]);
void evm_set_value(evm_t *evm, const uint256_t *value);
void evm_set_calldata(evm_t *evm, const uint8_t *data, size_t len);
int  evm_execute(evm_t *evm);
bool evm_step(evm_t *evm);
void evm_reset(evm_t *evm);

void uint256_zero(uint256_t *v);
void uint256_set64(uint256_t *v, uint64_t x);
int  uint256_cmp(const uint256_t *a, const uint256_t *b);
bool uint256_is_zero(const uint256_t *v);
void uint256_add(uint256_t *r, const uint256_t *a, const uint256_t *b);
void uint256_sub(uint256_t *r, const uint256_t *a, const uint256_t *b);
void uint256_mul(uint256_t *r, const uint256_t *a, const uint256_t *b);
void uint256_from_bytes(uint256_t *v, const uint8_t *b, size_t len);
void uint256_to_bytes(const uint256_t *v, uint8_t *b, size_t len);
void uint256_print(const uint256_t *v);

void stack_push(evm_stack_t *s, const uint256_t *v);
void stack_pop(evm_stack_t *s, uint256_t *v);
void stack_dup(evm_stack_t *s, int n);
void stack_swap(evm_stack_t *s, int n);

void memory_store(evm_memory_t *m, size_t offset, const uint8_t *data, size_t len);
void memory_load(const evm_memory_t *m, size_t offset, uint8_t *data, size_t len);
void memory_expand(evm_memory_t *m, size_t new_size);

bool storage_get(const evm_storage_t *s, const uint256_t *key, uint256_t *value);
void storage_set(evm_storage_t *s, const uint256_t *key, const uint256_t *value);
void storage_clear(evm_storage_t *s);

void address_copy(uint8_t dst[EVM_ADDR_LEN], const uint8_t src[EVM_ADDR_LEN]);
bool address_eq(const uint8_t a[EVM_ADDR_LEN], const uint8_t b[EVM_ADDR_LEN]);

#endif
