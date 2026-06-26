#ifndef SCRIPT_ENGINE_H
#define SCRIPT_ENGINE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Bitcoin Script — a stack-based, Forth-like programming language
 * used to specify conditions for spending UTXOs.
 *
 * Standards referenced:
 *   - Bitcoin Script specification (Bitcoin Wiki / BIP 62, BIP 66)
 *   - P2PKH, P2SH, P2WPKH templates
 *   - BIP 65 (OP_CHECKLOCKTIMEVERIFY), BIP 112 (OP_CHECKSEQUENCEVERIFY)
 *
 * Core theorem: Script evaluation is deterministic and bounded;
 * ScriptSig + ScriptPubKey concatenation produces a single linear execution.
 * Complexity: O(n) in script byte length.
 */

#define SCRIPT_MAX_SIZE         10000
#define SCRIPT_STACK_MAX_DEPTH  1000
#define SCRIPT_ALTSTACK_MAX     1000
#define SCRIPT_MAX_OPS          201
#define SCRIPT_MAX_ELEMENT_SIZE 520
#define SCRIPT_HASH_LEN         32

/* ── Script Opcodes (subset of Bitcoin opcodes) ── */

typedef enum {
    /* Constants */
    OP_0                  = 0x00,
    OP_PUSHDATA1          = 0x4c,
    OP_PUSHDATA2          = 0x4d,
    OP_PUSHDATA4          = 0x4e,
    OP_1NEGATE            = 0x4f,
    OP_1                  = 0x51,
    OP_2                  = 0x52,
    OP_3                  = 0x53,
    OP_4                  = 0x54,
    OP_5                  = 0x55,
    OP_6                  = 0x56,
    OP_7                  = 0x57,
    OP_8                  = 0x58,
    OP_9                  = 0x59,
    OP_10                 = 0x5a,
    OP_11                 = 0x5b,
    OP_12                 = 0x5c,
    OP_13                 = 0x5d,
    OP_14                 = 0x5e,
    OP_15                 = 0x5f,
    OP_16                 = 0x60,

    /* Flow control */
    OP_NOP                = 0x61,
    OP_IF                 = 0x63,
    OP_NOTIF              = 0x64,
    OP_ELSE               = 0x67,
    OP_ENDIF              = 0x68,
    OP_VERIFY             = 0x69,
    OP_RETURN             = 0x6a,

    /* Stack */
    OP_TOALTSTACK         = 0x6b,
    OP_FROMALTSTACK       = 0x6c,
    OP_DROP               = 0x75,
    OP_DUP                = 0x76,
    OP_NIP                = 0x77,
    OP_OVER               = 0x78,
    OP_PICK               = 0x79,
    OP_ROLL               = 0x7a,
    OP_SWAP               = 0x7c,
    OP_TUCK               = 0x7d,
    OP_2DROP              = 0x6d,
    OP_2DUP               = 0x6e,
    OP_3DUP               = 0x6f,
    OP_2OVER              = 0x70,
    OP_2SWAP              = 0x72,

    /* Splice */
    OP_SIZE               = 0x82,

    /* Bitwise */
    OP_EQUAL              = 0x87,
    OP_EQUALVERIFY        = 0x88,

    /* Arithmetic */
    OP_1ADD               = 0x8b,
    OP_1SUB               = 0x8c,
    OP_NEGATE             = 0x8f,
    OP_ABS                = 0x90,
    OP_NOT                = 0x91,
    OP_0NOTEQUAL          = 0x92,
    OP_ADD                = 0x93,
    OP_SUB                = 0x94,
    OP_BOOLAND            = 0x9a,
    OP_BOOLOR             = 0x9b,
    OP_NUMEQUAL           = 0x9c,
    OP_NUMEQUALVERIFY      = 0x9d,
    OP_NUMNOTEQUAL        = 0x9e,
    OP_LESSTHAN           = 0x9f,
    OP_GREATERTHAN        = 0xa0,
    OP_LESSTHANOREQUAL    = 0xa1,
    OP_GREATERTHANOREQUAL = 0xa2,
    OP_MIN                = 0xa3,
    OP_MAX                = 0xa4,
    OP_WITHIN             = 0xa5,

    /* Crypto */
    OP_RIPEMD160          = 0xa6,
    OP_SHA1               = 0xa7,
    OP_SHA256             = 0xa8,
    OP_HASH160            = 0xa9,
    OP_HASH256            = 0xaa,
    OP_CODESEPARATOR      = 0xab,
    OP_CHECKSIG           = 0xac,
    OP_CHECKSIGVERIFY     = 0xad,
    OP_CHECKMULTISIG      = 0xae,
    OP_CHECKMULTISIGVERIFY = 0xaf,

    /* Locktime */
    OP_CHECKLOCKTIMEVERIFY  = 0xb1,
    OP_CHECKSEQUENCEVERIFY  = 0xb2,
} script_opcode;

/* ── Script element (stack item) ── */

typedef struct {
    uint8_t *data;
    size_t   len;
} script_element;

/* ── Evaluation context ── */

typedef struct {
    script_element *stack;
    int             stack_depth;
    int             stack_capacity;

    script_element *altstack;
    int             altstack_depth;
    int             altstack_capacity;

    const uint8_t  *tx_data;
    size_t          tx_len;

    uint32_t        locktime;
    uint32_t        sequence;

    int             op_count;
    const uint8_t  *script;
    size_t          script_len;
    size_t          pc;

    /* Conditional execution stack */
    uint8_t         cond_stack[256];
    int             cond_depth;

    /* Verification state */
    int             verify_ok;
    int             error;
} script_context;

/* ── Script template builder ── */

typedef struct {
    uint8_t *script;
    size_t   len;
    size_t   capacity;
} script_builder;

/* ── API ── */

/* Context lifecycle */
int  script_ctx_init(script_context *ctx);
void script_ctx_free(script_context *ctx);

/* Stack operations */
int  script_stack_push(script_context *ctx, const uint8_t *data, size_t len);
int  script_stack_pop(script_context *ctx, uint8_t **data, size_t *len);
int  script_stack_top(const script_context *ctx, uint8_t **data, size_t *len);
int  script_stack_peek(const script_context *ctx, int index, uint8_t **data, size_t *len);

/* Script evaluation — core algorithm */
int  script_eval(script_context *ctx, const uint8_t *script, size_t len);
int  script_eval_sig_pub(const script_context *ctx,
                         const uint8_t *scriptSig, size_t sig_len,
                         const uint8_t *scriptPubKey, size_t pub_len,
                         int *valid);

/* Script builder */
int  script_builder_init(script_builder *b, size_t capacity);
void script_builder_free(script_builder *b);
int  script_builder_push_op(script_builder *b, script_opcode op);
int  script_builder_push_data(script_builder *b, const uint8_t *data, size_t len);
int  script_builder_push_int(script_builder *b, int64_t val);

/* Standard script templates (L7: Applications) */
int  script_p2pkh_lock(script_builder *b, const uint8_t pubkey_hash[20]);
int  script_p2pkh_unlock(script_builder *b, const uint8_t *sig, size_t sig_len,
                          const uint8_t *pubkey, size_t pubkey_len);
int  script_p2sh_redeem(script_builder *b, const uint8_t redeem_script_hash[20],
                         const uint8_t *redeem_script, size_t redeem_len);
int  script_multisig_lock(script_builder *b, int m, const uint8_t **pubkeys,
                           const size_t *pk_lens, int n);
int  script_cltv_lock(script_builder *b, uint32_t locktime,
                       const uint8_t pubkey_hash[20]);
int  script_htlc_lock(script_builder *b, const uint8_t hash[SCRIPT_HASH_LEN],
                       const uint8_t pubkey_hash[20],
                       const uint8_t revoke_pubkey_hash[20],
                       uint32_t timeout);

/* Utility */
char *script_disasm_single(uint8_t opcode);
void script_disasm(const uint8_t *script, size_t len, char *buf, size_t bufsz);

#ifdef __cplusplus
}
#endif

#endif
