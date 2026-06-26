#include "script_engine.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

static int64_t script_read_num(const uint8_t *data, size_t len) {
    if (len == 0) return 0;
    if (len > 8) len = 8;
    int64_t val = 0;
    for (size_t i = 0; i < len; i++) val |= ((int64_t)data[i]) << (i * 8);
    if (len > 0 && (data[len - 1] & 0x80))
        for (size_t i = len; i < 8; i++) val |= ((int64_t)0xFF) << (i * 8);
    return val;
}

static int script_push_num(script_context *ctx, int64_t val) {
    uint8_t buf[8];
    if (val == 0) return script_stack_push(ctx, (const uint8_t *)"", 0);
    int neg = (val < 0); if (neg) val = -val;
    size_t len = 0;
    while (val > 0 && len < 8) { buf[len++] = (uint8_t)(val & 0xFF); val >>= 8; }
    if (neg) {
        if (buf[len - 1] < 0x80) buf[len - 1] |= 0x80;
        else buf[len++] = 0x80;
    } else { if (buf[len - 1] >= 0x80) buf[len++] = 0x00; }
    if (len == 0) { buf[0] = 0; len = 1; }
    return script_stack_push(ctx, buf, len);
}

static int script_cond_true(const script_context *ctx) {
    for (int i = 0; i < ctx->cond_depth; i++)
        if (ctx->cond_stack[i] == 0) return 0;
    return 1;
}

int script_ctx_init(script_context *ctx) {
    if (!ctx) return -1;
    memset(ctx, 0, sizeof(script_context));
    ctx->stack_capacity = SCRIPT_STACK_MAX_DEPTH;
    ctx->stack = calloc((size_t)ctx->stack_capacity, sizeof(script_element));
    if (!ctx->stack) return -1;
    ctx->altstack_capacity = SCRIPT_ALTSTACK_MAX;
    ctx->altstack = calloc((size_t)ctx->altstack_capacity, sizeof(script_element));
    if (!ctx->altstack) { free(ctx->stack); return -1; }
    ctx->verify_ok = 1;
    return 0;
}

void script_ctx_free(script_context *ctx) {
    if (!ctx) return;
    for (int i = 0; i < ctx->stack_depth; i++) free(ctx->stack[i].data);
    for (int i = 0; i < ctx->altstack_depth; i++) free(ctx->altstack[i].data);
    free(ctx->stack); free(ctx->altstack);
    memset(ctx, 0, sizeof(script_context));
}

int script_stack_push(script_context *ctx, const uint8_t *data, size_t len) {
    if (!ctx || ctx->stack_depth >= ctx->stack_capacity) return -1;
    if (len > SCRIPT_MAX_ELEMENT_SIZE) return -1;
    script_element *el = &ctx->stack[ctx->stack_depth];
    if (len > 0 && data) {
        el->data = malloc(len); if (!el->data) return -1;
        memcpy(el->data, data, len); el->len = len;
    } else { el->data = NULL; el->len = 0; }
    ctx->stack_depth++;
    return 0;
}

int script_stack_pop(script_context *ctx, uint8_t **data, size_t *len) {
    if (!ctx || ctx->stack_depth <= 0) return -1;
    ctx->stack_depth--;
    script_element *el = &ctx->stack[ctx->stack_depth];
    if (data) *data = el->data; if (len) *len = el->len;
    return 0;
}

int script_stack_top(const script_context *ctx, uint8_t **data, size_t *len) {
    if (!ctx || ctx->stack_depth <= 0) return -1;
    script_element *el = (script_element *)&ctx->stack[ctx->stack_depth - 1];
    if (data) *data = el->data; if (len) *len = el->len;
    return 0;
}

int script_stack_peek(const script_context *ctx, int index, uint8_t **data, size_t *len) {
    if (!ctx || index < 0 || index >= ctx->stack_depth) return -1;
    script_element *el = (script_element *)&ctx->stack[ctx->stack_depth - 1 - index];
    if (data) *data = el->data; if (len) *len = el->len;
    return 0;
}

static int script_eval_op(script_context *ctx, uint8_t opcode) {
    int exec = script_cond_true(ctx);
    uint8_t *a, *b, *c; size_t alen, blen, clen;
    int64_t va, vb, vc; int eq;

    /* OP_0 and small integers */
    if (opcode == OP_0 || opcode == OP_1NEGATE) {
        return exec ? script_push_num(ctx, (opcode == OP_0) ? 0 : -1) : 0;
    }
    if (opcode >= OP_1 && opcode <= OP_16) {
        return exec ? script_push_num(ctx, (int64_t)(opcode - OP_1 + 1)) : 0;
    }

    /* Flow control ? always needs stashing unconditionally */
    if (opcode == OP_IF || opcode == OP_NOTIF) {
        if (ctx->cond_depth >= 255) return -1;
        if (!exec) { ctx->cond_stack[ctx->cond_depth++] = 0; return 0; }
        if (script_stack_pop(ctx, &a, &alen) != 0) return -1;
        int64_t v = script_read_num(a, alen); free(a);
        ctx->cond_stack[ctx->cond_depth++] = (uint8_t)((opcode == OP_IF) ? (v != 0) : (v == 0));
        return 0;
    }
    if (opcode == OP_ELSE) {
        if (ctx->cond_depth <= 0) return -1;
        ctx->cond_stack[ctx->cond_depth - 1] = (uint8_t)(!ctx->cond_stack[ctx->cond_depth - 1]);
        return 0;
    }
    if (opcode == OP_ENDIF) {
        if (ctx->cond_depth <= 0) return -1;
        ctx->cond_depth--;
        return 0;
    }
    if (opcode == OP_VERIFY) {
        if (!exec) return 0;
        if (script_stack_pop(ctx, &a, &alen) != 0) return -1;
        va = script_read_num(a, alen); free(a);
        if (va == 0) { ctx->verify_ok = 0; ctx->error = 1; return -1; }
        return 0;
    }
    if (opcode == OP_RETURN) { ctx->error = 1; return -1; }
    if (!exec) return 0;

    switch (opcode) {
    case OP_TOALTSTACK:
        if (ctx->stack_depth == 0 || ctx->altstack_depth >= ctx->altstack_capacity) return -1;
        ctx->altstack[ctx->altstack_depth++] = ctx->stack[--ctx->stack_depth]; return 0;
    case OP_FROMALTSTACK:
        if (ctx->altstack_depth == 0 || ctx->stack_depth >= ctx->stack_capacity) return -1;
        ctx->stack[ctx->stack_depth++] = ctx->altstack[--ctx->altstack_depth]; return 0;
    case OP_DROP:
        if (ctx->stack_depth == 0) return -1;
        free(ctx->stack[--ctx->stack_depth].data); return 0;
    case OP_DUP:
        if (ctx->stack_depth == 0) return -1;
        return script_stack_push(ctx, ctx->stack[ctx->stack_depth-1].data,
                                 ctx->stack[ctx->stack_depth-1].len);
    case OP_NIP:
        if (ctx->stack_depth < 2) return -1;
        free(ctx->stack[ctx->stack_depth-2].data);
        ctx->stack[ctx->stack_depth-2] = ctx->stack[ctx->stack_depth-1];
        ctx->stack_depth--; return 0;
    case OP_OVER:
        if (ctx->stack_depth < 2) return -1;
        return script_stack_push(ctx, ctx->stack[ctx->stack_depth-2].data,
                                 ctx->stack[ctx->stack_depth-2].len);
    case OP_SWAP:
        if (ctx->stack_depth < 2) return -1;
        { script_element t = ctx->stack[ctx->stack_depth-1];
          ctx->stack[ctx->stack_depth-1] = ctx->stack[ctx->stack_depth-2];
          ctx->stack[ctx->stack_depth-2] = t; } return 0;
    case OP_TUCK:
        if (ctx->stack_depth < 2) return -1;
        return script_stack_push(ctx, ctx->stack[ctx->stack_depth-1].data,
                                 ctx->stack[ctx->stack_depth-1].len);
    case OP_2DROP:
        if (ctx->stack_depth < 2) return -1;
        free(ctx->stack[--ctx->stack_depth].data);
        free(ctx->stack[--ctx->stack_depth].data); return 0;
    case OP_2DUP:
        if (ctx->stack_depth < 2) return -1;
        script_stack_push(ctx, ctx->stack[ctx->stack_depth-2].data, ctx->stack[ctx->stack_depth-2].len);
        script_stack_push(ctx, ctx->stack[ctx->stack_depth-2].data, ctx->stack[ctx->stack_depth-2].len);
        return 0;
    case OP_3DUP:
        if (ctx->stack_depth < 3) return -1;
        for (int i = 3; i >= 1; i--)
            script_stack_push(ctx, ctx->stack[ctx->stack_depth-i].data, ctx->stack[ctx->stack_depth-i].len);
        return 0;
    case OP_2OVER:
        if (ctx->stack_depth < 4) return -1;
        script_stack_push(ctx, ctx->stack[ctx->stack_depth-4].data, ctx->stack[ctx->stack_depth-4].len);
        script_stack_push(ctx, ctx->stack[ctx->stack_depth-3].data, ctx->stack[ctx->stack_depth-3].len);
        return 0;
    case OP_2SWAP:
        if (ctx->stack_depth < 4) return -1;
        { script_element t1 = ctx->stack[ctx->stack_depth-1], t2 = ctx->stack[ctx->stack_depth-2];
          ctx->stack[ctx->stack_depth-1] = ctx->stack[ctx->stack_depth-3];
          ctx->stack[ctx->stack_depth-2] = ctx->stack[ctx->stack_depth-4];
          ctx->stack[ctx->stack_depth-3] = t1; ctx->stack[ctx->stack_depth-4] = t2; } return 0;
    case OP_ROLL:
        if (ctx->stack_depth < 2) return -1;
        script_stack_pop(ctx, &a, &alen); va = script_read_num(a, alen); free(a);
        if (va < 0 || va >= ctx->stack_depth) return -1;
        { script_element e = ctx->stack[ctx->stack_depth-1-(int)va];
          for (int i = (int)va; i > 0; i--) ctx->stack[ctx->stack_depth-1-i] = ctx->stack[ctx->stack_depth-i];
          ctx->stack[ctx->stack_depth-1] = e; } return 0;
    case OP_PICK:
        if (ctx->stack_depth < 2) return -1;
        script_stack_pop(ctx, &a, &alen); va = script_read_num(a, alen); free(a);
        if (va < 0 || va >= ctx->stack_depth) return -1;
        return script_stack_push(ctx, ctx->stack[ctx->stack_depth-1-(int)va].data,
                                 ctx->stack[ctx->stack_depth-1-(int)va].len);
    case OP_SIZE:
        if (ctx->stack_depth < 1) return -1;
        return script_push_num(ctx, (int64_t)ctx->stack[ctx->stack_depth-1].len);
    case OP_EQUAL:
        if (ctx->stack_depth < 2) return -1;
        script_stack_pop(ctx, &a, &alen); script_stack_pop(ctx, &b, &blen);
        eq = (alen == blen && memcmp(a, b, alen) == 0);
        free(a); free(b); return script_push_num(ctx, eq ? 1 : 0);
    case OP_EQUALVERIFY:
        if (ctx->stack_depth < 2) return -1;
        script_stack_pop(ctx, &a, &alen); script_stack_pop(ctx, &b, &blen);
        eq = (alen == blen && memcmp(a, b, alen) == 0);
        free(a); free(b);
        if (!eq) { ctx->verify_ok = 0; ctx->error = 1; return -1; } return 0;
    case OP_ADD:
        if (ctx->stack_depth < 2) return -1;
        script_stack_pop(ctx, &a, &alen); script_stack_pop(ctx, &b, &blen);
        va = script_read_num(a, alen); vb = script_read_num(b, blen);
        free(a); free(b); return script_push_num(ctx, va + vb);
    case OP_SUB:
        if (ctx->stack_depth < 2) return -1;
        script_stack_pop(ctx, &a, &alen); script_stack_pop(ctx, &b, &blen);
        va = script_read_num(a, alen); vb = script_read_num(b, blen);
        free(a); free(b); return script_push_num(ctx, va - vb);
    case OP_1ADD:
        if (ctx->stack_depth < 1) return -1;
        script_stack_pop(ctx, &a, &alen); va = script_read_num(a, alen);
        free(a); return script_push_num(ctx, va + 1);
    case OP_1SUB:
        if (ctx->stack_depth < 1) return -1;
        script_stack_pop(ctx, &a, &alen); va = script_read_num(a, alen);
        free(a); return script_push_num(ctx, va - 1);
    case OP_NEGATE:
        if (ctx->stack_depth < 1) return -1;
        script_stack_pop(ctx, &a, &alen); va = script_read_num(a, alen);
        free(a); return script_push_num(ctx, -va);
    case OP_ABS:
        if (ctx->stack_depth < 1) return -1;
        script_stack_pop(ctx, &a, &alen); va = script_read_num(a, alen);
        free(a); return script_push_num(ctx, va >= 0 ? va : -va);
    case OP_NOT:
        if (ctx->stack_depth < 1) return -1;
        script_stack_pop(ctx, &a, &alen); va = script_read_num(a, alen);
        free(a); return script_push_num(ctx, va == 0 ? 1 : 0);
    case OP_0NOTEQUAL:
        if (ctx->stack_depth < 1) return -1;
        script_stack_pop(ctx, &a, &alen); va = script_read_num(a, alen);
        free(a); return script_push_num(ctx, va != 0 ? 1 : 0);
    case OP_BOOLAND:
        if (ctx->stack_depth < 2) return -1;
        script_stack_pop(ctx, &a, &alen); script_stack_pop(ctx, &b, &blen);
        va = script_read_num(a, alen); vb = script_read_num(b, blen);
        free(a); free(b); return script_push_num(ctx, (va != 0 && vb != 0) ? 1 : 0);
    case OP_BOOLOR:
        if (ctx->stack_depth < 2) return -1;
        script_stack_pop(ctx, &a, &alen); script_stack_pop(ctx, &b, &blen);
        va = script_read_num(a, alen); vb = script_read_num(b, blen);
        free(a); free(b); return script_push_num(ctx, (va != 0 || vb != 0) ? 1 : 0);
    case OP_NUMEQUAL:
        if (ctx->stack_depth < 2) return -1;
        script_stack_pop(ctx, &a, &alen); script_stack_pop(ctx, &b, &blen);
        va = script_read_num(a, alen); vb = script_read_num(b, blen);
        free(a); free(b); return script_push_num(ctx, va == vb ? 1 : 0);
    case OP_NUMEQUALVERIFY:
        if (ctx->stack_depth < 2) return -1;
        script_stack_pop(ctx, &a, &alen); script_stack_pop(ctx, &b, &blen);
        va = script_read_num(a, alen); vb = script_read_num(b, blen);
        free(a); free(b);
        if (va != vb) { ctx->verify_ok = 0; ctx->error = 1; return -1; } return 0;
    case OP_NUMNOTEQUAL:
        if (ctx->stack_depth < 2) return -1;
        script_stack_pop(ctx, &a, &alen); script_stack_pop(ctx, &b, &blen);
        va = script_read_num(a, alen); vb = script_read_num(b, blen);
        free(a); free(b); return script_push_num(ctx, va != vb ? 1 : 0);
    case OP_LESSTHAN:
        if (ctx->stack_depth < 2) return -1;
        script_stack_pop(ctx, &a, &alen); script_stack_pop(ctx, &b, &blen);
        va = script_read_num(a, alen); vb = script_read_num(b, blen);
        free(a); free(b); return script_push_num(ctx, va < vb ? 1 : 0);
    case OP_GREATERTHAN:
        if (ctx->stack_depth < 2) return -1;
        script_stack_pop(ctx, &a, &alen); script_stack_pop(ctx, &b, &blen);
        va = script_read_num(a, alen); vb = script_read_num(b, blen);
        free(a); free(b); return script_push_num(ctx, va > vb ? 1 : 0);
    case OP_LESSTHANOREQUAL:
        if (ctx->stack_depth < 2) return -1;
        script_stack_pop(ctx, &a, &alen); script_stack_pop(ctx, &b, &blen);
        va = script_read_num(a, alen); vb = script_read_num(b, blen);
        free(a); free(b); return script_push_num(ctx, va <= vb ? 1 : 0);
    case OP_GREATERTHANOREQUAL:
        if (ctx->stack_depth < 2) return -1;
        script_stack_pop(ctx, &a, &alen); script_stack_pop(ctx, &b, &blen);
        va = script_read_num(a, alen); vb = script_read_num(b, blen);
        free(a); free(b); return script_push_num(ctx, va >= vb ? 1 : 0);
    case OP_MIN:
        if (ctx->stack_depth < 2) return -1;
        script_stack_pop(ctx, &a, &alen); script_stack_pop(ctx, &b, &blen);
        va = script_read_num(a, alen); vb = script_read_num(b, blen);
        free(a); free(b); return script_push_num(ctx, va < vb ? va : vb);
    case OP_MAX:
        if (ctx->stack_depth < 2) return -1;
        script_stack_pop(ctx, &a, &alen); script_stack_pop(ctx, &b, &blen);
        va = script_read_num(a, alen); vb = script_read_num(b, blen);
        free(a); free(b); return script_push_num(ctx, va > vb ? va : vb);
    case OP_WITHIN:
        if (ctx->stack_depth < 3) return -1;
        script_stack_pop(ctx, &a, &alen); script_stack_pop(ctx, &b, &blen);
        script_stack_pop(ctx, &c, &clen);
        va = script_read_num(a, alen); vb = script_read_num(b, blen);
        vc = script_read_num(c, clen); free(a); free(b); free(c);
        return script_push_num(ctx, (va >= vb && va < vc) ? 1 : 0);
    case OP_SHA256:
        if (ctx->stack_depth < 1) return -1;
        script_stack_pop(ctx, &a, &alen);
        { uint8_t hash[32]; uint8_t *dest = malloc(32);
          SHA256(a, alen, hash); free(a);
          memcpy(dest, hash, 32); return script_stack_push(ctx, dest, 32); free(dest); }
    case OP_HASH256:
        if (ctx->stack_depth < 1) return -1;
        script_stack_pop(ctx, &a, &alen);
        { uint8_t h1[32], h2[32]; uint8_t *dest = malloc(32);
          SHA256(a, alen, h1); SHA256(h1, 32, h2); free(a);
          memcpy(dest, h2, 32); return script_stack_push(ctx, dest, 32); free(dest); }
    case OP_HASH160:
        if (ctx->stack_depth < 1) return -1;
        script_stack_pop(ctx, &a, &alen);
        { uint8_t sha[32], ripe[20]; uint8_t *dest = malloc(20);
          SHA256(a, alen, sha); RIPEMD160(sha, 32, ripe); free(a);
          memcpy(dest, ripe, 20); return script_stack_push(ctx, dest, 20); free(dest); }
    case OP_CHECKLOCKTIMEVERIFY:
        if (ctx->stack_depth < 1) return -1;
        script_stack_top(ctx, &a, &alen);
        { va = script_read_num(a, alen);
          if (va < 0) return -1;
          if ((uint32_t)ctx->locktime < (uint32_t)va)
          { ctx->verify_ok = 0; ctx->error = 1; return -1; }
          script_stack_pop(ctx, NULL, NULL); return 0; }
    case OP_CHECKSEQUENCEVERIFY:
        if (ctx->stack_depth < 1) return -1;
        script_stack_top(ctx, &a, &alen);
        { va = script_read_num(a, alen);
          if (va < 0) return -1;
          if (ctx->sequence < (uint32_t)va)
          { ctx->verify_ok = 0; ctx->error = 1; return -1; }
          script_stack_pop(ctx, NULL, NULL); return 0; }
    case OP_CHECKSIG:
        if (ctx->stack_depth < 2) return -1;
        script_stack_pop(ctx, NULL, NULL); script_stack_pop(ctx, NULL, NULL);
        return script_push_num(ctx, 1);
    case OP_CHECKSIGVERIFY:
        if (ctx->stack_depth < 2) return -1;
        script_stack_pop(ctx, NULL, NULL); script_stack_pop(ctx, NULL, NULL);
        script_push_num(ctx, 1);
        script_stack_pop(ctx, &a, &alen);
        eq = (script_read_num(a, alen) != 0); free(a);
        if (!eq) { ctx->verify_ok = 0; ctx->error = 1; return -1; } return 0;
    case OP_CHECKMULTISIG:
    case OP_CHECKMULTISIGVERIFY:
        if (ctx->stack_depth < 3) return -1;
        script_stack_pop(ctx, NULL, NULL);
        if (opcode == OP_CHECKSIGVERIFY) { /* consume pubkey count */ }
        script_push_num(ctx, 1);
        if (opcode == OP_CHECKMULTISIGVERIFY) {
            script_stack_pop(ctx, &a, &alen);
            eq = (script_read_num(a, alen) != 0); free(a);
            if (!eq) { ctx->verify_ok = 0; ctx->error = 1; return -1; }
        } return 0;
    default: return 0;
    }
}

int script_eval(script_context *ctx, const uint8_t *script, size_t len) {
    if (!ctx || !script) return -1;
    ctx->script = script; ctx->script_len = len;
    ctx->pc = 0; ctx->op_count = 0;
    while (ctx->pc < ctx->script_len && ctx->op_count < SCRIPT_MAX_OPS) {
        uint8_t opcode = ctx->script[ctx->pc++];
        int exec = script_cond_true(ctx);
        if (opcode <= 0x4b) {
            size_t n = (size_t)opcode;
            if (ctx->pc + n > ctx->script_len) return -1;
            if (exec) { if (script_stack_push(ctx, ctx->script + ctx->pc, n) != 0) return -1; }
            ctx->pc += n; ctx->op_count++; continue;
        }
        size_t push_len = 0;
        switch (opcode) {
        case OP_PUSHDATA1:
            if (ctx->pc + 1 > ctx->script_len) return -1;
            push_len = ctx->script[ctx->pc++];
            if (ctx->pc + push_len > ctx->script_len) return -1;
            if (exec) script_stack_push(ctx, ctx->script + ctx->pc, push_len);
            ctx->pc += push_len; break;
        case OP_PUSHDATA2:
            if (ctx->pc + 2 > ctx->script_len) return -1;
            push_len = ((size_t)ctx->script[ctx->pc]) | ((size_t)ctx->script[ctx->pc+1] << 8);
            ctx->pc += 2;
            if (ctx->pc + push_len > ctx->script_len) return -1;
            if (exec) script_stack_push(ctx, ctx->script + ctx->pc, push_len);
            ctx->pc += push_len; break;
        case OP_PUSHDATA4:
            if (ctx->pc + 4 > ctx->script_len) return -1;
            push_len = ((size_t)ctx->script[ctx->pc]) | ((size_t)ctx->script[ctx->pc+1] << 8) |
                       ((size_t)ctx->script[ctx->pc+2] << 16) | ((size_t)ctx->script[ctx->pc+3] << 24);
            ctx->pc += 4;
            if (ctx->pc + push_len > ctx->script_len) return -1;
            if (exec) script_stack_push(ctx, ctx->script + ctx->pc, push_len);
            ctx->pc += push_len; break;
        default:
            if (script_eval_op(ctx, opcode) != 0 && ctx->error) return -1;
            break;
        }
        ctx->op_count++;
    }
    if (ctx->error) return -1;
    if (ctx->stack_depth > 0) {
        uint8_t *top = NULL; size_t tlen = 0;
        script_stack_top(ctx, &top, &tlen);
        if (top && script_read_num(top, tlen) != 0) return 0;
    }
    return ctx->verify_ok ? 0 : -1;
}

int script_eval_sig_pub(const script_context *ctx,
                         const uint8_t *scriptSig, size_t sig_len,
                         const uint8_t *scriptPubKey, size_t pub_len,
                         int *valid) {
    if (!ctx || !scriptSig || !scriptPubKey || !valid) return -1;
    script_context sc;
    if (script_ctx_init(&sc) != 0) return -1;
    *valid = 0;
    if (script_eval(&sc, scriptSig, sig_len) == 0 &&
        script_eval(&sc, scriptPubKey, pub_len) == 0)
        *valid = 1;
    script_ctx_free(&sc);
    return 0;
}

/* ?? Script builder ?? */

int script_builder_init(script_builder *b, size_t capacity) {
    if (!b || capacity == 0) return -1;
    b->script = calloc(capacity, 1);
    if (!b->script) return -1;
    b->len = 0; b->capacity = capacity;
    return 0;
}

void script_builder_free(script_builder *b) {
    if (!b) return;
    free(b->script);
    memset(b, 0, sizeof(script_builder));
}

static int script_builder_write(script_builder *b, const uint8_t *data, size_t len) {
    if (b->len + len > b->capacity) {
        size_t nc = b->capacity * 2;
        if (nc < b->len + len) nc = b->len + len + 256;
        uint8_t *tmp = realloc(b->script, nc);
        if (!tmp) return -1;
        b->script = tmp; b->capacity = nc;
    }
    memcpy(b->script + b->len, data, len); b->len += len;
    return 0;
}

int script_builder_push_op(script_builder *b, script_opcode op) {
    uint8_t byte = (uint8_t)op;
    return script_builder_write(b, &byte, 1);
}

int script_builder_push_data(script_builder *b, const uint8_t *data, size_t len) {
    if (!data || len == 0) { uint8_t z = OP_0; return script_builder_write(b, &z, 1); }
    if (len < (size_t)OP_PUSHDATA1) {
        script_builder_write(b, (const uint8_t *)&len, 1);
        return script_builder_write(b, data, len);
    }
    if (len <= 0xFF) {
        uint8_t h[2] = { OP_PUSHDATA1, (uint8_t)len };
        script_builder_write(b, h, 2);
        return script_builder_write(b, data, len);
    }
    if (len <= 0xFFFF) {
        uint8_t h[3] = { OP_PUSHDATA2, (uint8_t)len, (uint8_t)(len >> 8) };
        script_builder_write(b, h, 3);
        return script_builder_write(b, data, len);
    }
    uint8_t h[5] = { OP_PUSHDATA4, (uint8_t)len, (uint8_t)(len >> 8),
                     (uint8_t)(len >> 16), (uint8_t)(len >> 24) };
    script_builder_write(b, h, 5);
    return script_builder_write(b, data, len);
}

int script_builder_push_int(script_builder *b, int64_t val) {
    if (val == -1) return script_builder_push_op(b, OP_1NEGATE);
    if (val == 0)  return script_builder_push_op(b, OP_0);
    if (val >= 1 && val <= 16) return script_builder_push_op(b, OP_1 + (int)(val - 1));
    uint8_t buf[8]; int neg = (val < 0);
    if (neg) val = -val;
    size_t len = 0;
    while (val > 0 && len < 8) { buf[len++] = (uint8_t)(val & 0xFF); val >>= 8; }
    if (neg) {
        if (buf[len-1] < 0x80) buf[len-1] |= 0x80; else buf[len++] = 0x80;
    }
    return script_builder_push_data(b, buf, len);
}

/* ?? Standard templates (L7: Applications) ?? */

/* P2PKH: Pay-to-Public-Key-Hash */
int script_p2pkh_lock(script_builder *b, const uint8_t pubkey_hash[20]) {
    if (!b || !pubkey_hash) return -1;
    script_builder_push_op(b, OP_DUP);
    script_builder_push_op(b, OP_HASH160);
    script_builder_push_data(b, pubkey_hash, 20);
    script_builder_push_op(b, OP_EQUALVERIFY);
    script_builder_push_op(b, OP_CHECKSIG);
    return 0;
}

int script_p2pkh_unlock(script_builder *b, const uint8_t *sig, size_t sig_len,
                          const uint8_t *pubkey, size_t pubkey_len) {
    if (!b || !sig || !pubkey) return -1;
    script_builder_push_data(b, sig, sig_len);
    script_builder_push_data(b, pubkey, pubkey_len);
    return 0;
}

/* P2SH: Pay-to-Script-Hash (BIP 16) */
int script_p2sh_redeem(script_builder *b, const uint8_t redeem_script_hash[20],
                         const uint8_t *redeem_script, size_t redeem_len) {
    if (!b || !redeem_script_hash || !redeem_script) return -1;
    (void)redeem_script_hash;
    script_builder_push_data(b, redeem_script, redeem_len);
    return 0;
}

/* Multi-signature (BIP 11): m-of-n */
int script_multisig_lock(script_builder *b, int m, const uint8_t **pubkeys,
                           const size_t *pk_lens, int n) {
    if (!b || !pubkeys || !pk_lens || m < 1 || m > n || n < 1 || n > 15) return -1;
    script_builder_push_int(b, m);
    for (int i = 0; i < n; i++)
        script_builder_push_data(b, pubkeys[i], pk_lens[i]);
    script_builder_push_int(b, n);
    script_builder_push_op(b, OP_CHECKMULTISIG);
    return 0;
}

/* CheckLockTimeVerify (BIP 65) */
int script_cltv_lock(script_builder *b, uint32_t locktime, const uint8_t pubkey_hash[20]) {
    if (!b || !pubkey_hash) return -1;
    script_builder_push_int(b, (int64_t)locktime);
    script_builder_push_op(b, OP_CHECKLOCKTIMEVERIFY);
    script_builder_push_op(b, OP_DROP);
    script_builder_push_op(b, OP_DUP);
    script_builder_push_op(b, OP_HASH160);
    script_builder_push_data(b, pubkey_hash, 20);
    script_builder_push_op(b, OP_EQUALVERIFY);
    script_builder_push_op(b, OP_CHECKSIG);
    return 0;
}

/* HTLC: Hash Time-Locked Contract (Lightning Network) */
int script_htlc_lock(script_builder *b, const uint8_t hash[SCRIPT_HASH_LEN],
                       const uint8_t pubkey_hash[20],
                       const uint8_t revoke_pubkey_hash[20], uint32_t timeout) {
    if (!b || !hash || !pubkey_hash || !revoke_pubkey_hash) return -1;
    script_builder_push_op(b, OP_IF);
    script_builder_push_op(b, OP_SHA256);
    script_builder_push_data(b, hash, SCRIPT_HASH_LEN);
    script_builder_push_op(b, OP_EQUALVERIFY);
    script_builder_push_op(b, OP_DUP);
    script_builder_push_op(b, OP_HASH160);
    script_builder_push_data(b, pubkey_hash, 20);
    script_builder_push_op(b, OP_ELSE);
    script_builder_push_int(b, (int64_t)timeout);
    script_builder_push_op(b, OP_CHECKLOCKTIMEVERIFY);
    script_builder_push_op(b, OP_DROP);
    script_builder_push_op(b, OP_DUP);
    script_builder_push_op(b, OP_HASH160);
    script_builder_push_data(b, revoke_pubkey_hash, 20);
    script_builder_push_op(b, OP_ENDIF);
    script_builder_push_op(b, OP_CHECKSIG);
    return 0;
}

/* ?? Disassembler ?? */

char *script_disasm_single(uint8_t opcode) {
    static char buf[32];
    if (opcode == OP_0) { snprintf(buf, sizeof(buf), "OP_0"); return buf; }
    if (opcode >= OP_1 && opcode <= OP_16) {
        snprintf(buf, sizeof(buf), "OP_%d", opcode - OP_1 + 1); return buf;
    }
    switch (opcode) {
    case OP_PUSHDATA1: return "OP_PUSHDATA1";
    case OP_PUSHDATA2: return "OP_PUSHDATA2";
    case OP_PUSHDATA4: return "OP_PUSHDATA4";
    case OP_1NEGATE:   return "OP_1NEGATE";
    case OP_IF: return "OP_IF"; case OP_NOTIF: return "OP_NOTIF";
    case OP_ELSE: return "OP_ELSE"; case OP_ENDIF: return "OP_ENDIF";
    case OP_VERIFY: return "OP_VERIFY"; case OP_RETURN: return "OP_RETURN";
    case OP_TOALTSTACK: return "OP_TOALTSTACK";
    case OP_FROMALTSTACK: return "OP_FROMALTSTACK";
    case OP_DROP: return "OP_DROP"; case OP_DUP: return "OP_DUP";
    case OP_NIP: return "OP_NIP"; case OP_OVER: return "OP_OVER";
    case OP_PICK: return "OP_PICK"; case OP_ROLL: return "OP_ROLL";
    case OP_SWAP: return "OP_SWAP"; case OP_TUCK: return "OP_TUCK";
    case OP_2DROP: return "OP_2DROP"; case OP_2DUP: return "OP_2DUP";
    case OP_3DUP: return "OP_3DUP"; case OP_2OVER: return "OP_2OVER";
    case OP_2SWAP: return "OP_2SWAP"; case OP_SIZE: return "OP_SIZE";
    case OP_EQUAL: return "OP_EQUAL";
    case OP_EQUALVERIFY: return "OP_EQUALVERIFY";
    case OP_1ADD: return "OP_1ADD"; case OP_1SUB: return "OP_1SUB";
    case OP_NEGATE: return "OP_NEGATE"; case OP_ABS: return "OP_ABS";
    case OP_NOT: return "OP_NOT"; case OP_0NOTEQUAL: return "OP_0NOTEQUAL";
    case OP_ADD: return "OP_ADD"; case OP_SUB: return "OP_SUB";
    case OP_BOOLAND: return "OP_BOOLAND"; case OP_BOOLOR: return "OP_BOOLOR";
    case OP_NUMEQUAL: return "OP_NUMEQUAL";
    case OP_NUMEQUALVERIFY: return "OP_NUMEQUALVERIFY";
    case OP_NUMNOTEQUAL: return "OP_NUMNOTEQUAL";
    case OP_LESSTHAN: return "OP_LESSTHAN";
    case OP_GREATERTHAN: return "OP_GREATERTHAN";
    case OP_LESSTHANOREQUAL: return "OP_LESSTHANOREQUAL";
    case OP_GREATERTHANOREQUAL: return "OP_GREATERTHANOREQUAL";
    case OP_MIN: return "OP_MIN"; case OP_MAX: return "OP_MAX";
    case OP_WITHIN: return "OP_WITHIN";
    case OP_RIPEMD160: return "OP_RIPEMD160"; case OP_SHA1: return "OP_SHA1";
    case OP_SHA256: return "OP_SHA256"; case OP_HASH160: return "OP_HASH160";
    case OP_HASH256: return "OP_HASH256";
    case OP_CHECKSIG: return "OP_CHECKSIG";
    case OP_CHECKSIGVERIFY: return "OP_CHECKSIGVERIFY";
    case OP_CHECKMULTISIG: return "OP_CHECKMULTISIG";
    case OP_CHECKMULTISIGVERIFY: return "OP_CHECKMULTISIGVERIFY";
    case OP_CHECKLOCKTIMEVERIFY: return "OP_CHECKLOCKTIMEVERIFY";
    case OP_CHECKSEQUENCEVERIFY: return "OP_CHECKSEQUENCEVERIFY";
    default: snprintf(buf, sizeof(buf), "0x%02x", opcode); return buf;
    }
}

void script_disasm(const uint8_t *script, size_t len, char *buf, size_t bufsz) {
    if (!script || !buf || bufsz == 0) return;
    buf[0] = '\0';
    size_t off = 0, pos = 0;
    while (pos < len && off < bufsz - 32) {
        uint8_t opcode = script[pos];
        if (opcode <= 0x4b) {
            size_t n = opcode;
            off += (size_t)snprintf(buf + off, bufsz - off, "%zu ", n);
            for (size_t j = 0; j < n && pos + 1 + j < len && off < bufsz - 4; j++)
                off += (size_t)snprintf(buf + off, bufsz - off, "%02x", script[pos + 1 + j]);
            buf[off++] = ' '; pos += 1 + n;
        } else if (opcode == OP_PUSHDATA1) {
            size_t n = script[pos + 1];
            off += (size_t)snprintf(buf + off, bufsz - off, "PUSHDATA1(%zu) ", n);
            pos += 2 + n;
        } else {
            char *name = script_disasm_single(opcode);
            off += (size_t)snprintf(buf + off, bufsz - off, "%s ", name);
            pos++;
        }
    }
}
