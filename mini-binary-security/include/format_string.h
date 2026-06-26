#ifndef FORMAT_STRING_H
#define FORMAT_STRING_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Format specifier types ── */
typedef enum {
    FMT_SPEC_NONE   = 0,
    FMT_SPEC_INT    = 1,   /* %d %i %u %x %X %o                    */
    FMT_SPEC_PTR    = 2,   /* %p                                    */
    FMT_SPEC_STR    = 3,   /* %s                                    */
    FMT_SPEC_CHAR   = 4,   /* %c                                    */
    FMT_SPEC_NWRITE = 5,   /* %n (write)                            */
    FMT_SPEC_LONG   = 6,   /* %ld %lu %lx                           */
    FMT_SPEC_LLONG  = 7,   /* %lld %llu %llx                        */
    FMT_SPEC_FLOAT  = 8,   /* %f %e %g                              */
    FMT_SPEC_WIDTH  = 9,   /* %* (dynamic width)                    */
    FMT_SPEC_COUNT  = 10,
} fmt_spec_type_t;

/* ── Parsed format specifier ── */
typedef struct {
    fmt_spec_type_t type;
    int             arg_position;   /* 0 = normal, N = %N$     */
    int             width;
    int             precision;
    bool            flag_plus;
    bool            flag_minus;
    bool            flag_space;
    bool            flag_zero;
    bool            flag_alt;       /* # flag                   */
    char            length_mod;     /* h hh l ll z t j         */
    int             bytes_written_at; /* %n write target        */
} fmt_spec_t;

/* ── Format string parse result ── */
#define FMT_MAX_SPECS 64
typedef struct {
    fmt_spec_t specs[FMT_MAX_SPECS];
    int        count;
    const char *str;
    bool       has_n_write;        /* contains %n               */
    bool       has_leak;           /* contains %p %x etc        */
} fmt_parse_result_t;

/* ── Format string attack primitives ── */
typedef enum {
    ATTACK_LEAK_STACK   = 0, /* leak stack values via %p        */
    ATTACK_LEAK_LIBC    = 1, /* leak libc address for ASLR bypass */
    ATTACK_WRITE_BYTE   = 2, /* %hhn write single byte           */
    ATTACK_WRITE_SHORT  = 3, /* %hn write two bytes              */
    ATTACK_WRITE_INT    = 4, /* %n write four bytes              */
    ATTACK_WRITE_LLONG  = 5, /* %lln write eight bytes           */
    ATTACK_GOT_OVERWRITE= 6, /* overwrite GOT entry              */
    ATTACK_DTOR_OVERWRITE=7, /* overwrite .fini_array            */
} fmt_attack_type_t;

/* ── Write primitive ── */
typedef struct {
    void     *target_addr;
    uint32_t  target_value;
    bool      incremental;    /* write in multiple %hhn steps     */
    int       num_writes;     /* number of %hhn writes needed     */
} fmt_write_primitive_t;

/* ── Attack specification ── */
typedef struct {
    fmt_attack_type_t  type;
    int                offset;         /* format string arg offset on stack  */
    void              *write_addr;     /* address to overwrite               */
    uint64_t           write_value;    /* value to write                     */
    bool               use_dpa;        /* use direct parameter access        */
    int                dpa_pos;        /* position for $ modifier            */
} fmt_attack_spec_t;

/* ── Generated payload ── */
#define FMT_PAYLOAD_MAX 512
typedef struct {
    char     payload[FMT_PAYLOAD_MAX];
    size_t   len;
    bool     valid;
} fmt_payload_t;

/* ── GOT entry ── */
typedef struct {
    const char *name;
    uint64_t    address;
    uint64_t    original_value;
    uint64_t    target_value;   /* overwrite to this                    */
} fmt_got_entry_t;

/* ── Printf family internal simulation ── */
typedef struct {
    va_list    args;
    int        char_count;
    bool       n_triggered;
    void      *n_target;
    uint32_t   n_value;
} fmt_printf_ctx_t;

/* ── API ── */

/* Format string parsing */
void        fmt_parse_result_init(fmt_parse_result_t *r);
void        fmt_parse(const char *format_str, fmt_parse_result_t *r);
void        fmt_print_spec(const fmt_spec_t *s);
void        fmt_print_parse_result(const fmt_parse_result_t *r);

/* Attack payload generation */
fmt_payload_t fmt_build_leak_payload(int offset);
fmt_payload_t fmt_build_write_payload(int offset, void *addr, uint64_t val);
fmt_payload_t fmt_build_dpa_write(int dpa_pos, void *addr, uint64_t val);
fmt_payload_t fmt_build_got_overwrite(int offset, fmt_got_entry_t *got, int count);
fmt_payload_t fmt_build_stack_leak(int offset, int num_leaks);

/* Write primitive calculation */
void        fmt_calc_write_primitive(uint64_t target_val,
                                      fmt_write_primitive_t *wp);
void        fmt_calc_width_bytes(uint32_t *vals, int count,
                                  char *buf, size_t buf_len);

/* Direct Parameter Access helpers */
int         fmt_dpa_calc_offset(const char *fmt, int param_num);
bool        fmt_dpa_is_supported(void);

/* Printf simulation (safe) */
void        fmt_simulate_printf(const char *fmt, ...);
void        fmt_simulate_vprintf(const char *fmt, va_list ap);
uint32_t    fmt_simulate_read_n(void *target, const char *fmt, int offset);

/* Leak simulation */
void        fmt_simulate_leak_stack(int offset, int count);
uint64_t    fmt_simulate_leak_addr(int offset);
void        fmt_got_leak_simulate(const char *func_name, int offset);

/* Payload utilities */
int         fmt_calc_pad_bytes(uint32_t current, uint32_t target);
void        fmt_embed_address(char *buf, void *addr, size_t buf_len);
bool        fmt_payload_has_null(const char *payload);

#ifdef __cplusplus
}
#endif

#endif /* FORMAT_STRING_H */
