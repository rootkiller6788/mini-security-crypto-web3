#ifndef BUFFER_OVERFLOW_H
#define BUFFER_OVERFLOW_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Stack frame layout (x86_64) ── */
typedef struct {
    char     buf[64];
    uint64_t saved_rbp;
    uint64_t return_addr;
} stack_frame_t;

/* ── glibc-style malloc chunk metadata ── */
typedef struct malloc_chunk {
    size_t               prev_size;
    size_t               size;       /* size | flags (PREV_INUSE, IS_MMAPPED, NON_MAIN_ARENA) */
    struct malloc_chunk *fd;         /* forward pointer  (bins) */
    struct malloc_chunk *bk;         /* backward pointer (bins) */
} malloc_chunk_t;

/* ── Use-after-free tracker ── */
typedef struct {
    void    *ptr;
    size_t   size;
    bool     freed;
    uint32_t id;
} uaf_entry_t;

typedef struct {
    uaf_entry_t entries[256];
    uint32_t    next_id;
    uint32_t    count;
} uaf_tracker_t;

/* ── Double-free tracker ── */
typedef struct {
    void    *freed_ptrs[128];
    uint32_t count;
} df_tracker_t;

/* ── Integer overflow flags ── */
typedef enum {
    INT_OVF_NONE  = 0,
    INT_OVF_ADD   = 1,
    INT_OVF_SUB   = 2,
    INT_OVF_MUL   = 3,
    INT_OVF_WRAP  = 4,
} int_ovf_type_t;

typedef struct {
    int_ovf_type_t type;
    int64_t        a, b;
    int64_t        result;
    bool           sign;
} int_ovf_result_t;

/* ── Shellcode context ── */
typedef struct {
    uint8_t *payload;
    size_t   payload_len;
    size_t   nop_sled_len;
    uint64_t target_addr;
    uint64_t ret_addr;
} shellcode_ctx_t;

/* ── Buffer overflow simulation ── */
typedef enum {
    BO_STACK_BASIC     = 0,
    BO_STACK_CANARY    = 1,
    BO_HEAP_UNLINK     = 2,
    BO_HEAP_FASTBIN    = 3,
    BO_OFF_BY_ONE      = 4,
    BO_INTEGER_WRAP    = 5,
    BO_FORMAT_N        = 6,
    BO_UAF             = 7,
    BO_DOUBLE_FREE     = 8,
} bo_type_t;

typedef struct {
    bo_type_t type;
    size_t    buf_size;
    size_t    input_len;
    char     *input;
    bool      canary_enabled;
    bool      nx_enabled;
    bool      detected;
} bo_result_t;

/* ── API ── */

/* Integer overflow detection */
bool        int_ovf_check_add_int32(int32_t a, int32_t b);
bool        int_ovf_check_add_uint32(uint32_t a, uint32_t b);
bool        int_ovf_check_mul_size(size_t a, size_t b);
bool        int_ovf_check_add_size(size_t a, size_t b);
int_ovf_result_t int_ovf_analyze(int64_t a, int64_t b, char op);

/* Stack overflow */
void        bo_stack_overflow_sim(const char *input, size_t len);
void        bo_stack_canary_sim(const char *input, size_t len);
void        bo_return_to_addr(uint64_t ret_addr);

/* Heap overflow */
void        bo_heap_overflow_sim(size_t alloc_sz, const char *input, size_t len);
void        bo_heap_unlink_attack_sim(void);
void        bo_heap_fastbin_dup_sim(void);

/* Use-after-free */
void        uaf_tracker_init(uaf_tracker_t *t);
void        uaf_tracker_add(uaf_tracker_t *t, void *ptr, size_t sz);
void        uaf_tracker_mark_free(uaf_tracker_t *t, void *ptr);
bool        uaf_tracker_is_dangling(const uaf_tracker_t *t, void *ptr);
void        uaf_simulate(void);

/* Double free */
void        df_tracker_init(df_tracker_t *t);
bool        df_tracker_check(df_tracker_t *t, void *ptr);
void        df_simulate(void);

/* Off-by-one */
void        off_by_one_null_byte(char *buf, size_t off, size_t len);
void        off_by_one_sim(void);

/* Format string %n write */
void        fmt_n_write_sim(uint32_t *target, uint32_t value);
void        fmt_leak_sim(const void *addr);

/* Shellcode helpers */
void        shellcode_build_nop_sled(char *buf, size_t sled_len);
void        shellcode_embed(char *buf, const uint8_t *sc, size_t sc_len);

#ifdef __cplusplus
}
#endif

#endif /* BUFFER_OVERFLOW_H */
