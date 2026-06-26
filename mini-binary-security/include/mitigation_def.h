#ifndef MITIGATION_DEF_H
#define MITIGATION_DEF_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Mitigation flags (bitmask) ── */
typedef enum {
    MITIG_NONE       = 0,
    MITIG_ASLR       = 1 << 0,  /* Address Space Layout Randomization  */
    MITIG_NX         = 1 << 1,  /* Non-eXecutable stack/heap           */
    MITIG_CANARY     = 1 << 2,  /* Stack canary (__stack_chk_fail)     */
    MITIG_RELRO      = 1 << 3,  /* Read-Only Relocations (partial)     */
    MITIG_FULL_RELRO = 1 << 4,  /* Full RELRO (BIND_NOW)               */
    MITIG_PIE        = 1 << 5,  /* Position Independent Executable     */
    MITIG_FORTIFY    = 1 << 6,  /* FORTIFY_SOURCE                      */
    MITIG_CFI        = 1 << 7,  /* Control Flow Integrity              */
    MITIG_CET_IBT    = 1 << 8,  /* Intel CET - Indirect Branch Tracking */
    MITIG_CET_SS     = 1 << 9,  /* Intel CET - Shadow Stack            */
    MITIG_CLANG_CFI  = 1 << 10, /* Clang CFI                           */
    MITIG_SAFESTACK  = 1 << 11, /* SafeStack (separate stack)          */
    MITIG_SHADOWSTACK= 1 << 12, /* Software shadow stack               */
    MITIG_PAUTH      = 1 << 13, /* ARM Pointer Authentication          */
    MITIG_MTE        = 1 << 14, /* ARM Memory Tagging Extension        */
    MITIG_SEHOP      = 1 << 15, /* Structured Exception Handler Overwrite Protection */
} mitigation_t;

/* ── Detailed ASLR info ── */
typedef struct {
    bool stack_rand;
    bool heap_rand;
    bool libc_rand;
    bool pie_rand;
    bool vdso_rand;
    uint8_t entropy_stack;    /* bits of entropy                         */
    uint8_t entropy_libc;
    uint8_t entropy_heap;
} aslr_info_t;

/* ── NX info ── */
typedef struct {
    bool stack_exec;
    bool heap_exec;
    bool data_exec;
    bool rodata_exec;
    bool text_writable;
} nx_info_t;

/* ── Canary info ── */
typedef struct {
    bool     present;
    bool     terminator;       /* canary ends with null byte             */
    uint64_t value;            /* mock value for demonstration           */
    bool     per_function;
    bool     re_randomize_on_fork;
} canary_info_t;

/* ── RELRO info ── */
typedef struct {
    bool partial;              /* .got.plt read-only after init          */
    bool full;                 /* .got entirely read-only, BIND_NOW      */
    bool lazy_binding;         /* lazy binding enabled (partial RELRO)    */
} relro_info_t;

/* ── CFI info ── */
typedef struct {
    bool shadow_stack;         /* hardware or software shadow stack      */
    bool ibt;                  /* indirect branch tracking (CET)         */
    bool clang_cfi;            /* clang forward-edge CFI                 */
    bool safe_stack;           /* dual stack layout                      */
    bool vtable_protection;    /* protected virtual table calls          */
} cfi_info_t;

/* ── PIE info ── */
typedef struct {
    bool     enabled;
    uint64_t base_addr;
    bool     aslr_compatible;
} pie_info_t;

/* ── Full security profile ── */
typedef enum {
    SEC_LVL_LOW    = 0,   /* few or no mitigations                */
    SEC_LVL_MEDIUM = 1,   /* basic mitigations (ASLR, NX, Canary) */
    SEC_LVL_HIGH   = 2,   /* + PIE, Full RELRO                    */
    SEC_LVL_MAX    = 3,   /* + CFI, CET, SafeStack                 */
} security_level_t;

typedef struct {
    mitigation_t     flags;
    aslr_info_t      aslr;
    nx_info_t        nx;
    canary_info_t    canary;
    relro_info_t     relro;
    pie_info_t       pie;
    cfi_info_t       cfi;
    security_level_t level;
    bool             fortify_source;
    char             compiler[32];
    char             arch[16];
} security_profile_t;

/* ── Bypass difficulty ── */
typedef enum {
    BYPASS_TRIVIAL    = 0,
    BYPASS_EASY       = 1,
    BYPASS_MODERATE   = 2,
    BYPASS_HARD       = 3,
    BYPASS_VERY_HARD  = 4,
    BYPASS_IMPOSSIBLE = 5,
} bypass_difficulty_t;

/* ── Attack technique vs mitigation matrix ── */
typedef struct {
    const char        *technique;
    mitigation_t       requires_absent;
    bypass_difficulty_t difficulty;
    const char        *bypass_method;
} attack_technique_t;

/* ── API ── */

/* Detection */
security_profile_t mitigation_detect(void);
void               mitigation_profile_init(security_profile_t *p);
bool               mitigation_check_aslr(security_profile_t *p);
bool               mitigation_check_nx(security_profile_t *p);
bool               mitigation_check_canary(security_profile_t *p);
bool               mitigation_check_relro(security_profile_t *p);
bool               mitigation_check_pie(security_profile_t *p);
bool               mitigation_check_cfi(security_profile_t *p);

/* Analysis */
security_level_t   mitigation_assess_level(const security_profile_t *p);
bypass_difficulty_t mitigation_bypass_difficulty(const security_profile_t *p,
                                                  const char *technique);
bool               mitigation_is_protected(const security_profile_t *p,
                                            mitigation_t check);

/* Display */
void               mitigation_print_profile(const security_profile_t *p);
void               mitigation_print_flags(mitigation_t flags);
const char        *mitigation_flag_name(mitigation_t flag);
const char        *security_level_name(security_level_t lvl);
const char        *bypass_difficulty_name(bypass_difficulty_t d);

/* Hardening recommendations */
void               mitigation_suggest(const security_profile_t *p);
uint32_t           mitigation_score(const security_profile_t *p);

#ifdef __cplusplus
}
#endif

#endif /* MITIGATION_DEF_H */
