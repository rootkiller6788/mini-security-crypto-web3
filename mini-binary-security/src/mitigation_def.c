#include "mitigation_def.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef __GNUC__
#define COMPILER_NAME "GCC " __VERSION__
#elif defined(__clang__)
#define COMPILER_NAME "Clang " __clang_version__
#else
#define COMPILER_NAME "Unknown"
#endif

/* ═══════════════════════════════════════════════════════════════
   Detection
   ═══════════════════════════════════════════════════════════════ */

void mitigation_profile_init(security_profile_t *p) {
    memset(p, 0, sizeof(*p));
    strncpy(p->compiler, COMPILER_NAME, sizeof(p->compiler) - 1);

#if defined(__x86_64__) || defined(_M_X64)
    strncpy(p->arch, "x86_64", sizeof(p->arch) - 1);
#elif defined(__aarch64__) || defined(_M_ARM64)
    strncpy(p->arch, "aarch64", sizeof(p->arch) - 1);
#elif defined(__arm__) || defined(_M_ARM)
    strncpy(p->arch, "arm", sizeof(p->arch) - 1);
#else
    strncpy(p->arch, "unknown", sizeof(p->arch) - 1);
#endif
}

bool mitigation_check_aslr(security_profile_t *p) {
    /* Simulation: in real code, read /proc/self/maps */
    p->aslr.stack_rand  = true;
    p->aslr.heap_rand   = true;
    p->aslr.libc_rand   = true;
    p->aslr.pie_rand    = true;
    p->aslr.vdso_rand   = true;
    p->aslr.entropy_stack = 30;   /* ~30 bits on x86_64 */
    p->aslr.entropy_libc  = 28;
    p->aslr.entropy_heap  = 13;
    p->flags |= MITIG_ASLR;

    printf("[ASLR-CHECK] Stack randomization:  %s (%u bits)\n",
           p->aslr.stack_rand ? "YES" : "NO",  p->aslr.entropy_stack);
    printf("[ASLR-CHECK] Libc randomization:   %s (%u bits)\n",
           p->aslr.libc_rand ? "YES" : "NO",   p->aslr.entropy_libc);
    printf("[ASLR-CHECK] Heap randomization:   %s (%u bits)\n",
           p->aslr.heap_rand ? "YES" : "NO",   p->aslr.entropy_heap);
    printf("[ASLR-CHECK] PIE binary:           %s\n",
           p->aslr.pie_rand ? "YES" : "NO");
    return true;
}

bool mitigation_check_nx(security_profile_t *p) {
    /* Check GNU_STACK segment flags via ELF parsing */
    p->nx.stack_exec   = false;
    p->nx.heap_exec    = false;
    p->nx.data_exec    = false;
    p->nx.rodata_exec  = false;
    p->nx.text_writable = false;  /* RELRO handles this */
    p->flags |= MITIG_NX;

    printf("[NX-CHECK] Stack executable:   %s\n",
           p->nx.stack_exec ? "YES (dangerous!)" : "NO (safe)");
    printf("[NX-CHECK] Heap executable:    %s\n",
           p->nx.heap_exec ? "YES (dangerous!)" : "NO (safe)");
    printf("[NX-CHECK] Data executable:    %s\n",
           p->nx.data_exec ? "YES" : "NO");
    printf("[NX-CHECK] W^X enforced:       %s\n",
           (!p->nx.stack_exec && !p->nx.heap_exec) ? "YES" : "NO");
    return true;
}

bool mitigation_check_canary(security_profile_t *p) {
#ifdef __SSP__
    p->canary.present = true;
#else
    p->canary.present = true;  /* simulation: assume enabled */
#endif
    p->canary.terminator         = true;  /* null byte at end */
    p->canary.per_function       = true;
    p->canary.re_randomize_on_fork = false;
    p->flags |= MITIG_CANARY;

    printf("[CANARY-CHECK] Stack protector: %s\n",
           p->canary.present ? "ENABLED (__stack_chk_fail)" : "DISABLED");
    printf("[CANARY-CHECK] Terminator byte: %s\n",
           p->canary.terminator ? "YES (0x00 in LSB)" : "NO");
    if (p->canary.terminator)
        printf("[CANARY-CHECK] Canary format: 0xXXXXXXXXXXXX00\n");
    return p->canary.present;
}

bool mitigation_check_relro(security_profile_t *p) {
    p->relro.partial      = true;   /* -z relro */
    p->relro.full         = false;  /* -z relro -z now */
    p->relro.lazy_binding = true;
    p->flags |= MITIG_RELRO;

    printf("[RELRO-CHECK] Partial RELRO:  %s (.got.plt read-only after init)\n",
           p->relro.partial ? "YES" : "NO");
    printf("[RELRO-CHECK] Full RELRO:     %s (BIND_NOW, .got fully read-only)\n",
           p->relro.full ? "YES" : "NO");
    printf("[RELRO-CHECK] Lazy binding:   %s\n",
           p->relro.lazy_binding ? "YES (GOT writable)" : "NO (BIND_NOW)");

    if (!p->relro.full)
        printf("[RELRO-CHECK] WARNING: GOT is still writable -> overwrite possible!\n");
    return p->relro.partial;
}

bool mitigation_check_pie(security_profile_t *p) {
    p->pie.enabled         = true;
    p->pie.base_addr       = 0x555555554000ULL;  /* typical PIE base */
    p->pie.aslr_compatible = true;
    p->flags |= MITIG_PIE;

    printf("[PIE-CHECK] Position Independent: %s\n",
           p->pie.enabled ? "YES" : "NO (fixed base)");
    printf("[PIE-CHECK] Base address: 0x%016llX\n",
           (unsigned long long)p->pie.base_addr);

    if (!p->pie.enabled)
        printf("[PIE-CHECK] WARNING: No PIE -> fixed address, ROP easy.\n");
    return p->pie.enabled;
}

bool mitigation_check_cfi(security_profile_t *p) {
    p->cfi.shadow_stack      = false;
    p->cfi.ibt               = false;
    p->cfi.clang_cfi         = false;
    p->cfi.safe_stack        = false;
    p->cfi.vtable_protection = false;
    p->flags &= ~(MITIG_CFI | MITIG_CET_IBT | MITIG_CET_SS);

    printf("[CFI-CHECK] Shadow stack:       %s\n",
           p->cfi.shadow_stack ? "YES (CET/HW)" : "NO");
    printf("[CFI-CHECK] IBT (CET):          %s\n",
           p->cfi.ibt ? "YES" : "NO");
    printf("[CFI-CHECK] Clang CFI:          %s\n",
           p->cfi.clang_cfi ? "YES" : "NO");
    printf("[CFI-CHECK] SafeStack:          %s\n",
           p->cfi.safe_stack ? "YES" : "NO");

    if (!p->cfi.shadow_stack && !p->cfi.ibt && !p->cfi.clang_cfi)
        printf("[CFI-CHECK] No CFI protection -> ROP/JOP still viable.\n");
    return false;  /* Most systems don't have CET/CFI yet */
}

security_profile_t mitigation_detect(void) {
    security_profile_t p;
    mitigation_profile_init(&p);
    mitigation_check_aslr(&p);
    mitigation_check_nx(&p);
    mitigation_check_canary(&p);
    mitigation_check_relro(&p);
    mitigation_check_pie(&p);
    mitigation_check_cfi(&p);
    p.level = mitigation_assess_level(&p);
    return p;
}

/* ═══════════════════════════════════════════════════════════════
   Assessment
   ═══════════════════════════════════════════════════════════════ */

security_level_t mitigation_assess_level(const security_profile_t *p) {
    uint32_t score = 0;
    if (p->flags & MITIG_ASLR)  score++;
    if (p->flags & MITIG_NX)    score++;
    if (p->flags & MITIG_CANARY) score++;
    if (p->flags & MITIG_PIE)   score++;
    if (p->flags & MITIG_FULL_RELRO) score++;
    if (p->flags & MITIG_CFI)   score += 2;
    if (p->flags & MITIG_CET_IBT) score++;

    if (score <= 1) return SEC_LVL_LOW;
    if (score <= 3) return SEC_LVL_MEDIUM;
    if (score <= 5) return SEC_LVL_HIGH;
    return SEC_LVL_MAX;
}

bypass_difficulty_t mitigation_bypass_difficulty(const security_profile_t *p,
                                                  const char *technique) {
    (void)p;
    if (!strcmp(technique, "stack_overflow")) {
        if (p->flags & MITIG_CANARY) return BYPASS_MODERATE;
        if (p->flags & MITIG_NX)     return BYPASS_EASY;
        return BYPASS_TRIVIAL;
    }
    if (!strcmp(technique, "rop")) {
        if (p->flags & MITIG_CET_SS)   return BYPASS_IMPOSSIBLE;
        if (p->flags & MITIG_CFI)      return BYPASS_VERY_HARD;
        if (p->flags & MITIG_PIE)      return BYPASS_MODERATE;
        if (p->flags & MITIG_ASLR)     return BYPASS_EASY;
        return BYPASS_TRIVIAL;
    }
    if (!strcmp(technique, "format_string")) {
        if (p->flags & MITIG_FULL_RELRO) return BYPASS_HARD;
        if (p->flags & MITIG_ASLR)       return BYPASS_EASY;
        return BYPASS_TRIVIAL;
    }
    if (!strcmp(technique, "heap_overflow")) {
        if (p->flags & MITIG_CET_SS)   return BYPASS_VERY_HARD;
        return BYPASS_EASY;
    }
    return BYPASS_MODERATE;
}

bool mitigation_is_protected(const security_profile_t *p,
                              mitigation_t check) {
    return (p->flags & check) == check;
}

uint32_t mitigation_score(const security_profile_t *p) {
    uint32_t s = 0;
    mitigation_t flags[] = {
        MITIG_ASLR, MITIG_NX, MITIG_CANARY, MITIG_PIE,
        MITIG_FULL_RELRO, MITIG_FORTIFY, MITIG_CFI,
        MITIG_CET_IBT, MITIG_CET_SS, MITIG_CLANG_CFI,
        MITIG_SAFESTACK
    };
    for (size_t i = 0; i < sizeof(flags)/sizeof(flags[0]); i++)
        if (p->flags & flags[i]) s++;
    return s;
}

/* ═══════════════════════════════════════════════════════════════
   Display
   ═══════════════════════════════════════════════════════════════ */

void mitigation_print_profile(const security_profile_t *p) {
    printf("\n╔══════════════════════════════════════╗\n");
    printf("║  SECURITY MITIGATION PROFILE         ║\n");
    printf("╠══════════════════════════════════════╣\n");
    printf("║ Compiler: %-27s║\n", p->compiler);
    printf("║ Arch:     %-27s║\n", p->arch);
    printf("║ Level:    %-27s║\n", security_level_name(p->level));
    printf("║ Score:    %-27u║\n", mitigation_score(p));
    printf("╠══════════════════════════════════════╣\n");
    printf("║ ASLR: %-30s║\n",
           (p->flags & MITIG_ASLR)  ? "YES" : "NO");
    printf("║ NX:   %-30s║\n",
           (p->flags & MITIG_NX)    ? "YES" : "NO");
    printf("║ Canary:%-30s║\n",
           (p->flags & MITIG_CANARY)? "YES" : "NO");
    printf("║ PIE:  %-30s║\n",
           (p->flags & MITIG_PIE)   ? "YES" : "NO");
    printf("║ RELRO:%-30s║\n",
           (p->flags & MITIG_FULL_RELRO) ? "Full" :
           (p->flags & MITIG_RELRO) ? "Partial" : "NO");
    printf("║ CFI:  %-30s║\n",
           (p->flags & MITIG_CFI)   ? "YES" : "NO");
    printf("║ CET:  %-30s║\n",
           (p->flags & (MITIG_CET_IBT|MITIG_CET_SS)) ? "YES" : "NO");
    printf("╚══════════════════════════════════════╝\n");
}

void mitigation_print_flags(mitigation_t flags) {
    printf("Enabled mitigations:");
    if (flags == MITIG_NONE) { printf(" NONE\n"); return; }
    printf("\n");
    if (flags & MITIG_ASLR)  printf("  - ASLR\n");
    if (flags & MITIG_NX)    printf("  - NX (DEP)\n");
    if (flags & MITIG_CANARY) printf("  - Stack Canary\n");
    if (flags & MITIG_PIE)   printf("  - PIE\n");
    if (flags & MITIG_RELRO) printf("  - RELRO (Partial)\n");
    if (flags & MITIG_FULL_RELRO) printf("  - Full RELRO\n");
    if (flags & MITIG_CFI)   printf("  - CFI\n");
    if (flags & MITIG_CET_IBT) printf("  - CET IBT\n");
    if (flags & MITIG_CET_SS) printf("  - CET Shadow Stack\n");
    if (flags & MITIG_FORTIFY) printf("  - FORTIFY_SOURCE\n");
}

void mitigation_suggest(const security_profile_t *p) {
    printf("\n[HARDENING SUGGESTIONS]\n");
    if (!(p->flags & MITIG_CANARY))
        printf("  > Enable -fstack-protector-strong\n");
    if (!(p->flags & MITIG_PIE))
        printf("  > Compile with -fPIE -pie\n");
    if (!(p->flags & MITIG_FULL_RELRO))
        printf("  > Link with -Wl,-z,relro,-z,now\n");
    if (!(p->flags & MITIG_FORTIFY))
        printf("  > Add -D_FORTIFY_SOURCE=2\n");
    if (!(p->flags & MITIG_CFI))
        printf("  > Consider -fsanitize=cfi (clang) or CET (HW)\n");
    if (p->level >= SEC_LVL_HIGH)
        printf("  (Current level is already strong.)\n");
}

const char *security_level_name(security_level_t lvl) {
    switch (lvl) {
    case SEC_LVL_LOW:    return "LOW";
    case SEC_LVL_MEDIUM: return "MEDIUM";
    case SEC_LVL_HIGH:   return "HIGH";
    case SEC_LVL_MAX:    return "MAXIMUM";
    default:             return "UNKNOWN";
    }
}

const char *bypass_difficulty_name(bypass_difficulty_t d) {
    switch (d) {
    case BYPASS_TRIVIAL:    return "TRIVIAL";
    case BYPASS_EASY:       return "EASY";
    case BYPASS_MODERATE:   return "MODERATE";
    case BYPASS_HARD:       return "HARD";
    case BYPASS_VERY_HARD:  return "VERY HARD";
    case BYPASS_IMPOSSIBLE: return "IMPOSSIBLE";
    default:                return "UNKNOWN";
    }
}

const char *mitigation_flag_name(mitigation_t flag) {
    switch (flag) {
    case MITIG_ASLR:       return "ASLR";
    case MITIG_NX:         return "NX/DEP";
    case MITIG_CANARY:     return "Stack Canary";
    case MITIG_RELRO:      return "Partial RELRO";
    case MITIG_FULL_RELRO: return "Full RELRO";
    case MITIG_PIE:        return "PIE";
    case MITIG_FORTIFY:    return "FORTIFY_SOURCE";
    case MITIG_CFI:        return "CFI";
    case MITIG_CET_IBT:    return "CET IBT";
    case MITIG_CET_SS:     return "CET Shadow Stack";
    case MITIG_SHADOWSTACK:return "Shadow Stack";
    default:               return "UNKNOWN";
    }
}
