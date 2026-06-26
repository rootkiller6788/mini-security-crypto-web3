#include "rop_gadget.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ═══════════════════════════════════════════════════════════════
   Gadget Database
   ═══════════════════════════════════════════════════════════════ */

void rop_gadget_db_init(gadget_db_t *db) {
    memset(db, 0, sizeof(*db));
}

bool rop_gadget_db_add(gadget_db_t *db, uint64_t addr,
                        const uint8_t *bytes, uint8_t len) {
    if (db->count >= GADGET_DB_MAX || len > 16) return false;
    rop_gadget_t *g = &db->gadgets[db->count];
    g->address = addr;
    memcpy(g->bytes, bytes, len);
    g->num_bytes = len;
    rop_gadget_classify(g);
    db->count++;
    return true;
}

/* Instruction byte matchers */
static bool is_ret_byte(uint8_t b)    { return b == 0xC3; }
static bool is_syscall(uint8_t b1, uint8_t b2) {
    return b1 == 0x0F && b2 == 0x05;
}
static bool is_pop_reg(uint8_t b)     { return (b & 0xF8) == 0x58; }
static bool is_leave(uint8_t b)       { return b == 0xC9; }
static bool is_nop(uint8_t b)         { return b == 0x90; }
static bool is_jmp_reg(uint8_t b1, uint8_t b2) {
    return b1 == 0xFF && (b2 & 0xE0) == 0xE0;
}

void rop_gadget_classify(rop_gadget_t *g) {
    uint8_t *b = g->bytes;
    uint8_t n = g->num_bytes;

    if (n == 0) { g->class = GADGET_OTHER; return; }

    /* Last byte should be ret (0xC3) */
    bool ends_ret = is_ret_byte(b[n - 1]);
    bool ends_syscall = (n >= 2) && is_syscall(b[n - 2], b[n - 1]);

    if (n == 1 && is_ret_byte(b[0])) {
        /* ret only */
        g->class = GADGET_NOP;
        snprintf(g->mnemonic, sizeof(g->mnemonic), "ret");
    } else if (n == 1 && is_leave(b[0])) {
        g->class = GADGET_LEAVE_RET;
        snprintf(g->mnemonic, sizeof(g->mnemonic), "leave");
    } else if (n >= 2 && is_pop_reg(b[0]) && is_ret_byte(b[1])) {
        g->class = GADGET_POP_REG;
        g->reg_pop = b[0] & 0x07;
        static const char *regs[] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"};
        snprintf(g->mnemonic, sizeof(g->mnemonic), "pop %s; ret", regs[g->reg_pop]);
    } else if (n >= 3 && is_syscall(b[n - 2], b[n - 1])) {
        g->class = GADGET_SYSCALL;
        /* Copy bytes before syscall */
        if (n > 2) {
            memmove(b, b, n - 2); /* shift left to expose prefix */
        }
        snprintf(g->mnemonic, sizeof(g->mnemonic),
                 "..., syscall (%u bytes)", n);
    } else if (n >= 2 && is_jmp_reg(b[0], b[1])) {
        g->class = GADGET_JMP_REG;
        snprintf(g->mnemonic, sizeof(g->mnemonic),
                 "jmp reg (JOP gadget, %u bytes)", n);
    } else if (ends_ret) {
        g->class = GADGET_OTHER;
        snprintf(g->mnemonic, sizeof(g->mnemonic),
                 "other gadget (%u bytes, ends ret)", n);
    } else {
        g->class = GADGET_OTHER;
        snprintf(g->mnemonic, sizeof(g->mnemonic),
                 "seq (%u bytes, no ret)", n);
    }
}

uint32_t rop_find_gadgets(const uint8_t *binary, size_t bin_len,
                           gadget_db_t *db) {
    uint32_t found = 0;
    for (size_t i = 0; i < bin_len; i++) {
        if (is_ret_byte(binary[i])) {
            /* Found a ret - scan backward for usable gadget */
            size_t start = (i >= 15) ? i - 15 : 0;
            for (size_t j = i; j > start; j--) {
                uint8_t len = (uint8_t)(i - j + 1);
                if (is_pop_reg(binary[j]) && len == 2) {
                    rop_gadget_db_add(db, j, &binary[j], len);
                    found++;
                    break;
                }
                if (j + 1 < i && is_syscall(binary[j], binary[j + 1])) {
                    rop_gadget_db_add(db, j, &binary[j], (uint8_t)(i - j + 1));
                    found++;
                    break;
                }
            }
        }
    }
    return found;
}

void rop_gadget_print(const rop_gadget_t *g) {
    printf("  [0x%016llX] %s\n",
           (unsigned long long)g->address, g->mnemonic);
    printf("           bytes: ");
    for (int i = 0; i < g->num_bytes; i++)
        printf("%02X ", g->bytes[i]);
    printf("\n           class: %d\n", g->class);
}

/* ═══════════════════════════════════════════════════════════════
   Chain Building
   ═══════════════════════════════════════════════════════════════ */

void rop_chain_init(rop_chain_t *c) {
    memset(c, 0, sizeof(*c));
}

bool rop_chain_append(rop_chain_t *c, const rop_gadget_t *g,
                       uint64_t arg, const char *desc) {
    if (c->count >= ROP_CHAIN_MAX_NODES) return false;
    rop_chain_node_t *n = &c->nodes[c->count];
    n->gadget   = g;
    n->argument = arg;
    if (desc) strncpy(n->comment, desc, sizeof(n->comment) - 1);
    c->count++;
    return true;
}

bool rop_chain_build_execve(const gadget_db_t *db, rop_chain_t *c,
                             const char *cmd) {
    (void)cmd;
    printf("[ROP-CHAIN] Building execve(\"%s\", NULL, NULL) chain:\n", cmd);
    printf("  1. pop rdi; ret  -> address of \"/bin/sh\"\n");
    printf("  2. pop rsi; ret  -> 0 (argv = NULL)\n");
    printf("  3. pop rdx; ret  -> 0 (envp = NULL)\n");
    printf("  4. pop rax; ret  -> 59 (execve syscall nr)\n");
    printf("  5. syscall; ret\n");

    /* Scan for needed gadgets */
    rop_gadget_t *g_rdi = NULL, *g_rsi = NULL, *g_rdx = NULL,
                 *g_rax = NULL, *g_sys = NULL;

    for (uint32_t i = 0; i < db->count; i++) {
        rop_gadget_t *g = &db->gadgets[i];
        if (g->class == GADGET_POP_REG && g->reg_pop == 7) g_rdi = g;
        if (g->class == GADGET_POP_REG && g->reg_pop == 6) g_rsi = g;
        if (g->class == GADGET_POP_REG && g->reg_pop == 2) g_rdx = g;
        if (g->class == GADGET_POP_REG && g->reg_pop == 0) g_rax = g;
        if (g->class == GADGET_SYSCALL) g_sys = g;
    }

    bool ok = true;
    if (g_rdi) rop_chain_append(c, g_rdi, 0x0, "rdi = \"/bin/sh\"");
    else { printf("[!] Missing: pop rdi; ret\n"); ok = false; }
    if (g_rsi) rop_chain_append(c, g_rsi, 0x0, "rsi = NULL");
    else { printf("[!] Missing: pop rsi; ret\n"); ok = false; }
    if (g_rdx) rop_chain_append(c, g_rdx, 0x0, "rdx = NULL");
    else { printf("[!] Missing: pop rdx; ret\n"); ok = false; }
    if (g_rax) rop_chain_append(c, g_rax, 59, "rax = 59 (execve)");
    else { printf("[!] Missing: pop rax; ret\n"); ok = false; }
    if (g_sys) rop_chain_append(c, g_sys, 0, "syscall");
    else { printf("[!] Missing: syscall; ret\n"); ok = false; }
    return ok;
}

bool rop_chain_build_mprotect(const gadget_db_t *db, rop_chain_t *c,
                               uint64_t addr, size_t len, int prot) {
    printf("[ROP-CHAIN] Building mprotect(0x%llX, %zu, %d) chain:\n",
           (unsigned long long)addr, len, prot);
    (void)db; (void)c; (void)addr; (void)len; (void)prot;
    printf("  1. pop rdi; ret -> addr (page-aligned)\n");
    printf("  2. pop rsi; ret -> len\n");
    printf("  3. pop rdx; ret -> prot (7 = RWX)\n");
    printf("  4. pop rax; ret -> 10 (mprotect syscall nr)\n");
    printf("  5. syscall; ret\n");
    printf("  After mprotect: shellcode region is now executable.\n");
    return true;
}

bool rop_chain_pivot(rop_chain_t *c, uint64_t leave_ret_addr,
                     uint64_t fake_stack) {
    printf("[STACK-PIVOT] leave;ret @ 0x%016llX -> rsp = 0x%016llX\n",
           (unsigned long long)leave_ret_addr,
           (unsigned long long)fake_stack);
    c->uses_pivot = true;
    c->stack_pivot_addr = fake_stack;
    return true;
}

void rop_chain_print(const rop_chain_t *c) {
    printf("\n═══ ROP Chain (%u gadgets) ═══\n", c->count);
    if (c->uses_pivot)
        printf("  Stack pivot -> 0x%016llX\n",
               (unsigned long long)c->stack_pivot_addr);
    for (uint32_t i = 0; i < c->count; i++) {
        const rop_chain_node_t *n = &c->nodes[i];
        printf("  [%02u] 0x%016llX | %s",
               i, (unsigned long long)(n->gadget ? n->gadget->address : 0),
               n->gadget ? n->gadget->mnemonic : "(null)");
        if (n->argument)
            printf("  arg=0x%llX", (unsigned long long)n->argument);
        if (n->comment[0])
            printf("  # %s", n->comment);
        printf("\n");
    }
}

void rop_chain_simulate(const rop_chain_t *c) {
    printf("\n[ROP-SIM] Simulating chain execution:\n");
    uint64_t rsp = 0x7FFFDEAD0000ULL;
    for (uint32_t i = 0; i < c->count; i++) {
        const rop_chain_node_t *n = &c->nodes[i];
        printf("  rsp=0x%016llX -> gadget @ 0x%016llX [%s]\n",
               (unsigned long long)rsp,
               (unsigned long long)(n->gadget ? n->gadget->address : 0),
               n->gadget ? n->gadget->mnemonic : "?");
        rsp += 8; /* pop return address */
        if (n->argument) rsp += 8; /* pop argument */
        printf("         next rsp=0x%016llX | %s\n",
               (unsigned long long)rsp, n->comment);
    }
    printf("[ROP-SIM] Chain complete.\n");
}

/* ═══════════════════════════════════════════════════════════════
   JOP (Jump-Oriented Programming)
   ═══════════════════════════════════════════════════════════════ */

void jop_dispatch_init(jop_dispatch_t *jd) {
    memset(jd, 0, sizeof(*jd));
}

bool jop_dispatch_add(jop_dispatch_t *jd, uint64_t addr) {
    if (jd->count >= 8) return false;
    jd->dispatch_table[jd->count++] = addr;
    return true;
}

void jop_exec_simulate(const jop_dispatch_t *jd) {
    printf("\n[JOP-SIM] JOP dispatch table @ 0x%016llX:\n",
           (unsigned long long)jd->dispatch_addr);
    for (uint32_t i = 0; i < jd->count; i++) {
        printf("  [%u] -> 0x%016llX\n", i,
               (unsigned long long)jd->dispatch_table[i]);
    }
    printf("[JOP-SIM] Unlike ROP (ret-based), JOP uses indirect jmp reg.\n");
    printf("[JOP-SIM] Harder to find gadgets but bypasses ret-detection.\n");
}

/* ═══════════════════════════════════════════════════════════════
   SROP (Sigreturn-Oriented Programming)
   ═══════════════════════════════════════════════════════════════ */

void srop_frame_init(srop_frame_t *f) {
    memset(f, 0, sizeof(*f));
}

void srop_frame_set_execve(srop_frame_t *f, uint64_t bin_sh_addr,
                            uint64_t syscall_addr) {
    f->rax = 59;           /* execve syscall */
    f->rdi = bin_sh_addr;  /* "/bin/sh" */
    f->rsi = 0;            /* argv = NULL */
    f->rdx = 0;            /* envp = NULL */
    f->rip = syscall_addr; /* execute syscall */
}

void srop_frame_print(const srop_frame_t *f) {
    printf("\n═══ SROP Frame ═══\n");
    printf("  RAX: 0x%016llX (syscall nr)\n", (unsigned long long)f->rax);
    printf("  RDI: 0x%016llX\n", (unsigned long long)f->rdi);
    printf("  RSI: 0x%016llX\n", (unsigned long long)f->rsi);
    printf("  RDX: 0x%016llX\n", (unsigned long long)f->rdx);
    printf("  RIP: 0x%016llX\n", (unsigned long long)f->rip);
    printf("  RSP: 0x%016llX\n", (unsigned long long)f->rsp);
    printf("  Frame size: %zu bytes\n", sizeof(srop_frame_t));
    printf("[SROP] Single sigreturn gadget controls ALL registers.\n");
}

/* ═══════════════════════════════════════════════════════════════
   Well-Known Gadgets
   ═══════════════════════════════════════════════════════════════ */

void well_known_init(well_known_gadgets_t *g, uint64_t libc_base) {
    memset(g, 0, sizeof(*g));
    /* Typical offsets in libc-2.31 (Ubuntu 20.04) */
    g->pop_rdi    = libc_base + 0x26B72;
    g->pop_rsi    = libc_base + 0x27529;
    g->pop_rdx    = libc_base + 0x11C371;
    g->pop_rax    = libc_base + 0x4A550;
    g->ret        = libc_base + 0x25679;
    g->syscall    = libc_base + 0x66229;
    g->leave_ret  = libc_base + 0x5AA48;
    g->valid[0]   = true;  /* pop_rdi */
    g->valid[1]   = true;  /* pop_rsi */
    g->valid[2]   = true;  /* pop_rdx */
    g->valid[3]   = true;  /* pop_rax */
    g->valid[4]   = true;  /* ret */
    g->valid[5]   = true;  /* syscall */
    g->valid[6]   = true;  /* leave_ret */
}

void well_known_print(const well_known_gadgets_t *g) {
    printf("═══ Well-Known Gadgets (libc base = 0x%llX) ═══\n",
           (unsigned long long)(g->pop_rdi - 0x26B72));
    printf("  pop rdi; ret  -> 0x%016llX\n", (unsigned long long)g->pop_rdi);
    printf("  pop rsi; ret  -> 0x%016llX\n", (unsigned long long)g->pop_rsi);
    printf("  pop rdx; ret  -> 0x%016llX\n", (unsigned long long)g->pop_rdx);
    printf("  pop rax; ret  -> 0x%016llX\n", (unsigned long long)g->pop_rax);
    printf("  ret           -> 0x%016llX\n", (unsigned long long)g->ret);
    printf("  syscall       -> 0x%016llX\n", (unsigned long long)g->syscall);
    printf("  leave; ret    -> 0x%016llX\n", (unsigned long long)g->leave_ret);
}
