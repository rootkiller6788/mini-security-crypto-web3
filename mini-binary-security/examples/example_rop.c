#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "rop_gadget.h"

int main(void) {
    printf("═══════════════════════════════════════════\n");
    printf("  Example: ROP Gadget Scanning & Chains\n");
    printf("═══════════════════════════════════════════\n\n");

    /* 1. Gadget database scanning */
    printf("─── 1. Gadget Scanning ───\n");
    gadget_db_t db;
    rop_gadget_db_init(&db);

    /* Simulated binary snippet containing gadgets */
    uint8_t binary[] = {
        0x90,                               /* nop */
        0x48, 0x89, 0xE0, 0xC3,            /* mov rax, rsp; ret */
        0x5F, 0xC3,                         /* pop rdi; ret       */
        0x5E, 0xC3,                         /* pop rsi; ret       */
        0x5A, 0xC3,                         /* pop rdx; ret       */
        0x58, 0xC3,                         /* pop rax; ret       */
        0xC9, 0xC3,                         /* leave; ret         */
        0x0F, 0x05, 0xC3,                  /* syscall; ret       */
        0xFF, 0xE0,                         /* jmp rax (JOP)      */
        0x48, 0x31, 0xC0, 0xC3,            /* xor rax, rax; ret  */
    };

    uint32_t found = rop_find_gadgets(binary, sizeof(binary), &db);
    printf("  Scanned %zu bytes, found %u gadgets:\n", sizeof(binary), found);

    for (uint32_t i = 0; i < db.count; i++) {
        printf("  [%2u] ", i);
        rop_gadget_print(&db.gadgets[i]);
    }
    printf("\n");

    /* 2. Build execve ROP chain */
    printf("─── 2. Building execve() ROP Chain ───\n");
    rop_chain_t chain;
    rop_chain_init(&chain);
    rop_chain_build_execve(&db, &chain, "/bin/sh");
    rop_chain_print(&chain);
    printf("\n");

    /* 3. Simulate chain execution */
    printf("─── 3. Chain Execution Simulation ───\n");
    rop_chain_simulate(&chain);
    printf("\n");

    /* 4. Build mprotect chain */
    printf("─── 4. Building mprotect() ROP Chain ───\n");
    rop_chain_t chain2;
    rop_chain_init(&chain2);
    rop_chain_build_mprotect(&db, &chain2, 0x7FFF0000, 4096, 7);
    printf("\n");

    /* 5. Stack pivot */
    printf("─── 5. Stack Pivot ───\n");
    rop_chain_t chain3;
    rop_chain_init(&chain3);
    rop_chain_pivot(&chain3, 0x7FFF10001000ULL, 0x7FFF20000000ULL);
    printf("  When the buffer is too small: use leave;ret to pivot stack.\n");
    printf("  Controlled fake stack enables full ROP chain execution.\n\n");

    /* 6. JOP simulation */
    printf("─── 6. JOP (Jump-Oriented Programming) ───\n");
    jop_dispatch_t jd;
    jop_dispatch_init(&jd);
    jop_dispatch_add(&jd, 0x400100);  /* load rdi    */
    jop_dispatch_add(&jd, 0x400200);  /* load rsi    */
    jop_dispatch_add(&jd, 0x400300);  /* load rdx    */
    jop_dispatch_add(&jd, 0x400400);  /* syscall     */
    jop_exec_simulate(&jd);
    printf("\n");

    /* 7. SROP simulation */
    printf("─── 7. SROP (Sigreturn-Oriented Programming) ───\n");
    srop_frame_t frame;
    srop_frame_init(&frame);
    srop_frame_set_execve(&frame, 0x7FFF00000000ULL, 0x400500ULL);
    srop_frame_print(&frame);
    printf("\n");

    /* 8. Well-known gadgets */
    printf("─── 8. Well-Known Gadgets ───\n");
    well_known_gadgets_t wkg;
    well_known_init(&wkg, 0x7FFFF7000000ULL);
    well_known_print(&wkg);
    printf("\n");

    printf("═══════════════════════════════════════════\n");
    printf("  All ROP concepts demonstrated.\n");
    printf("  Key: ROP chains bypass NX by reusing existing code.\n");
    printf("═══════════════════════════════════════════\n");
    return 0;
}
