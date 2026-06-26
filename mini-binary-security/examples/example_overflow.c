#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "buffer_overflow.h"

int main(void) {
    printf("═══════════════════════════════════════════\n");
    printf("  Example: Buffer Overflow Primitives\n");
    printf("═══════════════════════════════════════════\n\n");

    /* 1. Integer overflow leading to underallocation */
    printf("─── 1. Integer Overflow ───\n");
    int32_t a = INT32_MAX, b = 1;
    if (int_ovf_check_add_int32(a, b))
        printf("  [INT-OVF] %d + %d = OVERFLOW!\n", a, b);

    size_t count = 0x100000001ULL;
    size_t elem  = 16;
    if (int_ovf_check_mul_size(count, elem))
        printf("  [INT-OVF] %zu * %zu = OVERFLOW! (underallocated buffer)\n",
               count, elem);
    printf("  Real-world: malloc(count * elem) allocates too little.\n\n");

    /* 2. Stack overflow simulation */
    printf("─── 2. Stack Buffer Overflow ───\n");
    char payload[128];
    memset(payload, 'A', 128);
    /* Embed a fake return address at offset 72 (64 + 8) */
    uint64_t fake_ret = 0x00007FFFF70000DEULL;
    memcpy(payload + 72, &fake_ret, 8);
    bo_stack_overflow_sim(payload, sizeof(payload));
    printf("\n");

    /* 3. Stack canary bypass concept */
    printf("─── 3. Stack Canary Bypass ───\n");
    char safe_payload[64];
    memset(safe_payload, 'B', 64);
    bo_stack_canary_sim(safe_payload, sizeof(safe_payload));
    printf("\n");

    /* 4. Heap overflow */
    printf("─── 4. Heap Overflow ───\n");
    char heap_payload[96];
    memset(heap_payload, 0x41, 96);
    uint64_t fake_size = 0x0000000000000091ULL;
    memcpy(heap_payload + 64 + 16, &fake_size, 8);
    bo_heap_overflow_sim(64, heap_payload, sizeof(heap_payload));
    printf("\n");

    /* 5. Heap unlink attack */
    printf("─── 5. Unlink Attack ───\n");
    bo_heap_unlink_attack_sim();
    printf("\n");

    /* 6. Fastbin dup */
    printf("─── 6. Fastbin Double-Free ───\n");
    bo_heap_fastbin_dup_sim();
    printf("\n");

    /* 7. Use-after-free */
    printf("─── 7. Use-After-Free ───\n");
    uaf_simulate();
    printf("\n");

    /* 8. Double free */
    printf("─── 8. Double Free ───\n");
    df_simulate();
    printf("\n");

    /* 9. Off-by-one */
    printf("─── 9. Off-by-One ───\n");
    off_by_one_sim();
    printf("\n");

    /* 10. Format string %n write */
    printf("─── 10. Format String %%n ───\n");
    uint32_t target_val = 0;
    fmt_n_write_sim(&target_val, 0xDEADBEEF);
    printf("\n");

    /* 11. Format string leak */
    printf("─── 11. Format String Leak ───\n");
    fmt_leak_sim((void*)0x7FFF12345678);
    printf("\n");

    /* 12. Shellcode concept */
    printf("─── 12. Shellcode Injection ───\n");
    char sc_buf[256];
    shellcode_build_nop_sled(sc_buf, 32);
    uint8_t demo_sc[] = {
        0x31, 0xC0,           /* xor eax, eax */
        0x48, 0x31, 0xFF,     /* xor rdi, rdi */
        0xB0, 0x3C,           /* mov al, 60   */
        0x0F, 0x05,           /* syscall      */
    };
    shellcode_embed(sc_buf + 32, demo_sc, sizeof(demo_sc));
    printf("  NOP sled (32 bytes) + shellcode (%zu bytes)\n",
           sizeof(demo_sc));
    printf("  Total payload: 38 bytes\n");

    printf("\n═══════════════════════════════════════════\n");
    printf("  All buffer overflow primitives covered.\n");
    return 0;
}
