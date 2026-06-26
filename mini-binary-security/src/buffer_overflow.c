#include "buffer_overflow.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

/* ═══════════════════════════════════════════════════════════════
   Integer Overflow Detection
   ═══════════════════════════════════════════════════════════════ */

bool int_ovf_check_add_int32(int32_t a, int32_t b) {
    if (a > 0 && b > 0 && a > INT32_MAX - b) return true;
    if (a < 0 && b < 0 && a < INT32_MIN - b) return true;
    return false;
}

bool int_ovf_check_add_uint32(uint32_t a, uint32_t b) {
    return a > UINT32_MAX - b;
}

bool int_ovf_check_mul_size(size_t a, size_t b) {
    if (b == 0) return false;
    return a > SIZE_MAX / b;
}

bool int_ovf_check_add_size(size_t a, size_t b) {
    return a > SIZE_MAX - b;
}

int_ovf_result_t int_ovf_analyze(int64_t a, int64_t b, char op) {
    int_ovf_result_t r = {0};
    r.a = a; r.b = b;
    switch (op) {
    case '+':
        r.result = a + b;
        if ((a > 0 && b > 0 && r.result < 0) ||
            (a < 0 && b < 0 && r.result > 0)) {
            r.type = INT_OVF_ADD; r.sign = true;
        }
        break;
    case '*':
        r.result = a * b;
        if (a != 0 && r.result / a != b) {
            r.type = INT_OVF_MUL; r.sign = true;
        }
        break;
    case '-':
        r.result = a - b;
        if ((b > 0 && a < INT64_MIN + b) ||
            (b < 0 && a > INT64_MAX + b)) {
            r.type = INT_OVF_SUB; r.sign = true;
        }
        break;
    default:
        r.type = INT_OVF_NONE;
        break;
    }
    return r;
}

/* ═══════════════════════════════════════════════════════════════
   Stack Overflow Simulation
   ═══════════════════════════════════════════════════════════════ */

void bo_stack_overflow_sim(const char *input, size_t len) {
    char        buffer[64];
    uint64_t    canary   = 0xDEADBEEFCAFEBABEULL;
    stack_frame_t frame __attribute__((aligned(16)));

    memset(&frame, 0, sizeof(frame));
    frame.saved_rbp  = 0x7FFF12340000ULL;
    frame.return_addr = 0x400000ULL + 0x1234;  /* mock return address */

    printf("[STACK-OVF] Buffer @ %p  size=%zu  input_len=%zu\n",
           (void*)buffer, sizeof(buffer), len);
    printf("[STACK-OVF] Canary value:  0x%016llX\n",
           (unsigned long long)canary);
    printf("[STACK-OVF] Return addr:   0x%016llX\n",
           (unsigned long long)frame.return_addr);
    printf("[STACK-OVF] Saved RBP:    0x%016llX\n",
           (unsigned long long)frame.saved_rbp);

    if (len > sizeof(buffer)) {
        size_t over = len - sizeof(buffer);
        printf("[!] OVERFLOW DETECTED: %zu bytes past buffer\n", over);
        printf("[!] Return address offset (from buf): +%zu bytes\n",
               sizeof(buffer) + sizeof(uint64_t));

        if (len >= sizeof(buffer) + sizeof(uint64_t) + sizeof(uint64_t)) {
            uint64_t fake_ret;
            memcpy(&fake_ret, input + sizeof(buffer) + sizeof(uint64_t),
                   sizeof(uint64_t));
            printf("[!] RETURN ADDRESS OVERWRITE -> 0x%016llX\n",
                   (unsigned long long)fake_ret);
            printf("[!] Attacker redirects execution to 0x%016llX\n",
                   (unsigned long long)fake_ret);
        }
    }

    memcpy(buffer, input, len > sizeof(buffer) + 32
                        ? sizeof(buffer) + 32 : len);
    printf("[STACK-OVF] Copied %zu bytes to 64-byte buffer\n", len);
}

void bo_stack_canary_sim(const char *input, size_t len) {
    uint64_t canary = 0x00DEADBEEFCAFEBABEULL;  /* null-terminated canary */
    char     buffer[64];
    uint64_t saved_canary = canary;

    printf("[CANARY] Stack canary: 0x%016llX (null-terminated)\n",
           (unsigned long long)canary);
    memcpy(buffer, input, len);

    if (saved_canary != canary) {
        printf("[!] __stack_chk_fail() called! Canary: 0x%016llX -> 0x%016llX\n",
               (unsigned long long)saved_canary, (unsigned long long)canary);
        printf("[!] Process aborted. Stack smashing detected.\n");
    } else {
        printf("[CANARY] Intact. No stack smashing detected.\n");
    }

    /* Demonstrate canary leak approach */
    printf("[CANARY-BYPASS] If canary can be leaked (e.g., format string),\n"
           "                attacker can overwrite canary with correct value.\n");
}

void bo_return_to_addr(uint64_t ret_addr) {
    printf("[ROP] Would redirect execution to: 0x%016llX\n",
           (unsigned long long)ret_addr);
}

/* ═══════════════════════════════════════════════════════════════
   Heap Overflow Simulation
   ═══════════════════════════════════════════════════════════════ */

void bo_heap_overflow_sim(size_t alloc_sz, const char *input, size_t len) {
    char *chunk_a = (char*)malloc(alloc_sz);
    char *chunk_b = (char*)malloc(alloc_sz);

    malloc_chunk_t *meta_a = (malloc_chunk_t*)(chunk_a - sizeof(malloc_chunk_t));
    malloc_chunk_t *meta_b = (malloc_chunk_t*)(chunk_b - sizeof(malloc_chunk_t));

    printf("[HEAP-OVF] Chunk A @ %p (metadata @ %p) size=%zu\n",
           (void*)chunk_a, (void*)meta_a, alloc_sz);
    printf("[HEAP-OVF] Chunk B @ %p (metadata @ %p) size=%zu\n",
           (void*)chunk_b, (void*)meta_b, alloc_sz);
    printf("[HEAP-OVF] Gap between chunks: %td bytes\n",
           (ptrdiff_t)(chunk_b - chunk_a));
    printf("[HEAP-OVF] Chunk B prev_size: %zu, size: %zu\n",
           meta_b->prev_size, meta_b->size);

    if (len > alloc_sz) {
        printf("[!] HEAP OVERFLOW: %zu bytes into %zu-byte chunk\n",
               len, alloc_sz);
        memcpy(chunk_a, input, len);
        printf("[!] Chunk B metadata may be corrupted.\n");
        printf("[!] New Chunk B prev_size: %zu, size: %zu\n",
               meta_b->prev_size, meta_b->size);
    } else {
        memcpy(chunk_a, input, len);
    }

    free(chunk_b);
    free(chunk_a);
}

void bo_heap_unlink_attack_sim(void) {
    printf("[UNLINK-ATK] Classic unlink attack (pre-glibc-2.26):\n");
    printf("  Step 1: Find heap overflow that reaches next chunk's metadata.\n");
    printf("  Step 2: Forge fake chunk with fd and bk pointers.\n");
    printf("  Step 3: Trigger unlink when chunk is freed.\n");
    printf("  unlink macro: FD->bk = BK; BK->fd = FD;\n");
    printf("  Result: arbitrary write primitive (write-what-where).\n");
    printf("[UNLINK-ATK] Safe unlinking (glibc 2.26+):\n");
    printf("  Mitigation: P->fd->bk != P || P->bk->fd != P -> abort()\n");
    printf("  Bypass requires: P->fd->bk == P && P->bk->fd == P\n");
    printf("  Requires finding a pointer to P in memory.\n");
}

void bo_heap_fastbin_dup_sim(void) {
    printf("[FASTBIN-DUP] Fastbin double-free attack:\n");
    printf("  Step 1: malloc(A), malloc(B), free(A), free(B), free(A).\n");
    printf("  Fastbin list: A -> B -> A (cycle created).\n");
    printf("  Step 2: malloc returns A, overwrite A->fd to target.\n");
    printf("  Step 3: malloc x3 allocates at target address.\n");
    printf("  Result: arbitrary address allocation.\n");
    printf("[FASTBIN-DUP] Mitigation: glibc 2.29+ checks key field.\n");
}

/* ═══════════════════════════════════════════════════════════════
   Use-After-Free
   ═══════════════════════════════════════════════════════════════ */

void uaf_tracker_init(uaf_tracker_t *t) {
    memset(t, 0, sizeof(*t));
}

void uaf_tracker_add(uaf_tracker_t *t, void *ptr, size_t sz) {
    if (t->count >= 256) return;
    t->entries[t->count].ptr  = ptr;
    t->entries[t->count].size = sz;
    t->entries[t->count].freed = false;
    t->entries[t->count].id   = t->next_id++;
    t->count++;
    printf("[UAF-TRACK] Alloc #%u: ptr=%p size=%zu\n",
           t->entries[t->count - 1].id, ptr, sz);
}

void uaf_tracker_mark_free(uaf_tracker_t *t, void *ptr) {
    for (uint32_t i = 0; i < t->count; i++) {
        if (t->entries[i].ptr == ptr && !t->entries[i].freed) {
            t->entries[i].freed = true;
            printf("[UAF-TRACK] Free  #%u: ptr=%p (now dangling)\n",
                   t->entries[i].id, ptr);
            return;
        }
    }
}

bool uaf_tracker_is_dangling(const uaf_tracker_t *t, void *ptr) {
    for (uint32_t i = 0; i < t->count; i++) {
        if (t->entries[i].ptr == ptr && t->entries[i].freed)
            return true;
    }
    return false;
}

void uaf_simulate(void) {
    printf("[UAF-SIM] Use-After-Free demonstration:\n");

    uaf_tracker_t tracker;
    uaf_tracker_init(&tracker);

    void *obj = malloc(128);
    uaf_tracker_add(&tracker, obj, 128);

    /* Simulate use of object */
    memset(obj, 0x41, 128);
    printf("[UAF-SIM] Object @ %p filled with 'A'\n", obj);

    /* Free the object */
    free(obj);
    uaf_tracker_mark_free(&tracker, obj);

    if (uaf_tracker_is_dangling(&tracker, obj)) {
        printf("[!] UAF DETECTED: Accessing freed memory @ %p\n", obj);
        printf("[!] The dangling pointer still references freed heap.\n");
        printf("[!] Next malloc may reallocate this chunk with different data:\n");
    }

    /* Allocate something else that might reuse the freed chunk */
    void *obj2 = malloc(128);
    printf("[UAF-SIM] New allocation @ %p (may overlap with freed %p)\n",
           obj2, obj);

    if (uaf_tracker_is_dangling(&tracker, obj)) {
        printf("[!] Dangling pointer @ %p now points to %p's data\n", obj, obj2);
        printf("[!] Attacker contorls freed memory content via reallocation.\n");
    }

    free(obj2);
}

/* ═══════════════════════════════════════════════════════════════
   Double Free
   ═══════════════════════════════════════════════════════════════ */

void df_tracker_init(df_tracker_t *t) {
    memset(t, 0, sizeof(*t));
}

bool df_tracker_check(df_tracker_t *t, void *ptr) {
    for (uint32_t i = 0; i < t->count; i++) {
        if (t->freed_ptrs[i] == ptr) {
            printf("[!] DOUBLE FREE DETECTED: ptr=%p already freed\n", ptr);
            return true;
        }
    }
    if (t->count < 128) {
        t->freed_ptrs[t->count++] = ptr;
    }
    return false;
}

void df_simulate(void) {
    printf("[DOUBLE-FREE] Double-free vulnerability demonstration:\n");
    df_tracker_t tracker;
    df_tracker_init(&tracker);

    void *p = malloc(64);
    printf("[DOUBLE-FREE] Allocated @ %p\n", p);

    free(p);
    df_tracker_check(&tracker, p);
    printf("[DOUBLE-FREE] First free - OK\n");

    free(p); /* BUG: double free */
    if (df_tracker_check(&tracker, p))
        printf("[DOUBLE-FREE] Second free triggers corruption.\n");
    printf("[DOUBLE-FREE] Fastbin/tcache corruption allows arbitrary alloc.\n");
}

/* ═══════════════════════════════════════════════════════════════
   Off-by-One
   ═══════════════════════════════════════════════════════════════ */

void off_by_one_null_byte(char *buf, size_t off, size_t len) {
    printf("[OFF-BY-ONE] Writing null byte at offset %zu (buf size %zu)\n",
           off, len);
    if (off >= len) {
        printf("[!] Off-by-one: overflow past buffer boundary\n");
    }
    buf[off] = '\0';
    printf("[OFF-BY-ONE] Null byte written at index %zu\n", off);
}

void off_by_one_sim(void) {
    printf("[OFF-BY-ONE] Off-by-one null byte overflow:\n");
    printf("  Common in string operations: strncpy(dst, src, sizeof(dst));\n");
    printf("  If src >= sizeof(dst), no null terminator -> overflow on next write.\n");

    char buf[16];
    memset(buf, 'B', 16);
    buf[15] = '\0';
    printf("  Overflow at buf[16] overwrites adjacent variable/metadata.\n");
    printf("  Heap: overwrite next chunk's PREV_INUSE bit -> backward consolidate.\n");
    printf("  Result: overlapping chunks, heap exploitation.\n");
    (void)buf;
}

/* ═══════════════════════════════════════════════════════════════
   Format String %n Write
   ═══════════════════════════════════════════════════════════════ */

void fmt_n_write_sim(uint32_t *target, uint32_t value) {
    printf("[FMT-N] Simulating format string %%n write:\n");
    printf("[FMT-N] Target address: %p\n", (void*)target);
    printf("[FMT-N] Old value: %u (0x%08X)\n", *target, *target);
    printf("[FMT-N] Writing %u bytes via %%n (would require padding).\n", value);
    *target = value;
    printf("[FMT-N] New value: %u (0x%08X)\n", *target, *target);
    printf("[FMT-N] In real attack: use %%NUMc%%N$n (e.g., %%7$n)\n");
}

void fmt_leak_sim(const void *addr) {
    printf("[FMT-LEAK] Reading memory at %p via %%p or %%s format:\n",
           addr);
    printf("[FMT-LEAK] %%p reveals pointer value (bypass ASLR).\n");
    printf("[FMT-LEAK] %%s dereferences addr as string (reads arbitrary mem).\n");
    printf("[FMT-LEAK] Stack contents: can leak return address, canary, libc ptr.\n");
}

/* ═══════════════════════════════════════════════════════════════
   Shellcode Helpers
   ═══════════════════════════════════════════════════════════════ */

void shellcode_build_nop_sled(char *buf, size_t sled_len) {
    memset(buf, 0x90, sled_len);  /* x86 NOP = 0x90 */
    printf("[SHELLCODE] NOP sled built: %zu bytes of 0x90\n", sled_len);
}

void shellcode_embed(char *buf, const uint8_t *sc, size_t sc_len) {
    memcpy(buf, sc, sc_len);
    printf("[SHELLCODE] Embedded %zu bytes of shellcode\n", sc_len);
}
