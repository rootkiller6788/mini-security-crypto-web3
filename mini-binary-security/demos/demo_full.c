/*
 * mini-binary-security — Full Demo: Binary & Exploit Security
 *
 * Demonstrates: buffer overflows (stack/heap/UAF), ROP gadgets,
 *               exploit mitigations, format string attacks, fuzzing.
 */
#include "../include/buffer_overflow.h"
#include "../include/rop_gadget.h"
#include "../include/mitigation_def.h"
#include "../include/format_string.h"
#include "../include/fuzzing_tool.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

static exec_result_t demo_target(const uint8_t *data, size_t len, void *user_data) {
    (void)user_data;
    if (len >= 4 && data[0] == 'C' && data[1] == 'R' && data[2] == 'A' && data[3] == 'S')
        return EXEC_CRASH;
    if (len >= 4 && data[0] == 'H' && data[1] == 'A' && data[2] == 'N' && data[3] == 'G')
        return EXEC_HANG;
    return EXEC_OK;
}

int main(void) {
    printf("╔══════════════════════════════════════════╗\n");
    printf("║   mini-binary-security: Binary Exploit  ║\n");
    printf("╚══════════════════════════════════════════╝\n\n");

    /* Step 1: Buffer Overflow Detection */
    printf("── Step 1: Buffer Overflow Detection ──\n");
    bool ovf = int_ovf_check_add_int32(2000000000, 2000000000);
    printf("Integer overflow (2B+2B): %s\n", ovf ? "OVERFLOW DETECTED" : "OK");

    ovf = int_ovf_check_mul_size(65536, 65536);
    printf("Size_t overflow (64K*64K): %s\n", ovf ? "OVERFLOW DETECTED" : "OK");

    stack_canary_t canary;
    stack_canary_init(&canary);
    bool canary_ok = stack_canary_check(&canary);
    printf("Stack canary: value=0x%08X, check=%s\n", canary.value, canary_ok ? "OK" : "BREACHED");

    uaf_tracker_t uaf;
    uaf_tracker_init(&uaf);
    void *ptr = (void*)0x7ffd4000;
    uaf_tracker_add(&uaf, ptr, 64);
    uaf_tracker_mark_free(&uaf, ptr);
    bool dangling = uaf_tracker_is_dangling(&uaf, ptr);
    printf("UAF tracker: ptr=%p, dangling=%s\n", ptr, dangling ? "YES (UAF bug!)" : "NO");

    /* Step 2: ROP Gadget Analysis */
    printf("\n── Step 2: ROP Gadget Analysis ──\n");
    rop_gadget_t gadget1;
    memset(&gadget1, 0, sizeof(gadget1));
    gadget1.address = 0x401000;
    gadget1.bytes[0] = 0x5d; gadget1.bytes[1] = 0xc3; /* pop rbp; ret */
    gadget1.num_bytes = 2;
    rop_gadget_classify(&gadget1);
    printf("Gadget @ 0x%llX: type=%d, \"pop rbp; ret\"\n", (unsigned long long)gadget1.address, gadget1.type);

    rop_gadget_t gadget2;
    memset(&gadget2, 0, sizeof(gadget2));
    gadget2.address = 0x402000;
    gadget2.bytes[0] = 0x58; gadget2.bytes[1] = 0x5f; gadget2.bytes[2] = 0xc3; /* pop rax; pop rdi; ret */
    gadget2.num_bytes = 3;
    rop_gadget_classify(&gadget2);
    printf("Gadget @ 0x%llX: type=%d, \"pop rax; pop rdi; ret\"\n", (unsigned long long)gadget2.address, gadget2.type);

    rop_chain_t chain;
    rop_chain_init(&chain);
    rop_chain_add_gadget(&chain, &gadget1);
    rop_chain_add_gadget(&chain, &gadget2);
    printf("ROP chain: %d gadgets\n", chain.count);
    printf("Chain execution: pop rbp -> ret -> pop rax -> pop rdi -> ret\n");

    /* Step 3: Mitigation Detection */
    printf("\n── Step 3: Exploit Mitigation Detection ──\n");
    security_profile_t profile = mitigation_detect();
    printf("ASLR:      %s\n", profile.has_aslr ? "ENABLED" : "DISABLED");
    printf("NX/DEP:    %s\n", profile.has_nx ? "ENABLED" : "DISABLED");
    printf("Canary:    %s\n", profile.has_canary ? "ENABLED" : "DISABLED");
    printf("RELRO:     %s\n", profile.has_relro ? "FULL" : "PARTIAL/NONE");
    printf("PIE:       %s\n", profile.has_pie ? "ENABLED" : "DISABLED");
    printf("CFI:       %s\n", profile.has_cfi ? "ENABLED" : "DISABLED");
    printf("ShadowStack: %s\n", profile.has_shadow_stack ? "ENABLED" : "DISABLED");

    mitigation_assess_level(&profile);
    int score = mitigation_score(&profile);
    printf("Security score: %d/100\n", score);

    /* Step 4: Format String Attack */
    printf("\n── Step 4: Format String Attack Analysis ──\n");
    fmt_parse_result_t fmt_r;
    fmt_parse("%d %s %n %x %p %08x", &fmt_r);
    printf("Format string: \"%%d %%s %%n %%x %%p %%08x\"\n");
    printf("  Specifiers found: %d\n", fmt_r.specifier_count);
    printf("  Has %%n (write): %s [%s]\n",
           fmt_r.has_n_specifier ? "YES" : "NO",
           fmt_r.has_n_specifier ? "DANGEROUS" : "SAFE");
    printf("  Has %%s (read): %s\n", fmt_r.has_s_specifier ? "YES" : "NO");
    printf("  Has positional: %s\n", fmt_r.has_positional ? "YES" : "NO");

    bool vuln = fmt_is_vulnerable("%s%s%s%s%s%s%s%s%s%s");
    printf("Vulnerable format (10x %%s): %s\n", vuln ? "YES (info leak)" : "NO");

    /* Step 5: Fuzzing */
    printf("\n── Step 5: Coverage-Guided Fuzzing ──\n");
    fuzzer_state_t fs;
    fuzzer_init(&fs, ".", ".");
    fuzzer_set_target(&fs, demo_target, NULL);

    uint8_t seed1[] = "AAAA";
    uint8_t seed2[] = "BBBBBBBB";
    uint8_t seed3[] = "CRAS";
    fuzzer_add_seed(&fs, seed1, sizeof(seed1) - 1, "seed-AAAA");
    fuzzer_add_seed(&fs, seed2, sizeof(seed2) - 1, "seed-BBBB");
    fuzzer_add_seed(&fs, seed3, sizeof(seed3) - 1, "seed-CRAS");

    printf("Fuzzer initialized with 3 seeds\n");
    for (int round = 0; round < 10; round++) {
        fuzz_mutate_bitflip(&fs, 1);
        exec_result_t res = fuzz_execute(&fs);
        if (res != EXEC_OK) {
            printf("Round %d: CRASH/HANG found! Input triggers bug\n", round);
            break;
        }
    }
    printf("Fuzzing stats: %zu iterations, %zu unique paths, %zu crashes\n",
           fs.total_iterations, fs.unique_paths, fs.crash_count);

    fuzzer_free(&fs);

    printf("\n✓ Full binary security demo complete!\n");
    return 0;
}
