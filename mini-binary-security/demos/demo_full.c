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

    int_ovf_result_t ovf_r = int_ovf_analyze(INT64_MAX, 1, '+');
    printf("int_ovf_analyze(INT64_MAX, 1, '+'): type=%d sign=%d result=%lld\n",
           ovf_r.type, ovf_r.sign, (long long)ovf_r.result);

    uaf_tracker_t uaf;
    uaf_tracker_init(&uaf);
    void *ptr = (void*)0x7ffd4000;
    uaf_tracker_add(&uaf, ptr, 64);
    uaf_tracker_mark_free(&uaf, ptr);
    bool dangling = uaf_tracker_is_dangling(&uaf, ptr);
    printf("UAF tracker: ptr=%p, dangling=%s\n", ptr, dangling ? "YES (UAF bug!)" : "NO");

    df_tracker_t df;
    df_tracker_init(&df);
    df_tracker_check(&df, ptr);
    bool double_free = df_tracker_check(&df, ptr);
    printf("Double-free check: %s\n", double_free ? "DOUBLE FREE DETECTED!" : "first free ok");

    /* Step 2: ROP Gadget Analysis */
    printf("\n── Step 2: ROP Gadget Analysis ──\n");
    rop_gadget_t gadget1;
    memset(&gadget1, 0, sizeof(gadget1));
    gadget1.address = 0x401000;
    gadget1.bytes[0] = 0x5f; gadget1.bytes[1] = 0xc3; /* pop rdi; ret */
    gadget1.num_bytes = 2;
    rop_gadget_classify(&gadget1);
    printf("Gadget @ 0x%llX: class=%d, \"%s\"\n",
           (unsigned long long)gadget1.address, gadget1.class, gadget1.mnemonic);

    rop_gadget_t gadget2;
    memset(&gadget2, 0, sizeof(gadget2));
    gadget2.address = 0x402000;
    gadget2.bytes[0] = 0x5e; gadget2.bytes[1] = 0xc3; /* pop rsi; ret */
    gadget2.num_bytes = 2;
    rop_gadget_classify(&gadget2);
    printf("Gadget @ 0x%llX: class=%d, \"%s\"\n",
           (unsigned long long)gadget2.address, gadget2.class, gadget2.mnemonic);

    rop_chain_t chain;
    rop_chain_init(&chain);
    rop_chain_append(&chain, &gadget1, 0x7FFF0000, "pop rdi -> arg");
    rop_chain_append(&chain, &gadget2, 0x0, "pop rsi -> NULL");
    printf("ROP chain: %u gadgets\n", chain.count);
    rop_chain_print(&chain);

    /* Step 3: Mitigation Detection */
    printf("\n── Step 3: Exploit Mitigation Detection ──\n");
    security_profile_t profile = mitigation_detect();
    printf("ASLR:      %s\n", (profile.flags & MITIG_ASLR) ? "ENABLED" : "DISABLED");
    printf("NX/DEP:    %s\n", (profile.flags & MITIG_NX) ? "ENABLED" : "DISABLED");
    printf("Canary:    %s\n", (profile.flags & MITIG_CANARY) ? "ENABLED" : "DISABLED");
    printf("RELRO:     %s\n", (profile.flags & MITIG_FULL_RELRO) ? "FULL" :
                            (profile.flags & MITIG_RELRO) ? "PARTIAL" : "NONE");
    printf("PIE:       %s\n", (profile.flags & MITIG_PIE) ? "ENABLED" : "DISABLED");
    printf("CFI:       %s\n", (profile.flags & MITIG_CFI) ? "ENABLED" : "DISABLED");
    printf("CET:       %s\n", (profile.flags & (MITIG_CET_IBT|MITIG_CET_SS)) ? "ENABLED" : "DISABLED");

    uint32_t score = mitigation_score(&profile);
    printf("Security score: %u\n", score);
    printf("Security level: %s\n", security_level_name(profile.level));

    bypass_difficulty_t rop_diff = mitigation_bypass_difficulty(&profile, "rop");
    printf("ROP bypass difficulty: %s\n", bypass_difficulty_name(rop_diff));

    mitigation_suggest(&profile);

    /* Step 4: Format String Attack */
    printf("\n── Step 4: Format String Attack Analysis ──\n");
    fmt_parse_result_t fmt_r;
    fmt_parse("%d %s %n %x %p %08x", &fmt_r);
    printf("Format string: \"%%d %%s %%n %%x %%p %%08x\"\n");
    printf("  Specifiers found: %d\n", fmt_r.count);
    printf("  Has %%n (write): %s [%s]\n",
           fmt_r.has_n_write ? "YES" : "NO",
           fmt_r.has_n_write ? "DANGEROUS" : "SAFE");
    printf("  Has leak (%%p/%%x): %s\n", fmt_r.has_leak ? "YES" : "NO");

    fmt_payload_t leak_payload = fmt_build_leak_payload(7);
    printf("Leak payload (%zu bytes): %s\n", leak_payload.len, leak_payload.payload);

    fmt_payload_t stack_leak = fmt_build_stack_leak(1, 4);
    printf("Stack leak payload: %s\n", stack_leak.payload);

    bool has_null = fmt_payload_has_null(stack_leak.payload);
    printf("Payload has null byte: %s\n", has_null ? "YES (may terminate string)" : "NO");

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

    printf("Fuzzer initialized with %u seeds\n", fs.corpus.count);
    for (int round = 0; round < 10; round++) {
        fuzz_mutate_bitflip(&fs, 1);
        exec_result_t res = fuzz_execute(&fs);
        if (res != EXEC_OK) {
            printf("Round %d: CRASH/HANG found! Input triggers bug\n", round);
            break;
        }
    }
    fuzz_stats_update(&fs.stats, fs.stats.total_execs);
    fuzz_stats_print(&fs.stats);

    fuzzer_free(&fs);

    printf("\n✓ Full binary security demo complete!\n");
    return 0;
}
