#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "fuzzing_tool.h"

static exec_result_t demo_target(const uint8_t *data, size_t len, void *ud);
static int           crash_count = 0;

static exec_result_t demo_target(const uint8_t *data, size_t len, void *ud) {
    (void)ud;

    /* Simulate a vulnerable parser */
    if (len < 4) return EXEC_OK;

    /* Buffer overflow vulnerability: reads 4 bytes as length */
    uint32_t parse_len = (uint32_t)data[0] |
                         ((uint32_t)data[1] << 8) |
                         ((uint32_t)data[2] << 16) |
                         ((uint32_t)data[3] << 24);

    /* Use-after-free pattern */
    if (len >= 8 && data[4] == 0xAA && data[5] == 0xBB
        && data[6] == 0xCC && data[7] == 0xDD) {
        crash_count++;
        printf("[TARGET] UAF pattern detected -> simulated crash #%d\n",
               crash_count);
        return EXEC_CRASH;
    }

    /* Heap overflow: large allocation size */
    if (parse_len > 0xFFFF0000) {
        crash_count++;
        printf("[TARGET] Integer overflow in size -> crash #%d\n",
               crash_count);
        return EXEC_CRASH;
    }

    /* Double free pattern */
    if (len >= 12 && memcmp(data, "\xDE\xAD\xBE\xEF", 4) == 0) {
        crash_count++;
        printf("[TARGET] Double-free pattern -> crash #%d\n", crash_count);
        return EXEC_CRASH;
    }

    /* Stack buffer overflow */
    if (len >= 64 && data[32] == 0x42 && data[33] == 0x4F
        && data[34] == 0x0F && data[35] == 0xFF) {
        crash_count++;
        printf("[TARGET] Stack overflow pattern -> crash #%d\n", crash_count);
        return EXEC_CRASH;
    }

    return EXEC_OK;
}

int main(void) {
    printf("═══════════════════════════════════════════\n");
    printf("  Example: Coverage-Guided Fuzzing\n");
    printf("═══════════════════════════════════════════\n\n");

    fuzzer_state_t fs;
    fuzzer_init(&fs, ".", "./out");

    fuzzer_set_target(&fs, demo_target, NULL);

    /* Add seed inputs to the corpus */
    const char *seeds[] = {
        "\x00\x00\x00\x00\x00\x00\x00\x00",
        "\x10\x00\x00\x00\x41\x41\x41\x41",
        "\xFF\xFF\xFF\x7F\x00\x00\x00\x00",
        "\xDE\xAD\xBE\xEF\x00\x00\x00\x00\x00\x00\x00\x00",
        "AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEEEEFFFFFFFF"
        "B\x4F\x0F\xFF\x00\x00\x00\x00",
    };
    size_t seed_lens[] = { 8, 8, 8, 12, 68 };

    for (int i = 0; i < 5; i++) {
        fuzzer_add_seed(&fs, (const uint8_t*)seeds[i],
                         seed_lens[i], "seed");
    }

    printf("\n─── Mutation Test ───\n");
    fs.corpus.current_idx = 0;
    crash_count = 0;

    printf("Testing bitflip mutations...\n");
    fuzz_mutate_bitflip(&fs, 1);

    printf("Testing byte add/sub...\n");
    fuzz_mutate_byte_add(&fs);

    printf("Testing interesting values...\n");
    fuzz_mutate_interesting(&fs, 1);
    fuzz_mutate_interesting(&fs, 2);
    fuzz_mutate_interesting(&fs, 4);

    printf("Testing havoc...\n");
    fuzz_mutate_havoc(&fs);

    printf("\n─── Summary ───\n");
    fuzz_stats_update(&fs.stats, fs.stats.total_execs);
    fuzz_stats_print(&fs.stats);

    printf("\nCrashes found: %d\n", crash_count);
    for (uint32_t i = 0; i < fs.crashes.count; i++) {
        crash_info_t *c = &fs.crashes.crashes[i];
        printf("  Crash %u: [%s] at exec %llu, size=%zu\n",
               i, c->signal_desc,
               (unsigned long long)c->exec_at, c->len);
    }

    /* Corpus summary */
    printf("\nCorpus entries: %u\n", fs.corpus.count);
    for (uint32_t i = 0; i < fs.corpus.count; i++) {
        printf("  [%u] %s: %zu bytes\n", i,
               fs.corpus.entries[i].name,
               fs.corpus.entries[i].len);
    }

    /* Minimize corpus */
    printf("\n─── Corpus Minimization ───\n");
    fuzzer_minimize_corpus(&fs);

    fuzzer_free(&fs);

    printf("\n═══════════════════════════════════════════\n");
    printf("  Fuzzing example complete.\n");
    return 0;
}
