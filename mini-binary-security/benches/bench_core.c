/*
 * mini-binary-security — Benchmark: buffer overflow, ROP, mitigation, fuzzing
 *
 * Usage: bench_core [iterations]
 */
#include "../include/buffer_overflow.h"
#include "../include/rop_gadget.h"
#include "../include/mitigation_def.h"
#include "../include/format_string.h"
#include "../include/fuzzing_tool.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now_ms(void) {
    return (double)clock() / (double)(CLOCKS_PER_SEC / 1000);
}

static exec_result_t bench_target(const uint8_t *data, size_t len, void *user_data) {
    (void)user_data;
    if (len > 4 && data[0] == 'C' && data[1] == 'R' && data[2] == 'A' && data[3] == 'S')
        return EXEC_CRASH;
    return EXEC_OK;
}

int main(int argc, char **argv) {
    int N = (argc > 1) ? atoi(argv[1]) : 5000;
    printf("=== mini-binary-security Benchmarks (iterations=%d) ===\n\n", N);

    /* Integer overflow checks */
    {
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            int_ovf_check_add_int32(2000000000, 2000000000);
            int_ovf_check_mul_size(65536, 65536);
        }
        double dt = now_ms() - t0;
        printf("  int_ovf_check (add+mul):              %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    /* Format string parsing */
    {
        fmt_parse_result_t r;
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            fmt_parse("%d %s %n %x %p %08x", &r);
        }
        double dt = now_ms() - t0;
        printf("  fmt_parse:                            %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    /* ROP gadget classification */
    {
        rop_gadget_t g;
        memset(&g, 0, sizeof(g));
        g.address = 0x401000;
        g.bytes[0] = 0x5d; g.bytes[1] = 0xc3; /* pop rbp; ret */
        g.num_bytes = 2;
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            rop_gadget_classify(&g);
        }
        double dt = now_ms() - t0;
        printf("  rop_gadget_classify:                  %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    /* Mitigation detection */
    {
        double t0 = now_ms();
        for (int i = 0; i < N / 10; i++) {
            security_profile_t p = mitigation_detect();
            mitigation_assess_level(&p);
            mitigation_score(&p);
        }
        double dt = now_ms() - t0;
        printf("  mitigation_detect+assess:             %d ops in %.1f ms  (%.1f µs/op)\n",
               N / 10, dt, dt * 1000.0 / (double)(N / 10));
    }

    /* Fuzzer mutation */
    {
        uint8_t seed_data[] = "AAAA";
        fuzzer_state_t fs;
        fuzzer_init(&fs, ".", ".");
        fuzzer_set_target(&fs, bench_target, NULL);
        fuzzer_add_seed(&fs, seed_data, sizeof(seed_data) - 1, "seed");
        int k = N / 10 > 0 ? N / 10 : 1;
        double t0 = now_ms();
        for (int i = 0; i < k; i++) {
            fuzz_mutate_bitflip(&fs, 1);
            fuzz_execute(&fs);
        }
        double dt = now_ms() - t0;
        printf("  fuzz_mutate_bitflip+exec:             %d ops in %.1f ms  (%.1f µs/op)\n",
               k, dt, dt * 1000.0 / (double)k);
        fuzzer_free(&fs);
    }

    /* UAF tracker */
    {
        uaf_tracker_t t; uaf_tracker_init(&t);
        void *ptr = (void*)0x7fff1234;
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            uaf_tracker_add(&t, ptr, 64);
            uaf_tracker_mark_free(&t, ptr);
            uaf_tracker_is_dangling(&t, ptr);
        }
        double dt = now_ms() - t0;
        printf("  uaf_tracker add/free/check:           %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    printf("\n=== Benchmarks complete ===\n");
    return 0;
}
