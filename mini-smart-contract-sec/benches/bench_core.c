/*
 * mini-smart-contract-sec — Benchmark: EVM, reentrancy, overflow, access control, formal verify
 *
 * Usage: bench_core [iterations]
 */
#include "../include/evm_sim.h"
#include "../include/reentrancy_check.h"
#include "../include/overflow_detect.h"
#include "../include/access_control.h"
#include "../include/formal_verify.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now_ms(void) {
    return (double)clock() / (double)(CLOCKS_PER_SEC / 1000);
}

int main(int argc, char **argv) {
    int N = (argc > 1) ? atoi(argv[1]) : 5000;
    printf("=== mini-smart-contract-sec Benchmarks (iterations=%d) ===\n\n", N);

    /* EVM uint256 arithmetic */
    {
        uint256_t a, b, r;
        uint256_set64(&a, 123456789012345ULL);
        uint256_set64(&b, 987654321098765ULL);
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            uint256_add(&r, &a, &b);
            uint256_mul(&r, &a, &b);
        }
        double dt = now_ms() - t0;
        printf("  uint256_add+uint256_mul:              %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    /* EVM stack operations */
    {
        evm_stack_t stack; stack.sp = 0;
        uint256_t val; uint256_set64(&val, 42);
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            stack_push(&stack, &val);
            stack_pop(&stack, &val);
        }
        double dt = now_ms() - t0;
        printf("  stack_push+pop:                       %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    /* EVM mini bytecode execution */
    {
        uint8_t code[] = {OP_PUSH1, 0x2a, OP_PUSH1, 0x10, OP_ADD, OP_STOP};
        evm_t evm;
        evm_init(&evm, code, sizeof(code));
        double t0 = now_ms();
        for (int i = 0; i < N / 10; i++) {
            evm_execute(&evm);
            evm_reset(&evm);
        }
        double dt = now_ms() - t0;
        int k = N / 10 > 0 ? N / 10 : 1;
        printf("  evm_execute (PUSH+ADD):               %d ops in %.1f ms  (%.1f µs/op)\n",
               k, dt, dt * 1000.0 / (double)k);
    }

    /* Reentrancy detection */
    {
        rc_analyzer_t a;
        rc_init(&a);
        int f0 = rc_add_function(&a, "withdraw", true, 1);
        int f1 = rc_add_function(&a, "transfer", false, 0);
        rc_add_edge(&a, f0, f1, RC_EVT_CALL);
        rc_mark_external_call(&a, f0);
        rc_mark_state_write(&a, f0);
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            rc_detect_reentrancy(&a);
        }
        double dt = now_ms() - t0;
        printf("  rc_detect_reentrancy:                 %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    /* Overflow detection */
    {
        od_analyzer_t a;
        od_init(&a);
        uint64_t result;
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            od_add_overflow(0xFFFFFFFFFFFFFF00ULL, 0xFF, &result);
            od_mul_overflow(0x100000000ULL, 0x10000ULL, &result);
            od_sub_underflow(10, 20, &result);
        }
        double dt = now_ms() - t0;
        printf("  od_add+mul+sub check:                 %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    /* Access control: role operations */
    {
        ac_analyzer_t a;
        ac_init(&a);
        uint8_t addr[AC_ADDR_LEN]; memset(addr, 0xAA, AC_ADDR_LEN);
        uint8_t caller[AC_ADDR_LEN]; memset(caller, 0xBB, AC_ADDR_LEN);
        ac_role_t role;
        ac_role_init(&role, "admin");
        ac_set_owner(&a, addr);
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            ac_grant_role(&a, &role, caller, addr);
            ac_has_role(&a, &role, caller);
        }
        double dt = now_ms() - t0;
        printf("  ac_grant_role+has_role:               %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    /* Formal verification: CFG construction */
    {
        fv_analyzer_t a;
        fv_init(&a);
        int b0 = fv_cfg_add_block(&a.cfg, "entry", 1);
        int b1 = fv_cfg_add_block(&a.cfg, "conditional", 10);
        int b2 = fv_cfg_add_block(&a.cfg, "revert", 15);
        int b3 = fv_cfg_add_block(&a.cfg, "return", 20);
        fv_cfg_set_conditional(&a.cfg, b1, b2, b3);
        fv_cfg_set_assert(&a.cfg, b2, "balance >= amount");
        fv_cfg_set_revert(&a.cfg, b2);
        fv_cfg_set_return(&a.cfg, b3);
        double t0 = now_ms();
        for (int i = 0; i < N / 10; i++) {
            fv_check_assertions(&a);
        }
        double dt = now_ms() - t0;
        int k = N / 10 > 0 ? N / 10 : 1;
        printf("  fv_check_assertions:                  %d ops in %.1f ms  (%.1f µs/op)\n",
               k, dt, dt * 1000.0 / (double)k);
    }

    printf("\n=== Benchmarks complete ===\n");
    return 0;
}
