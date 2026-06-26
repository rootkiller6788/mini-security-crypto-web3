/*
 * mini-smart-contract-sec — Full Demo: Smart Contract Security
 *
 * Demonstrates: EVM simulation, reentrancy detection, overflow detection,
 *               access control (Ownable/RBAC/EIP-712), formal verification.
 */
#include "../include/evm_sim.h"
#include "../include/reentrancy_check.h"
#include "../include/overflow_detect.h"
#include "../include/access_control.h"
#include "../include/formal_verify.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    printf("=== mini-smart-contract-sec: Smart Contract Security Demo ===\n\n");

    /* Step 1: EVM Simulation */
    printf("-- Step 1: EVM Simulation --\n");
    uint8_t code[] = {
        OP_PUSH1, 0x2a,    /* PUSH1 42 */
        OP_PUSH1, 0x10,    /* PUSH1 16 */
        OP_ADD,             /* ADD */
        OP_PUSH1, 0x05,    /* PUSH1 5 */
        OP_MUL,             /* MUL */
        OP_STOP             /* STOP */
    };
    evm_t evm;
    evm_init(&evm, code, sizeof(code));
    evm.gas_limit = 100000;
    int result = evm_execute(&evm);
    printf("EVM bytecode: PUSH1 42, PUSH1 16, ADD, PUSH1 5, MUL, STOP\n");
    printf("Execution: %s (gas used=%llu, reverted=%s)\n",
           result == 0 ? "SUCCESS" : "FAILED",
           (unsigned long long)evm.gas_used, evm.reverted ? "YES" : "NO");

    uint256_t stack_top;
    stack_pop(&evm.stack, &stack_top);
    printf("Stack result: (42+16)*5 = %llu\n", (unsigned long long)stack_top.w[0]);

    /* Step 2: Reentrancy Detection */
    printf("\n-- Step 2: Reentrancy Detection --\n");
    rc_analyzer_t reent;
    rc_init(&reent);

    int f_withdraw = rc_add_function(&reent, "withdraw", true, 1);
    int f_transfer = rc_add_function(&reent, "transfer", false, 0);
    rc_mark_external_call(&reent, f_withdraw);
    rc_mark_state_write(&reent, f_withdraw);
    rc_add_edge(&reent, f_withdraw, f_transfer, RC_EVT_CALL);
    rc_set_guard(&reent, 1, true);

    int vuln_count = rc_detect_reentrancy(&reent);
    printf("Functions: withdraw (with guard), transfer\n");
    printf("Reentrancy detection: %d vulnerabilities found\n", vuln_count);

    if (reent.detected_reentrancy) {
        printf("  Pattern: %s\n", rc_pattern_name(reent.vulnerabilities[0]));
        printf("  Description: %s\n", reent.vuln_desc);
    } else {
        printf("  Pattern: %s (guarded with mutex)\n", rc_pattern_name(RC_PATTERN_GUARDED));
    }

    int cei_ok = rc_check_cei_pattern(&reent, f_withdraw);
    printf("CEI pattern check: %s\n", cei_ok ? "FOLLOWS CEI" : "VIOLATES CEI");

    /* Step 3: Overflow Detection */
    printf("\n-- Step 3: Overflow/Underflow Detection --\n");
    od_analyzer_t od;
    od_init(&od);

    uint64_t r;
    bool safe_add = od_add_overflow(0xFFFFFFFFFFFFFF00ULL, 0xFF, &r);
    bool safe_mul = od_mul_overflow(0x100000000ULL, 0x10000ULL, &r);
    bool safe_sub = od_sub_underflow(10, 20, &r);
    printf("uint64 add (max-256 + 256): %s\n", safe_add ? "SAFE" : "OVERFLOW!");
    printf("uint64 mul (4B * 64K): %s\n", safe_mul ? "SAFE" : "OVERFLOW!");
    printf("uint64 sub (10 - 20): %s\n", safe_sub ? "SAFE" : "UNDERFLOW!");

    od_check_operation(&od, "MUL", 0x100000000ULL, 0x10000ULL, 0, 42);
    od_check_operation(&od, "ADD", 0xFFFFFFFFFFFFFF00ULL, 0xFF, 0, 43);
    printf("Issues found: %d total (%d overflows, %d underflows)\n",
           od_total_issues(&od), od.overflow_count, od.underflow_count);

    od_fixed_t fx = od_fixed_from_int(150, 2);
    od_fixed_t fy = od_fixed_from_int(250, 2);
    od_fixed_t fsum = od_fixed_add(fx, fy);
    printf("Fixed-point: 1.50 + 2.50 = %llu.%02llu\n",
           (unsigned long long)(fsum.value / 100), (unsigned long long)(fsum.value % 100));

    /* Step 4: Access Control */
    printf("\n-- Step 4: Access Control --\n");
    ac_analyzer_t ac;
    ac_init(&ac);

    uint8_t owner[AC_ADDR_LEN]; memset(owner, 0xAA, AC_ADDR_LEN);
    ac_set_owner(&ac, owner);
    printf("Ownable: owner set\n");

    uint8_t user1[AC_ADDR_LEN]; memset(user1, 0xBB, AC_ADDR_LEN);
    ac_role_t admin_role, minter_role;
    ac_role_init(&admin_role, "ADMIN_ROLE");
    ac_role_init(&minter_role, "MINTER_ROLE");

    ac_grant_role(&ac, &admin_role, user1, owner);
    ac_grant_role(&ac, &minter_role, user1, owner);
    printf("RBAC: user granted ADMIN_ROLE and MINTER_ROLE\n");
    printf("  has ADMIN_ROLE: %s\n", ac_has_role(&ac, &admin_role, user1) ? "YES" : "NO");
    printf("  has MINTER_ROLE: %s\n", ac_has_role(&ac, &minter_role, user1) ? "YES" : "NO");

    ac_eip712_domain_t dom;
    uint8_t contract[AC_ADDR_LEN]; memset(contract, 0xCC, AC_ADDR_LEN);
    ac_eip712_init(&dom, "MyDApp", "1", 1, contract);
    printf("EIP-712 domain: %s v%s (chain=%llu)\n", dom.name, dom.version, (unsigned long long)dom.chain_id);

    ac_result_t tx_check = ac_check_tx_origin(&ac);
    printf("tx.origin check: %s\n", ac_result_string(tx_check));

    /* Step 5: Formal Verification */
    printf("\n-- Step 5: Formal Verification --\n");
    fv_analyzer_t fv;
    fv_init(&fv);

    int b0 = fv_cfg_add_block(&fv.cfg, "entry", 1);
    int b1 = fv_cfg_add_block(&fv.cfg, "check_balance", 10);
    int b2 = fv_cfg_add_block(&fv.cfg, "revert_path", 15);
    int b3 = fv_cfg_add_block(&fv.cfg, "success_path", 20);
    int b4 = fv_cfg_add_block(&fv.cfg, "return", 25);

    fv_cfg_add_edge(&fv.cfg, b0, b1);
    fv_cfg_set_conditional(&fv.cfg, b1, b3, b2);
    fv_cfg_set_assert(&fv.cfg, b2, "balance >= transfer_amount");
    fv_cfg_set_revert(&fv.cfg, b2);
    fv_cfg_add_edge(&fv.cfg, b2, b4);
    fv_cfg_add_edge(&fv.cfg, b3, b4);
    fv_cfg_set_return(&fv.cfg, b4);

    printf("CFG constructed: %d blocks\n", fv.cfg.block_count);
    fv_explore_all_paths(&fv);
    printf("Paths explored: %d\n", fv.total_paths_explored);

    int assert_failures = fv_check_assertions(&fv);
    printf("Assertion check: %d/%d passed, %d failures\n",
           fv.total_assertions - fv.assertion_failures, fv.total_assertions, assert_failures);

    /* Taint tracking */
    fv_taint_tracker_t taint;
    fv_taint_init(&taint);
    fv_taint_mark_input(&taint, "user_amount", "calldata");
    fv_taint_propagate(&taint, "user_amount", "transfer_amount");
    fv_taint_check_sink(&taint, "transfer_amount", "external_call", FV_TAINT_MEDIUM);
    printf("Taint: user_amount[USER_INPUT] -> transfer_amount[reaches_sensitive=%s]\n",
           taint.vars[0].reaches_sensitive ? "YES" : "NO");

    printf("\nSmart contract security demo complete!\n");
    return 0;
}
