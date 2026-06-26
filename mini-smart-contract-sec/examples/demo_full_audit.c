#include "evm_sim.h"
#include "reentrancy_check.h"
#include "overflow_detect.h"
#include "access_control.h"
#include "formal_verify.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static void fuzz_target_add(uint64_t a, uint64_t b) {
    uint64_t r;
    od_add_overflow(a, b, &r);
}

static void fuzz_target_mul(uint64_t a, uint64_t b) {
    uint64_t r;
    od_mul_overflow(a, b, &r);
}

int main(void) {
    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║     Smart Contract Full Security Audit Demo      ║\n");
    printf("║     EVM + Reentrancy + Overflow + Access + FV    ║\n");
    printf("╚══════════════════════════════════════════════════╝\n");

    /* ================================================================
     * Part 1: EVM Simulation - Execute a simple contract
     * ================================================================ */
    printf("\n══════════ Part 1: EVM Simulation ══════════\n");

    /* Contract bytecode: PUSH1 10, PUSH1 20, ADD, PUSH1 5, MUL, STOP
     * This computes (10 + 20) * 5 = 150 */
    uint8_t bytecode[] = {
        0x60, 0x0A,       /* PUSH1 10  */
        0x60, 0x14,       /* PUSH1 20  */
        0x01,             /* ADD       */
        0x60, 0x05,       /* PUSH1 5   */
        0x02,             /* MUL       */
        0x00              /* STOP      */
    };

    evm_t evm;
    evm_init(&evm, bytecode, sizeof(bytecode));

    printf("Executing: PUSH1 10, PUSH1 20, ADD, PUSH1 5, MUL\n");
    printf("Expected: (10 + 20) * 5 = 150\n");

    int steps = evm_execute(&evm);
    printf("Steps:     %d\n", steps);
    printf("Gas used:  %llu\n", (unsigned long long)evm.gas_used);
    printf("Reverted:  %s\n", evm.reverted ? "yes" : "no");

    if (evm.stack.sp >= 1) {
        printf("Result:    ");
        uint256_print(&evm.stack.data[0]);
        printf("\n");
    }

    /* Storage test */
    printf("\n--- Storage Test ---\n");
    uint256_t key, val;
    uint256_set64(&key, 0x01);
    uint256_set64(&val, 0xDEAD);
    storage_set(&evm.storage, &key, &val);
    printf("SSTORE: key=0x01, value=0xDEAD\n");

    uint256_t loaded;
    if (storage_get(&evm.storage, &key, &loaded)) {
        printf("SLOAD:  key=0x01 => ");
        uint256_print(&loaded);
        printf("\n");
    }

    /* Call context */
    uint8_t caller[EVM_ADDR_LEN] = {0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
                                    0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA};
    evm_set_caller(&evm, caller);
    uint256_t callvalue;
    uint256_set64(&callvalue, 1000000000000000000ULL);
    evm_set_value(&evm, &callvalue);
    printf("Caller set: 0xAA..AA, value: 1 ETH\n");

    /* Gas test - out of gas */
    printf("\n--- Gas Exhaustion Test ---\n");
    evm_t evm2;
    evm_init(&evm2, bytecode, sizeof(bytecode));
    evm2.gas = 50;
    evm_execute(&evm2);
    printf("Gas=50, reverted: %s (%s)\n",
           evm2.reverted ? "yes" : "no", evm2.revert_reason);

    /* REVERT test */
    printf("\n--- REVERT Opcode Test ---\n");
    uint8_t revert_bytecode[] = { 0x60, 0x01, 0x60, 0x02, 0xfd };
    evm_t evm3;
    evm_init(&evm3, revert_bytecode, sizeof(revert_bytecode));
    evm_execute(&evm3);
    printf("REVERT executed: %s (%s)\n",
           evm3.reverted ? "yes" : "no", evm3.revert_reason);

    /* ================================================================
     * Part 2: Reentrancy Detection - Full audit scenario
     * ================================================================ */
    printf("\n══════════ Part 2: Reentrancy Detection ══════════\n");

    rc_analyzer_t rc;
    rc_init(&rc);

    int withdraw  = rc_add_function(&rc, "withdraw", false, -1);
    int _transfer = rc_add_function(&rc, "_transfer", false, -1);
    int deposit   = rc_add_function(&rc, "deposit", false, -1);
    int adminWd   = rc_add_function(&rc, "adminWithdraw", false, -1);
    int safeWd    = rc_add_function(&rc, "safeWithdraw", true, 0);

    rc_mark_external_call(&rc, withdraw);
    rc_mark_state_write(&rc, withdraw);
    rc_mark_external_call(&rc, adminWd);
    rc_mark_state_write(&rc, adminWd);
    rc_mark_external_call(&rc, safeWd);
    rc_mark_state_write(&rc, safeWd);
    rc_mark_state_write(&rc, _transfer);
    rc_mark_state_write(&rc, deposit);

    rc_add_edge(&rc, withdraw, _transfer, RC_EVT_CALL);
    rc_add_edge(&rc, adminWd, _transfer, RC_EVT_CALL);

    rc_add_event(&rc, RC_EVT_CALL,   12, "user", "withdraw");
    rc_add_event(&rc, RC_EVT_SLOAD,  15, "balances", "withdraw");
    rc_add_event(&rc, RC_EVT_SSTORE, 25, "balances", "withdraw");

    rc_add_event(&rc, RC_EVT_SLOAD,  5, "balances", "safeWithdraw");
    rc_add_event(&rc, RC_EVT_SSTORE, 8, "balances", "safeWithdraw");
    rc_add_event(&rc, RC_EVT_CALL,  14, "user", "safeWithdraw");

    rc_add_event(&rc, RC_EVT_SSTORE, 3, "balances", "deposit");
    rc_add_event(&rc, RC_EVT_SLOAD,  6, "balances", "deposit");

    rc_add_event(&rc, RC_EVT_TRANSFER, 11, "user", "adminWd");
    rc_add_event(&rc, RC_EVT_SSTORE,   20, "admin", "adminWd");

    rc_set_guard(&rc, 0, true);

    printf("Analyzing 5 functions, 8 events, 2 edges...\n");
    int vulns = rc_detect_reentrancy(&rc);

    rc_simulate_attack(&rc, withdraw, true);
    rc_simulate_attack(&rc, safeWd, true);
    rc_simulate_attack(&rc, adminWd, true);

    rc_print_report(&rc);

    /* ================================================================
     * Part 3: Overflow Detection - Comprehensive checks
     * ================================================================ */
    printf("\n══════════ Part 3: Overflow Detection ══════════\n");

    od_analyzer_t od;
    od_init(&od);

    uint64_t r;

    printf("Running comprehensive overflow checks...\n");

    od_add_overflow(UINT64_MAX, 1, &r);
    od_check_operation(&od, "+", UINT64_MAX, 1, r, 1);

    od_sub_underflow(0, 1, &r);
    od_check_operation(&od, "-", 0, 1, r, 2);

    od_mul_overflow(0x10000000000000000ULL, 0x10, &r);
    od_check_operation(&od, "*", 0x10000000000000000ULL, 0x10, r, 3);

    od_check_operation(&od, "/", 100, 0, 0, 4);

    od_check_timestamp(&od, 0x100000000ULL, 5);
    od_check_timestamp(&od, 0x200000000ULL, 6);
    od_check_block_number(&od, 0x1FFFFFFFFULL, 7);

    od_check_truncation(&od, 256, 64, 8);
    od_check_truncation(&od, 256, 128, 9);

    od_fixed_t fp1 = od_fixed_from_int(1000000, 6);
    od_fixed_t fp2 = od_fixed_from_int(500000, 6);
    od_fixed_t fps = od_fixed_add(fp1, fp2);
    printf("Fixed-point: 1.0 + 0.5 = %llu (d=%d, valid=%d)\n",
           (unsigned long long)fps.value, fps.decimals, fps.valid);

    od_fixed_t fp3 = od_fixed_from_int(100, 18);
    od_fixed_t fp4 = od_fixed_from_int(200, 6);
    od_check_fixed_op(&od, &fp3, &fp4, "mixed_decimals", 10);

    od_print_report(&od);

    /* ================================================================
     * Part 4: Access Control - Full RBAC scenario
     * ================================================================ */
    printf("\n══════════ Part 4: Access Control ══════════\n");

    ac_analyzer_t ac;
    ac_init(&ac);

    uint8_t owner_addr[AC_ADDR_LEN], admin_addr[AC_ADDR_LEN],
            user_addr[AC_ADDR_LEN], bad_addr[AC_ADDR_LEN],
            upgrade_addr[AC_ADDR_LEN];

    ac_address_from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", owner_addr);
    ac_address_from_hex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", admin_addr);
    ac_address_from_hex("cccccccccccccccccccccccccccccccccccccccc", user_addr);
    ac_address_from_hex("dddddddddddddddddddddddddddddddddddddddd", bad_addr);
    ac_address_from_hex("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", upgrade_addr);

    memcpy(ac.msg_sender, owner_addr, AC_ADDR_LEN);
    memcpy(ac.tx_origin, owner_addr, AC_ADDR_LEN);
    memcpy(ac.rbac.admin, owner_addr, AC_ADDR_LEN);

    ac_set_owner(&ac, owner_addr);

    ac_role_t admin_role, operator_role, pauser_role;
    ac_role_init(&admin_role, "DEFAULT_ADMIN_ROLE");
    ac_role_init(&operator_role, "OPERATOR_ROLE");
    ac_role_init(&pauser_role, "PAUSER_ROLE");

    ac_grant_role(&ac, &operator_role, user_addr, owner_addr);
    ac_grant_role(&ac, &pauser_role, admin_addr, owner_addr);

    printf("RBAC: %d roles granted\n", ac.rbac.count);
    printf("  user has OPERATOR: %s\n",
           ac_has_role(&ac, &operator_role, user_addr) ? "YES" : "no");
    printf("  user has PAUSER:   %s\n",
           ac_has_role(&ac, &pauser_role, user_addr) ? "YES" : "no");

    memcpy(ac.tx_origin, bad_addr, AC_ADDR_LEN);
    ac_check_tx_origin(&ac);

    ac.is_delegatecall = true;
    ac_check_delegatecall_risk(&ac, upgrade_addr, false);

    ac_check_initializer(&ac, true);
    ac.initialized_state = true;
    ac_check_initializer(&ac, true);

    ac_print_report(&ac);

    /* ================================================================
     * Part 5: Formal Verification - Symbolic execution + Fuzzing
     * ================================================================ */
    printf("\n══════════ Part 5: Formal Verification ══════════\n");

    fv_analyzer_t fv;
    fv_init(&fv);

    printf("Building control flow graph...\n");

    int b0 = fv_cfg_add_block(&fv.cfg, "entry", 0);
    int b1 = fv_cfg_add_block(&fv.cfg, "check_balance", 5);
    int b2 = fv_cfg_add_block(&fv.cfg, "transfer", 10);
    int b3 = fv_cfg_add_block(&fv.cfg, "insufficient", 12);
    int b4 = fv_cfg_add_block(&fv.cfg, "update_state", 15);
    int b5 = fv_cfg_add_block(&fv.cfg, "emit_event", 20);
    int b6 = fv_cfg_add_block(&fv.cfg, "return", 25);

    fv.cfg.entry_block = b0;

    fv_cfg_add_edge(&fv.cfg, b0, b1);
    fv_cfg_set_conditional(&fv.cfg, b1, b2, b3);
    fv_cfg_add_edge(&fv.cfg, b2, b4);
    fv_cfg_set_assert(&fv.cfg, b3, "balance >= amount");
    fv_cfg_add_edge(&fv.cfg, b3, b6);
    fv_cfg_add_edge(&fv.cfg, b4, b5);
    fv_cfg_add_edge(&fv.cfg, b5, b6);
    fv_cfg_set_return(&fv.cfg, b6);

    printf("CFG: %d blocks built\n", fv.cfg.block_count);

    fv_symbolic_execute(&fv);
    printf("Symbolic execution: %d paths explored\n", fv.total_paths_explored);

    fv_add_invariant(&fv, "totalSupply == sum(balances)", true);
    fv_add_invariant(&fv, "balances[x] >= 0", true);
    fv_check_assertions(&fv);
    printf("Assertions: %d/%d passed\n",
           fv.total_assertions - fv.assertion_failures,
           fv.total_assertions);

    printf("\n--- Taint Analysis ---\n");
    fv_taint_init(&fv.taint);
    fv_taint_mark_input(&fv.taint, "_amount", "calldata[4:36]");
    fv_taint_mark_input(&fv.taint, "_to", "calldata[36:68]");
    fv_taint_propagate(&fv.taint, "_amount", "transferAmount");
    fv_taint_propagate(&fv.taint, "_to", "recipient");
    fv_taint_check_sink(&fv.taint, "transferAmount", "SSTORE", FV_TAINT_USER_INPUT);
    fv_taint_check_sink(&fv.taint, "recipient", "CALL", FV_TAINT_USER_INPUT);

    fv_taint_analyze(&fv);
    fv_print_taint(&fv.taint);

    printf("\n--- Fuzzing ---\n");
    fv_fuzz_init(&fv);
    fv_fuzz_run(&fv, fuzz_target_add, 10000);
    fv_fuzz_run_seed(&fv, fuzz_target_mul, 0xCAFEBABE, 5000);

    printf("Fuzz iterations: %llu (add) + 5000 (mul)\n",
           (unsigned long long)fv.fuzz_iterations);

    fv_print_report(&fv);
    fv_print_cfg(&fv.cfg);

    /* ================================================================
     * Final Summary
     * ================================================================ */
    printf("\n╔══════════════════════════════════════════════════╗\n");
    printf("║              Audit Summary                       ║\n");
    printf("╠══════════════════════════════════════════════════╣\n");
    printf("║ EVM Steps:        %-30d ║\n", steps);
    printf("║ EVM Gas Used:     %-30llu ║\n", (unsigned long long)evm.gas_used);
    printf("║ Reentrancy Vulns: %-30d ║\n", vulns);
    printf("║ Overflow Issues:  %-30d ║\n", od_total_issues(&od));
    printf("║ Access Issues:    %-30d ║\n", ac.findings_count);
    printf("║ FV Paths:         %-30d ║\n", fv.total_paths_explored);
    printf("║ FV Assertions:    %-20d/%-8d ║\n",
           fv.total_assertions - fv.assertion_failures, fv.total_assertions);
    printf("╚══════════════════════════════════════════════════╝\n");

    return 0;
}
