/*
 * mini-smart-contract-sec — Core Tests
 *
 * Unit tests for EVM simulation, reentrancy detection, overflow detection, access control, formal verification.
 */
#include "../include/evm_sim.h"
#include "../include/reentrancy_check.h"
#include "../include/overflow_detect.h"
#include "../include/access_control.h"
#include "../include/formal_verify.h"
#include <stdio.h>
#include <string.h>

static int tests_run = 0, tests_passed = 0;

#define TEST(name) do { tests_run++; printf("  TEST %s ... ", name); } while(0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); return 1; } while(0)
#define CHECK(cond, msg) if (!(cond)) FAIL(msg)

/* ── EVM Simulation Tests ── */
static int test_evm_execute_basic(void) {
    TEST("evm_execute_basic");
    uint8_t code[] = {
        OP_PUSH1, 0x2a,    /* PUSH1 42 */
        OP_PUSH1, 0x10,    /* PUSH1 16 */
        OP_ADD,             /* ADD */
        OP_STOP              /* STOP */
    };
    evm_t evm;
    evm_init(&evm, code, sizeof(code));
    evm.gas_limit = 100000;
    int result = evm_execute(&evm);
    CHECK(result == 0, "execution failed");
    CHECK(!evm.reverted, "unexpected revert");
    PASS();
    return 0;
}

static int test_evm_stack_operations(void) {
    TEST("evm_stack_operations");
    uint8_t code[] = {
        OP_PUSH1, 0x2a,    /* PUSH1 42 */
        OP_PUSH1, 0x10,    /* PUSH1 16 */
        OP_ADD,             /* ADD -> 58 */
        OP_PUSH1, 0x05,    /* PUSH1 5 */
        OP_MUL,             /* MUL -> 290 */
        OP_STOP
    };
    evm_t evm;
    evm_init(&evm, code, sizeof(code));
    evm.gas_limit = 100000;
    evm_execute(&evm);
    uint256_t top;
    stack_pop(&evm.stack, &top);
    CHECK(top.w[0] == 290, "stack result should be (42+16)*5 = 290");
    PASS();
    return 0;
}

/* ── Reentrancy Detection Tests ── */
static int test_reentrancy_detection(void) {
    TEST("reentrancy_detection");
    rc_analyzer_t reent;
    rc_init(&reent);
    int f_withdraw = rc_add_function(&reent, "withdraw", true, 1);
    int f_transfer = rc_add_function(&reent, "transfer", false, 0);
    rc_mark_external_call(&reent, f_withdraw);
    rc_mark_state_write(&reent, f_withdraw);
    rc_add_edge(&reent, f_withdraw, f_transfer, RC_EVT_CALL);
    rc_set_guard(&reent, 1, true);
    int vuln_count = rc_detect_reentrancy(&reent);
    CHECK(vuln_count == 0, "guarded function should have 0 vulnerabilities");
    PASS();
    return 0;
}

static int test_reentrancy_cei_pattern(void) {
    TEST("reentrancy_cei_pattern");
    rc_analyzer_t reent;
    rc_init(&reent);
    int f = rc_add_function(&reent, "withdraw", true, 1);
    rc_mark_external_call(&reent, f);
    int cei_ok = rc_check_cei_pattern(&reent, f);
    CHECK(cei_ok >= 0, "CEI check should succeed");
    PASS();
    return 0;
}

/* ── Overflow Detection Tests ── */
static int test_overflow_add(void) {
    TEST("overflow_add");
    uint64_t r;
    CHECK(od_add_overflow(0xFFFFFFFFFFFFFF00ULL, 0xFF, &r), "near-max add should overflow");
    CHECK(!od_add_overflow(10, 20, &r), "10+20 should not overflow");
    PASS();
    return 0;
}

static int test_underflow_sub(void) {
    TEST("underflow_sub");
    uint64_t r;
    CHECK(od_sub_underflow(10, 20, &r), "10-20 should underflow");
    CHECK(!od_sub_underflow(100, 50, &r), "100-50 should not underflow");
    PASS();
    return 0;
}

static int test_overflow_mul(void) {
    TEST("overflow_mul");
    uint64_t r;
    CHECK(od_mul_overflow(0x100000000ULL, 0x10000ULL, &r), "large mul should overflow");
    CHECK(!od_mul_overflow(100, 200, &r), "100*200 should not overflow");
    PASS();
    return 0;
}

/* ── Access Control Tests ── */
static int test_ownable(void) {
    TEST("ownable");
    ac_analyzer_t ac;
    ac_init(&ac);
    uint8_t owner[AC_ADDR_LEN]; memset(owner, 0xAA, AC_ADDR_LEN);
    ac_set_owner(&ac, owner);
    CHECK(memcmp(ac.owner, owner, AC_ADDR_LEN) == 0, "owner not set");
    PASS();
    return 0;
}

static int test_rbac_grant_role(void) {
    TEST("rbac_grant_role");
    ac_analyzer_t ac;
    ac_init(&ac);
    uint8_t owner[AC_ADDR_LEN]; memset(owner, 0xAA, AC_ADDR_LEN);
    ac_set_owner(&ac, owner);
    uint8_t user[AC_ADDR_LEN]; memset(user, 0xBB, AC_ADDR_LEN);
    ac_role_t role;
    ac_role_init(&role, "MINTER_ROLE");
    ac_grant_role(&ac, &role, user, owner);
    CHECK(ac_has_role(&ac, &role, user), "user should have MINTER_ROLE");
    PASS();
    return 0;
}

/* ── Formal Verification Tests ── */
static int test_fv_cfg_basic(void) {
    TEST("fv_cfg_basic");
    fv_analyzer_t fv;
    fv_init(&fv);
    int b0 = fv_cfg_add_block(&fv.cfg, "entry", 1);
    int b1 = fv_cfg_add_block(&fv.cfg, "return", 100);
    fv_cfg_add_edge(&fv.cfg, b0, b1);
    fv_cfg_set_return(&fv.cfg, b1);
    CHECK(fv.cfg.block_count == 2, "block count wrong");
    fv_explore_all_paths(&fv);
    CHECK(fv.total_paths_explored >= 1, "no paths explored");
    PASS();
    return 0;
}

static int test_fv_assertion_check(void) {
    TEST("fv_assertion_check");
    fv_analyzer_t fv;
    fv_init(&fv);
    int b0 = fv_cfg_add_block(&fv.cfg, "entry", 1);
    int b1 = fv_cfg_add_block(&fv.cfg, "check", 10);
    int b2 = fv_cfg_add_block(&fv.cfg, "revert", 15);
    int b3 = fv_cfg_add_block(&fv.cfg, "success", 20);
    int b4 = fv_cfg_add_block(&fv.cfg, "return", 25);
    fv_cfg_add_edge(&fv.cfg, b0, b1);
    fv_cfg_set_conditional(&fv.cfg, b1, b3, b2);
    fv_cfg_set_assert(&fv.cfg, b2, "balance >= amount");
    fv_cfg_set_revert(&fv.cfg, b2);
    fv_cfg_add_edge(&fv.cfg, b2, b4);
    fv_cfg_add_edge(&fv.cfg, b3, b4);
    fv_cfg_set_return(&fv.cfg, b4);
    fv_explore_all_paths(&fv);
    int failures = fv_check_assertions(&fv);
    CHECK(failures >= 0, "assertion check failed");
    CHECK(fv.total_assertions >= 1, "no assertions found");
    PASS();
    return 0;
}

int main(void) {
    printf("=== mini-smart-contract-sec Unit Tests ===\n\n");

    int failed = 0;
    failed += test_evm_execute_basic();
    failed += test_evm_stack_operations();
    failed += test_reentrancy_detection();
    failed += test_reentrancy_cei_pattern();
    failed += test_overflow_add();
    failed += test_underflow_sub();
    failed += test_overflow_mul();
    failed += test_ownable();
    failed += test_rbac_grant_role();
    failed += test_fv_cfg_basic();
    failed += test_fv_assertion_check();

    printf("\n=== Results: %d/%d passed, %d failed ===\n",
           tests_passed, tests_run, failed);
    return failed > 0 ? 1 : 0;
}
