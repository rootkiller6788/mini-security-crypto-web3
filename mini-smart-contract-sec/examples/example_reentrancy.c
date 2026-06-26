#include "reentrancy_check.h"
#include <stdio.h>

int main(void) {
    rc_analyzer_t analyzer;
    rc_init(&analyzer);

    /* Define functions */
    int withdraw_id = rc_add_function(&analyzer, "withdraw", false, -1);
    int transfer_id = rc_add_function(&analyzer, "transfer", false, -1);
    (void)rc_add_function(&analyzer, "donate", false, -1);

    /* Mark capabilities */
    rc_mark_external_call(&analyzer, withdraw_id);
    rc_mark_state_write(&analyzer, withdraw_id);
    rc_mark_state_write(&analyzer, transfer_id);

    /* Define call graph */
    rc_add_edge(&analyzer, withdraw_id, transfer_id, RC_EVT_CALL);

    /* Log events for withdraw: external call BEFORE state update = VULN */
    rc_add_event(&analyzer, RC_EVT_CALL,   10, "attacker", "withdraw");
    rc_add_event(&analyzer, RC_EVT_SLOAD,  15, "balances", "withdraw");
    rc_add_event(&analyzer, RC_EVT_SSTORE, 30, "balances", "withdraw");

    printf("=== Basic Reentrancy Example ===\n\n");

    printf("1. withdraw() calls external before updating state\n");
    printf("   Pattern: call -> sload -> sstore\n");

    /* Detect */
    rc_detect_reentrancy(&analyzer);

    /* Simulate attack */
    rc_simulate_attack(&analyzer, withdraw_id, true);

    /* --- Example 2: CEI Pattern (Safe) --- */
    rc_analyzer_t cei;
    rc_init(&cei);

    int safe_withdraw = rc_add_function(&cei, "withdrawSafe", false, -1);
    rc_mark_external_call(&cei, safe_withdraw);
    rc_mark_state_write(&cei, safe_withdraw);

    rc_add_event(&cei, RC_EVT_SLOAD,  5, "balances", "withdrawSafe");
    rc_add_event(&cei, RC_EVT_SSTORE, 7, "balances", "withdrawSafe");
    rc_add_event(&cei, RC_EVT_CALL,  12, "user", "withdrawSafe");

    printf("\n2. withdrawSafe() follows CEI (checks then effects then interactions)\n");
    printf("   Pattern: sload -> sstore -> call\n");

    rc_detect_reentrancy(&cei);

    /* --- Example 3: Guarded (Safe) --- */
    rc_analyzer_t guarded;
    rc_init(&guarded);

    int guarded_withdraw = rc_add_function(&guarded, "withdrawGuarded", true, 0);
    rc_mark_external_call(&guarded, guarded_withdraw);
    rc_mark_state_write(&guarded, guarded_withdraw);
    rc_set_guard(&guarded, 0, true);

    printf("\n3. withdrawGuarded() uses nonReentrant modifier\n");

    rc_detect_reentrancy(&guarded);

    /* Print reports */
    rc_print_report(&analyzer);
    printf("\n");
    rc_print_report(&cei);
    printf("\n");
    rc_print_report(&guarded);

    printf("\n=== Summary ===\n");
    printf("Vulnerable case:  detected=%d\n", analyzer.detected_reentrancy);
    printf("CEI pattern:      detected=%d\n", cei.detected_reentrancy);
    printf("Guarded:          detected=%d\n", guarded.detected_reentrancy);

    return 0;
}
