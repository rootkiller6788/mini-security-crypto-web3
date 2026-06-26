#include "access_control.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    ac_analyzer_t analyzer;
    ac_init(&analyzer);

    printf("=== Access Control Example ===\n\n");

    uint8_t owner[AC_ADDR_LEN], attacker[AC_ADDR_LEN], user[AC_ADDR_LEN],
            proxy[AC_ADDR_LEN], delegate[AC_ADDR_LEN];

    ac_address_from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", owner);
    ac_address_from_hex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", attacker);
    ac_address_from_hex("cccccccccccccccccccccccccccccccccccccccc", user);
    ac_address_from_hex("dddddddddddddddddddddddddddddddddddddddd", proxy);
    ac_address_from_hex("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", delegate);

    memcpy(analyzer.msg_sender, owner, AC_ADDR_LEN);
    memcpy(analyzer.tx_origin, owner, AC_ADDR_LEN);

    printf("1. Ownable (onlyOwner) pattern:\n");
    ac_result_t r = ac_set_owner(&analyzer, owner);
    printf("   Set owner: %s\n", ac_result_string(r));

    r = ac_only_owner(&analyzer, owner);
    printf("   Owner access: %s\n", ac_result_string(r));

    r = ac_only_owner(&analyzer, attacker);
    printf("   Attacker access: %s\n", ac_result_string(r));

    printf("\n2. Role-Based Access Control (RBAC):\n");

    memcpy(analyzer.rbac.admin, owner, AC_ADDR_LEN);

    ac_role_t admin_role, minter_role, burner_role;
    ac_role_init(&admin_role, "ADMIN_ROLE");
    ac_role_init(&minter_role, "MINTER_ROLE");
    ac_role_init(&burner_role, "BURNER_ROLE");

    r = ac_grant_role(&analyzer, &minter_role, user, owner);
    printf("   Grant MINTER to user: %s\n", ac_result_string(r));

    printf("   user has MINTER: %s\n",
           ac_has_role(&analyzer, &minter_role, user) ? "yes" : "no");
    printf("   user has BURNER: %s\n",
           ac_has_role(&analyzer, &burner_role, user) ? "yes" : "no");

    r = ac_revoke_role(&analyzer, &minter_role, user, owner);
    printf("   Revoke MINTER from user: %s\n", ac_result_string(r));
    printf("   user has MINTER: %s\n",
           ac_has_role(&analyzer, &minter_role, user) ? "yes" : "no");

    r = ac_grant_role(&analyzer, &minter_role, user, attacker);
    printf("   Attacker grant MINTER: %s\n", ac_result_string(r));

    printf("\n3. tx.origin vs msg.sender:\n");
    memcpy(analyzer.tx_origin, attacker, AC_ADDR_LEN);
    memcpy(analyzer.msg_sender, owner, AC_ADDR_LEN);
    r = ac_check_tx_origin(&analyzer);
    printf("   tx.origin != msg.sender: %s\n", ac_result_string(r));

    memcpy(analyzer.tx_origin, owner, AC_ADDR_LEN);
    r = ac_check_tx_origin(&analyzer);
    printf("   tx.origin == msg.sender: %s\n", ac_result_string(r));

    printf("\n4. Delegatecall risk check:\n");
    analyzer.is_delegatecall = true;
    r = ac_check_delegatecall_risk(&analyzer, delegate, false);
    printf("   Delegatecall to untrusted: %s\n", ac_result_string(r));

    r = ac_check_delegatecall_risk(&analyzer, proxy, true);
    printf("   Delegatecall to trusted: %s\n", ac_result_string(r));

    printf("\n5. Initializer vulnerability:\n");
    r = ac_check_initializer(&analyzer, true);
    printf("   First init call: %s\n", ac_result_string(r));
    analyzer.initialized_state = true;
    r = ac_check_initializer(&analyzer, true);
    printf("   Second init call: %s\n", ac_result_string(r));
    r = ac_check_initializer(&analyzer, false);
    printf("   Non-init after initialized: %s\n", ac_result_string(r));

    printf("\n6. EIP-712 domain setup:\n");
    ac_eip712_domain_t domain;
    ac_eip712_init(&domain, "MyToken", "1", 1, delegate);
    printf("   Domain: %s v%s (chain=%llu)\n",
           domain.name, domain.version, (unsigned long long)domain.chain_id);

    ac_print_report(&analyzer);

    printf("\n=== Summary ===\n");
    printf("Issues found: %d\n", analyzer.findings_count);

    return 0;
}
