#include "access_control.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

const char *ac_result_string(ac_result_t r) {
    switch (r) {
    case AC_OK:                return "OK";
    case AC_UNAUTHORIZED:      return "Unauthorized";
    case AC_INVALID_SIG:       return "Invalid Signature";
    case AC_EXPIRED:           return "Expired";
    case AC_REPLAYED:          return "Replayed";
    case AC_NOT_INITIALIZED:   return "Not Initialized";
    case AC_ALREADY_INIT:      return "Already Initialized";
    case AC_DELEGATECALL_RISK: return "Delegatecall Risk";
    case AC_TX_ORIGIN_ISSUE:   return "tx.origin Issue";
    default:                   return "Unknown";
    }
}

void ac_address_to_hex(const uint8_t addr[AC_ADDR_LEN], char *buf) {
    for (int i = 0; i < AC_ADDR_LEN; i++) {
        sprintf(buf + i * 2, "%02x", addr[i]);
    }
    buf[AC_ADDR_LEN * 2] = '\0';
}

void ac_address_from_hex(const char *hex, uint8_t addr[AC_ADDR_LEN]) {
    for (int i = 0; i < AC_ADDR_LEN; i++) {
        char b[3] = {hex[i * 2], hex[i * 2 + 1], '\0'};
        addr[i] = (uint8_t)strtoul(b, NULL, 16);
    }
}

bool ac_address_eq(const uint8_t a[AC_ADDR_LEN], const uint8_t b[AC_ADDR_LEN]) {
    return memcmp(a, b, AC_ADDR_LEN) == 0;
}

void ac_role_init(ac_role_t *r, const char *name) {
    memset(r->bytes, 0, 32);
    size_t n = strlen(name);
    for (size_t i = 0; i < n && i < 32; i++) {
        r->bytes[i] = (uint8_t)name[i];
    }
}

void ac_role_to_string(const ac_role_t *r, char *buf, size_t len) {
    size_t n = len < 33 ? len - 1 : 32;
    memcpy(buf, r->bytes, n);
    buf[n] = '\0';
}

void ac_init(ac_analyzer_t *a) {
    memset(a, 0, sizeof(ac_analyzer_t));
    memset(a->rbac.admin, 0xFF, AC_ADDR_LEN);
}

ac_result_t ac_set_owner(ac_analyzer_t *a, const uint8_t addr[AC_ADDR_LEN]) {
    if (a->ownable.initialized) {
        ac_ownable_t *o = &a->ownable;
        if (!ac_address_eq(o->owner, addr) && !ac_address_eq(a->rbac.admin, addr)) {
            return AC_UNAUTHORIZED;
        }
    }
    memcpy(a->ownable.owner, addr, AC_ADDR_LEN);
    a->ownable.initialized = true;
    return AC_OK;
}

ac_result_t ac_only_owner(const ac_analyzer_t *a, const uint8_t caller[AC_ADDR_LEN]) {
    if (!a->ownable.initialized) return AC_NOT_INITIALIZED;
    if (!ac_address_eq(a->ownable.owner, caller)) return AC_UNAUTHORIZED;
    return AC_OK;
}

static int ac_rbac_find_role(const ac_analyzer_t *a, const ac_role_t *role,
                              const uint8_t addr[AC_ADDR_LEN]) {
    for (int i = 0; i < a->rbac.count; i++) {
        if (memcmp(a->rbac.entries[i].role.bytes, role->bytes, 32) == 0 &&
            ac_address_eq(a->rbac.entries[i].member, addr)) {
            return i;
        }
    }
    return -1;
}

ac_result_t ac_grant_role(ac_analyzer_t *a, const ac_role_t *role,
                           const uint8_t addr[AC_ADDR_LEN],
                           const uint8_t caller[AC_ADDR_LEN]) {
    if (!ac_address_eq(a->rbac.admin, caller))
        return AC_UNAUTHORIZED;

    if (ac_rbac_find_role(a, role, addr) >= 0)
        return AC_OK;

    if (a->rbac.count >= 256)
        return AC_UNAUTHORIZED;

    a->rbac.entries[a->rbac.count].role = *role;
    memcpy(a->rbac.entries[a->rbac.count].member, addr, AC_ADDR_LEN);
    a->rbac.entries[a->rbac.count].granted = true;
    a->rbac.entries[a->rbac.count].granted_at = 0;
    a->rbac.count++;
    return AC_OK;
}

ac_result_t ac_revoke_role(ac_analyzer_t *a, const ac_role_t *role,
                            const uint8_t addr[AC_ADDR_LEN],
                            const uint8_t caller[AC_ADDR_LEN]) {
    if (!ac_address_eq(a->rbac.admin, caller))
        return AC_UNAUTHORIZED;

    int idx = ac_rbac_find_role(a, role, addr);
    if (idx < 0) return AC_OK;

    a->rbac.entries[idx].granted = false;
    return AC_OK;
}

bool ac_has_role(const ac_analyzer_t *a, const ac_role_t *role,
                 const uint8_t addr[AC_ADDR_LEN]) {
    int idx = ac_rbac_find_role(a, role, addr);
    return idx >= 0 && a->rbac.entries[idx].granted;
}

void ac_eip712_init(ac_eip712_domain_t *d, const char *name, const char *version,
                    uint64_t chain_id, const uint8_t verifying_contract[AC_ADDR_LEN]) {
    memset(d, 0, sizeof(ac_eip712_domain_t));
    strncpy(d->name, name, 63);
    d->name[63] = '\0';
    strncpy(d->version, version, 15);
    d->version[15] = '\0';
    d->chain_id = chain_id;
    memcpy(d->verifying_contract, verifying_contract, AC_ADDR_LEN);
}

/* ================================================================
 * L4: EIP-712 Typed Structured Data Hashing Verification
 *
 * EIP-712 defines a standard for hashing and signing typed structured
 * data. The verification involves:
 * 1. Compute the domain separator:
 *    domain_separator = keccak256(
 *      EIP712_DOMAIN_TYPEHASH ||
 *      keccak256(name) ||
 *      keccak256(version) ||
 *      chain_id ||
 *      verifying_contract ||
 *      salt
 *    )
 * 2. Compute the typed data hash using the type-specific encoding.
 * 3. Recover the signer address from (r, s, v) and compare.
 *
 * Theorem: ECDSA signature recovery deterministically maps (hash, r, s, v)
 * to a unique public key/address, enabling off-chain signed messages.
 *
 * This implementation provides a simplified signature format verification
 * (checking r,s are in valid range, v is 27/28) and domain validation.
 * Full ECDSA recovery requires secp256k1 which is beyond this library's scope.
 *
 * Reference: https://eips.ethereum.org/EIPS/eip-712
 * ================================================================ */
ac_result_t ac_verify_eip712(const ac_eip712_domain_t *domain,
                              const uint8_t digest[32],
                              const ac_signature_t *sig,
                              const uint8_t signer[AC_ADDR_LEN]) {
    /* Validate domain parameters */
    if (!domain || !sig || !digest || !signer) return AC_INVALID_SIG;
    if (domain->name[0] == '\0') return AC_INVALID_SIG;
    if (domain->chain_id == 0) return AC_INVALID_SIG;

    /* Validate signature format (EIP-712 uses v=27 or v=28) */
    if (sig->v != 27 && sig->v != 28) return AC_INVALID_SIG;

    /* Check r and s are non-zero (invalid signatures) */
    bool r_zero = true, s_zero = true;
    for (int i = 0; i < 32; i++) {
        if (sig->r[i] != 0) r_zero = false;
        if (sig->s[i] != 0) s_zero = false;
    }
    if (r_zero || s_zero) return AC_INVALID_SIG;

    /* Check s is in lower half of curve order (EIP-2 compliance) */
    /* secp256k1 order n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
     * s must be <= n/2 to prevent signature malleability */
    if (sig->s[0] >= 0x80) {
        /* If the high bit of s is set, it's > n/2 (malleable signature) */
        return AC_INVALID_SIG;
    }

    /* Simulated domain separator hash comparison.
     * In production, this would:
     * 1. Compute keccak256 of the domain typehash and parameters.
     * 2. Compute keccak256 of the structured data.
     * 3. Combine: keccak256("\x19\x01" || domain_separator || data_hash).
     * 4. Recover address via ecrecover(hash, v, r, s).
     * 5. Compare recovered address with signer. */
    (void)digest;
    (void)signer;

    /* For now: signature format is valid */
    return AC_OK;
}

/* ================================================================
 * L7: EIP-2612 Permit Verification (Gasless Token Approvals)
 *
 * EIP-2612 extends ERC-20 with a permit() function that allows
 * approvals to be made via signed messages, eliminating the need
 * for a separate approve() transaction.
 *
 * The permit message contains:
 * - owner: token holder granting the approval
 * - spender: address being approved
 * - value: allowance amount
 * - deadline: expiry timestamp
 * - nonce: replay protection (managed by the token contract)
 *
 * Verification:
 * 1. Check deadline has not passed (deadline >= block.timestamp).
 * 2. Compute the EIP-712 domain separator for the token.
 * 3. Compute permit typehash and hash the struct.
 * 4. Recover signer and verify it matches owner.
 *
 * Security considerations:
 * - Deadlines prevent stale signatures from being executed.
 * - Nonces prevent replay attacks.
 * - The owner must match the signer (no one else can permit).
 *
 * Reference: https://eips.ethereum.org/EIPS/eip-2612
 * ================================================================ */
ac_result_t ac_verify_eip2612_permit(const uint8_t owner[AC_ADDR_LEN],
                                      const uint8_t spender[AC_ADDR_LEN],
                                      uint64_t value, uint64_t deadline,
                                      const ac_signature_t *sig) {
    /* Validate inputs */
    if (!owner || !spender || !sig) return AC_INVALID_SIG;
    if (ac_address_eq(owner, spender)) return AC_INVALID_SIG;

    /* Check signature v value */
    if (sig->v != 27 && sig->v != 28) return AC_INVALID_SIG;

    /* Check r and s are non-zero */
    bool r_zero = true, s_zero = true;
    for (int i = 0; i < 32; i++) {
        if (sig->r[i] != 0) r_zero = false;
        if (sig->s[i] != 0) s_zero = false;
    }
    if (r_zero || s_zero) return AC_INVALID_SIG;

    /* EIP-2: s must be <= n/2 */
    if (sig->s[0] >= 0x80) return AC_INVALID_SIG;

    /* Check s is less than secp256k1 n/2 (simplified check) */
    /* The secp256k1 order n starts with 0xFFF... so we check the
     * first byte of s against the n/2 threshold */
    static const uint8_t half_n[32] = {
        0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0x5D,0x57,0x6E,0x73,0x57,0xA4,0x50,0x1D,
        0xDF,0xE9,0x2F,0x46,0x68,0x1B,0x20,0xA0
    };
    for (int i = 0; i < 32; i++) {
        if (sig->s[i] > half_n[i]) return AC_INVALID_SIG;
        if (sig->s[i] < half_n[i]) break;
    }

    /* Deadline check: permit is not valid after the deadline.
     * In a real implementation, this would compare against block.timestamp.
     * Here we simulate with a reasonable current timestamp. */
    uint64_t current_time = 1700000000ULL; /* approximate simulation time */
    if (deadline < current_time) return AC_EXPIRED;

    /* Value validation: zero-value permits are suspicious */
    if (value == 0) return AC_INVALID_SIG;

    (void)owner;
    (void)spender;
    (void)value;
    (void)deadline;

    /* In production, full ECDSA recovery would be performed here:
     *   address recovered = ecrecover(permit_hash, v, r, s);
     *   require(recovered == owner, "invalid permit signer");
     */

    return AC_OK;
}

ac_result_t ac_check_tx_origin(const ac_analyzer_t *a) {
    if (!ac_address_eq(a->tx_origin, a->msg_sender)) {
        return AC_TX_ORIGIN_ISSUE;
    }
    return AC_OK;
}

ac_result_t ac_check_delegatecall_risk(ac_analyzer_t *a,
                                        const uint8_t target[AC_ADDR_LEN],
                                        bool target_trusted) {
    if (!a->is_delegatecall) return AC_OK;
    if (!target_trusted) {
        if (a->findings_count < 64) {
            snprintf(a->finding_details[a->findings_count], 256,
                     "delegatecall to untrusted contract at ");
            ac_address_to_hex(target,
                              a->finding_details[a->findings_count] + 35);
            a->findings[a->findings_count] = AC_DELEGATECALL_RISK;
            a->findings_count++;
        }
        return AC_DELEGATECALL_RISK;
    }
    return AC_OK;
}

ac_result_t ac_check_initializer(ac_analyzer_t *a, bool is_initializer) {
    if (is_initializer && a->initialized_state) {
        if (a->findings_count < 64) {
            snprintf(a->finding_details[a->findings_count], 256,
                     "re-initialization attempt detected - contract already initialized");
            a->findings[a->findings_count] = AC_ALREADY_INIT;
            a->findings_count++;
        }
        return AC_ALREADY_INIT;
    }
    if (!is_initializer && !a->initialized_state) {
        if (a->findings_count < 64) {
            snprintf(a->finding_details[a->findings_count], 256,
                     "contract not initialized - missing initializer call");
            a->findings[a->findings_count] = AC_NOT_INITIALIZED;
            a->findings_count++;
        }
        return AC_NOT_INITIALIZED;
    }
    return AC_OK;
}

void ac_print_report(const ac_analyzer_t *a) {
    printf("\n========== Access Control Analysis Report ==========\n");
    char hex[AC_ADDR_LEN * 2 + 1];
    ac_address_to_hex(a->ownable.owner, hex);
    printf("Owner:              %s (%s)\n", hex,
           a->ownable.initialized ? "initialized" : "NOT initialized");
    ac_address_to_hex(a->msg_sender, hex);
    printf("msg.sender:         %s\n", hex);
    ac_address_to_hex(a->tx_origin, hex);
    printf("tx.origin:          %s\n", hex);
    printf("is delegatecall:    %s\n", a->is_delegatecall ? "yes" : "no");
    printf("RBAC roles:         %d\n", a->rbac.count);

    ac_result_t tx = ac_check_tx_origin(a);
    printf("tx.origin check:    %s\n", ac_result_string(tx));

    if (a->findings_count > 0) {
        printf("\n--- Issues ---\n");
        for (int i = 0; i < a->findings_count; i++) {
            printf("  [%d] %s: %s\n", i + 1,
                   ac_result_string(a->findings[i]),
                   a->finding_details[i]);
        }
    }
    printf("====================================================\n");
}
