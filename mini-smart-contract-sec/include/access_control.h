#ifndef ACCESS_CONTROL_H
#define ACCESS_CONTROL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define AC_ADDR_LEN        20
#define AC_ROLE_MAX        32
#define AC_SIG_LEN         65
#define AC_EIP712_DOMAIN_MAX 256

typedef enum {
    AC_OK               = 0,
    AC_UNAUTHORIZED     = 1,
    AC_INVALID_SIG      = 2,
    AC_EXPIRED          = 3,
    AC_REPLAYED         = 4,
    AC_NOT_INITIALIZED  = 5,
    AC_ALREADY_INIT     = 6,
    AC_DELEGATECALL_RISK = 7,
    AC_TX_ORIGIN_ISSUE  = 8
} ac_result_t;

typedef struct {
    uint8_t bytes[32];
} ac_role_t;

typedef struct {
    uint8_t r[32];
    uint8_t s[32];
    uint8_t v;
} ac_signature_t;

typedef struct {
    char     name[64];
    char     version[16];
    uint64_t chain_id;
    uint8_t  verifying_contract[AC_ADDR_LEN];
    uint8_t  salt[32];
} ac_eip712_domain_t;

typedef struct {
    uint8_t owner[AC_ADDR_LEN];
    bool    initialized;
} ac_ownable_t;

typedef struct {
    ac_role_t role;
    uint8_t   member[AC_ADDR_LEN];
    bool      granted;
    uint64_t  granted_at;
} ac_role_entry_t;

typedef struct {
    ac_role_entry_t entries[256];
    int             count;
    ac_role_t       admin_role;
    uint8_t         admin[AC_ADDR_LEN];
} ac_rbac_t;

typedef struct {
    ac_ownable_t   ownable;
    ac_rbac_t      rbac;
    uint8_t        tx_origin[AC_ADDR_LEN];
    uint8_t        msg_sender[AC_ADDR_LEN];
    bool           is_delegatecall;
    bool           initialized_state;
    int            findings_count;
    ac_result_t    findings[64];
    char           finding_details[64][256];
} ac_analyzer_t;

void ac_init(ac_analyzer_t *a);

ac_result_t ac_set_owner(ac_analyzer_t *a, const uint8_t addr[AC_ADDR_LEN]);
ac_result_t ac_only_owner(const ac_analyzer_t *a, const uint8_t caller[AC_ADDR_LEN]);

void ac_role_init(ac_role_t *r, const char *name);
ac_result_t ac_grant_role(ac_analyzer_t *a, const ac_role_t *role,
                           const uint8_t addr[AC_ADDR_LEN],
                           const uint8_t caller[AC_ADDR_LEN]);
ac_result_t ac_revoke_role(ac_analyzer_t *a, const ac_role_t *role,
                            const uint8_t addr[AC_ADDR_LEN],
                            const uint8_t caller[AC_ADDR_LEN]);
bool ac_has_role(const ac_analyzer_t *a, const ac_role_t *role,
                 const uint8_t addr[AC_ADDR_LEN]);

void ac_eip712_init(ac_eip712_domain_t *d, const char *name, const char *version,
                    uint64_t chain_id, const uint8_t verifying_contract[AC_ADDR_LEN]);

ac_result_t ac_verify_eip712(const ac_eip712_domain_t *domain,
                              const uint8_t digest[32],
                              const ac_signature_t *sig,
                              const uint8_t signer[AC_ADDR_LEN]);

ac_result_t ac_verify_eip2612_permit(const uint8_t owner[AC_ADDR_LEN],
                                      const uint8_t spender[AC_ADDR_LEN],
                                      uint64_t value, uint64_t deadline,
                                      const ac_signature_t *sig);

ac_result_t ac_check_tx_origin(const ac_analyzer_t *a);
ac_result_t ac_check_delegatecall_risk(const ac_analyzer_t *a,
                                        const uint8_t target[AC_ADDR_LEN],
                                        bool target_trusted);

ac_result_t ac_check_initializer(ac_analyzer_t *a, bool is_initializer);

void ac_print_report(const ac_analyzer_t *a);
const char *ac_result_string(ac_result_t r);

void ac_role_to_string(const ac_role_t *r, char *buf, size_t len);
void ac_address_to_hex(const uint8_t addr[AC_ADDR_LEN], char *buf);
bool ac_address_eq(const uint8_t a[AC_ADDR_LEN], const uint8_t b[AC_ADDR_LEN]);
void ac_address_from_hex(const char *hex, uint8_t addr[AC_ADDR_LEN]);

#endif
