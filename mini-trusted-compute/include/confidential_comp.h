#ifndef MINI_CONFIDENTIAL_COMP_H
#define MINI_CONFIDENTIAL_COMP_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CC_MAX_ENCRYPTED_REGIONS     64
#define CC_TME_KEY_SIZE              32
#define CC_TME_KEY_ID_SIZE           8
#define CC_TME_MAX_KEYS              16
#define CC_SECURE_IO_BUFFER_SIZE     4096
#define CC_MKTME_KEY_SIZE            32
#define CC_MKTME_KEY_ID_SIZE          16
#define CC_MKTME_MAX_KEYS             16
#define CC_CONST_TIME_BUFFER_SIZE     256
#define CC_SIDE_CHANNEL_LOG_SIZE      64
#define CC_VULNERABILITY_MAX_COUNT    32
#define CC_TRUST_BOUNDARY_DEPTH        8

typedef enum {
    CC_MEM_MODE_PLAINTEXT   = 0,
    CC_MEM_MODE_TME         = 1,
    CC_MEM_MODE_MKTME       = 2,
    CC_MEM_MODE_SEV         = 3,
    CC_MEM_MODE_TDX         = 4,
    CC_MEM_MODE_NONE        = 5
} cc_mem_mode_t;

typedef enum {
    CC_VULN_CLASS_HARDWARE   = 0,
    CC_VULN_CLASS_MICROCODE  = 1,
    CC_VULN_CLASS_SIDE_CHANNEL = 2,
    CC_VULN_CLASS_SPECULATIVE = 3,
    CC_VULN_CLASS_CRYPTO     = 4,
    CC_VULN_CLASS_PHYSICAL   = 5,
    CC_VULN_CLASS_SOFTWARE   = 6,
    CC_VULN_CLASS_UNKNOWN    = 7
} cc_vuln_class_t;

typedef enum {
    CC_SC_CACHE_TIMING     = 0,
    CC_SC_PAGE_FAULT       = 1,
    CC_SC_BRANCH_SHADOW    = 2,
    CC_SC_L1D_EVICTION     = 3,
    CC_SC_MICROARCH_DATA   = 4,
    CC_SC_SWAPGS           = 5,
    CC_SC_LOAD_VALUE_INJ   = 6,
    CC_SC_POWER_ANALYSIS   = 7,
    CC_SC_EM_RADIATION     = 8,
    CC_SC_THERMAL          = 9
} cc_side_channel_t;

typedef enum {
    CC_VULN_LVI            = 0,
    CC_VULN_SGAXE          = 1,
    CC_VULN_PLUNDERVOLT    = 2,
    CC_VULN_FORESHAWDOW    = 3,
    CC_VULN_ZOMBIELOAD     = 4,
    CC_VULN_RIDL           = 5,
    CC_VULN_MDS            = 6,
    CC_VULN_SEVERED        = 7,
    CC_VULN_CROSSTALK      = 8,
    CC_VULN_SRBDS          = 9,
    CC_VULN_MMIO_STALE     = 10,
    CC_VULN_AEPIC_LEAK     = 11,
    CC_VULN_MELTDOWN       = 12,
    CC_VULN_SPECTRE_V1     = 13,
    CC_VULN_SPECTRE_V2     = 14,
    CC_VULN_SPEC_STORE     = 15,
    CC_VULN_TAA            = 16,
    CC_VULN_L1TF           = 17,
    CC_VULN_L1DES          = 18
} cc_known_vuln_t;

typedef enum {
    CC_SGX_VULN_LVI             = 0,
    CC_SGX_VULN_SGAXE           = 1,
    CC_SGX_VULN_PLUNDERVOLT     = 2,
    CC_SGX_VULN_CROSSTALK       = 3,
    CC_SGX_VULN_MMIO_STALE      = 4,
    CC_SGX_VULN_AEPIC_LEAK      = 5,
    CC_SGX_VULN_MICROSCOPE      = 6,
    CC_SGX_VULN_TEECHANNEL      = 7,
    CC_SGX_VULN_FORESHADOW_SGX  = 8,
    CC_SGX_VULN_SMELTSPEC       = 9
} cc_sgx_vuln_t;

typedef enum {
    CC_SEV_VULN_SEVERED         = 0,
    CC_SEV_VULN_CACHE_ATTACK    = 1,
    CC_SEV_VULN_UNSAFE_IOPORT   = 2,
    CC_SEV_VULN_ECPT_FORGERY    = 3,
    CC_SEV_VULN_SMT_SIDE_CHANNEL = 4
} cc_sev_vuln_t;

#pragma pack(push, 1)

typedef struct {
    uint64_t phys_base;
    uint64_t phys_limit;
    cc_mem_mode_t mode;
    uint8_t  encryption_key[CC_TME_KEY_SIZE];
    uint8_t  key_id[CC_TME_KEY_ID_SIZE];
    bool     exclusive;
    bool     writable;
} cc_encrypted_region_t;

typedef struct {
    uint8_t  tme_root_key[CC_TME_KEY_SIZE];
    uint8_t  mktme_keys[CC_MKTME_MAX_KEYS][CC_MKTME_KEY_SIZE];
    uint8_t  mktme_key_ids[CC_MKTME_MAX_KEYS][CC_MKTME_KEY_ID_SIZE];
    uint32_t mktme_key_count;
    cc_mem_mode_t active_mode;
    bool     tme_enabled;
    bool     mktme_enabled;
    bool     tme_bypass;
    bool     tme_lock;
    uint32_t tme_capability;
} cc_memory_encryption_t;

typedef struct {
    uint32_t cache_sets;
    uint32_t cache_ways;
    uint32_t cache_line_size;
    uint32_t cache_level;
    bool     partitioned;
    uint8_t  partition_mask[8];
} cc_cache_layout_t;

typedef struct {
    uint8_t  source[CC_SECURE_IO_BUFFER_SIZE];
    uint32_t source_size;
    uint8_t  encrypted[CC_SECURE_IO_BUFFER_SIZE];
    uint32_t encrypted_size;
    uint8_t  session_key[32];
    uint8_t  session_id[16];
    bool     established;
    bool     integrity_checked;
} cc_secure_io_t;

typedef struct {
    uint8_t  cpu_package_id[16];
    uint8_t  cpu_model[8];
    uint8_t  stepping;
    bool     sgx_capable;
    bool     tdx_capable;
    bool     sev_capable;
    bool     tme_capable;
    uint32_t microcode_version;
    cc_encrypted_region_t regions[CC_MAX_ENCRYPTED_REGIONS];
    uint32_t region_count;
} cc_trust_boundary_t;

typedef struct {
    char     name[64];
    char     cve_id[24];
    cc_known_vuln_t vuln_type;
    cc_vuln_class_t vuln_class;
    bool     affects_sgx;
    bool     affects_tdx;
    bool     affects_sev;
    bool     has_mitigation;
    char     mitigation[128];
    uint32_t risk_score;
} cc_vulnerability_t;

typedef struct {
    cc_vulnerability_t vulns[CC_VULNERABILITY_MAX_COUNT];
    uint32_t vuln_count;
    uint32_t mitigated_count;
    uint32_t active_count;
    bool     full_mitigation;
} cc_vuln_database_t;

typedef struct {
    char     name[64];
    char     description[256];
    cc_side_channel_t type;
    bool     mitigated;
    bool     exploitable_in_sgx;
    bool     exploitable_in_sev;
    bool     exploitable_in_tdx;
} cc_side_channel_info_t;

typedef struct {
    uint8_t  constant_ptr[CC_CONST_TIME_BUFFER_SIZE];
    uint32_t constant_size;
    bool     is_constant_time;
    uint32_t operations_count;
    uint32_t variance_ns;
} cc_const_time_op_t;

#pragma pack(pop)

typedef struct cc_confidential_ctx_s {
    cc_memory_encryption_t mem_encryption;
    cc_trust_boundary_t    trust_boundary;
    cc_vuln_database_t     vulnerabilities;
    cc_secure_io_t         secure_io;
    bool                   initialized;
    bool                   attestation_bound;
    bool                   sealed_state;
    uint8_t                sealing_key[CC_TME_KEY_SIZE];
    uint8_t                master_key[CC_TME_KEY_SIZE];
    void                  *enclave_ctx;
    uint64_t               last_attestation_time;
    uint32_t               epoch;

    int (*encrypt_memory)(struct cc_confidential_ctx_s *ctx, uint64_t phys_addr,
                          size_t size, cc_mem_mode_t mode);
    int (*decrypt_memory)(struct cc_confidential_ctx_s *ctx, uint64_t phys_addr,
                          size_t size);
    int (*set_encryption_key)(struct cc_confidential_ctx_s *ctx,
                              const uint8_t *key, uint8_t key_id);
    int (*revoke_encryption_key)(struct cc_confidential_ctx_s *ctx, uint8_t key_id);
    int (*protect_page)(struct cc_confidential_ctx_s *ctx, uint64_t phys_addr,
                        bool exclusive);
    int (*unprotect_page)(struct cc_confidential_ctx_s *ctx, uint64_t phys_addr);
    int (*establish_secure_io)(struct cc_confidential_ctx_s *ctx,
                               const uint8_t *session_key,
                               cc_secure_io_t *io);
    int (*seal_state)(struct cc_confidential_ctx_s *ctx,
                      const uint8_t *sealing_key,
                      uint8_t *sealed_state, size_t *sealed_size);
    int (*unseal_state)(struct cc_confidential_ctx_s *ctx,
                        const uint8_t *sealed_state, size_t sealed_size,
                        const uint8_t *sealing_key);
    int (*check_attestation)(struct cc_confidential_ctx_s *ctx, uint64_t *timestamp);
} cc_confidential_ctx_t;

int  cc_init(cc_confidential_ctx_t *ctx);
int  cc_enable_tme(cc_confidential_ctx_t *ctx, const uint8_t *root_key);
int  cc_enable_mktme(cc_confidential_ctx_t *ctx, const uint8_t *root_key,
                     const uint8_t (*keys)[CC_MKTME_KEY_SIZE],
                     uint32_t key_count);
int  cc_register_encrypted_region(cc_confidential_ctx_t *ctx,
                                  uint64_t phys_base, uint64_t phys_limit,
                                  cc_mem_mode_t mode,
                                  const uint8_t *key);
int  cc_probe_platform(cc_confidential_ctx_t *ctx,
                       cc_trust_boundary_t *boundary);
int  cc_is_sgx_supported(cc_confidential_ctx_t *ctx, bool *supported);
int  cc_is_tdx_supported(cc_confidential_ctx_t *ctx, bool *supported);
int  cc_is_sev_supported(cc_confidential_ctx_t *ctx, bool *supported);
int  cc_is_tme_supported(cc_confidential_ctx_t *ctx, bool *supported);

int  cc_check_vulnerability(cc_confidential_ctx_t *ctx,
                            cc_known_vuln_t vuln_id, bool *present);
int  cc_get_sgx_vulnerabilities(cc_confidential_ctx_t *ctx,
                                cc_vuln_database_t *db);
int  cc_get_sev_vulnerabilities(cc_confidential_ctx_t *ctx,
                                cc_vuln_database_t *db);
int  cc_mitigate_cache_side_channel(cc_confidential_ctx_t *ctx,
                                    cc_cache_layout_t *layout,
                                    uint32_t partition_id);
int  cc_mitigate_page_fault_channel(cc_confidential_ctx_t *ctx);
int  cc_enable_patch_for_vuln(cc_confidential_ctx_t *ctx,
                              cc_known_vuln_t vuln_id);
int  cc_is_mitigated(cc_confidential_ctx_t *ctx,
                     cc_known_vuln_t vuln_id, bool *mitigated);

int  cc_constant_time_compare(const uint8_t *a, const uint8_t *b, size_t len);
int  cc_constant_time_select(bool condition, const uint8_t *a,
                             const uint8_t *b, uint8_t *result, size_t len);
int  cc_constant_time_copy(uint8_t *dst, const uint8_t *src, size_t len);
int  cc_constant_time_zero(uint8_t *buf, size_t len);
int  cc_constant_time_is_zero(const uint8_t *buf, size_t len, bool *is_zero);
int  cc_constant_time_increment(uint8_t *buf, size_t len);
int  cc_constant_time_equal(const uint8_t *a, const uint8_t *b, size_t len,
                            bool *equal);

int  cc_secure_io_negotiate(cc_confidential_ctx_t *ctx,
                            const uint8_t *peer_pubkey,
                            cc_secure_io_t *io);
int  cc_secure_io_send(cc_confidential_ctx_t *ctx,
                       const uint8_t *data, size_t data_size,
                       cc_secure_io_t *io);
int  cc_secure_io_receive(cc_confidential_ctx_t *ctx,
                          uint8_t *data, size_t *data_size,
                          cc_secure_io_t *io);

int  cc_seal_entire_state(cc_confidential_ctx_t *ctx,
                          uint8_t *sealed, size_t *sealed_size);
int  cc_unseal_entire_state(cc_confidential_ctx_t *ctx,
                            const uint8_t *sealed, size_t sealed_size);
int  cc_rotate_encryption_keys(cc_confidential_ctx_t *ctx);
int  cc_attest_platform(cc_confidential_ctx_t *ctx, uint8_t *evidence,
                        size_t *evidence_size);
int  cc_verify_attestation(cc_confidential_ctx_t *ctx,
                           const uint8_t *evidence, size_t evidence_size,
                           bool *valid);
int  cc_get_trust_boundary(cc_confidential_ctx_t *ctx,
                           cc_trust_boundary_t *boundary);
int  cc_free(cc_confidential_ctx_t *ctx);

void cc_print_vulnerability(const cc_vulnerability_t *vuln);
void cc_print_vuln_database(const cc_vuln_database_t *db);
void cc_print_trust_boundary(const cc_trust_boundary_t *boundary);

#ifdef __cplusplus
}
#endif

#endif /* MINI_CONFIDENTIAL_COMP_H */
