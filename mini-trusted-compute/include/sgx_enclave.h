#ifndef MINI_SGX_ENCLAVE_H
#define MINI_SGX_ENCLAVE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SGX_ENCLAVE_PAGE_SIZE       4096
#define SGX_EPC_PAGE_SIZE           4096
#define SGX_HASH_SIZE               32
#define SGX_SEAL_KEY_SIZE           32
#define SGX_REPORT_SIZE             512
#define SGX_QUOTE_MAX_SIZE          8192
#define SGX_MAC_SIZE                16
#define SGX_ATTRIBUTES_SIZE         16
#define SGX_MEASUREMENT_SIZE        32
#define SGX_EPID_SIZE               64
#define SGX_PLATFORM_KEY_SIZE       32

typedef enum {
    SGX_ENCLAVE_UNINITIALIZED = 0,
    SGX_ENCLAVE_INITIALIZED   = 1,
    SGX_ENCLAVE_DESTROYED     = 2,
    SGX_ENCLAVE_RUNNING       = 3,
    SGX_ENCLAVE_STOPPED       = 4
} sgx_enclave_state_t;

typedef enum {
    SGX_SECTION_TEXT  = 0,
    SGX_SECTION_DATA  = 1,
    SGX_SECTION_HEAP  = 2,
    SGX_SECTION_STACK = 3,
    SGX_SECTION_TCS   = 4,
    SGX_SECTION_SSA   = 5
} sgx_section_type_t;

typedef enum {
    SGX_PAGE_SECS    = 0,
    SGX_PAGE_TCS     = 1,
    SGX_PAGE_REGULAR = 2,
    SGX_PAGE_VA      = 3,
    SGX_PAGE_TRIM    = 4
} sgx_page_type_t;

typedef enum {
    SGX_ATTEST_LOCAL  = 0,
    SGX_ATTEST_REMOTE = 1,
    SGX_ATTEST_EPID   = 2,
    SGX_ATTEST_ECDSA  = 3
} sgx_attest_type_t;

typedef enum {
    SGX_KEY_POLICY_MRENCLAVE  = 0,
    SGX_KEY_POLICY_MRSIGNER   = 1,
    SGX_KEY_POLICY_NOISV      = 2,
    SGX_KEY_POLICY_CONFIGID   = 3
} sgx_key_policy_t;

typedef enum {
    SGX_SECINFO_R  = 0x01,
    SGX_SECINFO_W  = 0x02,
    SGX_SECINFO_X  = 0x04,
    SGX_SECINFO_PT = 0x08,
    SGX_SECINFO_TC = 0x10,
    SGX_SECINFO_EM = 0x20
} sgx_secinfo_flags_t;

#pragma pack(push, 1)

typedef struct {
    uint8_t  measurement[SGX_MEASUREMENT_SIZE];
    uint32_t size;
    uint32_t reserved;
} sgx_ssa_frame_t;

typedef struct {
    uint64_t reserved[2];
    uint64_t stack_limit_addr;
    uint64_t stack_base_addr;
    uint64_t reserved2[4];
    uint64_t ossa;
    uint32_t nssa;
    uint32_t reserved3;
    uint64_t ofs_base;
    uint64_t ogs_base;
    uint32_t fs_limit;
    uint32_t gs_limit;
    uint32_t tls_array[8];
} sgx_tcs_t;

typedef struct {
    uint32_t size;
    uint8_t  reserved[12];
    uint8_t  measurement[SGX_MEASUREMENT_SIZE];
    uint8_t  mr_signer[SGX_MEASUREMENT_SIZE];
    uint8_t  reserved2[32];
    uint8_t  attributes[SGX_ATTRIBUTES_SIZE];
    uint8_t  reserved3[32];
    uint64_t base_addr;
    uint64_t size_enc;
    uint32_t ssa_frame_size;
    uint32_t misc_select;
    uint16_t isv_prod_id;
    uint16_t isv_svn;
    uint8_t  reserved4[60];
} sgx_secs_t;

typedef struct {
    uint8_t  secs_flags[8];
    uint8_t  reserved[48];
} sgx_secinfo_t;

typedef struct {
    uint64_t lin_addr;
    uint64_t src_pge;
    uint64_t sec_info;
    uint64_t secs;
} sgx_pageinfo_t;

typedef struct {
    uint8_t  cpu_svn[16];
    uint32_t misc_select;
    uint8_t  reserved[28];
    uint8_t  attributes[SGX_ATTRIBUTES_SIZE];
    uint8_t  mr_enclave[SGX_MEASUREMENT_SIZE];
    uint8_t  reserved2[32];
    uint8_t  mr_signer[SGX_MEASUREMENT_SIZE];
    uint8_t  reserved3[96];
    uint16_t isv_prod_id;
    uint16_t isv_svn;
    uint8_t  reserved4[60];
    uint8_t  report_data[SGX_SEAL_KEY_SIZE];
} sgx_report_body_t;

typedef struct {
    sgx_report_body_t body;
    uint8_t           key_id[32];
    uint8_t           mac[SGX_MAC_SIZE];
} sgx_report_t;

typedef struct {
    uint32_t version;
    uint16_t att_key_type;
    uint16_t reserved;
    uint32_t qe_svn;
    uint16_t pce_svn;
    uint16_t reserved2;
    uint8_t  qe_vendor_id[16];
    uint8_t  user_data[20];
    sgx_report_body_t report_body;
    uint8_t  signature[256];
} sgx_quote_v3_t;

typedef struct {
    uint8_t  key[SGX_SEAL_KEY_SIZE];
    uint8_t  key_id[32];
    uint64_t policy;
    uint8_t  attributes[SGX_ATTRIBUTES_SIZE];
    uint8_t  cpu_svn[16];
    uint32_t isv_svn;
} sgx_seal_key_t;

typedef struct {
    uint8_t  sealed_blob[512];
    uint32_t sealed_size;
    uint8_t  payload_mac[SGX_MAC_SIZE];
    uint8_t  key_id[32];
    bool     is_sealed;
} sgx_sealed_data_t;

typedef struct {
    uint8_t  mr_enclave[SGX_MEASUREMENT_SIZE];
    uint8_t  mr_signer[SGX_MEASUREMENT_SIZE];
    uint8_t  attributes[SGX_ATTRIBUTES_SIZE];
    uint16_t isv_prod_id;
    uint16_t isv_svn;
    uint64_t base_addr;
    uint64_t size;
    sgx_enclave_state_t state;
    uint32_t page_count;
} sgx_enclave_identity_t;

typedef struct {
    uint8_t  cpu_svn[16];
    uint8_t  pce_id[4];
    uint8_t  fmspc[6];
    uint8_t  platform_instance_id[16];
} sgx_platform_info_t;

typedef struct {
    sgx_report_t source_report;
    sgx_report_t target_report;
    uint8_t      target_info[512];
    uint8_t      report_key[SGX_SEAL_KEY_SIZE];
    bool         verified;
} sgx_local_attest_ctx_t;

typedef struct {
    uint8_t  quote[SGX_QUOTE_MAX_SIZE];
    uint32_t quote_size;
    uint8_t  nonce[64];
    uint32_t nonce_len;
    uint8_t  signature[256];
    uint8_t  cert_chain[4096];
    uint32_t cert_chain_size;
    bool     verified;
    uint32_t revocation_status;
} sgx_remote_attest_ctx_t;

#pragma pack(pop)

typedef struct sgx_enclave_s {
    sgx_enclave_identity_t identity;
    sgx_enclave_state_t    state;
    uint8_t               *epc_pages;
    uint32_t                epc_page_count;
    sgx_secs_t             secs;
    sgx_seal_key_t         seal_key;
    void                  *entry_point;
    void                  *exit_target;
    void                  *user_ctx;
    bool                   debug;
    bool                   ss_enabled;
    uint32_t                ssa_count;
    size_t                  ssa_frame_size;

    int (*ecreate)(struct sgx_enclave_s *enclave);
    int (*eadd)(struct sgx_enclave_s *enclave, uint64_t addr, const uint8_t *data,
                size_t size, sgx_secinfo_t *secinfo, uint32_t page_type);
    int (*eextend)(struct sgx_enclave_s *enclave, uint64_t offset,
                   const uint8_t chunk[64]);
    int (*einit)(struct sgx_enclave_s *enclave, uint8_t *token);
    int (*eenter)(struct sgx_enclave_s *enclave, void *tcs, void *aep);
    int (*eexit)(struct sgx_enclave_s *enclave, void *target);
    int (*eremove)(struct sgx_enclave_s *enclave, uint64_t addr);
    int (*ereport)(struct sgx_enclave_s *enclave, const uint8_t *target_info,
                   const uint8_t *report_data, sgx_report_t *report);
    int (*egetkey)(struct sgx_enclave_s *enclave, const uint8_t *key_request,
                   uint8_t *key);
    int (*eseal)(struct sgx_enclave_s *enclave, const uint8_t *plain,
                 size_t plain_len, sgx_sealed_data_t *sealed);
    int (*eunseal)(struct sgx_enclave_s *enclave, const sgx_sealed_data_t *sealed,
                   uint8_t *plain, size_t *plain_len);
    int (*everify_report)(struct sgx_enclave_s *enclave,
                          const sgx_report_t *report, bool *result);
    int (*eaccept_copy)(struct sgx_enclave_s *enclave,
                        const sgx_pageinfo_t *page_info, uint64_t addr,
                        const uint8_t *data);
} sgx_enclave_t;

int  sgx_enclave_init(sgx_enclave_t *enclave, uint64_t size, bool debug);
int  sgx_enclave_create(sgx_enclave_t *enclave);
int  sgx_enclave_add_page(sgx_enclave_t *enclave, uint64_t addr,
                          const uint8_t *data, size_t size,
                          sgx_secinfo_flags_t flags,
                          sgx_page_type_t type);
int  sgx_enclave_extend_measurement(sgx_enclave_t *enclave, uint64_t offset,
                                    const uint8_t chunk[64]);
int  sgx_enclave_initialize(sgx_enclave_t *enclave);
int  sgx_enclave_enter(sgx_enclave_t *enclave, void *tcs, void *aep);
int  sgx_enclave_exit(sgx_enclave_t *enclave, void *target);
int  sgx_enclave_destroy(sgx_enclave_t *enclave);

int  sgx_enclave_generate_report(sgx_enclave_t *enclave,
                                 const uint8_t *target_info,
                                 const uint8_t *report_data,
                                 sgx_report_t *report);
int  sgx_enclave_verify_report(sgx_enclave_t *enclave,
                               const sgx_report_t *report, bool *valid);
int  sgx_enclave_local_attestation(sgx_enclave_t *src, sgx_enclave_t *dst,
                                   sgx_report_t *report);

int  sgx_enclave_derive_seal_key(sgx_enclave_t *enclave,
                                 sgx_key_policy_t policy);
int  sgx_enclave_seal_data(sgx_enclave_t *enclave, const uint8_t *plain,
                           size_t plain_len, sgx_sealed_data_t *sealed);
int  sgx_enclave_unseal_data(sgx_enclave_t *enclave,
                             const sgx_sealed_data_t *sealed,
                             uint8_t *plain, size_t *plain_len);

int  sgx_enclave_create_quote(sgx_enclave_t *enclave,
                              const uint8_t *report_data,
                              sgx_attest_type_t attest_type,
                              sgx_quote_v3_t *quote, uint32_t *quote_size);
int  sgx_enclave_get_identity(sgx_enclave_t *enclave,
                              sgx_enclave_identity_t *identity);
int  sgx_enclave_get_platform_info(sgx_platform_info_t *info);

void sgx_enclave_free(sgx_enclave_t *enclave);
void sgx_enclave_print_measurement(const uint8_t measurement[SGX_MEASUREMENT_SIZE]);
void sgx_enclave_print_report(const sgx_report_t *report);

#ifdef __cplusplus
}
#endif

#endif /* MINI_SGX_ENCLAVE_H */
