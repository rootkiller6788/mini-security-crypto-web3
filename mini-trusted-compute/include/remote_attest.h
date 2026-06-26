#ifndef MINI_REMOTE_ATTEST_H
#define MINI_REMOTE_ATTEST_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "sgx_enclave.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RA_CHALLENGE_SIZE         64
#define RA_RESPONSE_MAX_SIZE      8192
#define RA_QUOTE_MAX_SIZE         8192
#define RA_NONCE_SIZE             32
#define RA_ECDSA_SIG_SIZE         64
#define RA_ECDSA_PUBKEY_SIZE      64
#define RA_X509_CERT_MAX_SIZE     4096
#define RA_CERT_CHAIN_MAX_SIZE    12288
#define RA_SESSION_ID_SIZE        32
#define RA_REPORT_DATA_SIZE       64
#define RA_IAS_REPORT_SIZE        4096
#define RA_IAS_SIGNATURE_SIZE     256
#define RA_IAS_CERT_SIZE          2048
#define RA_VERIFICATION_TOKEN_SIZE 512
#define RA_FMSPC_SIZE             6
#define RA_PLATFORM_ID_SIZE       16
#define RA_DCAP_TCB_INFO_SIZE     512
#define RA_DCAP_QE_ID_SIZE        64

#define RA_IAS_DEV_URL  "https://api.trustedservices.intel.com/sgx/dev/attestation/v5"
#define RA_IAS_PROD_URL "https://api.trustedservices.intel.com/sgx/attestation/v5"

typedef enum {
    RA_ATTEST_UNKNOWN    = 0,
    RA_ATTEST_EPID       = 1,
    RA_ATTEST_ECDSA_P256 = 2,
    RA_ATTEST_ECDSA_P384 = 3,
    RA_ATTEST_TDX        = 4,
    RA_ATTEST_SEV        = 5,
    RA_ATTEST_SEV_SNP    = 6
} ra_attest_type_t;

typedef enum {
    RA_STATUS_OK                    = 0,
    RA_STATUS_INVALID_QUOTE         = 1,
    RA_STATUS_INVALID_SIGNATURE     = 2,
    RA_STATUS_INVALID_CERT_CHAIN    = 3,
    RA_STATUS_REVOKED               = 4,
    RA_STATUS_OUTDATED_TCB          = 5,
    RA_STATUS_CONFIG_NEEDED         = 6,
    RA_STATUS_SW_HARDENING_NEEDED   = 7,
    RA_STATUS_INVALID_GROUP_ID      = 8,
    RA_STATUS_MISMATCH_MEASUREMENT  = 9,
    RA_STATUS_INTERNAL_ERROR        = 0xFF
} ra_status_t;

typedef enum {
    RA_ISV_ENCLAVE_QUOTE_STATUS_OK                     = 0,
    RA_ISV_ENCLAVE_QUOTE_STATUS_SIG_INVALID            = 1,
    RA_ISV_ENCLAVE_QUOTE_STATUS_GROUP_REVOKED          = 2,
    RA_ISV_ENCLAVE_QUOTE_STATUS_SIG_REVOKED            = 3,
    RA_ISV_ENCLAVE_QUOTE_STATUS_KEY_REVOKED            = 4,
    RA_ISV_ENCLAVE_QUOTE_STATUS_CONFIG_NEEDED          = 5,
    RA_ISV_ENCLAVE_QUOTE_STATUS_SW_HARDENING_NEEDED    = 6,
    RA_ISV_ENCLAVE_QUOTE_STATUS_OUT_OF_DATE            = 7,
    RA_ISV_ENCLAVE_QUOTE_STATUS_OTHER                  = 0xFF
} ra_isv_quote_status_t;

typedef enum {
    RA_DCAP_PCK_ID_UNKNOWN        = 0,
    RA_DCAP_PCK_ID_PLAFORM        = 1,
    RA_DCAP_PCK_ID_PROCESSOR      = 2,
    RA_DCAP_PCK_ID_PLATFORM_MANIF = 3
} ra_dcap_pck_id_t;

#pragma pack(push, 1)

typedef struct {
    uint8_t  nonce[RA_NONCE_SIZE];
    uint32_t nonce_len;
    uint8_t  session_id[RA_SESSION_ID_SIZE];
    uint32_t timeout_seconds;
    bool     require_epid;
    bool     require_fmspc;
    uint8_t  expected_fmspc[RA_FMSPC_SIZE];
} ra_challenge_t;

typedef struct {
    uint8_t  quote[RA_QUOTE_MAX_SIZE];
    uint32_t quote_size;
    uint32_t quote_version;
    uint8_t  signature[RA_ECDSA_SIG_SIZE];
    uint32_t sig_size;
    uint8_t  cert_chain[RA_CERT_CHAIN_MAX_SIZE];
    uint32_t cert_chain_size;
    uint8_t  session_id[RA_SESSION_ID_SIZE];
    ra_attest_type_t attest_type;
    bool     tdx_enabled;
    bool     sev_enabled;
} ra_response_t;

typedef struct {
    uint8_t  mr_enclave[SGX_MEASUREMENT_SIZE];
    uint8_t  mr_signer[SGX_MEASUREMENT_SIZE];
    uint8_t  isv_prod_id[2];
    uint8_t  isv_svn[2];
    uint8_t  attributes[SGX_ATTRIBUTES_SIZE];
    uint8_t  report_data[RA_REPORT_DATA_SIZE];
    bool     debug_flag;
} ra_quote_body_t;

typedef struct {
    uint8_t  x509_cert[RA_X509_CERT_MAX_SIZE];
    uint32_t cert_size;
    uint8_t  public_key[RA_ECDSA_PUBKEY_SIZE];
    uint8_t  subject[256];
    uint8_t  issuer[256];
    uint64_t not_before;
    uint64_t not_after;
    uint8_t  fingerprint[32];
    bool     is_ca;
} ra_certificate_t;

typedef struct {
    ra_certificate_t certs[3];
    uint32_t         cert_count;
    bool             verified;
    uint8_t          root_ca_fingerprint[32];
} ra_cert_chain_t;

typedef struct {
    uint8_t  ias_report[RA_IAS_REPORT_SIZE];
    uint32_t ias_report_size;
    uint8_t  ias_signature[RA_IAS_SIGNATURE_SIZE];
    uint32_t ias_sig_size;
    uint8_t  ias_cert[RA_IAS_CERT_SIZE];
    uint32_t ias_cert_size;
    uint8_t  nonce[RA_NONCE_SIZE];
    ra_isv_quote_status_t quote_status;
    bool     is_valid;
    uint32_t timestamp;
} ra_ias_verification_t;

typedef struct {
    uint8_t  pck_cert[RA_X509_CERT_MAX_SIZE];
    uint32_t pck_cert_size;
    uint8_t  pck_ca_cert[RA_X509_CERT_MAX_SIZE];
    uint32_t pck_ca_cert_size;
    uint8_t  tcb_info[RA_DCAP_TCB_INFO_SIZE];
    uint32_t tcb_info_size;
    uint8_t  tcb_signature[RA_ECDSA_SIG_SIZE];
    uint8_t  qe_identity[RA_DCAP_QE_ID_SIZE];
    uint32_t qe_id_size;
    ra_dcap_pck_id_t pck_id;
    uint8_t  fmspc[RA_FMSPC_SIZE];
    uint64_t pce_svn;
    uint64_t pce_id;
    bool     tcb_up_to_date;
} ra_dcap_verification_t;

typedef struct {
    uint8_t  private_key[32];
    uint8_t  public_key[RA_ECDSA_PUBKEY_SIZE];
    uint8_t  tls_session_id[RA_SESSION_ID_SIZE];
    bool     attestation_required;
    bool     mutual_attestation;
    uint32_t tls_version;
    uint8_t  pre_shared_key[32];
} ra_tls_context_t;

typedef struct {
    uint32_t version;
    uint32_t attestation_type;
    uint32_t reserved;
    uint8_t  qe_vendor_id[16];
    uint8_t  user_data[20];
    ra_quote_body_t body;
    uint32_t signature_len;
    uint8_t  signature[256];
} ra_quote_v4_t;

#pragma pack(pop)

typedef struct ra_verifier_s {
    uint8_t  expected_mr_enclave[SGX_MEASUREMENT_SIZE];
    uint8_t  expected_mr_signer[SGX_MEASUREMENT_SIZE];
    uint8_t  expected_isv_prod_id[2];
    uint8_t  expected_isv_svn[2];
    uint16_t minimum_isv_svn;
    uint8_t  allowed_fmspc[RA_FMSPC_SIZE];
    bool     check_fmspc;
    bool     allow_debug;
    bool     check_tcb;
    uint8_t  trusted_root_ca_fingerprint[32];
    ra_status_t last_status;
    uint8_t  last_error_msg[256];

    int (*generate_challenge)(struct ra_verifier_s *verifier, ra_challenge_t *chall);
    int (*verify_response)(struct ra_verifier_s *verifier, const ra_response_t *resp,
                           ra_status_t *status);
    int (*verify_ias_report)(struct ra_verifier_s *verifier,
                             const ra_ias_verification_t *ias, bool *valid);
    int (*verify_dcap)(struct ra_verifier_s *verifier,
                       const ra_dcap_verification_t *dcap, bool *valid);
    int (*verify_cert_chain)(struct ra_verifier_s *verifier,
                             const ra_cert_chain_t *chain, bool *valid);
    int (*verify_quote_body)(struct ra_verifier_s *verifier,
                             const ra_quote_body_t *body, bool *valid);
    int (*check_revocation)(struct ra_verifier_s *verifier,
                            const uint8_t *group_id, bool *revoked);
    int (*get_verification_report)(struct ra_verifier_s *verifier,
                                   uint8_t *report, uint32_t *report_size);
} ra_verifier_t;

typedef struct ra_prover_s {
    sgx_enclave_t *enclave;
    uint8_t  platform_id[RA_PLATFORM_ID_SIZE];
    uint8_t  fmspc[RA_FMSPC_SIZE];
    ra_attest_type_t attest_type;
    uint8_t  target_info[512];
    uint32_t target_info_size;

    int (*generate_quote)(struct ra_prover_s *prover, const uint8_t *report_data,
                          uint32_t report_data_size, uint8_t *quote,
                          uint32_t *quote_size);
    int (*create_response)(struct ra_prover_s *prover, const ra_challenge_t *chall,
                           ra_response_t *resp);
    int (*create_tls_attestation)(struct ra_prover_s *prover, ra_tls_context_t *ctx);
    int (*get_platform_info)(struct ra_prover_s *prover,
                             sgx_platform_info_t *info);
    int (*generate_report_data)(struct ra_prover_s *prover, const uint8_t *nonce,
                                uint32_t nonce_len,
                                uint8_t report_data[RA_REPORT_DATA_SIZE]);
} ra_prover_t;

int  ra_verifier_init(ra_verifier_t *verifier,
                      const uint8_t *expected_mr_enclave,
                      const uint8_t *expected_mr_signer);
int  ra_verifier_set_measurement(ra_verifier_t *verifier,
                                 const uint8_t *mr_enclave,
                                 const uint8_t *mr_signer);
int  ra_verifier_set_tcb_policy(ra_verifier_t *verifier, bool check_tcb,
                                uint16_t min_isv_svn);
int  ra_verifier_set_fmspc(ra_verifier_t *verifier, const uint8_t *fmspc);
int  ra_verifier_set_root_ca(ra_verifier_t *verifier,
                             const uint8_t *fingerprint);

int  ra_prover_init(ra_prover_t *prover, sgx_enclave_t *enclave,
                    ra_attest_type_t attest_type);
int  ra_prover_set_platform_info(ra_prover_t *prover,
                                 const uint8_t *platform_id,
                                 const uint8_t *fmspc);

int  ra_generate_challenge(uint8_t *nonce, uint32_t nonce_size,
                           ra_challenge_t *challenge);
int  ra_generate_nonce(uint8_t nonce[RA_NONCE_SIZE], uint32_t *nonce_len);
int  ra_create_report_data(const uint8_t *nonce, uint32_t nonce_len,
                           const uint8_t *extra_data, uint32_t extra_len,
                           uint8_t report_data[RA_REPORT_DATA_SIZE]);

int  ra_verify_ias_attestation(const ra_response_t *response,
                               const uint8_t *ias_api_key,
                               ra_ias_verification_t *verification);
int  ra_verify_dcap_attestation(const ra_response_t *response,
                                ra_dcap_verification_t *verification);
int  ra_verify_quote_signature(const uint8_t *quote, uint32_t quote_size,
                               const uint8_t *public_key, bool *valid);

int  ra_tls_handshake_with_attestation(ra_tls_context_t *ctx,
                                       const uint8_t *client_hello,
                                       uint32_t client_hello_size,
                                       ra_response_t *attest_response);
int  ra_tls_verify_peer_attestation(ra_tls_context_t *ctx,
                                    const ra_response_t *peer_response,
                                    bool *attested);

int  ra_parse_quote_body(const uint8_t *quote, uint32_t quote_size,
                         ra_quote_body_t *body);
int  ra_extract_mrenclave(const uint8_t *quote, uint32_t quote_size,
                          uint8_t mr_enclave[SGX_MEASUREMENT_SIZE]);
int  ra_extract_mrsigner(const uint8_t *quote, uint32_t quote_size,
                         uint8_t mr_signer[SGX_MEASUREMENT_SIZE]);

int  ra_cert_chain_verify(const uint8_t *cert_chain, uint32_t chain_size,
                          const uint8_t *root_ca_fingerprint, bool *valid);
int  ra_cert_extract_public_key(const uint8_t *cert, uint32_t cert_size,
                                uint8_t public_key[RA_ECDSA_PUBKEY_SIZE]);

void ra_print_quote_body(const ra_quote_body_t *body);
void ra_print_verification(const ra_ias_verification_t *verification);
void ra_print_dcap_report(const ra_dcap_verification_t *dcap);

#ifdef __cplusplus
}
#endif

#endif /* MINI_REMOTE_ATTEST_H */
