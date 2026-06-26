#ifndef PKI_MODEL_H
#define PKI_MODEL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ─── PKI Core Types ─────────────────────────────────────────── */

typedef struct CaConfig {
    char    name[128];
    uint8_t private_key_pem[4096];
    size_t  private_key_len;
    uint8_t certificate_der[4096];
    size_t  certificate_len;
    bool    is_root;
} CaConfig;

/* ─── CSR (Certificate Signing Request) ──────────────────────── */

#define CSR_MAX_CN_LEN  128
#define CSR_MAX_DER_LEN 2048

typedef struct CsrRequest {
    char    common_name[CSR_MAX_CN_LEN];
    char    organization[128];
    char    country[4];
    uint8_t public_key[512];
    size_t  public_key_len;
    int     public_key_type; /* 0=RSA, 1=EC */
    uint8_t der_encoded[CSR_MAX_DER_LEN];
    size_t  der_len;
} CsrRequest;

void csr_init(CsrRequest *csr, const char *cn, const char *org, const char *country);
void csr_set_rsa_key(CsrRequest *csr, const uint8_t *pub_key, size_t pub_key_len);
void csr_set_ec_key(CsrRequest *csr, const uint8_t *pub_key, size_t pub_key_len);
bool csr_sign(CsrRequest *csr, const void *priv_key, size_t key_bits);
bool csr_verify(const CsrRequest *csr);

/* ─── Certificate Issuance ───────────────────────────────────── */

#include "digital_sig.h"

bool ca_issue_certificate(const CaConfig *ca,
                          const CsrRequest *csr,
                          X509Certificate *cert,
                          uint64_t valid_days);

bool ca_self_sign_root(CaConfig *ca, X509Certificate *cert);

/* ─── Trust Store ────────────────────────────────────────────── */

#define TRUST_STORE_MAX_CERTS 64

typedef struct TrustStore {
    X509Certificate certs[TRUST_STORE_MAX_CERTS];
    size_t          count;
} TrustStore;

void trust_store_init(TrustStore *store);
bool trust_store_add(TrustStore *store, const X509Certificate *cert);
bool trust_store_remove(TrustStore *store, const uint8_t *serial, size_t serial_len);
const X509Certificate *trust_store_find_by_subject(const TrustStore *store,
                                                    const char *cn);
bool trust_store_verify_chain(const TrustStore *store,
                              const X509Certificate *cert,
                              const CertificateRevocationList *crl,
                              uint64_t verify_time);

/* ─── ACME Simulation (Let's Encrypt Style) ──────────────────── */

typedef enum AcmeChallengeType {
    ACME_CHALLENGE_HTTP01,
    ACME_CHALLENGE_DNS01
} AcmeChallengeType;

typedef struct AcmeChallenge {
    AcmeChallengeType type;
    char token[128];
    char key_auth[256];
    char url[256];
    bool validated;
} AcmeChallenge;

typedef struct AcmeOrder {
    char    order_id[64];
    char    domain[256];
    CsrRequest csr;
    AcmeChallenge challenges[2];
    size_t  challenge_count;
    uint8_t certificate_der[4096];
    size_t  cert_len;
    char    status[32]; /* pending/ready/valid/invalid */
} AcmeOrder;

typedef struct AcmeAccount {
    char    account_id[64];
    uint8_t private_key[512];
    size_t  private_key_len;
    int     key_type;
    char    contact[128];
    bool    accepted_tos;
} AcmeAccount;

void acme_account_create(AcmeAccount *acc, const char *contact);
bool acme_new_order(AcmeOrder *order, const char *domain);
bool acme_submit_challenge_response(AcmeOrder *order, size_t chall_idx,
                                     const char *response);
bool acme_finalize_order(AcmeOrder *order, const CsrRequest *csr);
bool acme_download_certificate(AcmeOrder *order, uint8_t *der, size_t *der_len);
void acme_renew_certificate(AcmeOrder *order, uint8_t *der, size_t *der_len);

/* ─── OCSP Stapling ──────────────────────────────────────────── */

#define OCSP_MAX_RESPONSE 4096

typedef enum OcspCertStatus {
    OCSP_STATUS_GOOD,
    OCSP_STATUS_REVOKED,
    OCSP_STATUS_UNKNOWN
} OcspCertStatus;

typedef struct OcspSingleResponse {
    uint8_t         serial[X509_MAX_SERIAL];
    size_t          serial_len;
    OcspCertStatus  cert_status;
    uint64_t        revocation_time;
    int             revocation_reason;
    uint64_t        this_update;
    uint64_t        next_update;
} OcspSingleResponse;

typedef struct OcspResponse {
    uint8_t             responder_id_hash[32];
    uint64_t            produced_at;
    OcspSingleResponse  responses[8];
    size_t              response_count;
    uint8_t             signature[512];
    size_t              sig_len;
    bool                is_stapled;
} OcspResponse;

bool ocsp_request_build(const uint8_t *serial, size_t serial_len,
                        uint8_t *der, size_t *der_len);
bool ocsp_response_parse(const uint8_t *der, size_t der_len,
                          OcspResponse *resp);
bool ocsp_response_verify(const OcspResponse *resp,
                           const X509Certificate *responder_cert);
OcspCertStatus ocsp_check_status(const OcspResponse *resp,
                                  const uint8_t *serial, size_t serial_len);
bool ocsp_staple_verify(const uint8_t *stapled_data, size_t data_len,
                         const X509Certificate *responder_cert,
                         uint64_t current_time);

/* ─── Key Lifecycle Management ───────────────────────────────── */

typedef enum KeyState {
    KEY_STATE_PRE_ACTIVE,
    KEY_STATE_ACTIVE,
    KEY_STATE_DEACTIVATED,
    KEY_STATE_COMPROMISED,
    KEY_STATE_DESTROYED,
    KEY_STATE_ARCHIVED
} KeyState;

typedef enum KeyAlgorithm {
    KEY_ALGO_RSA_2048,
    KEY_ALGO_RSA_4096,
    KEY_ALGO_EC_P256,
    KEY_ALGO_EC_P384
} KeyAlgorithm;

typedef struct KeyMetadata {
    char        key_id[64];
    KeyAlgorithm algo;
    KeyState    state;
    uint64_t    created_at;
    uint64_t    activated_at;
    uint64_t    deactivated_at;
    uint64_t    expires_at;
    uint64_t    destroyed_at;
    uint32_t    usage_count;
    bool        exportable;
} KeyMetadata;

typedef struct ManagedKey {
    KeyMetadata  meta;
    uint8_t      key_data[4096];
    size_t       key_data_len;
    X509Certificate cert;
    bool         has_cert;
} ManagedKey;

void key_lifecycle_init(ManagedKey *mk, KeyAlgorithm algo, const char *key_id);
bool key_lifecycle_activate(ManagedKey *mk, uint64_t validity_days);
bool key_lifecycle_deactivate(ManagedKey *mk);
bool key_lifecycle_revoke_compromised(ManagedKey *mk);
bool key_lifecycle_destroy(ManagedKey *mk);
bool key_lifecycle_archive(ManagedKey *mk);
bool key_lifecycle_is_usable(const ManagedKey *mk, uint64_t now);

/* ─── Certificate Renewal Policy ─────────────────────────────── */

typedef enum RenewalStrategy {
    RENEWAL_FIXED_WINDOW,
    RENEWAL_PERCENTAGE_LIFETIME,
    RENEWAL_KEY_CHANGE,
    RENEWAL_MANUAL_ONLY
} RenewalStrategy;

typedef struct RenewalPolicy {
    RenewalStrategy strategy;
    uint64_t         renewal_window_secs;
    double           renewal_pct_lifetime;
    bool             require_new_key;
    uint32_t         max_auto_renewals;
    uint32_t         renewal_count;
    uint64_t         last_renewal_time;
} RenewalPolicy;

void renewal_policy_init(RenewalPolicy *policy, RenewalStrategy strategy);
bool renewal_policy_should_renew(const RenewalPolicy *policy,
                                  const X509Certificate *cert,
                                  uint64_t now);
bool renewal_policy_record_renewal(RenewalPolicy *policy);

/* ─── PKI Event Audit Log ─────────────────────────────────────── */

#define PKI_AUDIT_MAX_EVENTS 128

typedef enum PkiEventType {
    PKI_EVENT_KEY_GEN,
    PKI_EVENT_KEY_ACTIVATE,
    PKI_EVENT_KEY_DEACTIVATE,
    PKI_EVENT_KEY_COMPROMISE,
    PKI_EVENT_KEY_DESTROY,
    PKI_EVENT_CERT_ISSUE,
    PKI_EVENT_CERT_REVOKE,
    PKI_EVENT_CERT_RENEW,
    PKI_EVENT_CSR_RECEIVED,
    PKI_EVENT_OCSP_QUERY,
    PKI_EVENT_ACME_ORDER
} PkiEventType;

typedef struct PkiAuditEntry {
    uint64_t      timestamp;
    PkiEventType  event_type;
    char          description[256];
    uint8_t       fingerprint[32];
} PkiAuditEntry;

typedef struct PkiAuditLog {
    PkiAuditEntry entries[PKI_AUDIT_MAX_EVENTS];
    size_t        count;
} PkiAuditLog;

void pki_audit_init(PkiAuditLog *log);
void pki_audit_record(PkiAuditLog *log, PkiEventType type,
                      const char *desc, const uint8_t *fp);
const PkiAuditEntry *pki_audit_query(const PkiAuditLog *log,
                                      PkiEventType type, size_t *count);
void pki_audit_dump(const PkiAuditLog *log);

#endif /* PKI_MODEL_H */
