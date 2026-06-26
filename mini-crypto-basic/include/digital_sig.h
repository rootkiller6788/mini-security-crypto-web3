#ifndef DIGITAL_SIG_H
#define DIGITAL_SIG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ─── RSA-PSS ────────────────────────────────────────────────── */

#define PSS_SALT_LEN_MAX 32
#define PSS_HASH_SIZE    32

typedef enum PssHashAlgo {
    PSS_HASH_SHA256
} PssHashAlgo;

bool rsa_pss_sign(const void *rsa_priv, const uint8_t *msg, size_t msg_len,
                  PssHashAlgo algo, const uint8_t *salt, size_t salt_len,
                  uint8_t *sig, size_t *sig_len, size_t key_bits);
bool rsa_pss_verify(const void *rsa_pub, const uint8_t *msg, size_t msg_len,
                    PssHashAlgo algo, size_t salt_len,
                    const uint8_t *sig, size_t sig_len, size_t key_bits);

void pss_mgf1(uint8_t *mask, size_t mask_len, const uint8_t *seed, size_t seed_len,
              PssHashAlgo algo);

/* ─── ECDSA ──────────────────────────────────────────────────── */

#define ECDSA_SIG_MAX 72

typedef struct EcdsaSignature {
    uint8_t r[32];
    uint8_t s[32];
    size_t  r_len;
    size_t  s_len;
} EcdsaSignature;

bool ecdsa_sign(const uint8_t *priv_key, const uint8_t *hash, size_t hash_len,
                EcdsaSignature *sig);
bool ecdsa_verify(const void *pub_point, const uint8_t *hash, size_t hash_len,
                  const EcdsaSignature *sig);
void ecdsa_sig_encode(const EcdsaSignature *sig, uint8_t *der, size_t *der_len);

/* ─── Hash-then-Sign ─────────────────────────────────────────── */

typedef enum SignAlgorithm {
    SIG_RSA_PSS,
    SIG_ECDSA
} SignAlgorithm;

typedef struct Signer {
    SignAlgorithm algo;
    union {
        void *rsa_priv;
        void *ec_priv;
    } key;
    size_t key_bits;
} Signer;

typedef struct Verifier {
    SignAlgorithm algo;
    union {
        void *rsa_pub;
        void *ec_pub;
    } key;
    size_t key_bits;
} Verifier;

bool hash_then_sign(const Signer *signer, const uint8_t *msg, size_t msg_len,
                    uint8_t *sig, size_t *sig_len);
bool hash_then_verify(const Verifier *verifier, const uint8_t *msg, size_t msg_len,
                      const uint8_t *sig, size_t sig_len);

/* ─── X.509 Certificate ──────────────────────────────────────── */

#define X509_MAX_CN_LEN    128
#define X509_MAX_O_LEN     128
#define X509_MAX_SERIAL    20
#define X509_MAX_EXTENSIONS  8
#define X509_MAX_CERT_SIZE 4096

typedef struct X509Name {
    char common_name[X509_MAX_CN_LEN];
    char organization[X509_MAX_O_LEN];
    char country[4];
} X509Name;

typedef enum X509KeyUsage {
    X509_KU_DIGITAL_SIGNATURE = 1 << 0,
    X509_KU_KEY_ENCIPHERMENT  = 1 << 1,
    X509_KU_DATA_ENCIPHERMENT = 1 << 2,
    X509_KU_KEY_AGREEMENT     = 1 << 3,
    X509_KU_CERT_SIGN         = 1 << 4,
    X509_KU_CRL_SIGN          = 1 << 5
} X509KeyUsage;

typedef enum X509ExtKeyUsage {
    X509_EKU_SERVER_AUTH = 0,
    X509_EKU_CLIENT_AUTH = 1,
    X509_EKU_CODE_SIGNING = 2,
    X509_EKU_EMAIL_PROTECTION = 3,
    X509_EKU_TIME_STAMPING = 4,
    X509_EKU_OCSP_SIGNING = 5
} X509ExtKeyUsage;

typedef struct X509BasicConstraints {
    bool   is_ca;
    int    path_len_constraint;
} X509BasicConstraints;

typedef struct X509Extension {
    char oid[64];
    uint8_t value[256];
    size_t  value_len;
    bool    critical;
} X509Extension;

typedef struct X509Certificate {
    uint32_t              version;
    uint8_t               serial[X509_MAX_SERIAL];
    size_t                serial_len;
    SignAlgorithm         sig_algo;
    X509Name              issuer;
    X509Name              subject;
    uint64_t              not_before;
    uint64_t              not_after;
    uint8_t               pub_key_data[512];
    size_t                pub_key_len;
    int                   pub_key_type; /* 0=RSA, 1=EC */
    X509KeyUsage          key_usage;
    X509ExtKeyUsage       ext_key_usage;
    X509BasicConstraints  basic_constraints;
    X509Extension         extensions[X509_MAX_EXTENSIONS];
    size_t                ext_count;
    uint8_t               signature[512];
    size_t                sig_len;
} X509Certificate;

bool x509_parse_der(const uint8_t *der, size_t der_len, X509Certificate *cert);
bool x509_verify_signature(const X509Certificate *cert,
                           const X509Certificate *issuer);
bool x509_is_valid_at_time(const X509Certificate *cert, uint64_t timestamp);
void x509_print_certificate(const X509Certificate *cert);

/* ─── Certificate Chain ──────────────────────────────────────── */

#define CERT_CHAIN_MAX_DEPTH 8

typedef struct CertChain {
    X509Certificate certs[CERT_CHAIN_MAX_DEPTH];
    size_t          depth;
} CertChain;

bool cert_chain_verify(const CertChain *chain,
                       const X509Certificate *trust_root,
                       uint64_t verify_time);

/* ─── CRL ────────────────────────────────────────────────────── */

#define CRL_MAX_ENTRIES 256

typedef struct CrlEntry {
    uint8_t  serial[X509_MAX_SERIAL];
    size_t   serial_len;
    uint64_t revocation_date;
    int      reason; /* 0=unspecified,1=keyCompromise,2=caCompromise,
                        3=affiliationChanged,4=superseded,5=cessationOfOperation */
} CrlEntry;

typedef struct CertificateRevocationList {
    X509Name issuer;
    uint64_t this_update;
    uint64_t next_update;
    CrlEntry entries[CRL_MAX_ENTRIES];
    size_t   entry_count;
} CertificateRevocationList;

bool crl_is_revoked(const CertificateRevocationList *crl,
                    const uint8_t *serial, size_t serial_len);

#endif /* DIGITAL_SIG_H */
