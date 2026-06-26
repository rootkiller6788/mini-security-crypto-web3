#ifndef KMS_KEY_H
#define KMS_KEY_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define KMS_MAX_KEYS           128
#define KMS_MAX_GRANTS         256
#define KMS_MAX_REGIONS         16
#define KMS_KEY_ID_LEN          64
#define KMS_KEY_ARN_LEN        256
#define KMS_MAX_PLAINTEXT     65536
#define KMS_MAX_CIPHERTEXT    65536
#define KMS_AES_KEY_SIZE        32
#define KMS_AES_GCM_IV_SIZE     12
#define KMS_AES_GCM_TAG_SIZE    16
#define KMS_DATA_KEY_MAX       512

typedef enum {
    KMS_KEY_STATE_ENABLED          = 0,
    KMS_KEY_STATE_DISABLED         = 1,
    KMS_KEY_STATE_PENDING_DELETION = 2,
    KMS_KEY_STATE_PENDING_IMPORT   = 3,
    KMS_KEY_STATE_UNAVAILABLE      = 4
} kms_key_state_t;

typedef enum {
    KMS_KEY_SPEC_SYMMETRIC_DEFAULT = 0,
    KMS_KEY_SPEC_RSA_2048          = 1,
    KMS_KEY_SPEC_RSA_3072          = 2,
    KMS_KEY_SPEC_RSA_4096          = 3,
    KMS_KEY_SPEC_ECC_NIST_P256     = 4,
    KMS_KEY_SPEC_ECC_NIST_P384     = 5,
    KMS_KEY_SPEC_ECC_NIST_P521     = 6,
    KMS_KEY_SPEC_ECC_SECG_P256K1   = 7,
    KMS_KEY_SPEC_HMAC_256          = 8
} kms_key_spec_t;

typedef enum {
    KMS_KEY_USAGE_ENCRYPT_DECRYPT = 0,
    KMS_KEY_USAGE_SIGN_VERIFY     = 1,
    KMS_KEY_USAGE_GENERATE_VERIFY_MAC = 2
} kms_key_usage_t;

typedef enum {
    KMS_KEY_MATERIAL_KMS         = 0,
    KMS_KEY_MATERIAL_EXTERNAL    = 1,
    KMS_KEY_MATERIAL_CUSTOM_STORE= 2
} kms_origin_t;

typedef enum {
    KMS_GRANT_OP_ENCRYPT             = 1 << 0,
    KMS_GRANT_OP_DECRYPT             = 1 << 1,
    KMS_GRANT_OP_GENERATE_DATA_KEY   = 1 << 2,
    KMS_GRANT_OP_RE_ENCRYPT          = 1 << 3,
    KMS_GRANT_OP_DESCRIBE_KEY        = 1 << 4,
    KMS_GRANT_OP_CREATE_GRANT        = 1 << 5,
    KMS_GRANT_OP_RETIRE_GRANT        = 1 << 6,
    KMS_GRANT_OP_SIGN                = 1 << 7,
    KMS_GRANT_OP_VERIFY              = 1 << 8
} kms_grant_operation_t;

typedef struct {
    char          key_id[KMS_KEY_ID_LEN];
    char          arn[KMS_KEY_ARN_LEN];
    kms_key_spec_t spec;
    kms_key_usage_t usage;
    kms_origin_t   origin;
    kms_key_state_t state;
    unsigned char  key_material[KMS_AES_KEY_SIZE];
    unsigned char  hsm_backed;
    unsigned char  multi_region;
    char           primary_region[32];
    char           replica_regions[KMS_MAX_REGIONS][32];
    int            replica_count;
    unsigned char  rotation_enabled;
    int            rotation_days;
    time_t         last_rotation;
    time_t         creation_date;
    time_t         deletion_date;
    char           policy_json[8192];
} kms_key_t;

typedef struct {
    unsigned char ciphertext_blob[KMS_MAX_CIPHERTEXT];
    size_t        ciphertext_len;
    unsigned char plaintext[KMS_MAX_PLAINTEXT];
    size_t        plaintext_len;
} kms_encrypt_result_t;

typedef struct {
    unsigned char plaintext[KMS_MAX_PLAINTEXT];
    size_t        plaintext_len;
} kms_decrypt_result_t;

typedef struct {
    unsigned char plaintext_key[KMS_DATA_KEY_MAX];
    size_t        plaintext_len;
    unsigned char encrypted_key[KMS_DATA_KEY_MAX];
    size_t        encrypted_len;
    char          key_id[KMS_KEY_ID_LEN];
} kms_data_key_t;

typedef struct {
    char         grant_id[KMS_KEY_ID_LEN];
    char         grantee_principal[KMS_KEY_ARN_LEN];
    char         key_id[KMS_KEY_ID_LEN];
    uint32_t     operations;
    char         constraints[4096];
    char         retiring_principal[KMS_KEY_ARN_LEN];
    time_t       creation_date;
} kms_grant_t;

typedef struct {
    kms_key_t     keys[KMS_MAX_KEYS];
    int           key_count;
    kms_grant_t   grants[KMS_MAX_GRANTS];
    int           grant_count;
} kms_state_t;

kms_key_t*  kms_create_key(const char *description, kms_key_spec_t spec,
                            kms_key_usage_t usage, kms_origin_t origin,
                            unsigned char multi_region, unsigned char hsm);
kms_key_t*  kms_create_key_with_policy(const char *description, kms_key_spec_t spec,
                                        kms_key_usage_t usage, kms_origin_t origin,
                                        const char *policy_json);
void        kms_enable_key(kms_key_t *key);
void        kms_disable_key(kms_key_t *key);
void        kms_schedule_key_deletion(kms_key_t *key, int pending_days);
void        kms_cancel_key_deletion(kms_key_t *key);

int         kms_enable_rotation(kms_key_t *key, int days);
int         kms_rotate_key_on_demand(kms_key_t *key);
int         kms_rotate_key_if_needed(kms_key_t *key);

int         kms_encrypt(const kms_key_t *key,
                        const unsigned char *plaintext, size_t plaintext_len,
                        kms_encrypt_result_t *result);
int         kms_decrypt(const kms_key_t *key,
                        const unsigned char *ciphertext, size_t ciphertext_len,
                        kms_decrypt_result_t *result);

int         kms_generate_data_key(const kms_key_t *key,
                                   kms_data_key_t *data_key,
                                   int key_size_bits);
int         kms_encrypt_with_data_key(const kms_data_key_t *dk,
                                       const unsigned char *plaintext,
                                       size_t plaintext_len,
                                       unsigned char *ciphertext,
                                       size_t *ciphertext_len);
int         kms_decrypt_with_data_key(const kms_data_key_t *dk,
                                       const unsigned char *ciphertext,
                                       size_t ciphertext_len,
                                       unsigned char *plaintext,
                                       size_t *plaintext_len);
int         kms_envelope_encrypt(const kms_key_t *cmk,
                                  const unsigned char *plaintext,
                                  size_t plaintext_len,
                                  kms_data_key_t *out_data_key,
                                  unsigned char *out_ciphertext,
                                  size_t *out_ciphertext_len);
int         kms_envelope_decrypt(const kms_key_t *cmk,
                                  const kms_data_key_t *dk,
                                  const unsigned char *ciphertext,
                                  size_t ciphertext_len,
                                  unsigned char *plaintext,
                                  size_t *plaintext_len);

kms_grant_t* kms_create_grant(const kms_key_t *key,
                               const char *grantee_principal,
                               uint32_t operations,
                               const char *retiring_principal);
int          kms_retire_grant(kms_grant_t *grant);
int          kms_revoke_grant(const kms_key_t *key, const char *grant_id);

int          kms_add_replica_region(kms_key_t *key, const char *region);
int          kms_remove_replica_region(kms_key_t *key, const char *region);

const char*  kms_key_state_name(kms_key_state_t state);
const char*  kms_key_spec_name(kms_key_spec_t spec);

#endif
