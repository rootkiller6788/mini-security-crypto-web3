#ifndef MINI_TPM_TRUST_H
#define MINI_TPM_TRUST_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TPM_PCR_COUNT             24
#define TPM_PCR_SIZE              32
#define TPM_PRIMARY_KEY_SIZE      256
#define TPM_PUBLIC_KEY_MAX_SIZE    512
#define TPM_PRIVATE_KEY_MAX_SIZE   256
#define TPM_SIGNATURE_MAX_SIZE     512
#define TPM_QUOTE_MAX_SIZE         1024
#define TPM_ATTEST_MAX_SIZE        2048
#define TPM_NONCE_SIZE             32
#define TPM_SEALED_BLOB_MAX_SIZE   512
#define TPM_SEALED_DATA_MAX_SIZE   256
#define TPM_EK_CERT_SIZE           2048
#define TPM_AK_CERT_SIZE           2048
#define TPM_SESSION_SIZE           64
#define TPM_HASH_SIZE              32
#define TPM_EVENT_LOG_ENTRY_SIZE    128
#define TPM_MAX_EVENT_LOG_ENTRIES  512
#define TPM_DICE_CDI_SIZE          32
#define TPM_DICE_CERT_SIZE         2048
#define TPM_DICE_ALIAS_CERT_SIZE   2048

#define TPM_ALG_SHA1          0x0004
#define TPM_ALG_SHA256        0x000B
#define TPM_ALG_SHA384        0x000C
#define TPM_ALG_SHA512        0x000D
#define TPM_ALG_NULL          0x0010
#define TPM_ALG_RSA           0x0001
#define TPM_ALG_ECC           0x0023
#define TPM_ALG_AES           0x0006
#define TPM_ALG_HMAC          0x0005
#define TPM_ALG_KEYEDHASH    0x0008
#define TPM_ALG_XOR          0x000A
#define TPM_ALG_POLICY       0x000F

#define TPM_HANDLE_OWNER      0x40000001
#define TPM_HANDLE_ENDORSEMENT 0x4000000B
#define TPM_HANDLE_PLATFORM     0x4000000C
#define TPM_HANDLE_NULL       0x40000007

#define TPM_LOC_ZERO          0
#define TPM_LOC_ONE           1
#define TPM_LOC_TWO           2
#define TPM_LOC_THREE         3
#define TPM_LOC_FOUR          4

typedef enum {
    TPM_SU_CLEAR                 = 0x0000,
    TPM_SU_STATE                 = 0x0001,
    TPM_SU_PCR                   = 0x0002
} tpm_startup_t;

typedef enum {
    TPM_RC_SUCCESS               = 0x000,
    TPM_RC_BAD_TAG               = 0x01E,
    TPM_RC_INITIALIZE            = 0x100,
    TPM_RC_FAILURE               = 0x101,
    TPM_RC_SEQUENCE              = 0x103,
    TPM_RC_PRIVATE               = 0x10B,
    TPM_RC_HMAC                  = 0x119,
    TPM_RC_DISABLED              = 0x120,
    TPM_RC_EXCLUSIVE             = 0x121,
    TPM_RC_AUTH_TYPE             = 0x124,
    TPM_RC_AUTH_MISSING          = 0x125,
    TPM_RC_POLICY                = 0x126,
    TPM_RC_PCR                   = 0x127,
    TPM_RC_PCR_CHANGED           = 0x128,
    TPM_RC_UPGRADE               = 0x12D,
    TPM_RC_TOO_MANY_CONTEXTS     = 0x12E,
    TPM_RC_AUTH_UNAVAILABLE      = 0x12F,
    TPM_RC_REBOOT                = 0x130,
    TPM_RC_UNBALANCED            = 0x131,
    TPM_RC_COMMAND_SIZE          = 0x142,
    TPM_RC_COMMAND_CODE          = 0x143,
    TPM_RC_AUTHSIZE              = 0x144,
    TPM_RC_AUTH_CONTEXT          = 0x145,
    TPM_RC_NV_RANGE              = 0x146,
    TPM_RC_NV_SIZE               = 0x147,
    TPM_RC_NV_LOCKED             = 0x148,
    TPM_RC_NV_AUTHORIZATION      = 0x149,
    TPM_RC_NV_UNINITIALIZED      = 0x14A,
    TPM_RC_NV_SPACE              = 0x14B,
    TPM_RC_NV_DEFINED            = 0x14C,
    TPM_RC_HANDLE                = 0x18B,
    TPM_RC_SIGNATURE             = 0x1B4,
    TPM_RC_VALUE                 = 0x184,
    TPM_RC_HIERARCHY             = 0x185,
    TPM_RC_KEY_SIZE              = 0x187,
    TPM_RC_MGF                   = 0x188,
    TPM_RC_MODE                  = 0x18B,
    TPM_RC_TYPE                  = 0x18E,
    TPM_RC_PASSWORD              = 0x198,
    TPM_RC_SCHEME                = 0x1A2,
    TPM_RC_TICKET                = 0x1A8
} tpm_rc_t;

typedef enum {
    TPM_HIERARCHY_PLATFORM      = 0,
    TPM_HIERARCHY_OWNER         = 1,
    TPM_HIERARCHY_ENDORSEMENT   = 2,
    TPM_HIERARCHY_NULL          = 3
} tpm_hierarchy_t;

typedef enum {
    TPM_OBJECT_RSA          = 0x0001,
    TPM_OBJECT_ECC          = 0x0023,
    TPM_OBJECT_KEYEDHASH    = 0x0008,
    TPM_OBJECT_SYMCIPHER    = 0x0025,
    TPM_OBJECT_DATA         = 0x0000
} tpm_object_type_t;

typedef enum {
    TPM_SE_HMAC         = 0x0001,
    TPM_SE_POLICY       = 0x0002,
    TPM_SE_TRIAL        = 0x0003
} tpm_session_type_t;

typedef enum {
    TPM_AT_ANY                  = 0,
    TPM_AT_ERROR                = 1,
    TPM_AT_PV1                  = 2,
    TPM_AT_PLATFORM_MANIFEST    = 3,
    TPM_AT_KEY_SIGN             = 4,
    TPM_AT_PLATFORM_CONFIG      = 5,
    TPM_AT_PERMANENT            = 6,
    TPM_AT_NV                   = 7
} tpm_sign_attest_t;

typedef enum {
    DICE_LAYER_ROM          = 0,
    DICE_LAYER_BOOTLOADER   = 1,
    DICE_LAYER_OS           = 2,
    DICE_LAYER_APPLICATION  = 3,
    DICE_LAYER_MAX          = 4
} dice_layer_t;

#pragma pack(push, 1)

typedef struct {
    uint8_t  digest[TPM_PCR_SIZE];
    char     event[TPM_EVENT_LOG_ENTRY_SIZE];
    uint32_t pcr_index;
    uint32_t event_type;
    bool     extended;
    bool     reset;
} tpm_event_log_entry_t;

typedef struct {
    tpm_event_log_entry_t entries[TPM_MAX_EVENT_LOG_ENTRIES];
    uint32_t entry_count;
    uint64_t boot_counter;
    bool     measured_boot_complete;
} tpm_event_log_t;

typedef struct {
    uint8_t  pcr_values[TPM_PCR_COUNT][TPM_PCR_SIZE];
    uint32_t pcr_count;
    bool     pcr_initialized[TPM_PCR_COUNT];
    bool     pcr_reset[TPM_PCR_COUNT];
    uint32_t locality[TPM_PCR_COUNT];
    uint16_t hash_alg;
    uint16_t hash_size;
} tpm_pcr_bank_t;

typedef struct {
    uint8_t  modulus[TPM_PRIMARY_KEY_SIZE];
    uint32_t modulus_size;
    uint8_t  exponent[4];
    uint32_t exponent_size;
    uint32_t key_type;
    uint32_t key_scheme;
    uint16_t key_alg;
    bool     restricted;
    bool     sign;
    bool     decrypt;
    bool     fixed_tpm;
    bool     fixed_parent;
    bool     sensitive_data_origin;
    bool     user_with_auth;
    bool     admin_with_policy;
    bool     noda;
} tpm_public_key_t;

typedef struct {
    uint8_t  data[TPM_PRIVATE_KEY_MAX_SIZE];
    uint32_t data_size;
    uint32_t parent_handle;
    uint32_t auth_size;
    bool     is_encrypted;
    uint8_t  encrypted_seed[64];
} tpm_private_key_t;

typedef struct {
    uint8_t  magic[4];
    uint8_t  type[4];
    uint32_t qualified_signer_size;
    uint8_t  qualified_signer[TPM_QUOTE_MAX_SIZE];
    uint8_t  extra_data[TPM_NONCE_SIZE];
    uint8_t  clock_info[17];
    uint8_t  firmware_version[8];
    uint8_t  pcr_select[TPM_PCR_COUNT / 8];
    uint8_t  pcr_digest[TPM_PCR_SIZE];
    int32_t  pcr_count;
    uint8_t  selected_pcrs[TPM_PCR_COUNT][TPM_PCR_SIZE];
    uint32_t selected_count;
} tpm_attest_t;

typedef struct {
    uint8_t  public_key[TPM_PUBLIC_KEY_MAX_SIZE];
    uint32_t public_key_size;
    uint8_t  private_key[TPM_PRIVATE_KEY_MAX_SIZE];
    uint32_t private_key_size;
    uint32_t handle;
    uint32_t key_type;
    uint16_t key_alg;
    bool     is_primary;
    bool     is_restricted;
    uint32_t parent_handle;
    uint64_t auth_policy;
    uint16_t hash_alg;
    uint8_t  name[TPM_HASH_SIZE];
} tpm_key_t;

typedef struct {
    uint8_t  ek_certificate[TPM_EK_CERT_SIZE];
    uint32_t ek_cert_size;
    uint8_t  ek_public_key[TPM_PUBLIC_KEY_MAX_SIZE];
    uint32_t ek_public_key_size;
    uint32_t ek_handle;
    bool     ek_certified;
    uint8_t  ek_name[TPM_HASH_SIZE];
} tpm_endorsement_key_t;

typedef struct {
    uint8_t  ak_certificate[TPM_AK_CERT_SIZE];
    uint32_t ak_cert_size;
    uint8_t  ak_public_key[TPM_PUBLIC_KEY_MAX_SIZE];
    uint32_t ak_public_key_size;
    uint32_t ak_handle;
    bool     ak_certified;
    uint32_t ek_handle;
    uint8_t  ak_name[TPM_HASH_SIZE];
    bool     restricted_signing;
    bool     fixed_tpm;
    bool     fixed_qualifier;
} tpm_attestation_key_t;

typedef struct {
    uint8_t  sealed_data[TPM_SEALED_BLOB_MAX_SIZE];
    uint32_t sealed_size;
    uint32_t pcr_mask;
    uint32_t selected_pcr_indices[TPM_PCR_COUNT];
    uint32_t selected_count;
    uint8_t  pcr_values[TPM_PCR_COUNT][TPM_PCR_SIZE];
    uint32_t parent_handle;
    uint8_t  auth_value[32];
    uint32_t auth_size;
    bool     require_auth;
    bool     sealed;
    bool     unsealed;
} tpm_sealed_key_t;

typedef struct {
    uint8_t  quote_blob[TPM_QUOTE_MAX_SIZE];
    uint32_t quote_size;
    uint8_t  signature[TPM_SIGNATURE_MAX_SIZE];
    uint32_t sig_size;
    uint32_t sign_handle;
    tpm_attest_t attest_struct;
    uint32_t pcr_mask;
    bool     signed_by_ak;
    bool     valid;
} tpm_quote_t;

typedef struct {
    uint8_t  nv_data[TPM_QUOTE_MAX_SIZE];
    uint32_t nv_size;
    uint32_t nv_index;
    uint32_t nv_attributes;
    uint16_t nv_data_size_max;
    bool     written;
    bool     locked;
    bool     owner_read;
    bool     owner_write;
} tpm_nv_storage_t;

typedef struct {
    tpm_pcr_bank_t        pcr_banks[4];
    uint32_t              bank_count;
    tpm_endorsement_key_t ek;
    tpm_attestation_key_t ak;
    tpm_event_log_t       event_log;
    tpm_key_t             primary_keys[8];
    uint32_t              primary_key_count;
    tpm_nv_storage_t      nv_storage[16];
    uint32_t              nv_storage_count;
    bool                  initialized;
    bool                  ownership_taken;
    bool                  ek_generated;
    bool                  ak_generated;
    uint32_t              active_locality;
    uint8_t               owner_auth[32];
    uint8_t               endorsement_auth[32];
    uint8_t               lockout_auth[32];
    bool                  is_simulator;
    uint32_t              restart_counter;
} tpm_device_t;

typedef struct {
    uint8_t  cdi[TPM_DICE_CDI_SIZE];
    uint8_t  device_id_cert[TPM_DICE_CERT_SIZE];
    uint32_t device_id_cert_size;
    uint8_t  alias_cert[TPM_DICE_ALIAS_CERT_SIZE];
    uint32_t alias_cert_size;
    uint8_t  fwid_digest[TPM_DICE_CDI_SIZE];
    uint64_t security_version;
    bool     certified;
    dice_layer_t current_layer;
} tpm_dice_t;

typedef struct {
    uint8_t  cdi[TPM_DICE_CDI_SIZE];
    uint8_t  layer_pubkey[64];
    uint8_t  layer_cert[TPM_DICE_CERT_SIZE];
    uint32_t layer_cert_size;
    dice_layer_t layer;
    bool     attested;
} tpm_dice_layer_t;

#pragma pack(pop)

int  tpm_init(tpm_device_t *tpm, bool simulator);
int  tpm_startup(tpm_device_t *tpm, tpm_startup_t type);
int  tpm_self_test(tpm_device_t *tpm);
int  tpm_get_random(tpm_device_t *tpm, uint8_t *data, size_t size);
int  tpm_get_capability(tpm_device_t *tpm, uint32_t capability,
                        uint32_t property, uint32_t property_count,
                        uint8_t *data, size_t *data_size);

int  tpm_pcr_extend(tpm_device_t *tpm, uint32_t pcr_index,
                    const uint8_t *digest, uint32_t digest_size);
int  tpm_pcr_read(tpm_device_t *tpm, uint32_t pcr_index,
                  uint8_t *digest, uint32_t *digest_size);
int  tpm_pcr_reset(tpm_device_t *tpm, uint32_t pcr_index);
int  tpm_pcr_set_auth_policy(tpm_device_t *tpm, uint32_t pcr_index,
                             uint8_t *policy, uint32_t policy_size);
int  tpm_pcr_set_auth_value(tpm_device_t *tpm, uint32_t pcr_index,
                            const uint8_t *auth_value, uint32_t auth_size);

int  tpm_create_primary(tpm_device_t *tpm, tpm_hierarchy_t hierarchy,
                        const uint8_t *auth_value, uint32_t auth_size,
                        tpm_key_t *primary_key);
int  tpm_create_key(tpm_device_t *tpm, tpm_key_t *parent_key,
                    const uint8_t *auth_value, uint32_t auth_size,
                    tpm_object_type_t type, tpm_key_t *new_key);
int  tpm_load_key(tpm_device_t *tpm, tpm_key_t *parent_key,
                  const tpm_private_key_t *private_key,
                  tpm_key_t *loaded_key);
int  tpm_sign(tpm_device_t *tpm, tpm_key_t *key,
              const uint8_t *digest, uint32_t digest_size,
              uint8_t *signature, uint32_t *sig_size);
int  tpm_verify_signature(tpm_device_t *tpm, tpm_key_t *key,
                          const uint8_t *digest, uint32_t digest_size,
                          const uint8_t *signature, uint32_t sig_size,
                          bool *valid);

int  tpm_create_ek(tpm_device_t *tpm, tpm_endorsement_key_t *ek);
int  tpm_create_ak(tpm_device_t *tpm, tpm_attestation_key_t *ak,
                   const tpm_endorsement_key_t *ek);
int  tpm_certify_ek(tpm_device_t *tpm, tpm_endorsement_key_t *ek);
int  tpm_certify_ak(tpm_device_t *tpm, tpm_attestation_key_t *ak,
                    const tpm_endorsement_key_t *ek);

int  tpm_quote(tpm_device_t *tpm, tpm_attestation_key_t *ak,
               const uint8_t *pcr_selection, uint32_t pcr_count,
               const uint8_t *nonce, uint32_t nonce_size,
               tpm_quote_t *quote);
int  tpm_verify_quote(tpm_device_t *tpm, const tpm_quote_t *quote,
                      const tpm_attestation_key_t *ak, bool *valid);
int  tpm_attest(tpm_device_t *tpm, tpm_key_t *key,
                const uint8_t *attested_data, uint32_t data_size,
                tpm_sign_attest_t attest_type,
                tpm_attest_t *attestation);

int  tpm_seal(tpm_device_t *tpm, tpm_key_t *parent_key,
              const uint8_t *data, uint32_t data_size,
              const uint32_t *pcr_indices, uint32_t pcr_count,
              tpm_sealed_key_t *sealed_key);
int  tpm_unseal(tpm_device_t *tpm, tpm_sealed_key_t *sealed_key,
                uint8_t *data, uint32_t *data_size);
int  tpm_seal_policy(tpm_device_t *tpm, tpm_key_t *parent_key,
                     const uint8_t *data, uint32_t data_size,
                     const uint8_t *policy, uint32_t policy_size,
                     tpm_sealed_key_t *sealed_key);

int  tpm_nv_define_space(tpm_device_t *tpm, uint32_t index,
                         uint32_t size, uint32_t attributes);
int  tpm_nv_write(tpm_device_t *tpm, uint32_t index,
                  const uint8_t *data, uint32_t data_size);
int  tpm_nv_read(tpm_device_t *tpm, uint32_t index,
                 uint8_t *data, uint32_t *data_size);
int  tpm_nv_lock(tpm_device_t *tpm, uint32_t index);
int  tpm_nv_undefine_space(tpm_device_t *tpm, uint32_t index);

int  tpm_measured_boot_start(tpm_device_t *tpm);
int  tpm_measured_boot_extend(tpm_device_t *tpm, const char *event,
                              const uint8_t *digest, uint32_t digest_size);
int  tpm_measured_boot_complete(tpm_device_t *tpm);
int  tpm_measured_boot_verify(tpm_device_t *tpm, bool *trusted);

int  tpm_dice_compute_cdi(tpm_dice_t *dice, const uint8_t *firmware_id,
                          uint32_t fw_id_size);
int  tpm_dice_derive_key(tpm_dice_t *dice, dice_layer_t layer,
                         uint8_t *key, uint32_t *key_size);
int  tpm_dice_create_alias_cert(tpm_dice_t *dice,
                                const uint8_t *device_identity,
                                uint32_t identity_size);
int  tpm_dice_verify_chain(tpm_dice_t *dice, bool *valid);
int  tpm_dice_seal_to_cdi(tpm_dice_t *dice, const uint8_t *data,
                          uint32_t data_size, uint8_t *sealed,
                          uint32_t *sealed_size);

int  tpm_get_event_log(tpm_device_t *tpm, tpm_event_log_t *log);
int  tpm_replay_event_log(tpm_device_t *tpm, const tpm_event_log_t *log,
                          bool *consistent);
int  tpm_get_ek_certificate(tpm_device_t *tpm,
                            uint8_t *cert, uint32_t *cert_size);
int  tpm_provision(tpm_device_t *tpm, const uint8_t *ek_cert,
                   uint32_t ek_cert_size);

void tpm_print_pcr_values(const tpm_device_t *tpm);
void tpm_print_event_log(const tpm_event_log_t *log);
void tpm_print_attest(const tpm_attest_t *attest);
void tpm_print_quote(const tpm_quote_t *quote);
void tpm_print_dice(const tpm_dice_t *dice);
void tpm_print_key_info(const tpm_key_t *key);

void tpm_device_free(tpm_device_t *tpm);

#ifdef __cplusplus
}
#endif

#endif /* MINI_TPM_TRUST_H */
