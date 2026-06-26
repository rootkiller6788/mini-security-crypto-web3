#include "kms_key.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static kms_state_t g_kms_state;
static int g_next_key_id = 1;
static int g_next_grant_id = 1;

static void generate_random(unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buf[i] = (unsigned char)((rand() & 0xFF) ^ ((i * 97 + 13) & 0xFF));
    }
}

static void sim_aes_gcm_encrypt(const unsigned char *key, const unsigned char *iv,
                                  const unsigned char *plain, size_t plain_len,
                                  unsigned char *cipher, size_t *cipher_len) {
    *cipher_len = plain_len + KMS_AES_GCM_TAG_SIZE;
    for (size_t i = 0; i < plain_len; i++) {
        cipher[i] = plain[i] ^ key[i % KMS_AES_KEY_SIZE] ^ iv[i % KMS_AES_GCM_IV_SIZE];
    }
    for (size_t i = 0; i < KMS_AES_GCM_TAG_SIZE; i++) {
        cipher[plain_len + i] = key[i] ^ iv[i % KMS_AES_GCM_IV_SIZE] ^ 0xA5;
    }
}

static int sim_aes_gcm_decrypt(const unsigned char *key, const unsigned char *iv,
                                 const unsigned char *cipher, size_t cipher_len,
                                 unsigned char *plain, size_t *plain_len) {
    if (cipher_len < KMS_AES_GCM_TAG_SIZE) return -1;
    size_t pt_len = cipher_len - KMS_AES_GCM_TAG_SIZE;
    for (size_t i = 0; i < pt_len; i++) {
        plain[i] = cipher[i] ^ key[i % KMS_AES_KEY_SIZE] ^ iv[i % KMS_AES_GCM_IV_SIZE];
    }
    unsigned char tag_ok = 1;
    for (size_t i = 0; i < KMS_AES_GCM_TAG_SIZE; i++) {
        if (cipher[pt_len + i] != (unsigned char)(key[i] ^ iv[i % KMS_AES_GCM_IV_SIZE] ^ 0xA5))
            tag_ok = 0;
    }
    *plain_len = pt_len;
    return tag_ok ? 0 : -2;
}

kms_key_t* kms_create_key(const char *description, kms_key_spec_t spec,
                            kms_key_usage_t usage, kms_origin_t origin,
                            unsigned char multi_region, unsigned char hsm) {
    return kms_create_key_with_policy(description, spec, usage, origin,
                                       "{\"Version\":\"2012-10-17\",\"Statement\":[]}",
                                       multi_region, hsm);
}

kms_key_t* kms_create_key_with_policy(const char *desc, kms_key_spec_t spec,
                                       kms_key_usage_t usage, kms_origin_t origin,
                                       const char *policy_json,
                                       unsigned char multi_region,
                                       unsigned char hsm) {
    if (g_kms_state.key_count >= KMS_MAX_KEYS) return NULL;
    kms_key_t *k = &g_kms_state.keys[g_kms_state.key_count++];
    memset(k, 0, sizeof(kms_key_t));
    snprintf(k->key_id, KMS_KEY_ID_LEN, "cmk-%04d-%08lx", g_next_key_id, (unsigned long)time(NULL));
    snprintf(k->arn, KMS_KEY_ARN_LEN, "arn:aws:kms:us-east-1:123456789012:key/%s", k->key_id);
    k->spec = spec;
    k->usage = usage;
    k->origin = origin;
    k->state = KMS_KEY_STATE_ENABLED;
    k->hsm_backed = hsm;
    k->multi_region = multi_region;
    strncpy(k->primary_region, "us-east-1", 31);
    k->creation_date = time(NULL);
    if (policy_json) { strncpy(k->policy_json, policy_json, 2047); }
    if (spec == KMS_KEY_SPEC_SYMMETRIC_DEFAULT) {
        generate_random(k->key_material, KMS_AES_KEY_SIZE);
    }
    if (multi_region) { kms_add_replica_region(k, "us-west-2"); }
    g_next_key_id++;
    return k;
}

void kms_enable_key(kms_key_t *key) {
    if (key && key->state == KMS_KEY_STATE_DISABLED)
        key->state = KMS_KEY_STATE_ENABLED;
}

void kms_disable_key(kms_key_t *key) {
    if (key && key->state == KMS_KEY_STATE_ENABLED)
        key->state = KMS_KEY_STATE_DISABLED;
}

void kms_schedule_key_deletion(kms_key_t *key, int pending_days) {
    if (!key) return;
    key->state = KMS_KEY_STATE_PENDING_DELETION;
    key->deletion_date = time(NULL) + pending_days * 86400;
}

void kms_cancel_key_deletion(kms_key_t *key) {
    if (key && key->state == KMS_KEY_STATE_PENDING_DELETION) {
        key->state = KMS_KEY_STATE_DISABLED;
        key->deletion_date = 0;
    }
}

int kms_enable_rotation(kms_key_t *key, int days) {
    if (!key || key->spec != KMS_KEY_SPEC_SYMMETRIC_DEFAULT) return -1;
    key->rotation_enabled = 1;
    key->rotation_days = days > 0 ? days : 365;
    key->last_rotation = time(NULL);
    return 0;
}

int kms_rotate_key_on_demand(kms_key_t *key) {
    if (!key || key->state != KMS_KEY_STATE_ENABLED) return -1;
    if (key->spec != KMS_KEY_SPEC_SYMMETRIC_DEFAULT) return -2;
    generate_random(key->key_material, KMS_AES_KEY_SIZE);
    key->last_rotation = time(NULL);
    return 0;
}

int kms_rotate_key_if_needed(kms_key_t *key) {
    if (!key || !key->rotation_enabled) return 0;
    time_t now = time(NULL);
    if (now - key->last_rotation > key->rotation_days * 86400) {
        return kms_rotate_key_on_demand(key);
    }
    return 0;
}

int kms_encrypt(const kms_key_t *key,
                const unsigned char *plaintext, size_t plaintext_len,
                kms_encrypt_result_t *result) {
    if (!key || !plaintext || !result) return -1;
    if (key->state != KMS_KEY_STATE_ENABLED) return -3;
    if (plaintext_len > KMS_MAX_PLAINTEXT - KMS_AES_GCM_TAG_SIZE) return -4;

    unsigned char iv[KMS_AES_GCM_IV_SIZE];
    generate_random(iv, KMS_AES_GCM_IV_SIZE);

    memcpy(result->ciphertext_blob, iv, KMS_AES_GCM_IV_SIZE);
    size_t ct_len;
    sim_aes_gcm_encrypt(key->key_material, iv, plaintext, plaintext_len,
                         result->ciphertext_blob + KMS_AES_GCM_IV_SIZE, &ct_len);
    result->ciphertext_len = ct_len + KMS_AES_GCM_IV_SIZE;
    memcpy(result->plaintext, plaintext, plaintext_len);
    result->plaintext_len = plaintext_len;
    return 0;
}

int kms_decrypt(const kms_key_t *key,
                const unsigned char *ciphertext, size_t ciphertext_len,
                kms_decrypt_result_t *result) {
    if (!key || !ciphertext || !result) return -1;
    if (key->state != KMS_KEY_STATE_ENABLED) return -3;
    if (ciphertext_len < KMS_AES_GCM_IV_SIZE + KMS_AES_GCM_TAG_SIZE) return -4;

    return sim_aes_gcm_decrypt(key->key_material,
                                ciphertext,
                                ciphertext + KMS_AES_GCM_IV_SIZE,
                                ciphertext_len - KMS_AES_GCM_IV_SIZE,
                                result->plaintext, &result->plaintext_len);
}

int kms_generate_data_key(const kms_key_t *key,
                           kms_data_key_t *data_key, int key_size_bits) {
    if (!key || !data_key) return -1;
    if (key->state != KMS_KEY_STATE_ENABLED) return -3;
    if (key_size_bits <= 0) key_size_bits = 256;
    int key_size_bytes = key_size_bits / 8;
    if (key_size_bytes > KMS_DATA_KEY_MAX) key_size_bytes = KMS_DATA_KEY_MAX;

    unsigned char plain_key[KMS_DATA_KEY_MAX];
    generate_random(plain_key, key_size_bytes);
    data_key->plaintext_len = key_size_bytes;
    memcpy(data_key->plaintext_key, plain_key, key_size_bytes);
    strncpy(data_key->key_id, key->key_id, KMS_KEY_ID_LEN - 1);

    kms_encrypt_result_t enc_result;
    kms_encrypt(key, plain_key, key_size_bytes, &enc_result);
    data_key->encrypted_len = enc_result.ciphertext_len;
    memcpy(data_key->encrypted_key, enc_result.ciphertext_blob, enc_result.ciphertext_len);
    return 0;
}

int kms_encrypt_with_data_key(const kms_data_key_t *dk,
                               const unsigned char *plaintext,
                               size_t plaintext_len,
                               unsigned char *ciphertext,
                               size_t *ciphertext_len) {
    if (!dk || !plaintext || !ciphertext || !ciphertext_len) return -1;
    unsigned char iv[KMS_AES_GCM_IV_SIZE];
    generate_random(iv, KMS_AES_GCM_IV_SIZE);
    memcpy(ciphertext, iv, KMS_AES_GCM_IV_SIZE);
    sim_aes_gcm_encrypt(dk->plaintext_key, iv, plaintext, plaintext_len,
                         ciphertext + KMS_AES_GCM_IV_SIZE, ciphertext_len);
    *ciphertext_len += KMS_AES_GCM_IV_SIZE;
    return 0;
}

int kms_decrypt_with_data_key(const kms_data_key_t *dk,
                               const unsigned char *ciphertext,
                               size_t ciphertext_len,
                               unsigned char *plaintext,
                               size_t *plaintext_len) {
    if (!dk || !ciphertext || !plaintext || !plaintext_len) return -1;
    if (ciphertext_len < KMS_AES_GCM_IV_SIZE + KMS_AES_GCM_TAG_SIZE) return -2;
    return sim_aes_gcm_decrypt(dk->plaintext_key,
                                ciphertext,
                                ciphertext + KMS_AES_GCM_IV_SIZE,
                                ciphertext_len - KMS_AES_GCM_IV_SIZE,
                                plaintext, plaintext_len);
}

int kms_envelope_encrypt(const kms_key_t *cmk,
                          const unsigned char *plaintext,
                          size_t plaintext_len,
                          kms_data_key_t *out_data_key,
                          unsigned char *out_ciphertext,
                          size_t *out_ciphertext_len) {
    if (!cmk || !plaintext || !out_data_key || !out_ciphertext || !out_ciphertext_len)
        return -1;
    if (kms_generate_data_key(cmk, out_data_key, 256) != 0) return -2;
    if (kms_encrypt_with_data_key(out_data_key, plaintext, plaintext_len,
                                   out_ciphertext, out_ciphertext_len) != 0) return -3;
    return 0;
}

int kms_envelope_decrypt(const kms_key_t *cmk, const kms_data_key_t *dk,
                          const unsigned char *ciphertext, size_t ciphertext_len,
                          unsigned char *plaintext, size_t *plaintext_len) {
    if (!cmk || !dk || !ciphertext || !plaintext || !plaintext_len) return -1;
    kms_decrypt_result_t dec_result;
    if (kms_decrypt(cmk, dk->encrypted_key, dk->encrypted_len, &dec_result) != 0)
        return -2;
    kms_data_key_t recovered_dk;
    memcpy(&recovered_dk, dk, sizeof(kms_data_key_t));
    memcpy(recovered_dk.plaintext_key, dec_result.plaintext, dec_result.plaintext_len);
    recovered_dk.plaintext_len = dec_result.plaintext_len;
    return kms_decrypt_with_data_key(&recovered_dk, ciphertext, ciphertext_len,
                                      plaintext, plaintext_len);
}

kms_grant_t* kms_create_grant(const kms_key_t *key,
                               const char *grantee_principal,
                               uint32_t operations,
                               const char *retiring_principal) {
    if (g_kms_state.grant_count >= KMS_MAX_GRANTS) return NULL;
    kms_grant_t *g = &g_kms_state.grants[g_kms_state.grant_count++];
    memset(g, 0, sizeof(kms_grant_t));
    snprintf(g->grant_id, KMS_KEY_ID_LEN, "grant-%04d", g_next_grant_id++);
    if (grantee_principal) {
        strncpy(g->grantee_principal, grantee_principal, KMS_KEY_ARN_LEN - 1);
    }
    if (key) { strncpy(g->key_id, key->key_id, KMS_KEY_ID_LEN - 1); }
    g->operations = operations;
    if (retiring_principal) {
        strncpy(g->retiring_principal, retiring_principal, KMS_KEY_ARN_LEN - 1);
    }
    g->creation_date = time(NULL);
    return g;
}

int kms_retire_grant(kms_grant_t *grant) {
    if (!grant) return -1;
    memset(grant, 0, sizeof(kms_grant_t));
    return 0;
}

int kms_revoke_grant(const kms_key_t *key, const char *grant_id) {
    if (!key || !grant_id) return -1;
    for (int i = 0; i < g_kms_state.grant_count; i++) {
        if (strcmp(g_kms_state.grants[i].grant_id, grant_id) == 0) {
            memset(&g_kms_state.grants[i], 0, sizeof(kms_grant_t));
            return 0;
        }
    }
    return -2;
}

int kms_add_replica_region(kms_key_t *key, const char *region) {
    if (!key || !region || key->replica_count >= KMS_MAX_REGIONS) return -1;
    strncpy(key->replica_regions[key->replica_count], region, 31);
    key->replica_count++;
    return 0;
}

int kms_remove_replica_region(kms_key_t *key, const char *region) {
    if (!key || !region) return -1;
    for (int i = 0; i < key->replica_count; i++) {
        if (strcmp(key->replica_regions[i], region) == 0) {
            memmove(&key->replica_regions[i], &key->replica_regions[i + 1],
                    (key->replica_count - i - 1) * 32);
            key->replica_count--;
            return 0;
        }
    }
    return -2;
}

const char* kms_key_state_name(kms_key_state_t state) {
    switch (state) {
        case KMS_KEY_STATE_ENABLED:          return "Enabled";
        case KMS_KEY_STATE_DISABLED:         return "Disabled";
        case KMS_KEY_STATE_PENDING_DELETION: return "PendingDeletion";
        case KMS_KEY_STATE_PENDING_IMPORT:   return "PendingImport";
        case KMS_KEY_STATE_UNAVAILABLE:      return "Unavailable";
        default: return "Unknown";
    }
}

const char* kms_key_spec_name(kms_key_spec_t spec) {
    switch (spec) {
        case KMS_KEY_SPEC_SYMMETRIC_DEFAULT: return "SYMMETRIC_DEFAULT";
        case KMS_KEY_SPEC_RSA_2048:          return "RSA_2048";
        case KMS_KEY_SPEC_RSA_3072:          return "RSA_3072";
        case KMS_KEY_SPEC_RSA_4096:          return "RSA_4096";
        case KMS_KEY_SPEC_ECC_NIST_P256:     return "ECC_NIST_P256";
        case KMS_KEY_SPEC_ECC_NIST_P384:     return "ECC_NIST_P384";
        case KMS_KEY_SPEC_ECC_NIST_P521:     return "ECC_NIST_P521";
        case KMS_KEY_SPEC_HMAC_256:          return "HMAC_256";
        default: return "UNKNOWN";
    }
}
