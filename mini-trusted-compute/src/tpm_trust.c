#include "tpm_trust.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

static void tpm_rand_bytes(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++)
        buf[i] = (uint8_t)((i * 9973 + (time(NULL) & 0xFF)) & 0xFF);
}

static void tpm_hash256(const uint8_t *data, size_t len, uint8_t digest[TPM_HASH_SIZE]) {
    (void)data;
    for (int i = 0; i < 32; i++)
        digest[i] = (uint8_t)((i * len + 0xB7) & 0xFF);
}

static void tpm_pcr_extend_digest(uint8_t pcr[TPM_PCR_SIZE],
                                  const uint8_t *digest, uint32_t size) {
    uint8_t concat[TPM_PCR_SIZE * 2];
    memcpy(concat, pcr, TPM_PCR_SIZE);
    memcpy(concat + TPM_PCR_SIZE, digest, size < TPM_PCR_SIZE ? size : TPM_PCR_SIZE);
    tpm_hash256(concat, TPM_PCR_SIZE * 2, pcr);
}

int tpm_init(tpm_device_t *tpm, bool simulator) {
    if (!tpm) return -1;
    memset(tpm, 0, sizeof(*tpm));
    tpm->is_simulator = simulator;
    tpm->initialized = true;
    tpm->ownership_taken = false;
    tpm->ek_generated = false;
    tpm->ak_generated = false;
    tpm->active_locality = TPM_LOC_ZERO;
    tpm->restart_counter = 0;

    tpm->bank_count = 1;
    for (uint32_t i = 0; i < TPM_PCR_COUNT; i++) {
        memset(tpm->pcr_banks[0].pcr_values[i], 0, TPM_PCR_SIZE);
        tpm->pcr_banks[0].pcr_initialized[i] = false;
        tpm->pcr_banks[0].pcr_reset[i] = false;
        tpm->pcr_banks[0].locality[i] = TPM_LOC_ZERO;
    }
    tpm->pcr_banks[0].pcr_count = TPM_PCR_COUNT;
    tpm->pcr_banks[0].hash_alg = TPM_ALG_SHA256;
    tpm->pcr_banks[0].hash_size = TPM_PCR_SIZE;

    return 0;
}

int tpm_startup(tpm_device_t *tpm, tpm_startup_t type) {
    if (!tpm || !tpm->initialized) return -1;

    if (type == TPM_SU_CLEAR) {
        for (uint32_t b = 0; b < tpm->bank_count; b++) {
            for (uint32_t i = 0; i < tpm->pcr_banks[b].pcr_count; i++)
                tpm->pcr_banks[b].pcr_reset[i] = false;
        }
    }
    tpm->restart_counter++;
    return 0;
}

int tpm_self_test(tpm_device_t *tpm) {
    if (!tpm) return -1;
    return 0;
}

int tpm_get_random(tpm_device_t *tpm, uint8_t *data, size_t size) {
    if (!tpm || !data) return -1;
    tpm_rand_bytes(data, size);
    return 0;
}

int tpm_get_capability(tpm_device_t *tpm, uint32_t capability,
                       uint32_t property, uint32_t property_count,
                       uint8_t *data, size_t *data_size) {
    (void)capability; (void)property;
    if (!tpm || !data || !data_size) return -1;
    *data_size = property_count * 4;
    memset(data, 0, *data_size);
    return 0;
}

int tpm_pcr_extend(tpm_device_t *tpm, uint32_t pcr_index,
                   const uint8_t *digest, uint32_t digest_size) {
    if (!tpm || !digest) return -1;
    if (pcr_index >= TPM_PCR_COUNT) return -1;

    for (uint32_t b = 0; b < tpm->bank_count; b++) {
        if (!tpm->pcr_banks[b].pcr_initialized[pcr_index])
            tpm->pcr_banks[b].pcr_initialized[pcr_index] = true;

        tpm_pcr_extend_digest(tpm->pcr_banks[b].pcr_values[pcr_index],
                              digest, digest_size);

        tpm->pcr_banks[b].pcr_reset[pcr_index] = false;
    }

    tpm_event_log_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.pcr_index = pcr_index;
    memcpy(entry.digest, digest, digest_size < TPM_PCR_SIZE ? digest_size : TPM_PCR_SIZE);
    snprintf(entry.event, sizeof(entry.event), "PCR[%u] extended", pcr_index);
    entry.extended = true;

    if (tpm->event_log.entry_count < TPM_MAX_EVENT_LOG_ENTRIES)
        memcpy(&tpm->event_log.entries[tpm->event_log.entry_count++],
               &entry, sizeof(entry));

    return 0;
}

int tpm_pcr_read(tpm_device_t *tpm, uint32_t pcr_index,
                 uint8_t *digest, uint32_t *digest_size) {
    if (!tpm || !digest || !digest_size) return -1;
    if (pcr_index >= TPM_PCR_COUNT) return -1;

    *digest_size = TPM_PCR_SIZE;
    memcpy(digest, tpm->pcr_banks[0].pcr_values[pcr_index], TPM_PCR_SIZE);
    return 0;
}

int tpm_pcr_reset(tpm_device_t *tpm, uint32_t pcr_index) {
    if (!tpm) return -1;
    if (pcr_index >= TPM_PCR_COUNT) return -1;
    if (tpm->pcr_banks[0].locality[pcr_index] < 3) return -1;

    for (uint32_t b = 0; b < tpm->bank_count; b++) {
        memset(tpm->pcr_banks[b].pcr_values[pcr_index], 0, TPM_PCR_SIZE);
        tpm->pcr_banks[b].pcr_reset[pcr_index] = true;
    }
    return 0;
}

int tpm_pcr_set_auth_policy(tpm_device_t *tpm, uint32_t pcr_index,
                            uint8_t *policy, uint32_t policy_size) {
    (void)tpm; (void)pcr_index; (void)policy; (void)policy_size;
    return 0;
}

int tpm_pcr_set_auth_value(tpm_device_t *tpm, uint32_t pcr_index,
                           const uint8_t *auth_value, uint32_t auth_size) {
    (void)tpm; (void)pcr_index; (void)auth_value; (void)auth_size;
    return 0;
}

int tpm_create_primary(tpm_device_t *tpm, tpm_hierarchy_t hierarchy,
                       const uint8_t *auth_value, uint32_t auth_size,
                       tpm_key_t *primary_key) {
    if (!tpm || !primary_key) return -1;
    if (tpm->primary_key_count >= 8) return -1;

    memset(primary_key, 0, sizeof(*primary_key));
    primary_key->handle = TPM_HANDLE_OWNER + tpm->primary_key_count;
    primary_key->key_type = TPM_OBJECT_RSA;
    primary_key->key_alg = TPM_ALG_RSA;
    primary_key->is_primary = true;
    primary_key->is_restricted = true;
    primary_key->parent_handle = (uint32_t)hierarchy;

    tpm_rand_bytes(primary_key->public_key, 256);
    primary_key->public_key_size = 256;
    tpm_rand_bytes(primary_key->private_key, 128);
    primary_key->private_key_size = 128;
    tpm_hash256(primary_key->public_key, 256, primary_key->name);

    memcpy(&tpm->primary_keys[tpm->primary_key_count++],
           primary_key, sizeof(tpm_key_t));

    (void)auth_value; (void)auth_size;
    return 0;
}

int tpm_create_key(tpm_device_t *tpm, tpm_key_t *parent_key,
                   const uint8_t *auth_value, uint32_t auth_size,
                   tpm_object_type_t type, tpm_key_t *new_key) {
    if (!tpm || !new_key) return -1;

    memset(new_key, 0, sizeof(*new_key));
    new_key->handle = 0x81000000 + (tpm->primary_key_count * 16);
    new_key->key_type = type;
    new_key->is_primary = false;
    new_key->is_restricted = false;
    if (parent_key)
        new_key->parent_handle = parent_key->handle;

    tpm_rand_bytes(new_key->public_key, 64);
    new_key->public_key_size = 64;
    tpm_rand_bytes(new_key->private_key, 32);
    new_key->private_key_size = 32;
    tpm_hash256(new_key->public_key, 64, new_key->name);

    (void)auth_value; (void)auth_size;
    return 0;
}

int tpm_load_key(tpm_device_t *tpm, tpm_key_t *parent_key,
                 const tpm_private_key_t *private_key,
                 tpm_key_t *loaded_key) {
    (void)private_key;
    if (!tpm || !loaded_key) return -1;
    memset(loaded_key, 0, sizeof(*loaded_key));
    loaded_key->handle = 0x80000000;
    loaded_key->is_primary = false;
    if (parent_key)
        loaded_key->parent_handle = parent_key->handle;
    return 0;
}

int tpm_sign(tpm_device_t *tpm, tpm_key_t *key,
             const uint8_t *digest, uint32_t digest_size,
             uint8_t *signature, uint32_t *sig_size) {
    if (!tpm || !key || !digest || !signature || !sig_size) return -1;
    *sig_size = 256;
    for (uint32_t i = 0; i < *sig_size; i++)
        signature[i] = (uint8_t)(digest[i % digest_size] ^ key->name[i % TPM_HASH_SIZE]);
    return 0;
}

int tpm_verify_signature(tpm_device_t *tpm, tpm_key_t *key,
                         const uint8_t *digest, uint32_t digest_size,
                         const uint8_t *signature, uint32_t sig_size,
                         bool *valid) {
    (void)digest_size;
    if (!tpm || !key || !digest || !signature || !valid) return -1;
    *valid = (sig_size >= 64);
    return 0;
}

int tpm_create_ek(tpm_device_t *tpm, tpm_endorsement_key_t *ek) {
    if (!tpm || !ek) return -1;
    memset(ek, 0, sizeof(*ek));
    ek->ek_handle = 0x81010001;
    tpm_rand_bytes(ek->ek_public_key, 256);
    ek->ek_public_key_size = 256;
    tpm_rand_bytes(ek->ek_certificate, 1024);
    ek->ek_cert_size = 1024;
    ek->ek_certified = false;
    tpm_hash256(ek->ek_public_key, 256, ek->ek_name);

    memcpy(&tpm->ek, ek, sizeof(*ek));
    tpm->ek_generated = true;
    return 0;
}

int tpm_create_ak(tpm_device_t *tpm, tpm_attestation_key_t *ak,
                  const tpm_endorsement_key_t *ek) {
    if (!tpm || !ak) return -1;
    memset(ak, 0, sizeof(*ak));
    ak->ak_handle = 0x81010002;
    tpm_rand_bytes(ak->ak_public_key, 256);
    ak->ak_public_key_size = 256;
    ak->ak_certified = false;
    ak->restricted_signing = true;
    ak->fixed_tpm = true;
    ak->fixed_qualifier = true;

    if (ek) ak->ek_handle = ek->ek_handle;

    tpm_hash256(ak->ak_public_key, 256, ak->ak_name);
    memcpy(&tpm->ak, ak, sizeof(*ak));
    tpm->ak_generated = true;
    return 0;
}

int tpm_certify_ek(tpm_device_t *tpm, tpm_endorsement_key_t *ek) {
    if (!tpm || !ek) return -1;
    ek->ek_certified = true;
    tpm->ek.ek_certified = true;
    return 0;
}

int tpm_certify_ak(tpm_device_t *tpm, tpm_attestation_key_t *ak,
                   const tpm_endorsement_key_t *ek) {
    if (!tpm || !ak) return -1;
    ak->ak_certified = true;
    tpm->ak.ak_certified = true;
    (void)ek;
    return 0;
}

int tpm_quote(tpm_device_t *tpm, tpm_attestation_key_t *ak,
              const uint8_t *pcr_selection, uint32_t pcr_count,
              const uint8_t *nonce, uint32_t nonce_size,
              tpm_quote_t *quote) {
    if (!tpm || !ak || !quote) return -1;

    memset(quote, 0, sizeof(*quote));
    quote->sign_handle = ak->ak_handle;
    quote->signed_by_ak = true;
    quote->pcr_mask = 0;

    memset(&quote->attest_struct, 0, sizeof(quote->attest_struct));
    memcpy(quote->attest_struct.magic, "QUOT", 4);

    uint32_t count = pcr_count < TPM_PCR_COUNT ? pcr_count : TPM_PCR_COUNT;
    quote->attest_struct.selected_count = count;

    for (uint32_t i = 0; i < count; i++) {
        uint32_t pcr_idx = pcr_selection ? pcr_selection[i] : i;
        quote->pcr_mask |= (1U << (pcr_idx < 24 ? pcr_idx : 0));
        if (pcr_idx < TPM_PCR_COUNT)
            memcpy(quote->attest_struct.selected_pcrs[i],
                   tpm->pcr_banks[0].pcr_values[pcr_idx], TPM_PCR_SIZE);
    }

    if (nonce && nonce_size > 0)
        memcpy(quote->attest_struct.extra_data, nonce,
               nonce_size < TPM_NONCE_SIZE ? nonce_size : TPM_NONCE_SIZE);

    tpm_hash256((const uint8_t *)&quote->attest_struct,
                sizeof(quote->attest_struct),
                quote->attest_struct.pcr_digest);

    quote->quote_size = sizeof(quote->attest_struct);
    memmove(quote->quote_blob, &quote->attest_struct, quote->quote_size);

    tpm_rand_bytes(quote->signature, 256);
    quote->sig_size = 256;
    quote->valid = true;
    return 0;
}

int tpm_verify_quote(tpm_device_t *tpm, const tpm_quote_t *quote,
                     const tpm_attestation_key_t *ak, bool *valid) {
    (void)ak;
    if (!tpm || !quote || !valid) return -1;
    *valid = quote->valid && quote->signed_by_ak;
    return 0;
}

int tpm_attest(tpm_device_t *tpm, tpm_key_t *key,
               const uint8_t *attested_data, uint32_t data_size,
               tpm_sign_attest_t attest_type,
               tpm_attest_t *attestation) {
    (void)key; (void)attest_type;
    if (!tpm || !attestation) return -1;
    memset(attestation, 0, sizeof(*attestation));
    memcpy(attestation->magic, "ATST", 4);
    attestation->pcr_count = 0;

    if (attested_data && data_size > 0)
        memcpy(attestation->qualified_signer, attested_data,
               data_size < (uint32_t)sizeof(attestation->qualified_signer)
               ? data_size : sizeof(attestation->qualified_signer));

    return 0;
}

int tpm_seal(tpm_device_t *tpm, tpm_key_t *parent_key,
             const uint8_t *data, uint32_t data_size,
             const uint32_t *pcr_indices, uint32_t pcr_count,
             tpm_sealed_key_t *sealed_key) {
    if (!tpm || !data || !sealed_key) return -1;

    memset(sealed_key, 0, sizeof(*sealed_key));
    sealed_key->sealed_size = data_size < TPM_SEALED_DATA_MAX_SIZE
                              ? data_size : TPM_SEALED_DATA_MAX_SIZE;

    for (uint32_t i = 0; i < sealed_key->sealed_size; i++)
        sealed_key->sealed_data[i] = data[i] ^ 0xAA;

    sealed_key->selected_count = pcr_count < TPM_PCR_COUNT
                                 ? pcr_count : TPM_PCR_COUNT;
    sealed_key->pcr_mask = 0;
    for (uint32_t i = 0; i < sealed_key->selected_count; i++) {
        uint32_t idx = pcr_indices ? pcr_indices[i] : i;
        sealed_key->selected_pcr_indices[i] = idx < TPM_PCR_COUNT ? idx : 0;
        sealed_key->pcr_mask |= (1U << sealed_key->selected_pcr_indices[i]);
        if (idx < TPM_PCR_COUNT)
            memcpy(sealed_key->pcr_values[idx],
                   tpm->pcr_banks[0].pcr_values[idx], TPM_PCR_SIZE);
    }

    if (parent_key)
        sealed_key->parent_handle = parent_key->handle;
    sealed_key->require_auth = false;
    sealed_key->sealed = true;
    sealed_key->unsealed = false;
    return 0;
}

int tpm_unseal(tpm_device_t *tpm, tpm_sealed_key_t *sealed_key,
               uint8_t *data, uint32_t *data_size) {
    if (!tpm || !sealed_key || !data || !data_size) return -1;
    if (!sealed_key->sealed) return -1;

    for (uint32_t i = 0; i < sealed_key->selected_count; i++) {
        uint32_t idx = sealed_key->selected_pcr_indices[i];
        if (idx >= TPM_PCR_COUNT) continue;
        if (memcmp(sealed_key->pcr_values[idx],
                   tpm->pcr_banks[0].pcr_values[idx], TPM_PCR_SIZE) != 0)
            return -1;
    }

    *data_size = sealed_key->sealed_size;
    for (uint32_t i = 0; i < sealed_key->sealed_size; i++)
        data[i] = sealed_key->sealed_data[i] ^ 0xAA;

    sealed_key->unsealed = true;
    return 0;
}

int tpm_seal_policy(tpm_device_t *tpm, tpm_key_t *parent_key,
                    const uint8_t *data, uint32_t data_size,
                    const uint8_t *policy, uint32_t policy_size,
                    tpm_sealed_key_t *sealed_key) {
    (void)policy; (void)policy_size;
    return tpm_seal(tpm, parent_key, data, data_size, NULL, 0, sealed_key);
}

int tpm_nv_define_space(tpm_device_t *tpm, uint32_t index,
                        uint32_t size, uint32_t attributes) {
    if (!tpm) return -1;
    if (tpm->nv_storage_count >= 16) return -1;

    tpm_nv_storage_t *nv = &tpm->nv_storage[tpm->nv_storage_count++];
    memset(nv, 0, sizeof(*nv));
    nv->nv_index = index;
    nv->nv_size = size;
    nv->nv_attributes = attributes;
    nv->nv_data_size_max = (uint16_t)size;
    nv->locked = false;
    return 0;
}

int tpm_nv_write(tpm_device_t *tpm, uint32_t index,
                 const uint8_t *data, uint32_t data_size) {
    if (!tpm || !data) return -1;
    for (uint32_t i = 0; i < tpm->nv_storage_count; i++) {
        if (tpm->nv_storage[i].nv_index == index) {
            if (tpm->nv_storage[i].locked) return -1;
            memcpy(tpm->nv_storage[i].nv_data, data,
                   data_size < tpm->nv_storage[i].nv_size
                   ? data_size : tpm->nv_storage[i].nv_size);
            tpm->nv_storage[i].written = true;
            return 0;
        }
    }
    return -1;
}

int tpm_nv_read(tpm_device_t *tpm, uint32_t index,
                uint8_t *data, uint32_t *data_size) {
    if (!tpm || !data || !data_size) return -1;
    for (uint32_t i = 0; i < tpm->nv_storage_count; i++) {
        if (tpm->nv_storage[i].nv_index == index) {
            if (!tpm->nv_storage[i].written) return -1;
            *data_size = tpm->nv_storage[i].nv_size;
            memcpy(data, tpm->nv_storage[i].nv_data, *data_size);
            return 0;
        }
    }
    return -1;
}

int tpm_nv_lock(tpm_device_t *tpm, uint32_t index) {
    if (!tpm) return -1;
    for (uint32_t i = 0; i < tpm->nv_storage_count; i++) {
        if (tpm->nv_storage[i].nv_index == index) {
            tpm->nv_storage[i].locked = true;
            return 0;
        }
    }
    return -1;
}

int tpm_nv_undefine_space(tpm_device_t *tpm, uint32_t index) {
    if (!tpm) return -1;
    for (uint32_t i = 0; i < tpm->nv_storage_count; i++) {
        if (tpm->nv_storage[i].nv_index == index) {
            memset(&tpm->nv_storage[i], 0, sizeof(tpm_nv_storage_t));
            return 0;
        }
    }
    return -1;
}

int tpm_measured_boot_start(tpm_device_t *tpm) {
    if (!tpm) return -1;
    memset(&tpm->event_log, 0, sizeof(tpm->event_log));
    tpm->event_log.measured_boot_complete = false;
    tpm->event_log.boot_counter++;
    return 0;
}

int tpm_measured_boot_extend(tpm_device_t *tpm, const char *event,
                             const uint8_t *digest, uint32_t digest_size) {
    if (!tpm || !event || !digest) return -1;

    if (tpm->event_log.entry_count < TPM_MAX_EVENT_LOG_ENTRIES) {
        tpm_event_log_entry_t *entry =
            &tpm->event_log.entries[tpm->event_log.entry_count++];
        entry->pcr_index = tpm->event_log.entry_count % TPM_PCR_COUNT;
        memcpy(entry->digest, digest,
               digest_size < TPM_PCR_SIZE ? digest_size : TPM_PCR_SIZE);
        snprintf(entry->event, sizeof(entry->event), "%s", event);
        entry->extended = true;
        entry->event_type = 0x00000001;
    }

    return tpm_pcr_extend(tpm, tpm->event_log.entry_count % TPM_PCR_COUNT,
                          digest, digest_size);
}

int tpm_measured_boot_complete(tpm_device_t *tpm) {
    if (!tpm) return -1;
    tpm->event_log.measured_boot_complete = true;
    return 0;
}

int tpm_measured_boot_verify(tpm_device_t *tpm, bool *trusted) {
    if (!tpm || !trusted) return -1;
    *trusted = tpm->event_log.measured_boot_complete &&
               tpm->event_log.entry_count > 0;
    return 0;
}

int tpm_dice_compute_cdi(tpm_dice_t *dice, const uint8_t *firmware_id,
                         uint32_t fw_id_size) {
    if (!dice || !firmware_id) return -1;

    uint8_t concat[DICE_LAYER_MAX * TPM_DICE_CDI_SIZE];
    memset(concat, 0, sizeof(concat));
    memcpy(concat, firmware_id, fw_id_size < TPM_DICE_CDI_SIZE ? fw_id_size : TPM_DICE_CDI_SIZE);

    tpm_hash256(concat, sizeof(concat), dice->cdi);
    memcpy(dice->fwid_digest, firmware_id,
           fw_id_size < TPM_DICE_CDI_SIZE ? fw_id_size : TPM_DICE_CDI_SIZE);
    dice->current_layer = DICE_LAYER_ROM;
    dice->security_version = 1;
    return 0;
}

int tpm_dice_derive_key(tpm_dice_t *dice, dice_layer_t layer,
                        uint8_t *key, uint32_t *key_size) {
    if (!dice || !key || !key_size) return -1;

    uint8_t material[TPM_DICE_CDI_SIZE + 8];
    memcpy(material, dice->cdi, TPM_DICE_CDI_SIZE);
    material[TPM_DICE_CDI_SIZE] = (uint8_t)layer;

    *key_size = 32;
    tpm_hash256(material, TPM_DICE_CDI_SIZE + 1, key);
    dice->current_layer = layer;
    return 0;
}

int tpm_dice_create_alias_cert(tpm_dice_t *dice,
                               const uint8_t *device_identity,
                               uint32_t identity_size) {
    if (!dice || !device_identity) return -1;

    uint8_t alias_pub[32];
    uint32_t key_size;
    tpm_dice_derive_key(dice, DICE_LAYER_APPLICATION, alias_pub, &key_size);

    memset(dice->alias_cert, 0, TPM_DICE_ALIAS_CERT_SIZE);
    memcpy(dice->alias_cert, alias_pub, 32);
    memcpy(dice->alias_cert + 32, device_identity,
           identity_size < 32 ? identity_size : 32);
    dice->alias_cert_size = 64;
    return 0;
}

int tpm_dice_verify_chain(tpm_dice_t *dice, bool *valid) {
    if (!dice || !valid) return -1;
    *valid = dice->device_id_cert_size > 0 && dice->alias_cert_size > 0;
    return 0;
}

int tpm_dice_seal_to_cdi(tpm_dice_t *dice, const uint8_t *data,
                         uint32_t data_size, uint8_t *sealed,
                         uint32_t *sealed_size) {
    if (!dice || !data || !sealed || !sealed_size) return -1;

    *sealed_size = data_size < 256 ? data_size : 256;
    for (uint32_t i = 0; i < *sealed_size; i++)
        sealed[i] = data[i] ^ dice->cdi[i % TPM_DICE_CDI_SIZE];
    return 0;
}

int tpm_get_event_log(tpm_device_t *tpm, tpm_event_log_t *log) {
    if (!tpm || !log) return -1;
    memcpy(log, &tpm->event_log, sizeof(*log));
    return 0;
}

int tpm_replay_event_log(tpm_device_t *tpm, const tpm_event_log_t *log,
                         bool *consistent) {
    if (!tpm || !log || !consistent) return -1;
    *consistent = (log->entry_count == tpm->event_log.entry_count);
    return 0;
}

int tpm_get_ek_certificate(tpm_device_t *tpm,
                           uint8_t *cert, uint32_t *cert_size) {
    if (!tpm || !cert || !cert_size) return -1;
    *cert_size = tpm->ek.ek_cert_size;
    memcpy(cert, tpm->ek.ek_certificate, tpm->ek.ek_cert_size);
    return 0;
}

int tpm_provision(tpm_device_t *tpm, const uint8_t *ek_cert,
                  uint32_t ek_cert_size) {
    if (!tpm) return -1;
    if (ek_cert && ek_cert_size > 0)
        memcpy(tpm->ek.ek_certificate, ek_cert, ek_cert_size);
    tpm->ek.ek_certified = true;
    return 0;
}

void tpm_print_pcr_values(const tpm_device_t *tpm) {
    if (!tpm) return;
    printf("TPM PCR Values (Bank 0, SHA-256):\n");
    for (uint32_t i = 0; i < 8; i++) {
        printf("  PCR[%2u]: ", i);
        for (int j = 0; j < 8; j++)
            printf("%02x", tpm->pcr_banks[0].pcr_values[i][j]);
        printf("...\n");
    }
}

void tpm_print_event_log(const tpm_event_log_t *log) {
    if (!log) return;
    printf("Measured Boot Event Log (%u entries):\n", log->entry_count);
    for (uint32_t i = 0; i < log->entry_count && i < 10; i++) {
        printf("  [%2u] PCR[%u] %s\n",
               i, log->entries[i].pcr_index, log->entries[i].event);
    }
    if (log->entry_count > 10)
        printf("  ... and %u more entries\n", log->entry_count - 10);
}

void tpm_print_attest(const tpm_attest_t *attest) {
    if (!attest) return;
    printf("TPM Attestation:\n");
    printf("  Magic:        %.4s\n", attest->magic);
    printf("  PCR Count:    %d\n", attest->pcr_count);
    printf("  PCR Digest:   ");
    for (int i = 0; i < 8; i++) printf("%02x", attest->pcr_digest[i]);
    printf("...\n");
}

void tpm_print_quote(const tpm_quote_t *quote) {
    if (!quote) return;
    printf("TPM Quote:\n");
    printf("  Sign Handle:  0x%08x\n", quote->sign_handle);
    printf("  Quote Size:   %u\n", quote->quote_size);
    printf("  Sig Size:     %u\n", quote->sig_size);
    printf("  Valid:        %s\n", quote->valid ? "YES" : "NO");
    printf("  PCR Mask:     0x%08x\n", quote->pcr_mask);
}

void tpm_print_dice(const tpm_dice_t *dice) {
    if (!dice) return;
    printf("DICE Chain:\n");
    printf("  CDI:          ");
    for (int i = 0; i < 8; i++) printf("%02x", dice->cdi[i]);
    printf("...\n");
    printf("  FWID Digest:  ");
    for (int i = 0; i < 8; i++) printf("%02x", dice->fwid_digest[i]);
    printf("...\n");
    printf("  Security Ver: %llu\n", (unsigned long long)dice->security_version);
    printf("  Layer:        %d\n", dice->current_layer);
}

void tpm_print_key_info(const tpm_key_t *key) {
    if (!key) return;
    printf("TPM Key: Handle=0x%08x Type=%u Alg=0x%04x Primary=%c\n",
           key->handle, key->key_type, key->key_alg,
           key->is_primary ? 'Y' : 'N');
}

void tpm_device_free(tpm_device_t *tpm) {
    if (!tpm) return;
    memset(tpm, 0, sizeof(*tpm));
}
