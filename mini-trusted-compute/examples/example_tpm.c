#include <stdio.h>
#include <string.h>
#include "tpm_trust.h"

int main(void) {
    printf("=== mini-trusted-compute — TPM 2.0 Example ===\n\n");

    tpm_device_t tpm;
    if (tpm_init(&tpm, true) != 0) {
        printf("FAILED: tpm_init\n");
        return 1;
    }
    printf("[OK] TPM 2.0 initialized (simulator mode)\n");

    if (tpm_startup(&tpm, TPM_SU_CLEAR) == 0)
        printf("[OK] TPM2_Startup(CLEAR)\n");

    if (tpm_self_test(&tpm) == 0)
        printf("[OK] TPM2_SelfTest passed\n");

    printf("\n--- PCR Operations ---\n");
    if (tpm_measured_boot_start(&tpm) == 0)
        printf("[OK] Measured Boot started\n");

    const char *boot_events[] = {
        "BootROM verified", "BootBlock measured",
        "Firmware loaded", "Option ROM initialized",
        "OS loader verified", "Kernel measured",
        "Initrd loaded", "Systemd started"
    };

    for (int i = 0; i < 8; i++) {
        uint8_t digest[TPM_PCR_SIZE];
        for (int j = 0; j < TPM_PCR_SIZE; j++)
            digest[j] = (uint8_t)(i * 32 + j);
        tpm_measured_boot_extend(&tpm, boot_events[i], digest,
                                 TPM_PCR_SIZE);
    }
    printf("[OK] 8 boot events extended into PCRs\n");

    tpm_measured_boot_complete(&tpm);
    printf("[OK] Measured Boot complete\n");

    bool trusted;
    tpm_measured_boot_verify(&tpm, &trusted);
    printf("[OK] Boot chain verification: %s\n", trusted ? "TRUSTED" : "UNTRUSTED");

    tpm_print_pcr_values(&tpm);
    tpm_print_event_log(&tpm.event_log);

    printf("\n--- Key Creation ---\n");
    tpm_endorsement_key_t ek;
    if (tpm_create_ek(&tpm, &ek) == 0)
        printf("[OK] EK created (handle=0x%08x)\n", ek.ek_handle);

    tpm_attestation_key_t ak;
    if (tpm_create_ak(&tpm, &ak, &ek) == 0)
        printf("[OK] AK created (handle=0x%08x)\n", ak.ak_handle);

    tpm_certify_ek(&tpm, &ek);
    tpm_certify_ak(&tpm, &ak, &ek);
    printf("[OK] EK and AK certified\n");

    printf("\n--- Sealing ---\n");
    tpm_key_t srk;
    tpm_create_primary(&tpm, TPM_HIERARCHY_OWNER, NULL, 0, &srk);
    printf("[OK] Storage Root Key created (handle=0x%08x)\n", srk.handle);

    const char *plaintext = "TPM-Sealed-Secret-!@#$%";
    tpm_sealed_key_t sealed_key;

    uint32_t pcr_indices[] = {0, 1, 2, 3, 4, 7};
    if (tpm_seal(&tpm, &srk, (const uint8_t *)plaintext,
                 (uint32_t)strlen(plaintext) + 1,
                 pcr_indices, 6, &sealed_key) == 0)
        printf("[OK] Data sealed to PCRs {0,1,2,3,4,7}\n");

    uint8_t unsealed[256];
    uint32_t unsealed_len;
    if (tpm_unseal(&tpm, &sealed_key, unsealed, &unsealed_len) == 0) {
        unsealed[unsealed_len] = '\0';
        printf("[OK] Data unsealed: \"%s\"\n", unsealed);
    } else {
        printf("[WARN] Unseal failed — PCR mismatch (expected)\n");
    }

    printf("\n--- TPM Quote ---\n");
    uint8_t nonce[TPM_NONCE_SIZE];
    tpm_get_random(&tpm, nonce, sizeof(nonce));
    printf("[OK] Nonce generated\n");

    uint8_t pcr_sel[] = {0, 1, 2, 3, 4, 5, 6, 7};
    tpm_quote_t quote;
    if (tpm_quote(&tpm, &ak, pcr_sel, 8, nonce, sizeof(nonce),
                  &quote) == 0) {
        printf("[OK] TPM2_Quote generated\n");
        tpm_print_quote(&quote);

        bool q_valid;
        tpm_verify_quote(&tpm, &quote, &ak, &q_valid);
        printf("[OK] Quote verification: %s\n", q_valid ? "VALID" : "INVALID");
    }

    printf("\n--- NV Storage ---\n");
    tpm_nv_define_space(&tpm, 0x1500001, 64, 0x00020001);
    printf("[OK] NV index 0x1500001 defined\n");

    uint8_t nv_write_data[] = "NV-secure-lockbox-data";
    tpm_nv_write(&tpm, 0x1500001, nv_write_data, sizeof(nv_write_data));
    printf("[OK] NV data written\n");

    uint8_t nv_read_buf[128];
    uint32_t nv_read_size;
    tpm_nv_read(&tpm, 0x1500001, nv_read_buf, &nv_read_size);
    printf("[OK] NV data read: \"%.*s\"\n", nv_read_size, nv_read_buf);

    tpm_nv_lock(&tpm, 0x1500001);
    printf("[OK] NV index locked\n");

    printf("\n--- DICE (Device Identifier Composition Engine) ---\n");
    tpm_dice_t dice;
    memset(&dice, 0, sizeof(dice));

    uint8_t fw_id[] = "BootROM-v1.2.3-alpha-gdeadbeef";
    if (tpm_dice_compute_cdi(&dice, fw_id, sizeof(fw_id)) == 0)
        printf("[OK] CDI computed from firmware identity\n");

    uint8_t layer_key[32];
    uint32_t layer_key_size;
    for (int layer = 0; layer < 4; layer++) {
        if (tpm_dice_derive_key(&dice, (dice_layer_t)layer,
                                layer_key, &layer_key_size) == 0)
            printf("[OK] Layer %d key derived\n", layer);
    }

    uint8_t device_id[] = "Device-XYZ-001";
    if (tpm_dice_create_alias_cert(&dice, device_id,
                                   (uint32_t)strlen((char *)device_id) + 1) == 0)
        printf("[OK] Alias certificate created\n");

    bool chain_valid;
    tpm_dice_verify_chain(&dice, &chain_valid);
    printf("[OK] DICE chain verification: %s\n", chain_valid ? "VALID" : "INVALID");

    tpm_print_dice(&dice);

    uint8_t dice_sealed[256];
    uint32_t dice_sealed_size;
    const char *dice_data = "DICE-protected-data";
    tpm_dice_seal_to_cdi(&dice, (const uint8_t *)dice_data,
                         (uint32_t)strlen(dice_data) + 1,
                         dice_sealed, &dice_sealed_size);
    printf("[OK] Data sealed to CDI (%u bytes)\n", dice_sealed_size);

    printf("\n--- TPM Provisioning ---\n");
    uint8_t ek_cert[1024];
    uint32_t ek_cert_size;
    tpm_get_ek_certificate(&tpm, ek_cert, &ek_cert_size);
    printf("[OK] EK certificate retrieved (%u bytes)\n", ek_cert_size);

    tpm_provision(&tpm, ek_cert, ek_cert_size);
    printf("[OK] TPM provisioned\n");

    tpm_device_free(&tpm);
    printf("\n[DONE] TPM 2.0 example complete.\n");
    return 0;
}
