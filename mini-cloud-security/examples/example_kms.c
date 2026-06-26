#include "kms_key.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    printf("=== KMS Key Management Demo ===\n\n");

    kms_key_t *cmk = kms_create_key_with_policy(
        "ProductionApplicationKey",
        KMS_KEY_SPEC_SYMMETRIC_DEFAULT,
        KMS_KEY_USAGE_ENCRYPT_DECRYPT,
        KMS_KEY_MATERIAL_KMS,
        "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\","
        "\"Principal\":{\"AWS\":\"arn:aws:iam::123456789012:root\"},"
        "\"Action\":\"kms:*\",\"Resource\":\"*\"}]}"
    );
    printf("[1] Created CMK:\n");
    printf("    Key ID:    %s\n", cmk->key_id);
    printf("    ARN:       %s\n", cmk->arn);
    printf("    Spec:      %s\n", kms_key_spec_name(cmk->spec));
    printf("    State:     %s\n", kms_key_state_name(cmk->state));
    printf("    HSM:       %s\n", cmk->hsm_backed ? "yes" : "no");
    printf("    Multi-Reg: %s\n", cmk->multi_region ? "yes" : "no");

    kms_key_t *multi_key = kms_create_key("MultiRegionKey",
        KMS_KEY_SPEC_SYMMETRIC_DEFAULT, KMS_KEY_USAGE_ENCRYPT_DECRYPT,
        KMS_KEY_MATERIAL_KMS, 1, 0);
    printf("\n[2] Created Multi-Region Key: %s\n", multi_key->key_id);
    printf("    Replica regions: %d\n", multi_key->replica_count);

    kms_key_t *hsm_key = kms_create_key("HSMBackedKey",
        KMS_KEY_SPEC_RSA_2048, KMS_KEY_USAGE_SIGN_VERIFY,
        KMS_KEY_MATERIAL_KMS, 0, 1);
    printf("\n[3] Created HSM-backed Key: %s (spec=%s)\n",
           hsm_key->key_id, kms_key_spec_name(hsm_key->spec));

    printf("\n--- Key Rotation ---\n");
    kms_enable_rotation(cmk, 90);
    printf("Rotation enabled: every %d days\n", cmk->rotation_days);
    printf("Last rotation: %lld\n", (long long)cmk->last_rotation);
    kms_rotate_key_on_demand(cmk);
    printf("On-demand rotation complete.\n");

    printf("\n--- Envelope Encryption ---\n");
    const char *secret = "This is a highly sensitive database password: Sup3rS3cr3t!";
    unsigned char encrypted[2048];
    size_t encrypted_len;
    kms_data_key_t data_key;

    int rc = kms_envelope_encrypt(cmk, (const unsigned char *)secret,
                                   strlen(secret), &data_key, encrypted, &encrypted_len);
    printf("Envelope encrypt: rc=%d\n", rc);
    printf("  Data key ID:     %s\n", data_key.key_id);
    printf("  Plaintext key:    %zu bytes (encrypted: %zu bytes)\n",
           data_key.plaintext_len, data_key.encrypted_len);
    printf("  Ciphertext blob:  %zu bytes\n", encrypted_len);

    unsigned char decrypted[2048];
    size_t decrypted_len;
    rc = kms_envelope_decrypt(cmk, &data_key, encrypted, encrypted_len,
                               decrypted, &decrypted_len);
    decrypted[decrypted_len] = '\0';
    printf("Envelope decrypt: rc=%d -> '%s'\n", rc, (char *)decrypted);

    printf("\n--- Direct Encrypt/Decrypt ---\n");
    const char *msg = "Hello KMS!";
    kms_encrypt_result_t enc;
    rc = kms_encrypt(cmk, (const unsigned char *)msg, strlen(msg), &enc);
    printf("Encrypt: rc=%d, ciphertext=%zu bytes\n", rc, enc.ciphertext_len);

    kms_decrypt_result_t dec;
    rc = kms_decrypt(cmk, enc.ciphertext_blob, enc.ciphertext_len, &dec);
    if (rc == 0) {
        dec.plaintext[dec.plaintext_len] = '\0';
        printf("Decrypt: rc=%d -> '%s'\n", rc, (char *)dec.plaintext);
    } else {
        printf("Decrypt: rc=%d (FAILED)\n", rc);
    }

    printf("\n--- Generate Data Key ---\n");
    kms_data_key_t dk2;
    rc = kms_generate_data_key(cmk, &dk2, 256);
    printf("GenerateDataKey: rc=%d, key_size=%zu bytes (256-bit)\n", rc, dk2.plaintext_len);

    const char *payload = "Encrypted payload using data key";
    unsigned char dk_cipher[2048];
    size_t dk_ct_len;
    kms_encrypt_with_data_key(&dk2, (const unsigned char *)payload,
                               strlen(payload), dk_cipher, &dk_ct_len);
    printf("Data key encrypt: %zu bytes\n", dk_ct_len);

    unsigned char dk_plain[2048];
    size_t dk_pt_len;
    kms_decrypt_with_data_key(&dk2, dk_cipher, dk_ct_len, dk_plain, &dk_pt_len);
    dk_plain[dk_pt_len] = '\0';
    printf("Data key decrypt: '%s'\n", (char *)dk_plain);

    printf("\n--- Grants ---\n");
    kms_grant_t *g = kms_create_grant(cmk,
        "arn:aws:iam::123456789012:role/LambdaRole",
        KMS_GRANT_OP_ENCRYPT | KMS_GRANT_OP_DECRYPT | KMS_GRANT_OP_GENERATE_DATA_KEY,
        "arn:aws:iam::123456789012:role/AdminRole");
    printf("Grant created:\n");
    printf("  Grant ID:     %s\n", g->grant_id);
    printf("  Grantee:      %s\n", g->grantee_principal);
    printf("  Operations:   ENCRYPT|DECRYPT|GENERATE_DATA_KEY\n");
    printf("  Retiring:     %s\n", g->retiring_principal);

    kms_retire_grant(g);
    printf("Grant retired.\n");

    printf("\n--- Key Lifecycle ---\n");
    kms_disable_key(cmk);
    printf("Key disabled: state=%s\n", kms_key_state_name(cmk->state));
    kms_enable_key(cmk);
    printf("Key re-enabled: state=%s\n", kms_key_state_name(cmk->state));
    kms_schedule_key_deletion(cmk, 30);
    printf("Scheduled deletion in 30 days: state=%s\n", kms_key_state_name(cmk->state));
    kms_cancel_key_deletion(cmk);
    printf("Deletion cancelled: state=%s\n", kms_key_state_name(cmk->state));

    printf("\nAll KMS tests complete.\n");
    return 0;
}
