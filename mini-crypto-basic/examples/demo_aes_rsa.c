#include "symmetric_cipher.h"
#include "asymmetric_cipher.h"
#include "hash_func.h"
#include <stdio.h>
#include <string.h>

static void print_hex(const uint8_t *data, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) printf("%02x", data[i]);
}

int main(void) {
    printf("=== mini-crypto-basic AES / RSA / ECDH Demo ===\n\n");

    /* ── AES-128 ──────────────────────────────── */
    uint8_t aes_key[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
                           0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    uint8_t plaintext[16] = {0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,
                              0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34};
    uint8_t ciphertext[16];
    uint8_t decrypted[16];

    AesContext aes;
    aes128_key_schedule(&aes, aes_key);
    aes128_encrypt_block(&aes, plaintext, ciphertext);

    printf("AES-128 Encryption:\n");
    printf("  Plain:  "); print_hex(plaintext, 16); printf("\n");
    printf("  Key:    "); print_hex(aes_key, 16); printf("\n");
    printf("  Cipher: "); print_hex(ciphertext, 16); printf("\n");

    aes128_decrypt_block(&aes, ciphertext, decrypted);
    printf("  Decrypt:"); print_hex(decrypted, 16); printf("\n");
    printf("  Match: %s\n\n",
           memcmp(plaintext, decrypted, 16) == 0 ? "YES" : "NO");

    /* ── AES-CBC ──────────────────────────────── */
    uint8_t iv[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                      0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    const char *cbc_msg = "Encrypt me with CBC mode!";
    size_t msg_len = strlen(cbc_msg);
    uint8_t padded[48];
    size_t pad_len = pkcs7_pad((const uint8_t *)cbc_msg, msg_len, 16, padded);

    printf("PKCS7 Padding:\n");
    printf("  Original: %zu bytes, Padded: %zu bytes\n\n", msg_len, pad_len);

    CbcContext cbc;
    cbc_encrypt_init(&cbc, &aes, CIPHER_ALGO_AES128, iv);
    uint8_t cbc_out[64];
    size_t out_len;
    cbc_encrypt_update(&cbc, padded, pad_len, cbc_out, &out_len);
    cbc_encrypt_final(&cbc, cbc_out + out_len, &out_len);

    printf("CBC Encrypt: "); print_hex(cbc_out, pad_len); printf("\n");

    CbcContext cbc_dec;
    cbc_decrypt_init(&cbc_dec, &aes, CIPHER_ALGO_AES128, iv);
    uint8_t cbc_plain[48];
    cbc_decrypt_update(&cbc_dec, cbc_out, pad_len, cbc_plain, &out_len);
    cbc_decrypt_final(&cbc_dec, cbc_plain + out_len, &out_len);

    uint8_t unpadded[32];
    size_t unpad_len = pkcs7_unpad(cbc_plain, pad_len, unpadded);
    printf("CBC Decrypt: %s\n\n", (const char *)unpadded);

    /* ── CTR Mode ─────────────────────────────── */
    CtrContext ctr;
    ctr_crypt_init(&ctr, &aes, CIPHER_ALGO_AES128, iv);
    uint8_t ctr_out[48];
    ctr_crypt_update(&ctr, padded, pad_len, ctr_out, &out_len);
    printf("CTR Encrypt: "); print_hex(ctr_out, out_len); printf("\n");

    CtrContext ctr2;
    ctr_crypt_init(&ctr2, &aes, CIPHER_ALGO_AES128, iv);
    uint8_t ctr_plain[48];
    ctr_crypt_update(&ctr2, ctr_out, out_len, ctr_plain, &out_len);
    uint8_t unpad2[32];
    unpad_len = pkcs7_unpad(ctr_plain, out_len, unpad2);
    printf("CTR Decrypt: %s\n\n", (const char *)unpad2);

    /* ── RSA ──────────────────────────────────── */
    printf("RSA Key Generation + Sign/Verify:\n");
    RsaPrivateKey priv;
    RsaPublicKey pub;
    if (rsa_keygen(&priv, &pub, 1024)) {
        printf("  Keygen: OK (size=%zu bits)\n", pub.key_bits);

        const char *sig_msg = "Sign this text";
        uint8_t sig[512];
        size_t sig_len;
        uint8_t hash[32];
        sha256_hash((const uint8_t *)sig_msg, strlen(sig_msg), hash);
        rsa_sign(&priv, hash, 32, sig, &sig_len);
        printf("  Sign: OK (%zu bytes)\n", sig_len);

        bool verified = rsa_verify(&pub, hash, 32, sig, sig_len);
        printf("  Verify: %s\n", verified ? "OK" : "FAIL");
    }

    /* ── ECDH ─────────────────────────────────── */
    printf("\nECDH Key Exchange (secp256k1 sim):\n");
    EcKey alice_key, bob_key;
    ecdh_generate_keypair(&alice_key);
    ecdh_generate_keypair(&bob_key);

    uint8_t alice_secret[32], bob_secret[32];
    ecdh_compute_shared_secret(&alice_key, &bob_key.pub, alice_secret);
    ecdh_compute_shared_secret(&bob_key, &alice_key.pub, bob_secret);
    printf("  Alice shared: "); print_hex(alice_secret, 32); printf("\n");
    printf("  Bob shared:   "); print_hex(bob_secret, 32); printf("\n");
    printf("  Match: %s\n\n",
           memcmp(alice_secret, bob_secret, 32) == 0 ? "YES" : "NO");

    /* ── PEM ──────────────────────────────────── */
    printf("PEM Encoding (RSA Private Key):\n");
    char pem[4096];
    int pem_len = pem_encode_rsa_private(&priv, pem, sizeof(pem));
    printf("%s", pem);
    printf("PEM size: %d bytes\n\n", pem_len);

    return 0;
}
