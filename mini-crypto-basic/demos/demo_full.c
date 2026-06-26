/*
 * mini-crypto-basic — Full Demo: Cryptography fundamentals
 *
 * Demonstrates: SHA256, HMAC, AES-CBC, RSA keygen/encrypt/sign,
 *               ECDH key exchange, ECDSA, X.509 certs, PKI, ACME.
 */
#include "../include/hash_func.h"
#include "../include/symmetric_cipher.h"
#include "../include/asymmetric_cipher.h"
#include "../include/digital_sig.h"
#include "../include/pki_model.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

int main(void) {
    printf("╔══════════════════════════════════════════╗\n");
    printf("║   mini-crypto-basic: Core Cryptography  ║\n");
    printf("╚══════════════════════════════════════════╝\n\n");

    /* ── Step 1: SHA256 & HMAC ── */
    printf("── Step 1: Hash Functions ──\n");
    const char *msg = "The quick brown fox jumps over the lazy dog";
    uint8_t sha_digest[SHA256_DIGEST_SIZE];
    sha256_hash((const uint8_t *)msg, strlen(msg), sha_digest);
    printf("SHA256(\"%s\") = ", msg);
    for (int i = 0; i < 8; i++) printf("%02x", sha_digest[i]);
    printf("...\n");

    uint8_t hmac_key[16] = "secret-key-12345";
    uint8_t hmac_digest[SHA256_DIGEST_SIZE];
    hmac_sha256(hmac_key, 15, (const uint8_t *)msg, strlen(msg), hmac_digest);
    printf("HMAC-SHA256 = ");
    for (int i = 0; i < 8; i++) printf("%02x", hmac_digest[i]);
    printf("...\n");

    /* ── Step 2: AES-128-CBC ── */
    printf("\n── Step 2: Symmetric Encryption ──\n");
    uint8_t aes_key[AES_KEY_SIZE] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
                                      0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    uint8_t iv[AES_BLOCK_SIZE] = {0};
    AesContext aes;
    aes128_key_schedule(&aes, aes_key);

    const char *plaintext = "Secret message: launch at dawn!";
    uint8_t padded[48], cipher[48], decrypted[48];
    size_t pad_len = pkcs7_pad((const uint8_t *)plaintext, strlen(plaintext), AES_BLOCK_SIZE, padded);

    CbcContext cbc_enc;
    cbc_encrypt_init(&cbc_enc, &aes, CIPHER_ALGO_AES128, iv);
    size_t out_len;
    cbc_encrypt_update(&cbc_enc, padded, pad_len, cipher, &out_len);
    cbc_encrypt_final(&cbc_enc, cipher + out_len, &out_len);
    printf("Plaintext: \"%s\"\n", plaintext);
    printf("Ciphertext (%zu bytes): ", pad_len);
    for (int i = 0; i < 16; i++) printf("%02x", cipher[i]);
    printf("...\n");

    CbcContext cbc_dec;
    cbc_decrypt_init(&cbc_dec, &aes, CIPHER_ALGO_AES128, iv);
    cbc_decrypt_update(&cbc_dec, cipher, pad_len, decrypted, &out_len);
    cbc_decrypt_final(&cbc_dec, decrypted + out_len, &out_len);
    size_t plain_len = pkcs7_unpad(decrypted, pad_len, decrypted);
    decrypted[plain_len] = '\0';
    printf("Decrypted: \"%s\"\n", decrypted);

    /* ── Step 3: RSA ── */
    printf("\n── Step 3: RSA Asymmetric ──\n");
    RsaPrivateKey rsa_priv; RsaPublicKey rsa_pub;
    rsa_keygen(&rsa_priv, &rsa_pub, 1024);
    printf("RSA keypair: %zu-bit generated\n", rsa_pub.key_bits);

    uint8_t rsa_cipher[256], rsa_plain[256];
    size_t clen, plen;
    const char *rsa_msg = "RSA encrypted data";
    rsa_encrypt(&rsa_pub, (const uint8_t *)rsa_msg, strlen(rsa_msg), rsa_cipher, &clen);
    rsa_decrypt(&rsa_priv, rsa_cipher, clen, rsa_plain, &plen);
    rsa_plain[plen] = '\0';
    printf("RSA encrypt/decrypt: \"%s\" -> \"%s\"\n", rsa_msg, rsa_plain);

    /* ── Step 4: Digital Signatures ── */
    printf("\n── Step 4: Digital Signatures ──\n");
    const char *doc = "Alice pays Bob 100 tokens";
    uint8_t doc_hash[SHA256_DIGEST_SIZE];
    sha256_hash((const uint8_t *)doc, strlen(doc), doc_hash);

    uint8_t rsa_sig[256];
    size_t sig_len;
    rsa_sign(&rsa_priv, doc_hash, SHA256_DIGEST_SIZE, rsa_sig, &sig_len);
    bool rsa_verified = rsa_verify(&rsa_pub, doc_hash, SHA256_DIGEST_SIZE, rsa_sig, sig_len);
    printf("RSA-PSS sign/verify: %s\n", rsa_verified ? "VERIFIED" : "FAILED");

    EcKey ec_key;
    ecdh_generate_keypair(&ec_key);
    EcdsaSignature ec_sig;
    ecdsa_sign(ec_key.priv, doc_hash, SHA256_DIGEST_SIZE, &ec_sig);
    bool ec_verified = ecdsa_verify(&ec_key.pub, doc_hash, SHA256_DIGEST_SIZE, &ec_sig);
    printf("ECDSA sign/verify: %s\n", ec_verified ? "VERIFIED" : "FAILED");

    /* ── Step 5: X.509 Certificates ── */
    printf("\n── Step 5: PKI & X.509 ──\n");
    CaConfig ca;
    memset(&ca, 0, sizeof(ca));
    snprintf(ca.name, 128, "Demo Root CA");
    ca.is_root = true;
    X509Certificate root_cert;
    ca_self_sign_root(&ca, &root_cert);
    printf("Root CA: %s\n", root_cert.subject.common_name);
    x509_print_certificate(&root_cert);

    CsrRequest csr;
    csr_init(&csr, "api.example.com", "Example Inc", "US");
    csr_set_ec_key(&csr, ec_key.pub.x, 32);
    csr_sign(&csr, ec_key.priv, 256);
    printf("CSR: %s\n", csr.common_name);

    X509Certificate leaf_cert;
    ca_issue_certificate(&ca, &csr, &leaf_cert, 365);
    printf("Issued: %s (valid %lld days)\n", leaf_cert.subject.common_name, 365LL);

    TrustStore store;
    trust_store_init(&store);
    trust_store_add(&store, &root_cert);
    bool chain_ok = trust_store_verify_chain(&store, &leaf_cert, NULL, time(NULL));
    printf("Chain verification: %s\n", chain_ok ? "PASSED" : "FAILED");

    /* ── Step 6: ACME (Let's Encrypt) ── */
    printf("\n── Step 6: ACME Certificate Issuance ──\n");
    AcmeAccount acct;
    acme_account_create(&acct, "admin@example.com");
    printf("ACME account: %s\n", acct.account_id);

    AcmeOrder order;
    acme_new_order(&order, "demo.example.com");
    printf("ACME order: %s (%s)\n", order.order_id, order.status);
    acme_submit_challenge_response(&order, 0, "demo-response-token");
    acme_finalize_order(&order, &csr);

    uint8_t cert_der[4096];
    size_t der_len;
    acme_download_certificate(&order, cert_der, &der_len);
    printf("Certificate downloaded: %zu bytes\n", der_len);

    /* ── Step 7: OCSP ── */
    printf("\n── Step 7: OCSP Status Check ──\n");
    uint8_t req_der[256]; size_t req_len;
    ocsp_request_build(leaf_cert.serial, leaf_cert.serial_len, req_der, &req_len);
    printf("OCSP request: %zu bytes\n", req_len);

    OcspResponse ocsp_resp;
    memset(&ocsp_resp, 0, sizeof(ocsp_resp));
    ocsp_resp.responses[0].cert_status = OCSP_STATUS_GOOD;
    ocsp_resp.response_count = 1;
    OcspCertStatus st = ocsp_check_status(&ocsp_resp, leaf_cert.serial, leaf_cert.serial_len);
    printf("OCSP status: %s\n", st == OCSP_STATUS_GOOD ? "GOOD" : st == OCSP_STATUS_REVOKED ? "REVOKED" : "UNKNOWN");

    printf("\n✓ Full cryptography fundamentals demo complete!\n");
    return 0;
}
