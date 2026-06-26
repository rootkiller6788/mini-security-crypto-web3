/*
 * mini-crypto-basic — Core Tests
 *
 * Unit tests for hash, symmetric cipher, asymmetric cipher, digital sig, PKI.
 */
#include "../include/hash_func.h"
#include "../include/symmetric_cipher.h"
#include "../include/asymmetric_cipher.h"
#include "../include/digital_sig.h"
#include "../include/pki_model.h"
#include <stdio.h>
#include <string.h>

static int tests_run = 0, tests_passed = 0;

#define TEST(name) do { tests_run++; printf("  TEST %s ... ", name); } while(0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); return 1; } while(0)
#define CHECK(cond, msg) if (!(cond)) FAIL(msg)

/* ── Hash Tests ── */
static int test_sha256_known(void) {
    TEST("sha256_known_vector");
    const char *input = "abc";
    uint8_t digest[SHA256_DIGEST_SIZE];
    sha256_hash((const uint8_t *)input, 3, digest);
    CHECK(digest[0] == 0xba, "sha256 abc[0] mismatch");
    CHECK(digest[1] == 0x78, "sha256 abc[1] mismatch");
    PASS();
    return 0;
}

static int test_sha256_incremental(void) {
    TEST("sha256_incremental");
    Sha256Context ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t *)"hello ", 6);
    sha256_update(&ctx, (const uint8_t *)"world", 5);
    uint8_t digest[SHA256_DIGEST_SIZE];
    sha256_final(&ctx, digest);
    uint8_t expected[SHA256_DIGEST_SIZE];
    sha256_hash((const uint8_t *)"hello world", 11, expected);
    CHECK(memcmp(digest, expected, SHA256_DIGEST_SIZE) == 0, "incremental mismatch");
    PASS();
    return 0;
}

static int test_hmac_sha256(void) {
    TEST("hmac_sha256");
    uint8_t key[16] = "key";
    uint8_t digest[SHA256_DIGEST_SIZE];
    hmac_sha256(key, 3, (const uint8_t *)"data", 4, digest);
    CHECK(digest[0] != 0 || digest[1] != 0, "hmac all zeros");
    PASS();
    return 0;
}

/* ── AES Tests ── */
static int test_aes128_encrypt_decrypt(void) {
    TEST("aes128_encrypt_decrypt");
    uint8_t key[AES_KEY_SIZE]; memset(key, 0x2b, AES_KEY_SIZE);
    AesContext aes;
    aes128_key_schedule(&aes, key);
    uint8_t plain[AES_BLOCK_SIZE]; memset(plain, 0x6b, AES_BLOCK_SIZE);
    uint8_t cipher[AES_BLOCK_SIZE], decrypted[AES_BLOCK_SIZE];
    aes128_encrypt_block(&aes, plain, cipher);
    CHECK(memcmp(plain, cipher, AES_BLOCK_SIZE) != 0, "encrypt did nothing");
    aes128_decrypt_block(&aes, cipher, decrypted);
    CHECK(memcmp(plain, decrypted, AES_BLOCK_SIZE) == 0, "decrypt mismatch");
    PASS();
    return 0;
}

static int test_aes_cbc(void) {
    TEST("aes_cbc_encrypt_decrypt");
    uint8_t key[AES_KEY_SIZE]; memset(key, 0x42, AES_KEY_SIZE);
    AesContext aes;
    aes128_key_schedule(&aes, key);
    uint8_t iv[AES_BLOCK_SIZE]; memset(iv, 0, AES_BLOCK_SIZE);
    const char *msg = "Hello, AES-CBC mode!";
    uint8_t padded[48], cipher[48], decrypted[48];
    size_t pad_len = pkcs7_pad((const uint8_t *)msg, strlen(msg), AES_BLOCK_SIZE, padded);
    CbcContext cbc_enc;
    cbc_encrypt_init(&cbc_enc, &aes, CIPHER_ALGO_AES128, iv);
    size_t out_len;
    cbc_encrypt_update(&cbc_enc, padded, pad_len, cipher, &out_len);
    cbc_encrypt_final(&cbc_enc, cipher + out_len, &out_len);
    CbcContext cbc_dec;
    cbc_decrypt_init(&cbc_dec, &aes, CIPHER_ALGO_AES128, iv);
    cbc_decrypt_update(&cbc_dec, cipher, pad_len, decrypted, &out_len);
    cbc_decrypt_final(&cbc_dec, decrypted + out_len, &out_len);
    size_t plain_len = pkcs7_unpad(decrypted, pad_len, decrypted);
    CHECK(plain_len == strlen(msg), "plain len mismatch");
    CHECK(memcmp(msg, decrypted, plain_len) == 0, "cbc decrypt mismatch");
    PASS();
    return 0;
}

static int test_des_encrypt_decrypt(void) {
    TEST("des_encrypt_decrypt");
    uint8_t key[DES_KEY_SIZE]; memset(key, 0x13, DES_KEY_SIZE);
    DesContext des;
    des_key_schedule(&des, key);
    uint8_t plain[DES_BLOCK_SIZE]; memset(plain, 0x01, DES_BLOCK_SIZE);
    uint8_t cipher[DES_BLOCK_SIZE], decrypted[DES_BLOCK_SIZE];
    des_encrypt_block(&des, plain, cipher);
    CHECK(memcmp(plain, cipher, DES_BLOCK_SIZE) != 0, "des encrypt did nothing");
    des_decrypt_block(&des, cipher, decrypted);
    CHECK(memcmp(plain, decrypted, DES_BLOCK_SIZE) == 0, "des decrypt mismatch");
    PASS();
    return 0;
}

/* ── BigInt Tests ── */
static int test_bigint_add(void) {
    TEST("bigint_add");
    BigInt a, b, r;
    bigint_from_uint64(&a, 12345);
    bigint_from_uint64(&b, 67890);
    bigint_add(&r, &a, &b);
    BigInt expected; bigint_from_uint64(&expected, 80235);
    CHECK(bigint_compare(&r, &expected) == 0, "add wrong");
    PASS();
    return 0;
}

static int test_bigint_mod_exp(void) {
    TEST("bigint_mod_exp");
    BigInt base, exp, mod, r;
    bigint_from_uint64(&base, 3);
    bigint_from_uint64(&exp, 5);
    bigint_from_uint64(&mod, 13);
    bigint_mod_exp(&r, &base, &exp, &mod);
    BigInt expected; bigint_from_uint64(&expected, 9); /* 3^5 mod 13 = 243 mod 13 = 9 */
    CHECK(bigint_compare(&r, &expected) == 0, "mod_exp wrong");
    PASS();
    return 0;
}

/* ── RSA Tests ── */
static int test_rsa_keygen_encrypt(void) {
    TEST("rsa_keygen_encrypt_decrypt");
    RsaPrivateKey priv; RsaPublicKey pub;
    CHECK(rsa_keygen(&priv, &pub, 1024), "keygen failed");
    CHECK(pub.key_bits >= 1024, "key bits too small");
    const char *msg = "RSA test message";
    uint8_t cipher[256], plain[256];
    size_t clen, plen;
    CHECK(rsa_encrypt(&pub, (const uint8_t *)msg, strlen(msg), cipher, &clen), "encrypt failed");
    CHECK(rsa_decrypt(&priv, cipher, clen, plain, &plen), "decrypt failed");
    CHECK(plen == strlen(msg), "decrypt len mismatch");
    CHECK(memcmp(msg, plain, plen) == 0, "decrypt wrong");
    PASS();
    return 0;
}

/* ── ECDH Tests ── */
static int test_ecdh_shared_secret(void) {
    TEST("ecdh_shared_secret");
    EcKey alice, bob;
    ecdh_generate_keypair(&alice);
    ecdh_generate_keypair(&bob);
    uint8_t s1[EC_FIELD_BYTES], s2[EC_FIELD_BYTES];
    CHECK(ecdh_compute_shared_secret(&alice, &bob.pub, s1), "alice secret failed");
    CHECK(ecdh_compute_shared_secret(&bob, &alice.pub, s2), "bob secret failed");
    CHECK(memcmp(s1, s2, EC_FIELD_BYTES) == 0, "shared secrets differ");
    PASS();
    return 0;
}

/* ── ECDSA Tests ── */
static int test_ecdsa_sign_verify(void) {
    TEST("ecdsa_sign_verify");
    EcKey key;
    ecdh_generate_keypair(&key);
    uint8_t hash[SHA256_DIGEST_SIZE];
    sha256_hash((const uint8_t *)"signed document", 15, hash);
    EcdsaSignature sig;
    CHECK(ecdsa_sign(key.priv, hash, SHA256_DIGEST_SIZE, &sig), "sign failed");
    CHECK(ecdsa_verify(&key.pub, hash, SHA256_DIGEST_SIZE, &sig), "verify failed");
    PASS();
    return 0;
}

/* ── PEM Tests ── */
static int test_pem_rsa(void) {
    TEST("pem_rsa_encode_decode");
    RsaPrivateKey priv; RsaPublicKey pub;
    rsa_keygen(&priv, &pub, 1024);
    char pem[PEM_MAX_SIZE];
    int len = pem_encode_rsa_public(&pub, pem, PEM_MAX_SIZE);
    CHECK(len > 0, "encode failed");
    RsaPublicKey decoded;
    CHECK(pem_decode_rsa_public(pem, &decoded), "decode failed");
    CHECK(bigint_compare(&pub.n, &decoded.n) == 0, "decoded n mismatch");
    PASS();
    return 0;
}

/* ── X.509 Tests ── */
static int test_x509_time_validity(void) {
    TEST("x509_time_validity");
    CaConfig ca; memset(&ca, 0, sizeof(ca));
    snprintf(ca.name, 128, "Test CA"); ca.is_root = true;
    X509Certificate cert;
    ca_self_sign_root(&ca, &cert);
    cert.not_before = time(NULL) - 86400;
    cert.not_after  = time(NULL) + 86400;
    CHECK(x509_is_valid_at_time(&cert, time(NULL)), "cert should be valid now");
    CHECK(!x509_is_valid_at_time(&cert, time(NULL) + 172800), "cert should be expired");
    PASS();
    return 0;
}

/* ── Trust Store Tests ── */
static int test_trust_store(void) {
    TEST("trust_store");
    TrustStore ts;
    trust_store_init(&ts);
    CaConfig ca; memset(&ca, 0, sizeof(ca));
    snprintf(ca.name, 128, "TS-CA"); ca.is_root = true;
    X509Certificate cert;
    ca_self_sign_root(&ca, &cert);
    CHECK(trust_store_add(&ts, &cert), "add to store failed");
    CHECK(ts.count == 1, "store count wrong");
    const X509Certificate *found = trust_store_find_by_subject(&ts, "TS-CA");
    CHECK(found != NULL, "find by subject failed");
    PASS();
    return 0;
}

int main(void) {
    printf("=== mini-crypto-basic Unit Tests ===\n\n");

    int failed = 0;
    failed += test_sha256_known();
    failed += test_sha256_incremental();
    failed += test_hmac_sha256();
    failed += test_aes128_encrypt_decrypt();
    failed += test_aes_cbc();
    failed += test_des_encrypt_decrypt();
    failed += test_bigint_add();
    failed += test_bigint_mod_exp();
    failed += test_rsa_keygen_encrypt();
    failed += test_ecdh_shared_secret();
    failed += test_ecdsa_sign_verify();
    failed += test_pem_rsa();
    failed += test_x509_time_validity();
    failed += test_trust_store();

    printf("\n=== Results: %d/%d passed, %d failed ===\n",
           tests_passed, tests_run, failed);
    return failed > 0 ? 1 : 0;
}
