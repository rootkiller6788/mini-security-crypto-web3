/*
 * mini-crypto-basic — Benchmark: hash, cipher, signature throughput
 *
 * Measures SHA256, AES, RSA, ECDH, HMAC, and cert operations.
 * Usage: bench_core [iterations]
 */
#include "../include/hash_func.h"
#include "../include/symmetric_cipher.h"
#include "../include/asymmetric_cipher.h"
#include "../include/digital_sig.h"
#include "../include/pki_model.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now_ms(void) {
    return (double)clock() / (double)(CLOCKS_PER_SEC / 1000);
}

int main(int argc, char **argv) {
    int N = (argc > 1) ? atoi(argv[1]) : 10000;
    printf("=== mini-crypto-basic Benchmarks (iterations=%d) ===\n\n", N);

    /* SHA256 hash */
    {
        uint8_t data[64] = "benchmark data for SHA256 hashing test throughput test";
        uint8_t digest[SHA256_DIGEST_SIZE];
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            sha256_hash(data, 64, digest);
        }
        double dt = now_ms() - t0;
        printf("  sha256_hash (64 bytes):             %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    /* HMAC-SHA256 */
    {
        uint8_t key[32] = "benchmark-secret-key-32bytes!";
        uint8_t data[64] = "benchmark data for HMAC throughput test...";
        uint8_t digest[SHA256_DIGEST_SIZE];
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            hmac_sha256(key, 32, data, 64, digest);
        }
        double dt = now_ms() - t0;
        printf("  hmac_sha256 (key=32, data=64):      %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    /* AES-128 encrypt block */
    {
        AesContext aes;
        uint8_t key[AES_KEY_SIZE];
        memset(key, 0x42, AES_KEY_SIZE);
        aes128_key_schedule(&aes, key);
        uint8_t plain[AES_BLOCK_SIZE], cipher[AES_BLOCK_SIZE];
        memset(plain, 0, AES_BLOCK_SIZE);
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            aes128_encrypt_block(&aes, plain, cipher);
        }
        double dt = now_ms() - t0;
        printf("  aes128_encrypt_block:               %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    /* AES-128-CBC encrypt */
    {
        AesContext aes;
        uint8_t key[AES_KEY_SIZE]; memset(key, 0x42, AES_KEY_SIZE);
        aes128_key_schedule(&aes, key);
        uint8_t iv[AES_BLOCK_SIZE]; memset(iv, 0, AES_BLOCK_SIZE);
        uint8_t plain[256], cipher[280];
        memset(plain, 0xAA, 256);
        double t0 = now_ms();
        for (int i = 0; i < N / 10; i++) {
            CbcContext cbc;
            cbc_encrypt_init(&cbc, &aes, CIPHER_ALGO_AES128, iv);
            size_t out_len;
            cbc_encrypt_update(&cbc, plain, 256, cipher, &out_len);
            cbc_encrypt_final(&cbc, cipher + out_len, &out_len);
        }
        double dt = now_ms() - t0;
        printf("  aes128-cbc encrypt (256 bytes):     %d ops in %.1f ms  (%.1f µs/op)\n",
               N / 10, dt, dt * 1000.0 / (double)(N / 10));
    }

    /* RSA keygen */
    {
        int k = N / 100 > 0 ? N / 100 : 1;
        double t0 = now_ms();
        for (int i = 0; i < k; i++) {
            RsaPrivateKey priv; RsaPublicKey pub;
            rsa_keygen(&priv, &pub, 1024);
        }
        double dt = now_ms() - t0;
        printf("  rsa_keygen (1024-bit):               %d ops in %.1f ms  (%.1f µs/op)\n",
               k, dt, dt * 1000.0 / (double)k);
    }

    /* BigInt mod exp */
    {
        BigInt base, exp, mod, result;
        bigint_from_uint64(&base, 12345);
        bigint_from_uint64(&exp, 65537);
        bigint_from_uint64(&mod, 1000000007);
        double t0 = now_ms();
        for (int i = 0; i < N / 10; i++) {
            bigint_mod_exp(&result, &base, &exp, &mod);
        }
        double dt = now_ms() - t0;
        printf("  bigint_mod_exp:                     %d ops in %.1f ms  (%.1f µs/op)\n",
               N / 10, dt, dt * 1000.0 / (double)(N / 10));
    }

    /* ECDH key exchange */
    {
        double t0 = now_ms();
        for (int i = 0; i < N / 10; i++) {
            EcKey alice, bob;
            ecdh_generate_keypair(&alice);
            ecdh_generate_keypair(&bob);
            uint8_t secret[EC_FIELD_BYTES];
            ecdh_compute_shared_secret(&alice, &bob.pub, secret);
        }
        double dt = now_ms() - t0;
        printf("  ecdh keygen+exchange:               %d ops in %.1f ms  (%.1f µs/op)\n",
               N / 10, dt, dt * 1000.0 / (double)(N / 10));
    }

    printf("\n=== Benchmarks complete ===\n");
    return 0;
}
