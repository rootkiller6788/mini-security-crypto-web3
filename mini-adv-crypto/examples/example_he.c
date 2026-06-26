#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "homomorphic_enc.h"

static void demo_paillier_basic(void) {
    printf("\n=== Paillier Homomorphic Encryption ===\n");

    he_paillier_pub_t pub;
    he_paillier_prv_t prv;
    int ret = he_paillier_keygen(&pub, &prv, 512);
    printf("Keygen: %s\n", ret == 0 ? "OK" : "FAIL");

    he_bigint_t m1, m2;
    he_bigint_set_u64(&m1, 15);
    he_bigint_set_u64(&m2, 25);

    printf("Plaintexts: ");
    he_bigint_print("m1=", &m1);
    printf(", ");
    he_bigint_print("m2=", &m2);
    printf("\n");

    he_paillier_ct_t c1, c2, c_sum;
    he_paillier_encrypt(&c1, &m1, &pub);
    he_paillier_encrypt(&c2, &m2, &pub);

    printf("Ciphertexts: ");
    he_paillier_print_ct("c1=", &c1);
    he_paillier_print_ct("c2=", &c2);

    he_paillier_add(&c_sum, &c1, &c2, &pub);
    printf("Homomorphic add: Enc(15) + Enc(25) => ");
    he_paillier_print_ct("c_sum=", &c_sum);

    he_bigint_t decrypted;
    he_paillier_decrypt(&decrypted, &c_sum, &prv);
    printf("Decrypted sum: ");
    he_bigint_print("", &decrypted);
    printf(" (expect 40)\n");

    assert(decrypted.limbs[0] == 40 && "Paillier add failed");

    printf("=== Scalar Multiplication ===\n");
    he_bigint_t scalar;
    he_bigint_set_u64(&scalar, 3);
    he_paillier_ct_t c_scaled;
    he_paillier_scalar_mul(&c_scaled, &c1, &scalar, &pub);

    he_bigint_t scaled_dec;
    he_paillier_decrypt(&scaled_dec, &c_scaled, &prv);
    printf("Enc(15) * 3 = ");
    he_bigint_print("", &scaled_dec);
    printf(" (expect 45)\n");
}

static void demo_paillier_addition_chain(void) {
    printf("\n=== Paillier Addition Chain ===\n");

    he_paillier_pub_t pub;
    he_paillier_prv_t prv;
    he_paillier_keygen(&pub, &prv, 512);

    he_bigint_t nums[5];
    he_paillier_ct_t cts[5];

    for (int i = 0; i < 5; i++) {
        he_bigint_set_u64(&nums[i], (uint64_t)(i + 1) * 10);
        he_paillier_encrypt(&cts[i], &nums[i], &pub);
    }

    printf("Inputs: 10 + 20 + 30 + 40 + 50 (encrypted)\n");

    he_paillier_ct_t accumulator = cts[0];
    for (int i = 1; i < 5; i++) {
        he_paillier_ct_t temp;
        he_paillier_add(&temp, &accumulator, &cts[i], &pub);
        accumulator = temp;
    }

    he_bigint_t result;
    he_paillier_decrypt(&result, &accumulator, &prv);
    printf("Encrypted sum = ");
    he_bigint_print("", &result);
    printf(" (expect 150)\n");

    assert(result.limbs[0] == 150 && "Paillier chain failed");
}

static void demo_bfv_scheme(void) {
    printf("\n=== BFV Fully Homomorphic Encryption ===\n");

    he_bfv_params_t params;
    he_bfv_params_init(&params, 8, 65537);

    he_bfv_secret_t sk;
    he_bfv_keygen(&sk, &params);
    printf("BFV keygen: OK (degree=%u)\n", params.poly_degree);

    he_bfv_plain_t pt1, pt2;
    memset(&pt1, 0, sizeof(pt1));
    memset(&pt2, 0, sizeof(pt2));
    pt1.coeff[0] = 7;
    pt1.coeff[1] = 3;
    pt1.noise_budget = 100;
    pt2.coeff[0] = 2;
    pt2.coeff[1] = 5;
    pt2.noise_budget = 100;

    printf("Plaintext 1: [7, 3, ...]\n");
    printf("Plaintext 2: [2, 5, ...]\n");

    he_bfv_cipher_t ct1, ct2;
    he_bfv_encrypt(&ct1, &pt1, &sk, &params);
    he_bfv_encrypt(&ct2, &pt2, &sk, &params);

    printf("Encrypted: noise_budget1=%u noise_budget2=%u\n",
           ct1.noise_budget, ct2.noise_budget);

    he_bfv_cipher_t ct_add;
    he_bfv_add(&ct_add, &ct1, &ct2, &params);
    printf("Add: noise_level=%u noise_budget=%u\n",
           ct_add.noise_level, ct_add.noise_budget);

    he_bfv_plain_t pt_add;
    he_bfv_decrypt(&pt_add, &ct_add, &sk, &params);
    printf("Decrypted add: [%llu, %llu] (expect [9, 8])\n",
           (unsigned long long)pt_add.coeff[0],
           (unsigned long long)pt_add.coeff[1]);

    he_bfv_cipher_t ct_mul;
    he_bfv_mul(&ct_mul, &ct1, &ct2, &params);
    printf("Mul: noise_level=%u noise_budget=%d\n",
           ct_mul.noise_level, he_bfv_noise_budget(&ct_mul));

    he_bfv_plain_t pt_mul;
    he_bfv_decrypt(&pt_mul, &ct_mul, &sk, &params);
    printf("Decrypted mul: [%llu, %llu] (expect [14, 15])\n",
           (unsigned long long)pt_mul.coeff[0],
           (unsigned long long)pt_mul.coeff[1]);

    if (he_bfv_noise_budget(&ct_mul) < HE_NOISE_WARN) {
        printf("WARNING: Noise budget running low! Consider bootstrap.\n");
    }
}

static void demo_bigint_operations(void) {
    printf("\n=== BigInt Utilities ===\n");

    he_bigint_t a, b, g, l, p;
    he_bigint_set_u64(&a, 48);
    he_bigint_set_u64(&b, 180);

    he_bigint_gcd(&g, &a, &b);
    printf("GCD(48, 180) = ");
    he_bigint_print("", &g);
    printf(" (expect 12)\n");

    he_bigint_lcm(&l, &a, &b);
    printf("LCM(48, 180) = ");
    he_bigint_print("", &l);
    printf(" (expect 720)\n");

    he_bigint_add(&p, &a, &b);
    printf("48 + 180 = ");
    he_bigint_print("", &p);
    printf("\n");

    int cmp = he_bigint_cmp(&a, &b);
    printf("CMP(48, 180) = %d\n", cmp);
}

int main(void) {
    printf("===========================================\n");
    printf("  mini-adv-crypto: Homomorphic Encryption\n");
    printf("===========================================\n");

    he_module_version();

    demo_bigint_operations();
    demo_paillier_basic();
    demo_paillier_addition_chain();
    demo_bfv_scheme();

    printf("\n=== All HE examples completed ===\n");
    return 0;
}
