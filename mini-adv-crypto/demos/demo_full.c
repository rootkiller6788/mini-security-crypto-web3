/*
 * mini-adv-crypto — Full Demo: Advanced Cryptography
 *
 * Demonstrates: ZK proofs (Groth16/R1CS), homomorphic encryption (Paillier),
 *               secure MPC (Shamir secret sharing), post-quantum (Kyber/Dilithium),
 *               threshold signatures (FROST).
 */
#include "../include/zk_proof.h"
#include "../include/homomorphic_enc.h"
#include "../include/mpc_proto.h"
#include "../include/post_quantum.h"
#include "../include/threshold_sig.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    printf("=== mini-adv-crypto: Advanced Cryptography Demo ===\n\n");

    /* Step 1: Zero-Knowledge Proofs (R1CS + Groth16) */
    printf("-- Step 1: Zero-Knowledge Proofs (R1CS + Groth16) --\n");
    zk_field_t field;
    zk_field_init(&field, ZK_FIELD_BN254);
    printf("Field initialized: BN254 (order ~2^254)\n");

    zk_r1cs_t r1cs;
    zk_r1cs_init(&r1cs, &field, 4, 1);
    zk_r1cs_add_constraint(&r1cs, 0, 1, 2, 3);
    printf("R1CS: %zu variables, %zu constraints\n", r1cs.num_variables, r1cs.num_constraints);

    zk_proving_key_t pk;
    zk_verification_key_t vk;
    zk_setup(&r1cs, &pk, &vk);
    printf("Trusted setup: proving key + verification key generated\n");

    zk_witness_t witness;
    zk_witness_init(&witness, &r1cs);
    zk_witness_set_public(&witness, 0, 15);
    zk_witness_set_private(&witness, 1, 3);
    zk_witness_set_private(&witness, 2, 5);

    zk_proof_t proof;
    zk_prove(&pk, &witness, &proof);
    printf("Proof generated (%zu bytes)\n", proof.proof_size);

    bool zk_valid = zk_verify(&vk, &proof, witness.public_inputs, witness.num_public);
    printf("Proof verification: %s\n", zk_valid ? "VALID" : "INVALID");

    /* Step 2: Homomorphic Encryption (Paillier) */
    printf("\n-- Step 2: Homomorphic Encryption (Paillier) --\n");
    paillier_keypair_t pai_key;
    paillier_keygen(&pai_key, 512);
    printf("Paillier keypair: 512-bit modulus generated\n");

    paillier_plaintext_t m1, m2;
    paillier_plaintext_from_int(&m1, 42);
    paillier_plaintext_from_int(&m2, 58);

    paillier_ciphertext_t c1, c2;
    paillier_encrypt(&pai_key.pub, &m1, &c1);
    paillier_encrypt(&pai_key.pub, &m2, &c2);
    printf("Encrypted: 42 and 58\n");

    paillier_ciphertext_t c_add;
    paillier_add(&pai_key.pub, &c1, &c2, &c_add);
    paillier_plaintext_t sum;
    paillier_decrypt(&pai_key.priv, &c_add, &sum);
    printf("Homomorphic add: E(42) + E(58) => D(E(42+58)) = %d\n", sum.value);

    paillier_ciphertext_t c_mul;
    paillier_scalar_mul(&pai_key.pub, &c1, 3, &c_mul);
    paillier_plaintext_t prod;
    paillier_decrypt(&pai_key.priv, &c_mul, &prod);
    printf("Homomorphic scalar mul: 3 * E(42) => D(E(126)) = %d\n", prod.value);

    /* Step 3: Secure MPC (Shamir Secret Sharing) */
    printf("\n-- Step 3: Secure Multi-Party Computation --\n");
    mpc_shamir_t shamir;
    shamir_init(&shamir, 3, 5, 0xFFFFFFFFFFFFFFC5ULL);
    printf("Shamir scheme: %d-of-%d threshold\n", shamir.threshold, shamir.parties);

    uint64_t secret = 0xDEADBEEFCAFE1234ULL;
    uint64_t shares[5];
    shamir_split(&shamir, secret, shares);
    printf("Secret split into 5 shares:\n");
    printf("  Share[0] = 0x%016llX\n", (unsigned long long)shares[0]);
    printf("  Share[1] = 0x%016llX\n", (unsigned long long)shares[1]);
    printf("  Share[4] = 0x%016llX\n", (unsigned long long)shares[4]);

    uint64_t indices[] = {0, 2, 4};
    uint64_t recovered;
    shamir_reconstruct(&shamir, indices, 3, &recovered);
    printf("Reconstructed from shares [0,2,4]: %s\n",
           recovered == secret ? "MATCH" : "MISMATCH");

    /* Step 4: Post-Quantum Cryptography */
    printf("\n-- Step 4: Post-Quantum Cryptography --\n");
    pq_kem_keypair_t kyber_keys;
    kyber_keygen(&kyber_keys);
    printf("Kyber-768 KEM: keypair generated\n");

    uint8_t shared_secret[32], ciphertext[1088];
    kyber_encaps(&kyber_keys.pub, shared_secret, ciphertext);
    printf("Kyber encaps: 32-byte shared secret derived\n");

    uint8_t dec_secret[32];
    bool kyber_ok = kyber_decaps(&kyber_keys.priv, ciphertext, dec_secret);
    printf("Kyber decaps: %s (shared secrets %s)\n",
           kyber_ok ? "OK" : "FAIL",
           memcmp(shared_secret, dec_secret, 32) == 0 ? "match" : "MISMATCH");

    pq_sig_keypair_t dil_keys;
    dilithium_keygen(&dil_keys);
    printf("Dilithium3: signature keypair generated\n");

    uint8_t msg_hash[32];
    memset(msg_hash, 0xAB, 32);
    pq_signature_t dil_sig;
    dilithium_sign(&dil_keys.priv, msg_hash, 32, &dil_sig);
    bool dil_valid = dilithium_verify(&dil_keys.pub, msg_hash, 32, &dil_sig);
    printf("Dilithium sign+verify: %s\n", dil_valid ? "VALID" : "INVALID");

    /* Step 5: Threshold Signatures (FROST) */
    printf("\n-- Step 5: Threshold Signatures (FROST) --\n");
    frost_ctx_t frost;
    frost_init(&frost, 7, 10);
    printf("FROST: %d-of-%d threshold signing\n", frost.threshold, frost.num_signers);

    frost_keygen_round1(&frost);
    printf("Round 1: Signers generate nonce pairs\n");

    uint8_t frost_msg[32];
    memset(frost_msg, 0xB0, 32);
    frost_signing_commitments_t commits;
    frost_sign_round1(&frost, frost_msg, &commits);
    printf("Round 2: Commitments published\n");

    frost_signature_share_t sig_shares[10];
    frost_sign_round2(&frost, &commits, frost_msg, sig_shares);
    printf("Round 3: %d signature shares produced\n", frost.threshold);

    frost_final_signature_t final_sig;
    frost_aggregate(&frost, sig_shares, frost.threshold, &final_sig);
    bool frost_valid = frost_verify(&frost, frost_msg, &final_sig);
    printf("Aggregated signature: %s\n", frost_valid ? "VERIFIED" : "FAILED");

    printf("\nAdvanced cryptography demo complete!\n");
    return 0;
}
