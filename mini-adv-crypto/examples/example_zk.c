#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zk_proof.h"

static void demo_r1cs_system(void) {
    printf("\n=== R1CS Constraint System ===\n");

    zk_r1cs_t r1cs;
    zk_r1cs_init(&r1cs, 3, 2);

    int32_t a1[] = {0, 1, 0, 0};
    int32_t b1[] = {0, 0, 1, 0};
    int32_t c1[] = {0, 0, 0, 1};
    zk_r1cs_add_constraint(&r1cs, 0, a1, b1, c1);

    int32_t a2[] = {0, 0, 1, 0};
    int32_t b2[] = {0, 0, 0, 1};
    int32_t c2[] = {0, 1, 0, 0};
    zk_r1cs_add_constraint(&r1cs, 1, a2, b2, c2);

    zk_r1cs_print(&r1cs);

    int32_t witness[] = {1, 3, 4, 12};
    int ret = zk_r1cs_verify_witness(&r1cs, witness);
    printf("R1CS witness check: %s (expect PASS)\n", ret == 0 ? "PASS" : "FAIL");
}

static void demo_groth16(void) {
    printf("\n=== Groth16 Protocol ===\n");

    zk_r1cs_t r1cs;
    zk_r1cs_init(&r1cs, 4, 2);

    int32_t a1[] = {0, 1, 0, 0, 0};
    int32_t b1[] = {0, 0, 1, 0, 0};
    int32_t c1[] = {0, 0, 0, 1, 0};
    zk_r1cs_add_constraint(&r1cs, 0, a1, b1, c1);

    int32_t a2[] = {0, 0, 0, 1, 0};
    int32_t b2[] = {0, 0, 0, 0, 1};
    int32_t c2[] = {0, 1, 0, 0, 0};
    zk_r1cs_add_constraint(&r1cs, 1, a2, b2, c2);

    zk_proving_key_t pk;
    zk_verification_key_t vk;
    zk_setup_info_t info = {4, 1, {{0}}};
    zk_trusted_setup(&pk, &vk, &r1cs, &info);

    printf("Setup complete: num_vars=%u num_inputs=%u\n", pk.num_vars, pk.num_inputs);

    printf("Simulating MPC toxic waste ceremony...\n");
    zk_setup_toxic_mpc(&pk, 5);

    int32_t witness[] = {1, 3, 4, 12, 7};
    int32_t pub[] = {84};

    zk_groth16_proof_t proof;
    zk_groth16_prove(&proof, &pk, witness, 1);
    printf("Proof generated:\n");
    zk_groth16_print(&proof);

    int ret = zk_groth16_verify(&proof, &vk, pub, 1);
    printf("Groth16 verification: %s (expect PASS)\n", ret == 0 ? "PASS" : "FAIL");

    zk_proving_key_free(&pk);
    zk_verification_key_free(&vk);
}

static void demo_qap_pinocchio(void) {
    printf("\n=== QAP + Pinocchio Protocol ===\n");

    zk_r1cs_t r1cs;
    zk_r1cs_init(&r1cs, 3, 2);

    int32_t a1[] = {0, 1, 0, 0};
    int32_t b1[] = {0, 0, 1, 0};
    int32_t c1[] = {0, 0, 0, 1};
    zk_r1cs_add_constraint(&r1cs, 0, a1, b1, c1);

    zk_qap_t qap;
    zk_qap_from_r1cs(&qap, &r1cs);
    printf("QAP degree: %u\n", qap.degree);

    int32_t ea, eb, ec, et;
    zk_qap_evaluate(&qap, 2, &ea, &eb, &ec, &et);
    printf("QAP eval at x=2: A=%d B=%d C=%d T=%d\n", ea, eb, ec, et);

    zk_groth16_proof_t proof;
    int32_t witness[] = {1, 3, 4, 12};
    zk_pinocchio_prove(&proof, &qap, witness, 2);

    int32_t io[] = {12, 3};
    int ret = zk_pinocchio_verify(&proof, &qap, io, 2);
    printf("Pinocchio verification: %s\n", ret == 0 ? "PASS" : "FAIL");
}

static void demo_stark_basics(void) {
    printf("\n=== zk-STARK Basics ===\n");

    int32_t exec_trace[] = {
        1, 0, 2,
        2, 1, 0,
        3, 2, 1,
        4, 3, 2,
        5, 4, 3
    };

    zk_stark_trace_t trace;
    zk_stark_trace_commit(&trace, exec_trace, 5, 3);

    printf("Trace: width=%u height=%u\n", trace.width, trace.height);

    zk_field_t root[4];
    zk_stark_merkle_root(root, &trace);
    printf("Merkle root:\n");
    for (int i = 0; i < 4; i++) {
        zk_field_print("  ", &root[i]);
    }

    int ret = zk_stark_fri_verify(&trace, 3);
    printf("FRI verification: %s\n", ret == 0 ? "PASS" : "EXPECT-UNVERIFIABLE");
}

int main(void) {
    printf("===========================================\n");
    printf("  mini-adv-crypto: Zero-Knowledge Proofs\n");
    printf("===========================================\n");

    zk_module_version();

    zk_field_t a, b, r;
    zk_field_from_u64(&a, 42);
    zk_field_from_u64(&b, 100);
    zk_field_add(&r, &a, &b);
    printf("Field add: 42 + 100 = ");
    zk_field_print("", &r);

    demo_r1cs_system();
    demo_groth16();
    demo_qap_pinocchio();
    demo_stark_basics();

    printf("\n=== All ZK examples completed ===\n");
    return 0;
}
