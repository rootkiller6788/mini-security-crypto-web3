#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mpc_proto.h"

static void demo_shamir_secret_sharing(void) {
    printf("\n=== Shamir Secret Sharing ===\n");

    mpc_shamir_ctx_t ctx;
    int64_t secret = 12345;
    int ret = mpc_shamir_split(&ctx, secret, 3, 5);
    printf("Split: t=%u n=%u secret=%lld => %s\n",
           ctx.threshold, ctx.total, (long long)secret,
           ret == 0 ? "OK" : "FAIL");

    mpc_shamir_print(&ctx);

    uint32_t indices1[] = {0, 2, 4};
    int64_t recovered1;
    ret = mpc_shamir_reconstruct(&recovered1, &ctx, indices1, 3);
    printf("Reconstruct(0,2,4): %lld => %s\n",
           (long long)recovered1, (ret == 0 && recovered1 == secret) ? "PASS" : "FAIL");

    uint32_t indices2[] = {1, 3};
    int64_t recovered2;
    ret = mpc_shamir_reconstruct(&recovered2, &ctx, indices2, 2);
    printf("Reconstruct(1,3): %s (insufficient shares: ret=%d)\n",
           ret != 0 ? "DENIED" : "ALLOWED", ret);

    mpc_shamir_share_t r;
    mpc_shamir_add_share(&r, &ctx.shares[0], &ctx.shares[1]);
    printf("Share 0 + Share 1: (%lld, %lld) => (%lld, %lld)\n",
           (long long)ctx.shares[0].x, (long long)ctx.shares[0].y,
           (long long)r.x, (long long)r.y);
}

static void demo_garbled_circuit(void) {
    printf("\n=== Yao Garbled Circuit ===\n");

    mpc_garbled_circuit_t gc;
    mpc_garble_circuit_init(&gc, 4, 2, 1);
    printf("Circuit: %u gates, %u inputs, %u outputs\n",
           gc.num_gates, gc.num_inputs, gc.num_outputs);

    for (uint32_t g = 0; g < gc.num_gates; g++) {
        uint64_t wire_a = (uint64_t)(g * 2);
        uint64_t wire_b = (uint64_t)(g * 2 + 1);
        uint64_t wire_out = (uint64_t)(g + 10);
        mpc_garble_and_gate(&gc.gates[g], wire_a, wire_b, wire_out);
    }

    mpc_garble_print_circuit(&gc);

    mpc_garbled_key_t keys[2];
    mpc_garble_encode_input(&keys[0], 1, 0);
    mpc_garble_encode_input(&keys[1], 1, 1);

    uint64_t output;
    mpc_garble_evaluate_circuit(&output, &gc, keys, 2);
    int decoded = mpc_garble_decode_output(output, 0);
    printf("Evaluate: output=%016llx decoded=%d\n",
           (unsigned long long)output, decoded);
}

static void demo_oblivious_transfer(void) {
    printf("\n=== 1-out-of-2 Oblivious Transfer ===\n");

    mpc_ot_sender_t sender;
    mpc_ot_sender_init(&sender);

    mpc_ot_message_t m0, m1;
    memset(&m0, 0, sizeof(m0));
    memset(&m1, 0, sizeof(m1));
    m0.limbs[0] = 0xDEADBEEFCAFEULL;
    m1.limbs[0] = 0xBAADF00DFEEDULL;

    mpc_ot_send_messages(&sender, &m0, &m1);
    mpc_ot_print_messages(&sender);

    for (int choice = 0; choice < 2; choice++) {
        mpc_ot_receiver_t receiver;
        mpc_ot_receiver_choose(&receiver, (uint64_t)choice, sender.public_key);

        uint64_t result;
        mpc_ot_1_of_2(&result, &m0.limbs[0], &m1.limbs[0], (uint64_t)choice);
        printf("Receiver(choice=%d): got 0x%016llx\n", choice, (unsigned long long)result);
    }
}

static void demo_spdz(void) {
    printf("\n=== SPDZ Protocol ===\n");

    mpc_spdz_ctx_t ctx;
    mpc_spdz_init(&ctx, 4, 1234567);

    mpc_spdz_share(&ctx, 0, 100);
    mpc_spdz_share(&ctx, 1, 200);
    mpc_spdz_share(&ctx, 2, 300);
    mpc_spdz_share(&ctx, 3, 400);

    printf("SPDZ shares: %lld, %lld, %lld, %lld (MAC key=%lld)\n",
           (long long)ctx.shares[0].value, (long long)ctx.shares[1].value,
           (long long)ctx.shares[2].value, (long long)ctx.shares[3].value,
           (long long)ctx.global_mac_key);

    int64_t sum;
    int ret = mpc_spdz_reconstruct(&sum, &ctx);
    printf("Reconstruct: sum=%lld mac_ok=%s\n",
           (long long)sum, ret == 0 ? "YES" : "NO");

    mpc_spdz_share_t r;
    mpc_spdz_add(&r, &ctx.shares[0], &ctx.shares[1]);
    printf("Share[0] + Share[1]: value=%lld mac=%lld\n",
           (long long)r.value, (long long)r.mac);

    int verify = mpc_spdz_verify(&ctx);
    printf("SPDZ verify: %s\n", verify == 0 ? "PASS" : "FAIL");
}

static void demo_multi_party_sum(void) {
    printf("\n=== Multi-Party Sum (privacy-preserving) ===\n");

    int64_t inputs[] = {15, 22, 8, 41, 33, 19, 56, 7};
    uint32_t n = 8;

    printf("Individual inputs: ");
    for (uint32_t i = 0; i < n; i++) printf("%lld ", (long long)inputs[i]);
    printf("\n");

    int64_t result;
    mpc_multi_party_sum(&result, inputs, n);
    printf("MPC sum (no party reveals its input): %lld\n", (long long)result);

    int64_t expected = 0;
    for (uint32_t i = 0; i < n; i++) expected += inputs[i];
    printf("Verification: %s\n", result == expected ? "PASS" : "FAIL");
}

int main(void) {
    printf("===========================================\n");
    printf("  mini-adv-crypto: Secure Multi-Party Computation\n");
    printf("===========================================\n");

    mpc_module_version();

    demo_shamir_secret_sharing();
    demo_garbled_circuit();
    demo_oblivious_transfer();
    demo_spdz();
    demo_multi_party_sum();

    printf("\n=== All MPC examples completed ===\n");
    return 0;
}
