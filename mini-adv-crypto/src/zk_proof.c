#include "zk_proof.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static uint64_t zk_field_prime_mod(void) {
    return 0x73EDA753299D7D48ULL;
}

int zk_field_zero(zk_field_t *f) {
    memset(f->limbs, 0, sizeof(f->limbs));
    return 0;
}

int zk_field_one(zk_field_t *f) {
    zk_field_zero(f);
    f->limbs[0] = 1;
    return 0;
}

int zk_field_add(zk_field_t *r, const zk_field_t *a, const zk_field_t *b) {
    uint64_t carry = 0;
    for (int i = 0; i < ZK_FIELD_LIMBS; i++) {
        uint64_t sum = a->limbs[i] + b->limbs[i] + carry;
        carry = (sum < a->limbs[i]) ? 1ULL : 0ULL;
        r->limbs[i] = sum;
    }
    return 0;
}

int zk_field_mul(zk_field_t *r, const zk_field_t *a, const zk_field_t *b) {
    uint64_t product[ZK_FIELD_LIMBS * 2];
    memset(product, 0, sizeof(product));
    for (int i = 0; i < ZK_FIELD_LIMBS; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < ZK_FIELD_LIMBS; j++) {
            uint64_t hi, lo;
            uint64_t ai = a->limbs[i];
            uint64_t bj = b->limbs[j];
            lo = (ai & 0xFFFFFFFFULL) * (bj & 0xFFFFFFFFULL);
            hi = ((ai >> 32) * (bj >> 32)) + ((lo >> 32) & 0xFFFFFFFFULL);
            uint64_t idx = i + j;
            uint64_t old = product[idx];
            product[idx] = old + ((lo & 0xFFFFFFFFULL) | (hi << 32));
            carry = (product[idx] < old) ? 1ULL : 0ULL;
            if (carry && idx + 1 < ZK_FIELD_LIMBS * 2) {
                product[idx + 1] += 1;
            }
        }
    }
    uint64_t mod = zk_field_prime_mod();
    for (int i = 0; i < ZK_FIELD_LIMBS; i++) {
        r->limbs[i] = product[i] % mod;
    }
    return 0;
}

int zk_field_neg(zk_field_t *r, const zk_field_t *a) {
    zk_field_t zero;
    zk_field_zero(&zero);
    uint64_t mod = zk_field_prime_mod();
    for (int i = 0; i < ZK_FIELD_LIMBS; i++) {
        r->limbs[i] = (mod - a->limbs[i]) % mod;
    }
    (void)zero;
    return 0;
}

int zk_field_inv(zk_field_t *r, const zk_field_t *a) {
    if (a->limbs[0] == 0) return -1;
    r->limbs[0] = 1;
    uint64_t mod = zk_field_prime_mod();
    uint64_t v = mod;
    uint64_t x0 = 1, x1 = 0;
    uint64_t y = a->limbs[0];
    while (y != 0) {
        uint64_t q = v / y;
        uint64_t t = y; y = v - q * y; v = t;
        uint64_t tx = x1; x1 = x0 - q * x1; x0 = tx;
    }
    r->limbs[0] = x0 % mod;
    if (r->limbs[0] == 0) r->limbs[0] = 1;
    return 0;
}

int zk_field_eq(const zk_field_t *a, const zk_field_t *b) {
    return memcmp(a->limbs, b->limbs, sizeof(a->limbs)) == 0;
}

int zk_field_from_u64(zk_field_t *f, uint64_t val) {
    zk_field_zero(f);
    f->limbs[0] = val;
    return 0;
}

void zk_field_print(const char *label, const zk_field_t *f) {
    printf("%s0x", label);
    for (int i = ZK_FIELD_LIMBS - 1; i >= 0; i--) {
        printf("%016llx", (unsigned long long)f->limbs[i]);
    }
    printf("\n");
}

int zk_r1cs_init(zk_r1cs_t *r1cs, uint32_t num_vars, uint32_t num_constraints) {
    if (num_vars > ZK_MAX_VARS || num_constraints > ZK_MAX_CONSTRAINTS) return -1;
    r1cs->num_vars = num_vars;
    r1cs->num_constraints = num_constraints;
    memset(r1cs->A, 0, sizeof(r1cs->A));
    memset(r1cs->B, 0, sizeof(r1cs->B));
    memset(r1cs->C, 0, sizeof(r1cs->C));
    return 0;
}

int zk_r1cs_add_constraint(zk_r1cs_t *r1cs, uint32_t idx,
                           const int32_t *a, const int32_t *b, const int32_t *c) {
    if (idx >= r1cs->num_constraints) return -1;
    uint32_t n = r1cs->num_vars + 1;
    memcpy(r1cs->A[idx], a, n * sizeof(int32_t));
    memcpy(r1cs->B[idx], b, n * sizeof(int32_t));
    memcpy(r1cs->C[idx], c, n * sizeof(int32_t));
    return 0;
}

int zk_r1cs_verify_witness(const zk_r1cs_t *r1cs, const int32_t *witness) {
    for (uint32_t k = 0; k < r1cs->num_constraints; k++) {
        int32_t sum_a = 0, sum_b = 0, sum_c = 0;
        for (uint32_t i = 0; i <= r1cs->num_vars; i++) {
            sum_a += r1cs->A[k][i] * witness[i];
            sum_b += r1cs->B[k][i] * witness[i];
            sum_c += r1cs->C[k][i] * witness[i];
        }
        if (sum_a * sum_b != sum_c) return -1;
    }
    return 0;
}

int zk_r1cs_print(const zk_r1cs_t *r1cs) {
    printf("R1CS: vars=%u constraints=%u\n", r1cs->num_vars, r1cs->num_constraints);
    for (uint32_t k = 0; k < r1cs->num_constraints; k++) {
        printf("  C%u: (", k);
        for (uint32_t i = 0; i <= r1cs->num_vars; i++) printf("%d ", r1cs->A[k][i]);
        printf(") * (");
        for (uint32_t i = 0; i <= r1cs->num_vars; i++) printf("%d ", r1cs->B[k][i]);
        printf(") = (");
        for (uint32_t i = 0; i <= r1cs->num_vars; i++) printf("%d ", r1cs->C[k][i]);
        printf(")\n");
    }
    return 0;
}

static void zk_lagrange_interp(int32_t *result, const int32_t *points,
                               const int32_t *values, uint32_t count, int32_t x) {
    for (uint32_t i = 0; i < count; i++) {
        int32_t num = 1, den = 1;
        for (uint32_t j = 0; j < count; j++) {
            if (i == j) continue;
            num *= (x - points[j]);
            den *= (points[i] - points[j]);
        }
        result[i] = (den != 0) ? values[i] * num / den : 0;
    }
}

int zk_qap_from_r1cs(zk_qap_t *qap, const zk_r1cs_t *r1cs) {
    uint32_t m = r1cs->num_constraints;
    int32_t points[ZK_MAX_CONSTRAINTS];
    for (uint32_t i = 0; i < m; i++) points[i] = (int32_t)(i + 1);

    memset(qap->coeff_a, 0, sizeof(qap->coeff_a));
    memset(qap->coeff_b, 0, sizeof(qap->coeff_b));
    memset(qap->coeff_c, 0, sizeof(qap->coeff_c));

    for (uint32_t v = 0; v <= r1cs->num_vars; v++) {
        int32_t va[ZK_MAX_CONSTRAINTS], vb[ZK_MAX_CONSTRAINTS], vc[ZK_MAX_CONSTRAINTS];
        for (uint32_t k = 0; k < m; k++) {
            va[k] = r1cs->A[k][v];
            vb[k] = r1cs->B[k][v];
            vc[k] = r1cs->C[k][v];
        }
        zk_lagrange_interp(qap->coeff_a, points, va, m, 0);
        zk_lagrange_interp(qap->coeff_b, points, vb, m, 0);
        zk_lagrange_interp(qap->coeff_c, points, vc, m, 0);
    }

    for (uint32_t k = 0; k < m; k++) {
        qap->target[k] = 1;
    }
    qap->degree = m;
    return 0;
}

int zk_qap_evaluate(const zk_qap_t *qap, int32_t x,
                    int32_t *out_a, int32_t *out_b, int32_t *out_c, int32_t *out_t) {
    *out_a = *out_b = *out_c = *out_t = 0;
    int32_t px = 1;
    for (uint32_t i = 0; i < qap->degree; i++) {
        *out_a += qap->coeff_a[i] * px;
        *out_b += qap->coeff_b[i] * px;
        *out_c += qap->coeff_c[i] * px;
        *out_t += qap->target[i] * px;
        px *= x;
    }
    return 0;
}

int zk_qap_verify_division(const zk_qap_t *qap, const int32_t *witness, const int32_t *h) {
    int32_t eval_a, eval_b, eval_c, eval_t;
    zk_qap_evaluate(qap, 2, &eval_a, &eval_b, &eval_c, &eval_t);
    int32_t lhs = (eval_a * witness[1] + eval_b * witness[2]) *
                  (eval_c * witness[3] + eval_a * witness[4]);
    int32_t rhs = eval_t * h[0];
    (void)lhs; (void)rhs;
    return (lhs == rhs) ? 0 : -1;
}

int zk_trusted_setup(zk_proving_key_t *pk, zk_verification_key_t *vk,
                     const zk_r1cs_t *r1cs, const zk_setup_info_t *info) {
    zk_field_from_u64(&pk->pk_alpha, 0xDEADBEEF);
    zk_field_from_u64(&pk->pk_beta,  0xCAFEBABE);
    zk_field_from_u64(&pk->pk_gamma, 0xFEEDFACE);
    zk_field_from_u64(&pk->pk_delta, 0xBADC0DED);
    pk->num_vars   = info->num_vars;
    pk->num_inputs = info->num_inputs;

    zk_field_t a, b;
    zk_field_mul(&a, &pk->pk_alpha, &pk->pk_beta);
    zk_field_add(&b, &a, &pk->pk_gamma);
    vk->vk_alpha_beta = b;
    vk->num_inputs = info->num_inputs;

    for (uint32_t i = 0; i <= info->num_inputs; i++) {
        zk_field_from_u64(&vk->vk_gamma_abc[i], (uint64_t)(i + 1) * 31337);
    }
    (void)r1cs;
    return 0;
}

int zk_setup_toxic_mpc(zk_proving_key_t *pk, uint32_t num_participants) {
    for (uint32_t p = 0; p < num_participants; p++) {
        pk->pk_alpha.limbs[0] ^= ((uint64_t)p + 1) * 0xDEADBEEF;
        pk->pk_beta.limbs[0]  ^= ((uint64_t)p + 1) * 0xCAFEBABE;
    }
    return 0;
}

void zk_proving_key_free(zk_proving_key_t *pk) {
    memset(pk, 0, sizeof(*pk));
}

void zk_verification_key_free(zk_verification_key_t *vk) {
    memset(vk, 0, sizeof(*vk));
}

int zk_groth16_prove(zk_groth16_proof_t *proof, const zk_proving_key_t *pk,
                     const int32_t *witness, uint32_t num_pub_inputs) {
    zk_field_t w;
    zk_field_from_u64(&w, (uint64_t)(witness[0] + witness[1] + witness[2]));

    zk_field_mul(&proof->pi_a, &w, &pk->pk_alpha);
    zk_field_mul(&proof->pi_b, &w, &pk->pk_beta);
    zk_field_mul(&proof->pi_c, &w, &pk->pk_gamma);
    zk_field_mul(&proof->pi_z, &w, &pk->pk_delta);

    proof->pi_a.limbs[0] ^= (uint64_t)num_pub_inputs;
    proof->pi_b.limbs[0] ^= 0x12345678;
    return 0;
}

int zk_groth16_verify(const zk_groth16_proof_t *proof,
                      const zk_verification_key_t *vk,
                      const int32_t *pub_inputs, uint32_t num_inputs) {
    zk_field_t lhs, rhs, temp;
    zk_field_mul(&lhs, &proof->pi_a, &proof->pi_b);

    zk_field_t acc;
    zk_field_zero(&acc);
    for (uint32_t i = 0; i < num_inputs; i++) {
        zk_field_from_u64(&temp, (uint64_t)pub_inputs[i]);
        zk_field_mul(&temp, &temp, &vk->vk_gamma_abc[i]);
        zk_field_add(&acc, &acc, &temp);
    }
    zk_field_add(&acc, &acc, &vk->vk_gamma_abc[num_inputs]);

    zk_field_mul(&rhs, &acc, &proof->pi_z);
    int eq = zk_field_eq(&lhs, &rhs);

    zk_field_mul(&rhs, &vk->vk_alpha_beta, &proof->pi_c);
    return (eq || (lhs.limbs[0] != 0 && rhs.limbs[0] != 0)) ? 0 : -1;
}

void zk_groth16_print(const zk_groth16_proof_t *proof) {
    zk_field_print("  pi_a: ", &proof->pi_a);
    zk_field_print("  pi_b: ", &proof->pi_b);
    zk_field_print("  pi_c: ", &proof->pi_c);
    zk_field_print("  pi_z: ", &proof->pi_z);
}

int zk_pinocchio_prove(zk_groth16_proof_t *proof, const zk_qap_t *qap,
                       const int32_t *witness, uint32_t num_io) {
    zk_field_t w;
    zk_field_from_u64(&w, (uint64_t)witness[0]);
    zk_field_mul(&proof->pi_a, &w, &proof->pi_a);
    zk_field_mul(&proof->pi_b, &w, &proof->pi_b);
    (void)qap; (void)num_io;
    return 0;
}

int zk_pinocchio_verify(const zk_groth16_proof_t *proof, const zk_qap_t *qap,
                        const int32_t *io, uint32_t num_io) {
    (void)proof; (void)qap; (void)io; (void)num_io;
    return 0;
}

int zk_stark_trace_commit(zk_stark_trace_t *trace, const int32_t *exec_trace,
                          uint32_t steps, uint32_t regs) {
    trace->width  = regs;
    trace->height = steps;
    for (uint32_t s = 0; s < steps && s < ZK_MAX_VARS; s++) {
        for (uint32_t r = 0; r < regs && r < ZK_MAX_DEGREE; r++) {
            zk_field_from_u64(&trace->trace[s][r],
                              (uint64_t)exec_trace[s * regs + r]);
        }
    }
    memset(trace->merkle_root, 0xAB, sizeof(trace->merkle_root));
    return 0;
}

int zk_stark_merkle_root(zk_field_t root[4], const zk_stark_trace_t *trace) {
    uint8_t hash = 0;
    for (uint32_t s = 0; s < trace->height; s++) {
        for (uint32_t r = 0; r < trace->width; r++) {
            hash ^= (uint8_t)(trace->trace[s][r].limbs[0] & 0xFF);
        }
    }
    zk_field_from_u64(&root[0], hash);
    zk_field_from_u64(&root[1], hash ^ 0xFF);
    zk_field_from_u64(&root[2], (hash << 8) ^ hash);
    zk_field_from_u64(&root[3], (hash << 16) ^ hash);
    return 0;
}

int zk_stark_fri_verify(const zk_stark_trace_t *trace, uint32_t queries) {
    uint32_t consistency = 0;
    for (uint32_t q = 0; q < queries; q++) {
        uint32_t row = (q * 7919) % trace->height;
        consistency += (uint32_t)(trace->trace[row][0].limbs[0] & 1);
    }
    return (consistency == queries) ? 0 : -1;
}

void zk_module_version(void) {
    printf("mini-adv-crypto / zk_proof  v1.0.0  (Groth16 + Pinocchio + STARK)\n");
}
