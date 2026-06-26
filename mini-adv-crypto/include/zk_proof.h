#ifndef ZK_PROOF_H
#define ZK_PROOF_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZK_MAX_VARS       64
#define ZK_MAX_CONSTRAINTS 128
#define ZK_MAX_DEGREE      256
#define ZK_FIELD_BITS      128
#define ZK_FIELD_LIMBS    ((ZK_FIELD_BITS + 63) / 64)

typedef struct {
    uint64_t limbs[ZK_FIELD_LIMBS];
} zk_field_t;

typedef struct {
    uint32_t num_vars;
    uint32_t num_constraints;
    int32_t  A[ZK_MAX_CONSTRAINTS][ZK_MAX_VARS + 1];
    int32_t  B[ZK_MAX_CONSTRAINTS][ZK_MAX_VARS + 1];
    int32_t  C[ZK_MAX_CONSTRAINTS][ZK_MAX_VARS + 1];
} zk_r1cs_t;

typedef struct {
    uint32_t   degree;
    int32_t    coeff_a[ZK_MAX_DEGREE];
    int32_t    coeff_b[ZK_MAX_DEGREE];
    int32_t    coeff_c[ZK_MAX_DEGREE];
    int32_t    target[ZK_MAX_DEGREE];
} zk_qap_t;

typedef struct {
    uint32_t   num_vars;
    uint32_t   num_inputs;
    zk_field_t toxic_waste;
} zk_setup_info_t;

typedef struct {
    uint32_t   num_vars;
    uint32_t   num_inputs;
    zk_field_t pk_alpha;
    zk_field_t pk_beta;
    zk_field_t pk_gamma;
    zk_field_t pk_delta;
    zk_field_t vk_alpha_beta;
    zk_field_t vk_gamma_abc[ZK_MAX_VARS + 1];
} zk_proving_key_t;

typedef struct {
    uint32_t   num_inputs;
    zk_field_t vk_alpha_beta;
    zk_field_t vk_gamma_abc[ZK_MAX_VARS + 1];
} zk_verification_key_t;

typedef struct {
    zk_field_t pi_a;
    zk_field_t pi_b;
    zk_field_t pi_c;
    zk_field_t pi_z;
} zk_groth16_proof_t;

typedef enum {
    ZK_PROTOCOL_GROTH16 = 0,
    ZK_PROTOCOL_PINOCCIO = 1,
    ZK_PROTOCOL_STARK   = 2
} zk_protocol_t;

typedef struct {
    uint32_t    width;
    uint32_t    height;
    zk_field_t  trace[ZK_MAX_VARS][ZK_MAX_DEGREE];
    zk_field_t  merkle_root[4];
} zk_stark_trace_t;

int       zk_field_zero(zk_field_t *f);
int       zk_field_one(zk_field_t *f);
int       zk_field_add(zk_field_t *r, const zk_field_t *a, const zk_field_t *b);
int       zk_field_mul(zk_field_t *r, const zk_field_t *a, const zk_field_t *b);
int       zk_field_neg(zk_field_t *r, const zk_field_t *a);
int       zk_field_inv(zk_field_t *r, const zk_field_t *a);
int       zk_field_eq(const zk_field_t *a, const zk_field_t *b);
int       zk_field_from_u64(zk_field_t *f, uint64_t val);
void      zk_field_print(const char *label, const zk_field_t *f);

int       zk_r1cs_init(zk_r1cs_t *r1cs, uint32_t num_vars, uint32_t num_constraints);
int       zk_r1cs_add_constraint(zk_r1cs_t *r1cs, uint32_t idx,
                                 const int32_t *a, const int32_t *b, const int32_t *c);
int       zk_r1cs_verify_witness(const zk_r1cs_t *r1cs, const int32_t *witness);
int       zk_r1cs_print(const zk_r1cs_t *r1cs);

int       zk_qap_from_r1cs(zk_qap_t *qap, const zk_r1cs_t *r1cs);
int       zk_qap_evaluate(const zk_qap_t *qap, int32_t x,
                          int32_t *out_a, int32_t *out_b, int32_t *out_c, int32_t *out_t);
int       zk_qap_verify_division(const zk_qap_t *qap, const int32_t *witness, const int32_t *h);

int       zk_trusted_setup(zk_proving_key_t *pk, zk_verification_key_t *vk,
                           const zk_r1cs_t *r1cs, const zk_setup_info_t *info);
int       zk_setup_toxic_mpc(zk_proving_key_t *pk, uint32_t num_participants);
void      zk_proving_key_free(zk_proving_key_t *pk);
void      zk_verification_key_free(zk_verification_key_t *vk);

int       zk_groth16_prove(zk_groth16_proof_t *proof, const zk_proving_key_t *pk,
                           const int32_t *witness, uint32_t num_pub_inputs);
int       zk_groth16_verify(const zk_groth16_proof_t *proof,
                            const zk_verification_key_t *vk,
                            const int32_t *pub_inputs, uint32_t num_inputs);
void      zk_groth16_print(const zk_groth16_proof_t *proof);

int       zk_pinocchio_prove(zk_groth16_proof_t *proof, const zk_qap_t *qap,
                             const int32_t *witness, uint32_t num_io);
int       zk_pinocchio_verify(const zk_groth16_proof_t *proof, const zk_qap_t *qap,
                              const int32_t *io, uint32_t num_io);

int       zk_stark_trace_commit(zk_stark_trace_t *trace, const int32_t *exec_trace,
                                uint32_t steps, uint32_t regs);
int       zk_stark_merkle_root(zk_field_t root[4], const zk_stark_trace_t *trace);
int       zk_stark_fri_verify(const zk_stark_trace_t *trace, uint32_t queries);

void      zk_module_version(void);

#ifdef __cplusplus
}
#endif

#endif
