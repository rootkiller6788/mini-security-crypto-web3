#ifndef PET_TOOLS_H
#define PET_TOOLS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- PET landscape ---------- */

typedef enum {
    PET_ON_DEVICE      = 0,
    PET_DP             = 1,
    PET_SMPC           = 2,
    PET_FEDERATED      = 3,
    PET_TEE            = 4,
    PET_ZKP            = 5,
    PET_ANON_CREDS     = 6,
    PET_PSEUDONYM      = 7,
    PET_HOMOMORPHIC    = 8,
    PET_DATAMIN        = 9,
    PET_PRIVACY_BY_DESIGN = 10,
    PET_COUNT
} PETCategory;

typedef struct {
    const char *name;
    PETCategory category;
    int         maturity;    /* 1-5 */
    int         overhead;    /* 1-5, higher = more */
    int         privacy_strength;
    const char *use_case;
} PETDescriptor;

const PETDescriptor *pet_get_descriptor(PETCategory cat);
void                 pet_print_landscape(void);

/* ---------- on-device processing ---------- */

typedef struct {
    double  *local_data;
    size_t   num_features;
    size_t   num_samples;
    int      processed_on_device;
    int      data_sent_to_server;  /* bytes transmitted */
} OnDeviceProcessor;

void odproc_init(            OnDeviceProcessor *odp, size_t num_features,
                             size_t num_samples);
void odproc_compute_local(   OnDeviceProcessor *odp, double *result, size_t result_len);
int  odproc_minimize_upload( OnDeviceProcessor *odp, double *essential_data,
                             size_t *essential_len, double budget);
void odproc_free(            OnDeviceProcessor *odp);

/* ---------- differential privacy reports ---------- */

typedef struct {
    double  true_value;
    double  perturbed_value;
    double  epsilon_used;
    double  confidence_interval[2];
    int     mechanism;
    uint8_t *serialized_report;
    size_t   report_len;
} DPReport;

void dprep_init(             DPReport *report);
void dprep_generate(         DPReport *report, double true_value, double sensitivity,
                             double epsilon, int mechanism, uint64_t seed);
int  dprep_verify(           const DPReport *report, double epsilon);
void dprep_serialize(        const DPReport *report, uint8_t *buf, size_t *len);
void dprep_deserialize(      DPReport *report, const uint8_t *buf, size_t len);
void dprep_free(             DPReport *report);

/* ---------- secure enclave computation (TEE abstraction) ---------- */

typedef struct {
    uint8_t *enclave_memory;
    size_t   memory_size;
    uint8_t *sealed_data;
    size_t   sealed_size;
    int      attestation_verified;
    uint8_t  measurement[32];   /* MRENCLAVE-style */
} SecureEnclave;

void enclave_init(           SecureEnclave *se, size_t memory_size);
int  enclave_attest(         SecureEnclave *se, const uint8_t *expected_measurement);
void enclave_load_data(      SecureEnclave *se, const uint8_t *data, size_t len);
void enclave_compute(        SecureEnclave *se,
                             void (*func)(uint8_t *, size_t, void *), void *ctx);
void enclave_seal(           SecureEnclave *se, uint8_t *sealed_out, size_t *len);
int  enclave_verify_sealing( SecureEnclave *se, const uint8_t *sealed, size_t len);
void enclave_free(           SecureEnclave *se);

/* ---------- anonymous credentials ---------- */

typedef struct {
    uint8_t *credential;
    size_t   cred_len;
    uint8_t *blind_factor;
    size_t   blind_len;
    uint8_t *issuer_pubkey;
    size_t   pubkey_len;
    int      revealed_attrs[16];
    int      num_revealed;
} AnonCredential;

void anoncred_init(          AnonCredential *ac, const uint8_t *issuer_pubkey,
                             size_t pubkey_len);
void anoncred_request(       AnonCredential *ac, const uint8_t *attributes,
                             size_t num_attrs, size_t attr_len);
void anoncred_issue(         AnonCredential *ac, const uint8_t *issuer_secret,
                             size_t secret_len);
int  anoncred_present(       AnonCredential *ac, const int *attrs_to_reveal,
                             int num_reveal, uint8_t *proof, size_t *proof_len);
int  anoncred_verify_presentation(const uint8_t *proof, size_t proof_len,
                                  const uint8_t *issuer_pubkey, size_t pubkey_len);
void anoncred_free(          AnonCredential *ac);

/* ---------- zero-knowledge proofs for identity ---------- */

typedef struct {
    uint8_t *witness;
    size_t   witness_len;
    uint8_t *statement;
    size_t   statement_len;
    uint8_t *proof;
    size_t   proof_len;
    int      proof_type;  /* 0=Schnorr, 1=Sigma, 2=Groth16-style */
} ZKIdentityProof;

void zkidp_init(             ZKIdentityProof *zkp, int proof_type);
void zkidp_set_statement(    ZKIdentityProof *zkp, const uint8_t *stmt, size_t len);
void zkidp_set_witness(      ZKIdentityProof *zkp, const uint8_t *wit, size_t len);
int  zkidp_prove(            ZKIdentityProof *zkp);
int  zkidp_verify(           const ZKIdentityProof *zkp);
int  zkidp_range_proof(      const ZKIdentityProof *zkp, int64_t value,
                             int64_t lo, int64_t hi, uint8_t *pf, size_t *len);
void zkidp_free(             ZKIdentityProof *zkp);

/* ---------- verifiable credentials (W3C) ---------- */

typedef struct {
    uint8_t *vc_json;
    size_t   vc_len;
    uint8_t *issuer_did;
    size_t   did_len;
    uint8_t *proof_jws;
    size_t   proof_len;
    uint8_t *revocation_list;
    size_t   revoke_len;
} VerifiableCredential;

void vc_create(              VerifiableCredential *vc, const char *subject,
                             const char **claims, const char **values, int num_claims);
int  vc_issue(               VerifiableCredential *vc, const uint8_t *issuer_key,
                             size_t key_len);
int  vc_verify(              const VerifiableCredential *vc, const uint8_t *issuer_pub);
int  vc_check_revocation(    const VerifiableCredential *vc,
                             const uint8_t *revocation_registry);
void vc_free(                VerifiableCredential *vc);

/* ---------- data minimization ---------- */

typedef struct {
    double   *data;
    size_t    total_features;
    size_t    minimized_features;
    int      *feature_mask;      /* 1=retained, 0=dropped */
    double    information_loss;
} DataMinimizer;

void datamin_init(           DataMinimizer *dm, size_t num_features);
void datamin_collect_purpose(const double *feature_importance, size_t n, double threshold,
                             DataMinimizer *dm);
void datamin_apply(          DataMinimizer *dm, const double *input,
                             double *minimized);
void datamin_audit(          const DataMinimizer *dm, char *audit_log, size_t max_len);
void datamin_free(           DataMinimizer *dm);

/* ---------- privacy by design ---------- */

typedef struct {
    int    privacy_requirements[8];
    int    num_requirements;
    int    data_flow_map[16][16];
    int    num_data_nodes;
    double risk_scores[16];
    int    compliance_checklist[10];
} PbDDesign;

void pbd_init(               PbDDesign *pbd);
void pbd_add_requirement(    PbDDesign *pbd, int req_id);
void pbd_map_dataflow(       PbDDesign *pbd, int source, int sink, int allowed);
void pbd_assess_risk(        PbDDesign *pbd);
int  pbd_validate_design(    const PbDDesign *pbd, char *report, size_t max_len);
int  pbd_check_gdpr(         const PbDDesign *pbd);

/* ---------- PET orchestrator ---------- */

typedef struct {
    PETDescriptor *enabled_pets;
    int            num_enabled;
    double         overall_privacy_budget;
    int            audit_enabled;
    char           audit_log[4096];
    int            log_len;
} PETOrchestrator;

void petorch_init(           PETOrchestrator *orch);
void petorch_enable(         PETOrchestrator *orch, PETCategory cat);
void petorch_disable(        PETOrchestrator *orch, PETCategory cat);
void petorch_assess_privacy( const PETOrchestrator *orch, double *score);
int  petorch_audit_log_event(PETOrchestrator *orch, const char *event);

#ifdef __cplusplus
}
#endif

#endif /* PET_TOOLS_H */
