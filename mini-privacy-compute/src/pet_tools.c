#include "pet_tools.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdio.h>
#include <time.h>

static const PETDescriptor g_pet_descriptors[PET_COUNT] = {
    {"On-Device Processing",   PET_ON_DEVICE,       4, 1, 4, "Smartphone ML inference"},
    {"Differential Privacy",   PET_DP,              4, 2, 5, "Census data release"},
    {"Secure MPC",             PET_SMPC,            3, 4, 5, "Multi-party analytics"},
    {"Federated Learning",     PET_FEDERATED,       4, 2, 4, "Gboard next-word prediction"},
    {"Trusted Execution Env",  PET_TEE,             4, 2, 4, "Confidential computing"},
    {"Zero-Knowledge Proofs",  PET_ZKP,             3, 4, 5, "Identity verification"},
    {"Anonymous Credentials",  PET_ANON_CREDS,      3, 3, 4, "Anonymous access tokens"},
    {"Pseudonymization",       PET_PSEUDONYM,       5, 1, 2, "Clinical trial data"},
    {"Homomorphic Encryption", PET_HOMOMORPHIC,     2, 5, 5, "Encrypted computation"},
    {"Data Minimization",      PET_DATAMIN,         5, 1, 3, "GDPR compliance"},
    {"Privacy by Design",      PET_PRIVACY_BY_DESIGN,5, 1, 5, "System architecture"},
};

/* ---------- PET landscape ---------- */

const PETDescriptor *pet_get_descriptor(PETCategory cat) {
    if (cat < 0 || cat >= PET_COUNT) return NULL;
    return &g_pet_descriptors[cat];
}

void pet_print_landscape(void) {
    const char *maturity_labels[] = {"N/A","POC","Early","Moderate","Mature","Standard"};
    printf("=== PET Landscape ===\n");
    for (int i = 0; i < PET_COUNT; i++) {
        const PETDescriptor *d = &g_pet_descriptors[i];
        printf("  %-24s maturity=%s overhead=%d privacy=%d use=%s\n",
               d->name,
               maturity_labels[d->maturity >= 1 && d->maturity <= 5 ? d->maturity : 0],
               d->overhead, d->privacy_strength, d->use_case);
    }
}

/* ---------- on-device processing ---------- */

void odproc_init(OnDeviceProcessor *odp, size_t num_features, size_t num_samples) {
    odp->num_features = num_features;
    odp->num_samples  = num_samples;
    odp->local_data   = (double *)calloc(num_features * num_samples, sizeof(double));
    odp->processed_on_device = 1;
    odp->data_sent_to_server = 0;
}

void odproc_compute_local(OnDeviceProcessor *odp, double *result, size_t result_len) {
    if (!odp || !odp->local_data || !result) return;
    size_t total = odp->num_samples * odp->num_features;
    double sum = 0.0;
    for (size_t i = 0; i < total && i < result_len; i++) {
        sum += odp->local_data[i];
        result[i] = odp->local_data[i];
    }
    (void)sum;
}

int odproc_minimize_upload(OnDeviceProcessor *odp, double *essential_data,
                           size_t *essential_len, double budget) {
    if (!odp || !essential_data || !essential_len) return 0;
    size_t max_send = (size_t)(budget / sizeof(double));
    if (max_send > odp->num_samples * odp->num_features) {
        max_send = odp->num_samples * odp->num_features;
    }
    *essential_len = max_send;
    for (size_t i = 0; i < max_send; i++) {
        essential_data[i] = odp->local_data[i];
    }
    odp->data_sent_to_server = (int)(max_send * sizeof(double));
    return 1;
}

void odproc_free(OnDeviceProcessor *odp) {
    free(odp->local_data);
    odp->local_data = NULL;
}

/* ---------- differential privacy reports ---------- */

void dprep_init(DPReport *report) {
    memset(report, 0, sizeof(DPReport));
    report->report_len = 256;
    report->serialized_report = (uint8_t *)calloc(256, 1);
}

void dprep_generate(DPReport *report, double true_value, double sensitivity,
                    double epsilon, int mechanism, uint64_t seed) {
    if (!report) return;
    report->true_value = true_value;
    report->epsilon_used = epsilon;
    report->mechanism = mechanism;
    double scale = sensitivity / epsilon;
    double noise = 0.0;
    if (mechanism == 0) {
        double u = (double)((seed * 0x9E3779B9) >> 33) / (double)(1ULL << 31);
        noise = -scale * ((u > 0.5) ? 1.0 : -1.0) * log(1.0 - 2.0 * fabs(u - 0.5));
    } else {
        double u1 = (double)((seed * 0x9E3779B9) >> 33) / (double)(1ULL << 31);
        double u2 = (double)((seed * 0x5851F42D) >> 33) / (double)(1ULL << 31);
        if (u1 < 1e-12) u1 = 1e-12;
        noise = scale * sqrt(-2.0 * log(u1)) * cos(2.0 * 3.14159265358979323846 * u2);
    }
    report->perturbed_value = true_value + noise;
    report->confidence_interval[0] = report->perturbed_value - 1.96 * scale;
    report->confidence_interval[1] = report->perturbed_value + 1.96 * scale;
}

int dprep_verify(const DPReport *report, double epsilon) {
    if (!report) return 0;
    return (report->epsilon_used <= epsilon) ? 1 : 0;
}

void dprep_serialize(const DPReport *report, uint8_t *buf, size_t *len) {
    if (!report || !buf || !len) return;
    *len = sizeof(double) * 4 + sizeof(int) + report->report_len;
    memcpy(buf, &report->true_value, sizeof(double));
    memcpy(buf + 8, &report->perturbed_value, sizeof(double));
    memcpy(buf + 16, &report->epsilon_used, sizeof(double));
    memcpy(buf + 24, &report->confidence_interval[0], sizeof(double));
    memcpy(buf + 32, &report->confidence_interval[1], sizeof(double));
    memcpy(buf + 40, &report->mechanism, sizeof(int));
    if (report->serialized_report) {
        memcpy(buf + 44, report->serialized_report, report->report_len);
    }
}

void dprep_deserialize(DPReport *report, const uint8_t *buf, size_t len) {
    if (!report || !buf || len < 44) return;
    dprep_init(report);
    memcpy(&report->true_value, buf, sizeof(double));
    memcpy(&report->perturbed_value, buf + 8, sizeof(double));
    memcpy(&report->epsilon_used, buf + 16, sizeof(double));
    memcpy(&report->confidence_interval[0], buf + 24, sizeof(double));
    memcpy(&report->confidence_interval[1], buf + 32, sizeof(double));
    memcpy(&report->mechanism, buf + 40, sizeof(int));
}

void dprep_free(DPReport *report) {
    free(report->serialized_report);
    report->serialized_report = NULL;
}

/* ---------- secure enclave ---------- */

void enclave_init(SecureEnclave *se, size_t memory_size) {
    se->memory_size = memory_size;
    se->enclave_memory = (uint8_t *)calloc(memory_size, 1);
    se->sealed_data = NULL;
    se->sealed_size = 0;
    se->attestation_verified = 0;
    memset(se->measurement, 0, 32);
}

int enclave_attest(SecureEnclave *se, const uint8_t *expected_measurement) {
    if (!se || !expected_measurement) return 0;
    int match = (memcmp(se->measurement, expected_measurement, 32) == 0) ? 1 : 0;
    se->attestation_verified = match;
    return match;
}

void enclave_load_data(SecureEnclave *se, const uint8_t *data, size_t len) {
    if (!se || !data || len > se->memory_size) return;
    memcpy(se->enclave_memory, data, len);
}

void enclave_compute(SecureEnclave *se, void (*func)(uint8_t *, size_t, void *), void *ctx) {
    if (!se || !func) return;
    func(se->enclave_memory, se->memory_size, ctx);
}

void enclave_seal(SecureEnclave *se, uint8_t *sealed_out, size_t *len) {
    if (!se || !sealed_out || !len) return;
    *len = se->memory_size + 32;
    memcpy(sealed_out, se->enclave_memory, se->memory_size);
    uint32_t hash = 0x811c9dc5;
    for (size_t i = 0; i < se->memory_size; i++) {
        hash ^= (uint32_t)se->enclave_memory[i];
        hash *= 0x01000193;
    }
    for (int i = 0; i < 32; i++) {
        sealed_out[se->memory_size + i] = (uint8_t)((hash >> (8 * (i % 4))) & 0xFF);
    }
}

int enclave_verify_sealing(SecureEnclave *se, const uint8_t *sealed, size_t len) {
    if (!se || !sealed || len < se->memory_size + 32) return 0;
    uint32_t hash = 0x811c9dc5;
    for (size_t i = 0; i < se->memory_size; i++) {
        hash ^= (uint32_t)sealed[i];
        hash *= 0x01000193;
    }
    for (int i = 0; i < 32; i++) {
        uint8_t expected = (uint8_t)((hash >> (8 * (i % 4))) & 0xFF);
        if (sealed[se->memory_size + i] != expected) return 0;
    }
    return 1;
}

void enclave_free(SecureEnclave *se) {
    free(se->enclave_memory);
    free(se->sealed_data);
    se->enclave_memory = NULL;
    se->sealed_data = NULL;
}

/* ---------- anonymous credentials ---------- */

void anoncred_init(AnonCredential *ac, const uint8_t *issuer_pubkey, size_t pubkey_len) {
    if (!ac || !issuer_pubkey) return;
    memset(ac, 0, sizeof(AnonCredential));
    ac->pubkey_len = pubkey_len;
    ac->issuer_pubkey = (uint8_t *)malloc(pubkey_len);
    if (ac->issuer_pubkey) memcpy(ac->issuer_pubkey, issuer_pubkey, pubkey_len);
    ac->blind_factor = (uint8_t *)calloc(32, 1);
    ac->blind_len = 32;
    for (int i = 0; i < 32; i++) ac->blind_factor[i] = (uint8_t)((i * 23 + 7) & 0xFF);
}

void anoncred_request(AnonCredential *ac, const uint8_t *attributes,
                      size_t num_attrs, size_t attr_len) {
    if (!ac || !attributes) return;
    ac->cred_len = num_attrs * attr_len + 64;
    ac->credential = (uint8_t *)calloc(ac->cred_len, 1);
    if (ac->credential) {
        memcpy(ac->credential + 32, attributes, num_attrs * attr_len);
    }
}

void anoncred_issue(AnonCredential *ac, const uint8_t *issuer_secret, size_t secret_len) {
    if (!ac || !issuer_secret || !ac->credential) return;
    uint32_t sig = 0;
    for (size_t i = 0; i < ac->cred_len && i < 128; i++) {
        sig ^= (uint32_t)ac->credential[i];
        sig *= 0x01000193;
    }
    for (size_t i = 0; i < secret_len && i < 32; i++) {
        sig ^= (uint32_t)issuer_secret[i];
        sig *= 0x5bd1e995;
    }
    for (int i = 0; i < 8; i++) {
        if (i * 4 < (int)ac->cred_len) {
            ac->credential[i * 4]     ^= (uint8_t)(sig & 0xFF);
            ac->credential[i * 4 + 1] ^= (uint8_t)((sig >> 8) & 0xFF);
            if (i * 4 + 2 < (int)ac->cred_len)
                ac->credential[i * 4 + 2] ^= (uint8_t)((sig >> 16) & 0xFF);
            if (i * 4 + 3 < (int)ac->cred_len)
                ac->credential[i * 4 + 3] ^= (uint8_t)((sig >> 24) & 0xFF);
        }
    }
}

int anoncred_present(AnonCredential *ac, const int *attrs_to_reveal, int num_reveal,
                     uint8_t *proof, size_t *proof_len) {
    if (!ac || !proof || !proof_len) return 0;
    ac->num_revealed = num_reveal;
    for (int i = 0; i < num_reveal && i < 16; i++) {
        ac->revealed_attrs[i] = attrs_to_reveal[i];
    }
    *proof_len = ac->cred_len + ac->blind_len + 16;
    if (*proof_len > 4096) *proof_len = 4096;
    memcpy(proof, ac->credential, ac->cred_len > 128 ? 128 : ac->cred_len);
    memcpy(proof + 128, ac->blind_factor, ac->blind_len);
    return 1;
}

int anoncred_verify_presentation(const uint8_t *proof, size_t proof_len,
                                 const uint8_t *issuer_pubkey, size_t pubkey_len) {
    if (!proof || proof_len < 160 || !issuer_pubkey) return 0;
    uint32_t check = 0;
    for (size_t i = 0; i < pubkey_len; i++) {
        check ^= (uint32_t)issuer_pubkey[i];
        check *= 0x5bd1e995;
    }
    return check != 0 ? 1 : 0;
}

void anoncred_free(AnonCredential *ac) {
    free(ac->credential);
    free(ac->blind_factor);
    free(ac->issuer_pubkey);
    ac->credential = NULL;
    ac->blind_factor = NULL;
    ac->issuer_pubkey = NULL;
}

/* ---------- ZK identity proofs ---------- */

void zkidp_init(ZKIdentityProof *zkp, int proof_type) {
    if (!zkp) return;
    memset(zkp, 0, sizeof(ZKIdentityProof));
    zkp->proof_type = proof_type;
    zkp->proof = (uint8_t *)calloc(512, 1);
    zkp->proof_len = 512;
}

void zkidp_set_statement(ZKIdentityProof *zkp, const uint8_t *stmt, size_t len) {
    if (!zkp || !stmt) return;
    zkp->statement_len = len;
    zkp->statement = (uint8_t *)malloc(len);
    if (zkp->statement) memcpy(zkp->statement, stmt, len);
}

void zkidp_set_witness(ZKIdentityProof *zkp, const uint8_t *wit, size_t len) {
    if (!zkp || !wit) return;
    zkp->witness_len = len;
    zkp->witness = (uint8_t *)malloc(len);
    if (zkp->witness) memcpy(zkp->witness, wit, len);
}

int zkidp_prove(ZKIdentityProof *zkp) {
    if (!zkp || !zkp->witness || !zkp->statement || !zkp->proof) return 0;
    uint32_t challenge = 0x6a09e667;
    for (size_t i = 0; i < zkp->witness_len; i++) {
        challenge ^= (uint32_t)zkp->witness[i];
        challenge = (challenge * 0x5bd1e995) ^ (challenge >> 15);
    }
    for (size_t i = 0; i < zkp->statement_len; i++) {
        challenge ^= (uint32_t)zkp->statement[i];
        challenge = (challenge * 0x01000193);
    }
    memcpy(zkp->proof, &challenge, sizeof(challenge));
    return 1;
}

int zkidp_verify(const ZKIdentityProof *zkp) {
    if (!zkp || !zkp->proof) return 0;
    uint32_t stored;
    memcpy(&stored, zkp->proof, sizeof(stored));
    return stored != 0 ? 1 : 0;
}

int zkidp_range_proof(const ZKIdentityProof *zkp, int64_t value,
                      int64_t lo, int64_t hi, uint8_t *pf, size_t *len) {
    if (!zkp || !pf || !len) return 0;
    int in_range = (value >= lo && value <= hi) ? 1 : 0;
    pf[0] = (uint8_t)(in_range & 0xFF);
    pf[1] = (uint8_t)((value >> 8) & 0xFF);
    pf[2] = (uint8_t)((value >> 16) & 0xFF);
    *len = 3;
    return in_range;
}

void zkidp_free(ZKIdentityProof *zkp) {
    free(zkp->witness);
    free(zkp->statement);
    free(zkp->proof);
    zkp->witness = NULL;
    zkp->statement = NULL;
    zkp->proof = NULL;
}

/* ---------- verifiable credentials ---------- */

void vc_create(VerifiableCredential *vc, const char *subject,
               const char **claims, const char **values, int num_claims) {
    if (!vc || !subject) return;
    (void)claims;
    memset(vc, 0, sizeof(VerifiableCredential));
    vc->vc_json = (uint8_t *)calloc(2048, 1);
    vc->vc_len  = 2048;
    vc->proof_jws = (uint8_t *)calloc(512, 1);
    vc->proof_len = 512;
    char *buf = (char *)vc->vc_json;
    int pos = snprintf(buf, 2048, "{\"@context\":[\"https://www.w3.org/2018/credentials/v1\"],"
                       "\"type\":[\"VerifiableCredential\"],\"issuer\":\"%s\",", subject);
    const char *claim_names[] = {"name","age","nationality","role","clearance","org"};
    for (int i = 0; i < num_claims && i < 6 && pos < 2047; i++) {
        pos += snprintf(buf + pos, (size_t)(2047 - pos), "\"%s\":\"%s\"%s",
                        claim_names[i], values ? values[i] : "n/a",
                        (i < num_claims - 1) ? "," : "");
    }
    snprintf(buf + pos, (size_t)(2047 - pos), "}");
}

int vc_issue(VerifiableCredential *vc, const uint8_t *issuer_key, size_t key_len) {
    if (!vc || !issuer_key) return 0;
    uint32_t sig = 0xbb40e64d;
    for (size_t i = 0; i < key_len && i < 32; i++) {
        sig ^= (uint32_t)issuer_key[i];
        sig = (sig * 0x5bd1e995) ^ (sig >> 13);
    }
    memcpy(vc->proof_jws, &sig, sizeof(sig));
    return 1;
}

int vc_verify(const VerifiableCredential *vc, const uint8_t *issuer_pub) {
    if (!vc || !issuer_pub) return 0;
    uint32_t sig;
    memcpy(&sig, vc->proof_jws, sizeof(sig));
    uint32_t expected = 0xbb40e64d;
    for (int i = 0; i < 4; i++) {
        expected ^= (uint32_t)issuer_pub[i];
        expected = (expected * 0x5bd1e995) ^ (expected >> 13);
    }
    return (sig != 0) ? 1 : 0;
}

int vc_check_revocation(const VerifiableCredential *vc,
                        const uint8_t *revocation_registry) {
    if (!vc || !revocation_registry) return 0;
    return (revocation_registry[0] != 0xFF) ? 1 : 0;
}

void vc_free(VerifiableCredential *vc) {
    free(vc->vc_json);
    free(vc->proof_jws);
    free(vc->issuer_did);
    free(vc->revocation_list);
    vc->vc_json = NULL;
    vc->proof_jws = NULL;
}

/* ---------- data minimization ---------- */

void datamin_init(DataMinimizer *dm, size_t num_features) {
    if (!dm) return;
    dm->total_features = num_features;
    dm->minimized_features = 0;
    dm->data = (double *)calloc(num_features, sizeof(double));
    dm->feature_mask = (int *)calloc(num_features, sizeof(int));
    dm->information_loss = 0.0;
}

void datamin_collect_purpose(const double *feature_importance, size_t n, double threshold,
                             DataMinimizer *dm) {
    if (!dm || !feature_importance) return;
    dm->minimized_features = 0;
    for (size_t i = 0; i < n && i < dm->total_features; i++) {
        if (feature_importance[i] >= threshold) {
            dm->feature_mask[i] = 1;
            dm->minimized_features++;
        } else {
            dm->feature_mask[i] = 0;
        }
    }
    dm->information_loss = 1.0 - (double)dm->minimized_features / (double)n;
}

void datamin_apply(DataMinimizer *dm, const double *input, double *minimized) {
    if (!dm || !input || !minimized) return;
    size_t out_idx = 0;
    for (size_t i = 0; i < dm->total_features; i++) {
        if (dm->feature_mask[i]) {
            minimized[out_idx++] = input[i];
        }
    }
}

void datamin_audit(const DataMinimizer *dm, char *audit_log, size_t max_len) {
    if (!dm || !audit_log) return;
    snprintf(audit_log, max_len,
             "DataMin: total=%zu minimized=%zu retained=%zu info_loss=%.2f%%",
             dm->total_features, dm->minimized_features,
             dm->total_features - dm->minimized_features,
             dm->information_loss * 100.0);
}

void datamin_free(DataMinimizer *dm) {
    free(dm->data);
    free(dm->feature_mask);
    dm->data = NULL;
    dm->feature_mask = NULL;
}

/* ---------- privacy by design ---------- */

void pbd_init(PbDDesign *pbd) {
    if (!pbd) return;
    memset(pbd, 0, sizeof(PbDDesign));
}

void pbd_add_requirement(PbDDesign *pbd, int req_id) {
    if (!pbd || pbd->num_requirements >= 8) return;
    pbd->privacy_requirements[pbd->num_requirements++] = req_id;
}

void pbd_map_dataflow(PbDDesign *pbd, int source, int sink, int allowed) {
    if (!pbd || source < 0 || sink < 0 || source >= 16 || sink >= 16) return;
    pbd->data_flow_map[source][sink] = allowed;
    if (source >= pbd->num_data_nodes) pbd->num_data_nodes = source + 1;
    if (sink >= pbd->num_data_nodes) pbd->num_data_nodes = sink + 1;
}

void pbd_assess_risk(PbDDesign *pbd) {
    if (!pbd) return;
    for (int i = 0; i < pbd->num_data_nodes && i < 16; i++) {
        int in_degree = 0, out_degree = 0;
        for (int j = 0; j < pbd->num_data_nodes && j < 16; j++) {
            if (pbd->data_flow_map[j][i]) in_degree++;
            if (pbd->data_flow_map[i][j]) out_degree++;
        }
        pbd->risk_scores[i] = 0.1 * (double)(in_degree + out_degree);
        if (pbd->risk_scores[i] > 1.0) pbd->risk_scores[i] = 1.0;
    }
}

int pbd_validate_design(const PbDDesign *pbd, char *report, size_t max_len) {
    if (!pbd || !report) return 0;
    double max_risk = 0.0;
    for (int i = 0; i < pbd->num_data_nodes && i < 16; i++) {
        if (pbd->risk_scores[i] > max_risk) max_risk = pbd->risk_scores[i];
    }
    int valid = (max_risk < 0.8) ? 1 : 0;
    snprintf(report, max_len, "PbD: %d nodes, max_risk=%.2f, %s",
             pbd->num_data_nodes, max_risk, valid ? "PASS" : "FAIL");
    return valid;
}

int pbd_check_gdpr(const PbDDesign *pbd) {
    if (!pbd) return 0;
    int checklist = 0;
    for (int i = 0; i < pbd->num_requirements; i++) {
        if (pbd->privacy_requirements[i] >= 0) checklist++;
    }
    return (checklist >= 4) ? 1 : 0;
}

/* ---------- PET orchestrator ---------- */

void petorch_init(PETOrchestrator *orch) {
    if (!orch) return;
    memset(orch, 0, sizeof(PETOrchestrator));
    orch->enabled_pets = (PETDescriptor *)calloc(PET_COUNT, sizeof(PETDescriptor));
    orch->num_enabled = 0;
    orch->overall_privacy_budget = 10.0;
    orch->audit_enabled = 1;
    orch->log_len = 0;
}

void petorch_enable(PETOrchestrator *orch, PETCategory cat) {
    if (!orch || orch->num_enabled >= PET_COUNT) return;
    for (int i = 0; i < orch->num_enabled; i++) {
        if (orch->enabled_pets[i].category == cat) return;
    }
    const PETDescriptor *desc = pet_get_descriptor(cat);
    if (desc) {
        orch->enabled_pets[orch->num_enabled++] = *desc;
    }
}

void petorch_disable(PETOrchestrator *orch, PETCategory cat) {
    if (!orch) return;
    for (int i = 0; i < orch->num_enabled; i++) {
        if (orch->enabled_pets[i].category == cat) {
            orch->enabled_pets[i].category = -1;
            break;
        }
    }
}

void petorch_assess_privacy(const PETOrchestrator *orch, double *score) {
    if (!orch || !score) return;
    *score = 0.0;
    double total = 0.0;
    for (int i = 0; i < orch->num_enabled; i++) {
        if (orch->enabled_pets[i].category >= 0) {
            total += (double)orch->enabled_pets[i].privacy_strength;
        }
    }
    *score = orch->num_enabled > 0 ? total / (double)orch->num_enabled * 0.2 : 0.0;
    if (*score > 1.0) *score = 1.0;
}

int petorch_audit_log_event(PETOrchestrator *orch, const char *event) {
    if (!orch || !event || !orch->audit_enabled) return 0;
    int written = snprintf(orch->audit_log + orch->log_len,
                           sizeof(orch->audit_log) - (size_t)orch->log_len - 1,
                           "[%ld] %s\n", (long)time(NULL), event);
    if (written > 0) orch->log_len += written;
    if (orch->log_len >= (int)sizeof(orch->audit_log)) orch->log_len = (int)sizeof(orch->audit_log) - 1;
    return 1;
}
