#ifndef SIGSTORE_COSIGN_H
#define SIGSTORE_COSIGN_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char* issuer_url;
    char* client_id;
    char* subject;
    char* email;
    char* id_token;
    char* access_token;
    time_t token_expiry;
} oidc_identity_t;

typedef struct {
    char* certificate_pem;
    char* certificate_chain_pem;
    char* issuer;
    char* subject_alternative_name;
    char* oidc_issuer;
    char* key_algorithm;
    int key_size;
    time_t not_before;
    time_t not_after;
    char* serial_number;
    char* fulcio_root_hash;
} fulcio_certificate_t;

typedef struct {
    char* log_index;
    char* log_id;
    char* body_base64;
    char* integrated_time;
    char* signature_base64;
    char* verification_material;
    char* entry_uuid;
    bool verified;
} rekor_entry_t;

typedef struct {
    char* image_reference;
    char* image_digest;
    char* signature_base64;
    char* payload_base64;
    fulcio_certificate_t* certificate;
    rekor_entry_t* rekor_entry;
    char* annotation;
    time_t signed_timestamp;
} cosign_signature_t;

typedef struct {
    char* predicate_type;
    char* subject;
    char* subject_digest_sha256;
    char* predicate_json;
    cosign_signature_t* signature;
    char* bundle_json;
} cosign_attestation_t;

typedef enum {
    SIGSTORE_POLICY_ACTION_ALLOW,
    SIGSTORE_POLICY_ACTION_DENY,
    SIGSTORE_POLICY_ACTION_WARN
} sigstore_policy_action_t;

typedef struct {
    char* pattern;
    char* value;
} sigstore_policy_pattern_t;

typedef struct {
    char* name;
    char** allowed_issuers;
    size_t allowed_issuer_count;
    char** allowed_subjects;
    size_t allowed_subject_count;
    char** allowed_email_domains;
    size_t allowed_domain_count;
    char** required_annotations;
    size_t required_annotation_count;
    bool require_rekor_entry;
    bool require_fulcio_cert;
    char* fulcio_root_ca_path;
    sigstore_policy_action_t default_action;
} sigstore_policy_t;

oidc_identity_t* sigstore_oidc_authenticate(const char* issuer_url,
                                              const char* client_id);
bool sigstore_oidc_validate_token(const oidc_identity_t* identity);
int sigstore_oidc_refresh_token(oidc_identity_t* identity);
void sigstore_oidc_free(oidc_identity_t* identity);

fulcio_certificate_t* sigstore_fulcio_request_certificate(
    const oidc_identity_t* identity,
    const char* public_key_pem,
    const char* fulcio_url);
int sigstore_fulcio_verify_certificate_chain(
    const fulcio_certificate_t* cert,
    const char* root_ca_pem);
bool sigstore_fulcio_validate_cert_identity(
    const fulcio_certificate_t* cert,
    const oidc_identity_t* identity);
void sigstore_fulcio_free(fulcio_certificate_t* cert);

rekor_entry_t* sigstore_rekor_create_entry(
    const char* artifact_signature,
    const char* artifact_payload,
    const fulcio_certificate_t* cert,
    const char* rekor_url);
int sigstore_rekor_verify_entry(const rekor_entry_t* entry,
                                 const char* rekor_pubkey_pem);
bool sigstore_rekor_check_inclusion(const rekor_entry_t* entry);
int sigstore_rekor_query_by_artifact(const char* artifact_digest,
                                      const char* rekor_url,
                                      rekor_entry_t*** out_entries,
                                      size_t* out_count);
void sigstore_rekor_free(rekor_entry_t* entry);

cosign_signature_t* cosign_sign_image(const char* image_reference,
                                       const char* private_key_pem,
                                       bool use_keyless);
cosign_signature_t* cosign_sign_image_keyless(
    const char* image_reference,
    oidc_identity_t* identity,
    const char* fulcio_url,
    const char* rekor_url);
int cosign_verify_image(const char* image_reference,
                         const char* public_key_pem,
                         sigstore_policy_t* policy,
                         cosign_signature_t*** out_signatures,
                         size_t* out_count);
int cosign_verify_image_signatures(const char* image_reference,
                                    char** allowed_pubkeys,
                                    size_t key_count,
                                    bool* out_verified);
int cosign_attach_signature(const char* image_reference,
                             cosign_signature_t* signature);
int cosign_clean_signatures(const char* image_reference);
void cosign_signature_free(cosign_signature_t* sig);

cosign_attestation_t* cosign_attestation_create(const char* image_reference,
                                                 const char* predicate_type,
                                                 const char* predicate_json);
int cosign_attestation_sign(cosign_attestation_t* attestation,
                             const char* private_key_pem,
                             bool use_keyless,
                             oidc_identity_t* identity);
int cosign_attestation_verify(const cosign_attestation_t* attestation,
                               const char* public_key_pem,
                               sigstore_policy_t* policy);
char* cosign_attestation_export_bundle(const cosign_attestation_t* attestation);
void cosign_attestation_free(cosign_attestation_t* attestation);

sigstore_policy_t* sigstore_policy_create(const char* name);
void sigstore_policy_add_issuer(sigstore_policy_t* policy, const char* issuer);
void sigstore_policy_add_subject(sigstore_policy_t* policy, const char* subject);
void sigstore_policy_add_email_domain(sigstore_policy_t* policy, const char* domain);
void sigstore_policy_add_annotation(sigstore_policy_t* policy, const char* annotation);
sigstore_policy_action_t sigstore_policy_evaluate(
    const sigstore_policy_t* policy,
    const cosign_signature_t* signature,
    char** out_reason);
sigstore_policy_t* sigstore_policy_from_cue(const char* cue_policy);
char* sigstore_policy_export_cue(const sigstore_policy_t* policy);
void sigstore_policy_free(sigstore_policy_t* policy);

#ifdef __cplusplus
}
#endif

#endif
