#ifndef PROVENANCE_MODEL_H
#define PROVENANCE_MODEL_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#include "slsa_framework.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char* uri;
    char* digest_sha256;
    char* digest_sha1;
    char* digest_sha512;
} in_toto_artifact_t;

typedef struct {
    char* step_name;
    char* pubkey_id;
    char** expected_command;
    size_t expected_command_count;
    in_toto_artifact_t** expected_materials;
    size_t expected_material_count;
    in_toto_artifact_t** expected_products;
    size_t expected_product_count;
    char* threshold_count;
    char** functionaries;
    size_t functionary_count;
    char** pub_keys;
    size_t pub_key_count;
} in_toto_step_t;

typedef struct {
    char* inspection_name;
    char** expected_material_patterns;
    size_t expected_material_pattern_count;
    char** expected_product_patterns;
    size_t expected_product_pattern_count;
    char* run_command;
    char** functionary_keys;
    size_t functionary_key_count;
} in_toto_inspection_t;

typedef struct {
    char* layout_name;
    in_toto_step_t** steps;
    size_t step_count;
    in_toto_inspection_t** inspections;
    size_t inspection_count;
    char** keys;
    size_t key_count;
    time_t expires;
    char* readme;
} in_toto_layout_t;

typedef struct {
    char* link_name;
    char* functionary_name;
    in_toto_artifact_t** materials;
    size_t material_count;
    in_toto_artifact_t** products;
    size_t product_count;
    char* byproducts_json;
    char* command;
    char* environment_json;
    char* signature_base64;
    char* signing_key_id;
} in_toto_link_t;

typedef struct {
    in_toto_link_t** links;
    size_t link_count;
    in_toto_layout_t* layout;
    bool layout_verified;
    bool all_links_verified;
    char* verification_error;
} attestation_bundle_t;

typedef struct {
    char* predicate_type;
    char* predicate_json;
    char* subject_name;
    char* subject_digest;
    slsa_level_t slsa_level;
    char* builder_id;
    in_toto_artifact_t** materials;
    size_t material_count;
    in_toto_artifact_t** resolved_dependencies;
    size_t resolved_dep_count;
    bool reproducible;
} slsa_predicate_t;

typedef struct {
    char* binary_path;
    char* binary_digest;
    char** allowed_builder_ids;
    size_t allowed_builder_count;
    char** allowed_signer_ids;
    size_t allowed_signer_count;
    slsa_level_t minimum_slsa_level;
    char** required_predicate_types;
    size_t required_predicate_count;
    bool require_reproducible_build;
} bin_auth_policy_t;

typedef enum {
    BIN_AUTH_DECISION_ALLOW,
    BIN_AUTH_DECISION_DENY,
    BIN_AUTH_DECISION_NEED_ATTESTATION
} bin_auth_decision_t;

typedef struct {
    bin_auth_decision_t decision;
    char* reason;
    char** missing_attestations;
    size_t missing_count;
    char* matched_policy;
} bin_auth_result_t;

typedef struct {
    char* note_name;
    char* note_project;
    char* note_kind;
    char* note_short_description;
    char* note_long_description;
    char** related_urls;
    size_t related_url_count;
    time_t create_time;
    time_t update_time;
} grafeas_note_t;

typedef enum {
    GRAFEAS_KIND_VULNERABILITY,
    GRAFEAS_KIND_BUILD,
    GRAFEAS_KIND_IMAGE,
    GRAFEAS_KIND_PACKAGE,
    GRAFEAS_KIND_DEPLOYMENT,
    GRAFEAS_KIND_ATTESTATION,
    GRAFEAS_KIND_CUSTOM
} grafeas_note_kind_t;

typedef struct {
    char* occurrence_name;
    char* note_name;
    char* resource_uri;
    grafeas_note_kind_t kind;
    char* remediation_text;
    char* vulnerability_cve_id;
    time_t discovered_time;
    bool fixed;
} grafeas_occurrence_t;

typedef struct {
    grafeas_note_t** notes;
    size_t note_count;
    grafeas_occurrence_t** occurrences;
    size_t occurrence_count;
    char* project_name;
} grafeas_project_t;

typedef enum {
    KRITIS_ACTION_ALLOW,
    KRITIS_ACTION_DENY
} kritis_action_t;

typedef struct {
    char* policy_name;
    char** required_attestors;
    size_t required_attestor_count;
    char** required_predicate_types;
    size_t required_predicate_count;
    char** required_builder_ids;
    size_t required_builder_count;
    slsa_level_t minimum_slsa_level;
    bool require_vulnerability_scan;
    int max_critical_vulnerabilities;
    int max_high_vulnerabilities;
    bool require_sbom;
    kritis_action_t default_action;
    bool breakglass_enabled;
} kritis_policy_t;

typedef struct {
    bool allowed;
    char* decision_reason;
    bool attestation_satisfied;
    bool vulnerability_satisfied;
    bool sbom_satisfied;
    int critical_vulns_found;
    int high_vulns_found;
    char** violation_reasons;
    size_t violation_count;
} kritis_decision_t;

in_toto_layout_t* provenance_layout_create(const char* name);
void provenance_layout_add_step(in_toto_layout_t* layout, const char* step_name,
                                 const char* pubkey_id, const char** expected_command,
                                 size_t command_count);
void provenance_layout_add_inspection(in_toto_layout_t* layout,
                                       const char* inspection_name,
                                       const char* run_command);
void provenance_layout_add_key(in_toto_layout_t* layout, const char* key_pem);
int provenance_layout_sign(in_toto_layout_t* layout, const char* private_key_pem);
char* provenance_layout_export_json(const in_toto_layout_t* layout);
in_toto_layout_t* provenance_layout_import_json(const char* json_data);
void provenance_layout_free(in_toto_layout_t* layout);

in_toto_link_t* provenance_link_create(const char* name, const char* functionary,
                                         const char* command);
void provenance_link_add_material(in_toto_link_t* link, const char* uri,
                                    const char* sha256_digest);
void provenance_link_add_product(in_toto_link_t* link, const char* uri,
                                   const char* sha256_digest);
void provenance_link_set_byproducts(in_toto_link_t* link, const char* json_byproducts);
void provenance_link_set_environment(in_toto_link_t* link, const char* json_env);
int provenance_link_sign(in_toto_link_t* link, const char* private_key_pem,
                           const char* key_id);
int provenance_link_verify(const in_toto_link_t* link, const char* public_key_pem);
char* provenance_link_export_json(const in_toto_link_t* link);
in_toto_link_t* provenance_link_import_json(const char* json_data);
void provenance_link_free(in_toto_link_t* link);

attestation_bundle_t* provenance_bundle_create(in_toto_layout_t* layout);
void provenance_bundle_add_link(attestation_bundle_t* bundle, in_toto_link_t* link);
int provenance_bundle_verify(const attestation_bundle_t* bundle,
                               const char** trusted_pubkeys,
                               size_t trusted_key_count);
bool provenance_bundle_validate_layout(const attestation_bundle_t* bundle);
char* provenance_bundle_export_json(const attestation_bundle_t* bundle);
void provenance_bundle_free(attestation_bundle_t* bundle);

slsa_predicate_t* provenance_slsa_predicate_create(const char* subject,
                                                      const char* digest,
                                                      slsa_level_t level);
void provenance_slsa_predicate_add_material(slsa_predicate_t* pred,
                                              const char* uri, const char* digest);
void provenance_slsa_predicate_add_dependency(slsa_predicate_t* pred,
                                                const char* uri, const char* digest);
char* provenance_slsa_predicate_export_json(const slsa_predicate_t* pred);
void provenance_slsa_predicate_free(slsa_predicate_t* pred);

bin_auth_policy_t* bin_auth_policy_create(const char* binary_path);
void bin_auth_policy_add_builder(bin_auth_policy_t* policy, const char* builder_id);
void bin_auth_policy_add_signer(bin_auth_policy_t* policy, const char* signer_id);
bin_auth_result_t* bin_auth_check_binary(const char* binary_path,
                                           const char* binary_digest,
                                           const attestation_bundle_t* bundle,
                                           const bin_auth_policy_t* policy);
void bin_auth_result_free(bin_auth_result_t* result);
void bin_auth_policy_free(bin_auth_policy_t* policy);

grafeas_note_t* grafeas_note_create(const char* name, const char* project,
                                      grafeas_note_kind_t kind,
                                      const char* short_desc);
void grafeas_note_add_url(grafeas_note_t* note, const char* url);
char* grafeas_note_export_json(const grafeas_note_t* note);
grafeas_note_t* grafeas_note_import_json(const char* json_data);
void grafeas_note_free(grafeas_note_t* note);

grafeas_occurrence_t* grafeas_occurrence_create(const char* name,
                                                   const char* resource_uri,
                                                   grafeas_note_kind_t kind);
void grafeas_occurrence_attach_note(grafeas_occurrence_t* occurrence, const char* note_name);
void grafeas_occurrence_set_vulnerability(grafeas_occurrence_t* occurrence,
                                           const char* cve_id,
                                           const char* remediation);
char* grafeas_occurrence_export_json(const grafeas_occurrence_t* occurrence);
void grafeas_occurrence_free(grafeas_occurrence_t* occurrence);

grafeas_project_t* grafeas_project_create(const char* name);
void grafeas_project_add_note(grafeas_project_t* project, grafeas_note_t* note);
void grafeas_project_add_occurrence(grafeas_project_t* project,
                                      grafeas_occurrence_t* occurrence);
char* grafeas_project_export_json(const grafeas_project_t* project);
void grafeas_project_free(grafeas_project_t* project);

kritis_policy_t* kritis_policy_create(const char* name, kritis_action_t default_action);
void kritis_policy_add_attestor(kritis_policy_t* policy, const char* attestor);
void kritis_policy_add_predicate_type(kritis_policy_t* policy, const char* predicate_type);
void kritis_policy_add_builder(kritis_policy_t* policy, const char* builder_id);
void kritis_policy_set_vulnerability_threshold(kritis_policy_t* policy,
                                                 int max_critical, int max_high);
kritis_decision_t* kritis_evaluate(const kritis_policy_t* policy,
                                     const attestation_bundle_t* bundle,
                                     const char* image_reference);
bool kritis_is_allowed(const kritis_decision_t* decision);
char* kritis_decision_to_string(const kritis_decision_t* decision);
void kritis_decision_free(kritis_decision_t* decision);
void kritis_policy_free(kritis_policy_t* policy);

#ifdef __cplusplus
}
#endif

#endif
