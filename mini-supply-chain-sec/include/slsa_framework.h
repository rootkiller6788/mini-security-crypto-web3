#ifndef SLSA_FRAMEWORK_H
#define SLSA_FRAMEWORK_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SLSA_LEVEL_0,
    SLSA_LEVEL_1,
    SLSA_LEVEL_2,
    SLSA_LEVEL_3,
    SLSA_LEVEL_4
} slsa_level_t;

typedef enum {
    SLSA_VCS_GIT,
    SLSA_VCS_MERCURIAL,
    SLSA_VCS_SVN
} slsa_vcs_type_t;

typedef struct {
    slsa_vcs_type_t vcs_type;
    char* repo_url;
    char* commit_sha;
    char* branch_name;
    bool signed_commit;
    char* signer_identity;
    char* signer_key_fingerprint;
    time_t commit_timestamp;
    bool two_person_review;
    bool protected_branch;
    char* code_review_url;
} slsa_source_t;

typedef enum {
    SLSA_BUILD_ISOLATION_CONTAINER,
    SLSA_BUILD_ISOLATION_VM,
    SLSA_BUILD_ISOLATION_SANDBOX,
    SLSA_BUILD_ISOLATION_NONE
} slsa_build_isolation_t;

typedef struct {
    bool hermetic;
    bool parameterless;
    bool isolated;
    slsa_build_isolation_t isolation_type;
    char* build_platform;
    char* build_image_digest;
    char* build_command;
    char** build_inputs;
    size_t input_count;
    char** build_outputs;
    size_t output_count;
    bool reproducible;
    char* builder_id;
    char* build_invocation_id;
    time_t build_started;
    time_t build_finished;
} slsa_build_config_t;

typedef struct {
    char* predicate_type;
    char* predicate_json;
    char* subject_name;
    char* subject_digest_sha256;
    char* builder_id;
    char* build_type;
    char* build_invocation_id;
    slsa_source_t* source;
    slsa_build_config_t* build_config;
    char** materials;
    size_t material_count;
    char* signature_base64;
} slsa_provenance_t;

typedef struct {
    bool verified;
    slsa_level_t claimed_level;
    slsa_level_t assessed_level;
    char* verification_message;
    bool signature_valid;
    bool builder_trusted;
    bool source_integrity_ok;
    bool build_config_compliant;
    bool materials_verified;
} slsa_verification_result_t;

typedef struct {
    char* step_name;
    char* description;
    char* container_image;
    char* entrypoint;
    char** arguments;
    size_t arg_count;
    char** environment;
    size_t env_count;
    char** input_artifacts;
    size_t input_count;
    char** output_artifacts;
    size_t output_count;
    bool isolated;
    char* timeout_seconds;
} pipeline_step_t;

typedef struct {
    char* pipeline_name;
    char* pipeline_version;
    pipeline_step_t** steps;
    size_t step_count;
    char** global_environments;
    size_t global_env_count;
    char* default_image;
    bool require_isolation;
    slsa_level_t required_level;
} pipeline_t;

slsa_level_t slsa_assess_source_level(const slsa_source_t* source);
slsa_level_t slsa_assess_build_level(const slsa_build_config_t* build);
slsa_level_t slsa_determine_overall_level(slsa_level_t source_level,
                                           slsa_level_t build_level);
const char* slsa_level_to_string(slsa_level_t level);
slsa_level_t slsa_level_from_string(const char* str);

slsa_source_t* slsa_source_create(const char* repo_url, const char* commit_sha);
void slsa_source_set_signed(slsa_source_t* source, const char* signer,
                             const char* key_fingerprint);
bool slsa_source_verify_signature(const slsa_source_t* source, const char* pubkey);
void slsa_source_free(slsa_source_t* source);

slsa_build_config_t* slsa_build_config_create(const char* platform, const char* builder_id);
void slsa_build_config_set_hermetic(slsa_build_config_t* config, bool hermetic,
                                      slsa_build_isolation_t isolation);
void slsa_build_config_add_input(slsa_build_config_t* config, const char* input_uri);
void slsa_build_config_add_output(slsa_build_config_t* config, const char* output_uri);
bool slsa_build_config_validate(const slsa_build_config_t* config, slsa_level_t target_level);
void slsa_build_config_free(slsa_build_config_t* config);

slsa_provenance_t* slsa_provenance_create(const char* subject,
                                           const char* subject_digest,
                                           const char* predicate_type);
void slsa_provenance_attach_source(slsa_provenance_t* prov, const slsa_source_t* source);
void slsa_provenance_attach_build(slsa_provenance_t* prov,
                                   const slsa_build_config_t* build);
void slsa_provenance_add_material(slsa_provenance_t* prov, const char* material_uri);
int slsa_provenance_sign(slsa_provenance_t* prov, const char* private_key_pem);
int slsa_provenance_export_intoto(slsa_provenance_t* prov, char** out_json);
slsa_provenance_t* slsa_provenance_import_intoto(const char* json);
slsa_verification_result_t* slsa_verify_provenance(const slsa_provenance_t* prov,
                                                    const char* trusted_builders[],
                                                    size_t trusted_builder_count,
                                                    const char* public_key_pem);
void slsa_provenance_free(slsa_provenance_t* prov);
void slsa_verification_result_free(slsa_verification_result_t* result);

pipeline_t* pipeline_create(const char* name, const char* version);
void pipeline_add_step(pipeline_t* pipeline, const char* step_name,
                       const char* image, const char* entrypoint,
                       bool isolated);
void pipeline_step_add_argument(pipeline_step_t* step, const char* arg);
void pipeline_step_add_environment(pipeline_step_t* step, const char* key, const char* value);
void pipeline_step_add_input(pipeline_step_t* step, const char* artifact);
void pipeline_step_add_output(pipeline_step_t* step, const char* artifact);
bool pipeline_validate_slsa(const pipeline_t* pipeline, slsa_level_t target_level);
char* pipeline_export_declarative(const pipeline_t* pipeline);
void pipeline_free(pipeline_t* pipeline);

#ifdef __cplusplus
}
#endif

#endif
