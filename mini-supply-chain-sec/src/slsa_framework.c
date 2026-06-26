#include "slsa_framework.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static char* slsa_strdup(const char* s) {
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char* dup = (char*)malloc(len);
    if (dup) memcpy(dup, s, len);
    return dup;
}

slsa_level_t slsa_assess_source_level(const slsa_source_t* source) {
    if (!source) return SLSA_LEVEL_0;
    slsa_level_t level = SLSA_LEVEL_0;
    if (source->repo_url && source->commit_sha) level = SLSA_LEVEL_1;
    if (level >= SLSA_LEVEL_1 && source->signed_commit) level = SLSA_LEVEL_2;
    if (level >= SLSA_LEVEL_2 && source->two_person_review &&
        source->protected_branch && source->code_review_url)
        level = SLSA_LEVEL_3;
    return level;
}

slsa_level_t slsa_assess_build_level(const slsa_build_config_t* build) {
    if (!build) return SLSA_LEVEL_0;
    slsa_level_t level = SLSA_LEVEL_0;
    if (build->build_platform && build->builder_id) level = SLSA_LEVEL_1;
    if (level >= SLSA_LEVEL_1 && build->hermetic) level = SLSA_LEVEL_2;
    if (level >= SLSA_LEVEL_2 && build->isolated &&
        build->isolation_type != SLSA_BUILD_ISOLATION_NONE)
        level = SLSA_LEVEL_3;
    if (level >= SLSA_LEVEL_3 && build->parameterless &&
        build->reproducible && build->build_invocation_id)
        level = SLSA_LEVEL_4;
    return level;
}

slsa_level_t slsa_determine_overall_level(slsa_level_t source_level,
                                           slsa_level_t build_level) {
    return (source_level < build_level) ? source_level : build_level;
}

const char* slsa_level_to_string(slsa_level_t level) {
    switch (level) {
    case SLSA_LEVEL_0: return "Level 0 - No guarantees";
    case SLSA_LEVEL_1: return "Level 1 - Build scripted";
    case SLSA_LEVEL_2: return "Level 2 - Build service";
    case SLSA_LEVEL_3: return "Level 3 - Hardened builds";
    case SLSA_LEVEL_4: return "Level 4 - Hermetic, reproducible";
    default: return "Unknown";
    }
}

slsa_level_t slsa_level_from_string(const char* str) {
    if (!str) return SLSA_LEVEL_0;
    if (strstr(str, "Level 4") || strstr(str, "SLSA_LEVEL_4")) return SLSA_LEVEL_4;
    if (strstr(str, "Level 3") || strstr(str, "SLSA_LEVEL_3")) return SLSA_LEVEL_3;
    if (strstr(str, "Level 2") || strstr(str, "SLSA_LEVEL_2")) return SLSA_LEVEL_2;
    if (strstr(str, "Level 1") || strstr(str, "SLSA_LEVEL_1")) return SLSA_LEVEL_1;
    return SLSA_LEVEL_0;
}

slsa_source_t* slsa_source_create(const char* repo_url, const char* commit_sha) {
    slsa_source_t* src = (slsa_source_t*)calloc(1, sizeof(slsa_source_t));
    if (!src) return NULL;
    src->vcs_type = SLSA_VCS_GIT;
    src->repo_url = slsa_strdup(repo_url);
    src->commit_sha = slsa_strdup(commit_sha);
    src->branch_name = slsa_strdup("main");
    src->signed_commit = false;
    src->commit_timestamp = 0;
    src->two_person_review = false;
    src->protected_branch = false;
    return src;
}

void slsa_source_set_signed(slsa_source_t* source, const char* signer,
                             const char* key_fingerprint) {
    if (!source) return;
    source->signed_commit = true;
    source->signer_identity = slsa_strdup(signer);
    source->signer_key_fingerprint = slsa_strdup(key_fingerprint);
}

bool slsa_source_verify_signature(const slsa_source_t* source, const char* pubkey) {
    if (!source || !pubkey) return false;
    return source->signed_commit &&
           source->signer_key_fingerprint &&
           strstr(pubkey, source->signer_key_fingerprint) != NULL;
}

void slsa_source_free(slsa_source_t* source) {
    if (!source) return;
    free(source->repo_url);
    free(source->commit_sha);
    free(source->branch_name);
    free(source->signer_identity);
    free(source->signer_key_fingerprint);
    free(source->code_review_url);
    free(source);
}

slsa_build_config_t* slsa_build_config_create(const char* platform, const char* builder_id) {
    slsa_build_config_t* cfg = (slsa_build_config_t*)calloc(1, sizeof(slsa_build_config_t));
    if (!cfg) return NULL;
    cfg->build_platform = slsa_strdup(platform);
    cfg->builder_id = slsa_strdup(builder_id);
    cfg->hermetic = false;
    cfg->parameterless = false;
    cfg->isolated = false;
    cfg->isolation_type = SLSA_BUILD_ISOLATION_NONE;
    cfg->reproducible = false;
    cfg->build_started = time(NULL);
    return cfg;
}

void slsa_build_config_set_hermetic(slsa_build_config_t* config, bool hermetic,
                                      slsa_build_isolation_t isolation) {
    if (!config) return;
    config->hermetic = hermetic;
    config->isolated = (isolation != SLSA_BUILD_ISOLATION_NONE);
    config->isolation_type = isolation;
}

void slsa_build_config_add_input(slsa_build_config_t* config, const char* input_uri) {
    if (!config || !input_uri) return;
    size_t n = config->input_count + 1;
    char** new_in = (char**)realloc(config->build_inputs, n * sizeof(char*));
    if (new_in) {
        new_in[config->input_count] = slsa_strdup(input_uri);
        config->build_inputs = new_in;
        config->input_count = n;
    }
}

void slsa_build_config_add_output(slsa_build_config_t* config, const char* output_uri) {
    if (!config || !output_uri) return;
    size_t n = config->output_count + 1;
    char** new_out = (char**)realloc(config->build_outputs, n * sizeof(char*));
    if (new_out) {
        new_out[config->output_count] = slsa_strdup(output_uri);
        config->build_outputs = new_out;
        config->output_count = n;
    }
}

bool slsa_build_config_validate(const slsa_build_config_t* config, slsa_level_t target_level) {
    if (!config) return false;
    slsa_level_t assessed = slsa_assess_build_level(config);
    return assessed >= target_level;
}

void slsa_build_config_free(slsa_build_config_t* config) {
    if (!config) return;
    free(config->build_platform);
    free(config->builder_id);
    free(config->build_image_digest);
    free(config->build_command);
    free(config->build_invocation_id);
    for (size_t i = 0; i < config->input_count; i++)
        free(config->build_inputs[i]);
    free(config->build_inputs);
    for (size_t i = 0; i < config->output_count; i++)
        free(config->build_outputs[i]);
    free(config->build_outputs);
    free(config);
}

slsa_provenance_t* slsa_provenance_create(const char* subject,
                                           const char* subject_digest,
                                           const char* predicate_type) {
    slsa_provenance_t* prov = (slsa_provenance_t*)calloc(1, sizeof(slsa_provenance_t));
    if (!prov) return NULL;
    prov->subject_name = slsa_strdup(subject);
    prov->subject_digest_sha256 = slsa_strdup(subject_digest);
    prov->predicate_type = slsa_strdup(predicate_type ?
        predicate_type : "https://slsa.dev/provenance/v1");
    return prov;
}

void slsa_provenance_attach_source(slsa_provenance_t* prov, const slsa_source_t* source) {
    if (!prov || !source) return;
    if (prov->source) slsa_source_free(prov->source);
    slsa_source_t* copy = (slsa_source_t*)calloc(1, sizeof(slsa_source_t));
    if (!copy) return;
    copy->vcs_type = source->vcs_type;
    copy->repo_url = slsa_strdup(source->repo_url);
    copy->commit_sha = slsa_strdup(source->commit_sha);
    copy->branch_name = slsa_strdup(source->branch_name);
    copy->signed_commit = source->signed_commit;
    copy->signer_identity = slsa_strdup(source->signer_identity);
    copy->signer_key_fingerprint = slsa_strdup(source->signer_key_fingerprint);
    copy->commit_timestamp = source->commit_timestamp;
    copy->two_person_review = source->two_person_review;
    copy->protected_branch = source->protected_branch;
    copy->code_review_url = slsa_strdup(source->code_review_url);
    prov->source = copy;
}

void slsa_provenance_attach_build(slsa_provenance_t* prov, const slsa_build_config_t* build) {
    if (!prov || !build) return;
    if (prov->build_config) slsa_build_config_free(prov->build_config);
    slsa_build_config_t* copy = slsa_build_config_create(
        build->build_platform, build->builder_id);
    if (!copy) return;
    copy->hermetic = build->hermetic;
    copy->parameterless = build->parameterless;
    copy->isolated = build->isolated;
    copy->isolation_type = build->isolation_type;
    copy->build_image_digest = slsa_strdup(build->build_image_digest);
    copy->build_command = slsa_strdup(build->build_command);
    copy->build_invocation_id = slsa_strdup(build->build_invocation_id);
    copy->reproducible = build->reproducible;
    copy->build_started = build->build_started;
    copy->build_finished = build->build_finished;
    prov->build_config = copy;
}

void slsa_provenance_add_material(slsa_provenance_t* prov, const char* material_uri) {
    if (!prov || !material_uri) return;
    size_t n = prov->material_count + 1;
    char** new_mat = (char**)realloc(prov->materials, n * sizeof(char*));
    if (new_mat) {
        new_mat[prov->material_count] = slsa_strdup(material_uri);
        prov->materials = new_mat;
        prov->material_count = n;
    }
}

int slsa_provenance_sign(slsa_provenance_t* prov, const char* private_key_pem) {
    if (!prov || !private_key_pem) return -1;
    size_t sig_len = strlen(private_key_pem) + 256;
    prov->signature_base64 = (char*)calloc(1, sig_len);
    if (!prov->signature_base64) return -2;
    snprintf(prov->signature_base64, sig_len,
        "PROV-SIG::%s::%s", prov->subject_name, private_key_pem);
    return 0;
}

int slsa_provenance_export_intoto(slsa_provenance_t* prov, char** out_json) {
    if (!prov || !out_json) return -1;
    size_t cap = 32768;
    *out_json = (char*)malloc(cap);
    if (!*out_json) return -2;
    snprintf(*out_json, cap,
        "{\n  \"_type\": \"https://in-toto.io/Statement/v1\",\n"
        "  \"subject\": [{\"name\": \"%s\", \"digest\": {\"sha256\": \"%s\"}}],\n"
        "  \"predicateType\": \"%s\",\n"
        "  \"predicate\": {\"builder\": {\"id\": \"%s\"},\n"
        "    \"buildType\": \"%s\"}\n}\n",
        prov->subject_name ? prov->subject_name : "unknown",
        prov->subject_digest_sha256 ? prov->subject_digest_sha256 : "",
        prov->predicate_type,
        prov->build_config ? prov->build_config->builder_id : "unknown",
        "custom");
    return 0;
}

slsa_provenance_t* slsa_provenance_import_intoto(const char* json) {
    if (!json) return NULL;
    slsa_provenance_t* prov = slsa_provenance_create("imported", "", NULL);
    return prov;
}

slsa_verification_result_t* slsa_verify_provenance(const slsa_provenance_t* prov,
                                                    const char* trusted_builders[],
                                                    size_t trusted_builder_count,
                                                    const char* public_key_pem) {
    slsa_verification_result_t* result = (slsa_verification_result_t*)
        calloc(1, sizeof(slsa_verification_result_t));
    if (!result) return NULL;
    if (!prov) { result->verified = false; return result; }
    result->signature_valid = prov->signature_base64 != NULL;
    result->builder_trusted = false;
    if (prov->build_config && prov->build_config->builder_id && trusted_builders) {
        for (size_t i = 0; i < trusted_builder_count; i++) {
            if (trusted_builders[i] &&
                strcmp(prov->build_config->builder_id, trusted_builders[i]) == 0) {
                result->builder_trusted = true;
                break;
            }
        }
    }
    result->source_integrity_ok = prov->source && prov->source->signed_commit;
    result->build_config_compliant = prov->build_config &&
        prov->build_config->hermetic;
    result->materials_verified = prov->material_count > 0;
    result->claimed_level = prov->build_config ?
        slsa_assess_build_level(prov->build_config) : SLSA_LEVEL_0;
    result->assessed_level = result->claimed_level;
    result->verified = result->signature_valid && result->builder_trusted;
    return result;
}

void slsa_provenance_free(slsa_provenance_t* prov) {
    if (!prov) return;
    free(prov->predicate_type);
    free(prov->predicate_json);
    free(prov->subject_name);
    free(prov->subject_digest_sha256);
    free(prov->builder_id);
    free(prov->build_type);
    free(prov->build_invocation_id);
    if (prov->source) slsa_source_free(prov->source);
    if (prov->build_config) slsa_build_config_free(prov->build_config);
    for (size_t i = 0; i < prov->material_count; i++)
        free(prov->materials[i]);
    free(prov->materials);
    free(prov->signature_base64);
    free(prov);
}

void slsa_verification_result_free(slsa_verification_result_t* result) {
    if (!result) return;
    free(result->verification_message);
    free(result);
}

pipeline_t* pipeline_create(const char* name, const char* version) {
    pipeline_t* pipe = (pipeline_t*)calloc(1, sizeof(pipeline_t));
    if (!pipe) return NULL;
    pipe->pipeline_name = slsa_strdup(name);
    pipe->pipeline_version = slsa_strdup(version ? version : "1.0.0");
    pipe->require_isolation = true;
    pipe->required_level = SLSA_LEVEL_3;
    pipe->default_image = slsa_strdup("ubuntu:24.04");
    return pipe;
}

void pipeline_add_step(pipeline_t* pipeline, const char* step_name,
                       const char* image, const char* entrypoint,
                       bool isolated) {
    if (!pipeline || !step_name) return;
    pipeline_step_t* step = (pipeline_step_t*)calloc(1, sizeof(pipeline_step_t));
    if (!step) return;
    step->step_name = slsa_strdup(step_name);
    step->container_image = slsa_strdup(image ? image : pipeline->default_image);
    step->entrypoint = slsa_strdup(entrypoint);
    step->isolated = isolated;
    size_t n = pipeline->step_count + 1;
    pipeline_step_t** new_steps = (pipeline_step_t**)realloc(
        pipeline->steps, n * sizeof(pipeline_step_t*));
    if (new_steps) {
        new_steps[pipeline->step_count] = step;
        pipeline->steps = new_steps;
        pipeline->step_count = n;
    } else {
        free(step->step_name); free(step->container_image);
        free(step->entrypoint); free(step);
    }
}

void pipeline_step_add_argument(pipeline_step_t* step, const char* arg) {
    if (!step || !arg) return;
    size_t n = step->arg_count + 1;
    char** new_args = (char**)realloc(step->arguments, n * sizeof(char*));
    if (new_args) {
        new_args[step->arg_count] = slsa_strdup(arg);
        step->arguments = new_args;
        step->arg_count = n;
    }
}

void pipeline_step_add_environment(pipeline_step_t* step, const char* key, const char* value) {
    if (!step || !key || !value) return;
    size_t n = step->env_count + 1;
    char** new_env = (char**)realloc(step->environment, n * sizeof(char*));
    if (new_env) {
        size_t kv_len = strlen(key) + strlen(value) + 64;
        char* kv = (char*)malloc(kv_len);
        if (kv) {
            snprintf(kv, kv_len, "%s=%s", key, value);
            new_env[step->env_count] = kv;
            step->environment = new_env;
            step->env_count = n;
        }
    }
}

void pipeline_step_add_input(pipeline_step_t* step, const char* artifact) {
    if (!step || !artifact) return;
    size_t n = step->input_count + 1;
    char** new_in = (char**)realloc(step->input_artifacts, n * sizeof(char*));
    if (new_in) {
        new_in[step->input_count] = slsa_strdup(artifact);
        step->input_artifacts = new_in;
        step->input_count = n;
    }
}

void pipeline_step_add_output(pipeline_step_t* step, const char* artifact) {
    if (!step || !artifact) return;
    size_t n = step->output_count + 1;
    char** new_out = (char**)realloc(step->output_artifacts, n * sizeof(char*));
    if (new_out) {
        new_out[step->output_count] = slsa_strdup(artifact);
        step->output_artifacts = new_out;
        step->output_count = n;
    }
}

bool pipeline_validate_slsa(const pipeline_t* pipeline, slsa_level_t target_level) {
    if (!pipeline) return false;
    if (target_level >= SLSA_LEVEL_3 && !pipeline->require_isolation)
        return false;
    if (target_level >= SLSA_LEVEL_4) {
        for (size_t i = 0; i < pipeline->step_count; i++) {
            pipeline_step_t* s = pipeline->steps[i];
            if (s && s->arg_count > 0) return false;
        }
    }
    return pipeline->required_level >= target_level;
}

char* pipeline_export_declarative(const pipeline_t* pipeline) {
    if (!pipeline) return NULL;
    size_t cap = 16384;
    char* out = (char*)malloc(cap);
    if (!out) return NULL;
    size_t len = 0;
    len += snprintf(out + len, cap - len,
        "# Declarative Pipeline: %s (v%s)\n"
        "# Required SLSA Level: %d\n\n",
        pipeline->pipeline_name, pipeline->pipeline_version,
        (int)pipeline->required_level);
    for (size_t i = 0; i < pipeline->step_count; i++) {
        pipeline_step_t* s = pipeline->steps[i];
        len += snprintf(out + len, cap - len,
            "step \"%s\":\n  image: %s\n  entrypoint: %s\n"
            "  isolated: %s\n",
            s->step_name, s->container_image,
            s->entrypoint ? s->entrypoint : "bash",
            s->isolated ? "true" : "false");
    }
    return out;
}

void pipeline_free(pipeline_t* pipeline) {
    if (!pipeline) return;
    free(pipeline->pipeline_name);
    free(pipeline->pipeline_version);
    free(pipeline->default_image);
    for (size_t i = 0; i < pipeline->global_env_count; i++)
        free(pipeline->global_environments[i]);
    free(pipeline->global_environments);
    for (size_t i = 0; i < pipeline->step_count; i++) {
        pipeline_step_t* s = pipeline->steps[i];
        if (!s) continue;
        free(s->step_name);
        free(s->description);
        free(s->container_image);
        free(s->entrypoint);
        free(s->timeout_seconds);
        for (size_t j = 0; j < s->arg_count; j++) free(s->arguments[j]);
        free(s->arguments);
        for (size_t j = 0; j < s->env_count; j++) free(s->environment[j]);
        free(s->environment);
        for (size_t j = 0; j < s->input_count; j++) free(s->input_artifacts[j]);
        free(s->input_artifacts);
        for (size_t j = 0; j < s->output_count; j++) free(s->output_artifacts[j]);
        free(s->output_artifacts);
        free(s);
    }
    free(pipeline->steps);
    free(pipeline);
}
