#include "provenance_model.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

static char* pm_strdup(const char* s) {
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char* dup = (char*)malloc(len);
    if (dup) memcpy(dup, s, len);
    return dup;
}

in_toto_layout_t* provenance_layout_create(const char* name) {
    in_toto_layout_t* layout = (in_toto_layout_t*)calloc(1, sizeof(in_toto_layout_t));
    if (!layout) return NULL;
    layout->layout_name = pm_strdup(name ? name : "unnamed-layout");
    layout->expires = time(NULL) + (365L * 24L * 3600L);
    return layout;
}

static void free_step(in_toto_step_t* s) {
    if (!s) return;
    free(s->step_name); free(s->pubkey_id); free(s->threshold_count);
    if (s->expected_command) {
        for (size_t i = 0; i < s->expected_command_count; i++)
            free(s->expected_command[i]);
        free(s->expected_command);
    }
    if (s->expected_materials) {
        for (size_t i = 0; i < s->expected_material_count; i++) {
            in_toto_artifact_t* a = s->expected_materials[i];
            free(a->uri); free(a->digest_sha256);
            free(a->digest_sha1); free(a->digest_sha512); free(a);
        }
        free(s->expected_materials);
    }
    if (s->expected_products) {
        for (size_t i = 0; i < s->expected_product_count; i++) {
            in_toto_artifact_t* a = s->expected_products[i];
            free(a->uri); free(a->digest_sha256);
            free(a->digest_sha1); free(a->digest_sha512); free(a);
        }
        free(s->expected_products);
    }
    for (size_t i = 0; i < s->functionary_count; i++) free(s->functionaries[i]);
    free(s->functionaries);
    for (size_t i = 0; i < s->pub_key_count; i++) free(s->pub_keys[i]);
    free(s->pub_keys);
    free(s);
}

void provenance_layout_add_step(in_toto_layout_t* layout, const char* step_name,
                                 const char* pubkey_id, const char** expected_command,
                                 size_t command_count) {
    if (!layout || !step_name) return;
    in_toto_step_t* step = (in_toto_step_t*)calloc(1, sizeof(in_toto_step_t));
    if (!step) return;
    step->step_name = pm_strdup(step_name);
    step->pubkey_id = pm_strdup(pubkey_id);
    if (expected_command && command_count > 0) {
        step->expected_command = (char**)malloc(command_count * sizeof(char*));
        if (step->expected_command) {
            for (size_t i = 0; i < command_count; i++)
                step->expected_command[i] = pm_strdup(expected_command[i]);
            step->expected_command_count = command_count;
        }
    }
    size_t n = layout->step_count + 1;
    in_toto_step_t** new_steps = (in_toto_step_t**)realloc(
        layout->steps, n * sizeof(in_toto_step_t*));
    if (new_steps) {
        new_steps[layout->step_count] = step;
        layout->steps = new_steps;
        layout->step_count = n;
    } else {
        free_step(step);
    }
}

void provenance_layout_add_inspection(in_toto_layout_t* layout,
                                       const char* inspection_name,
                                       const char* run_command) {
    if (!layout || !inspection_name) return;
    in_toto_inspection_t* insp = (in_toto_inspection_t*)
        calloc(1, sizeof(in_toto_inspection_t));
    if (!insp) return;
    insp->inspection_name = pm_strdup(inspection_name);
    insp->run_command = pm_strdup(run_command);
    size_t n = layout->inspection_count + 1;
    in_toto_inspection_t** new_insp = (in_toto_inspection_t**)realloc(
        layout->inspections, n * sizeof(in_toto_inspection_t*));
    if (new_insp) {
        new_insp[layout->inspection_count] = insp;
        layout->inspections = new_insp;
        layout->inspection_count = n;
    } else {
        free(insp->inspection_name); free(insp->run_command); free(insp);
    }
}

void provenance_layout_add_key(in_toto_layout_t* layout, const char* key_pem) {
    if (!layout || !key_pem) return;
    size_t n = layout->key_count + 1;
    char** new_keys = (char**)realloc(layout->keys, n * sizeof(char*));
    if (new_keys) {
        new_keys[layout->key_count] = pm_strdup(key_pem);
        layout->keys = new_keys;
        layout->key_count = n;
    }
}

int provenance_layout_sign(in_toto_layout_t* layout, const char* private_key_pem) {
    if (!layout || !private_key_pem) return -1;
    return 0;
}

char* provenance_layout_export_json(const in_toto_layout_t* layout) {
    if (!layout) return NULL;
    size_t cap = 32768;
    char* json = (char*)malloc(cap);
    if (!json) return NULL;
    size_t len = 0;
    len += snprintf(json + len, cap - len,
        "{\"_type\":\"layout\",\"name\":\"%s\",\"expires\":%ld,\"steps\":[",
        layout->layout_name ? layout->layout_name : "unknown",
        (long)layout->expires);
    for (size_t i = 0; i < layout->step_count; i++) {
        in_toto_step_t* s = layout->steps[i];
        len += snprintf(json + len, cap - len,
            "{\"name\":\"%s\",\"pubkey\":\"%s\"}%s",
            s->step_name ? s->step_name : "",
            s->pubkey_id ? s->pubkey_id : "",
            i + 1 < layout->step_count ? "," : "");
    }
    snprintf(json + len, cap - len, "]}");
    return json;
}

in_toto_layout_t* provenance_layout_import_json(const char* json_data) {
    if (!json_data) return NULL;
    return provenance_layout_create("imported-layout");
}

void provenance_layout_free(in_toto_layout_t* layout) {
    if (!layout) return;
    free(layout->layout_name);
    free(layout->readme);
    for (size_t i = 0; i < layout->step_count; i++)
        free_step(layout->steps[i]);
    free(layout->steps);
    for (size_t i = 0; i < layout->inspection_count; i++) {
        in_toto_inspection_t* insp = layout->inspections[i];
        free(insp->inspection_name); free(insp->run_command);
        for (size_t j = 0; j < insp->expected_material_pattern_count; j++)
            free(insp->expected_material_patterns[j]);
        free(insp->expected_material_patterns);
        for (size_t j = 0; j < insp->expected_product_pattern_count; j++)
            free(insp->expected_product_patterns[j]);
        free(insp->expected_product_patterns);
        for (size_t j = 0; j < insp->functionary_key_count; j++)
            free(insp->functionary_keys[j]);
        free(insp->functionary_keys);
        free(insp);
    }
    free(layout->inspections);
    for (size_t i = 0; i < layout->key_count; i++) free(layout->keys[i]);
    free(layout->keys);
    free(layout);
}

static void free_artifact(in_toto_artifact_t* a) {
    if (!a) return;
    free(a->uri); free(a->digest_sha256);
    free(a->digest_sha1); free(a->digest_sha512);
    free(a);
}

in_toto_link_t* provenance_link_create(const char* name, const char* functionary,
                                         const char* command) {
    in_toto_link_t* link = (in_toto_link_t*)calloc(1, sizeof(in_toto_link_t));
    if (!link) return NULL;
    link->link_name = pm_strdup(name);
    link->functionary_name = pm_strdup(functionary);
    link->command = pm_strdup(command);
    return link;
}

void provenance_link_add_material(in_toto_link_t* link, const char* uri,
                                    const char* sha256_digest) {
    if (!link || !uri) return;
    in_toto_artifact_t* art = (in_toto_artifact_t*)calloc(1, sizeof(in_toto_artifact_t));
    if (!art) return;
    art->uri = pm_strdup(uri);
    art->digest_sha256 = pm_strdup(sha256_digest);
    size_t n = link->material_count + 1;
    in_toto_artifact_t** new_mat = (in_toto_artifact_t**)realloc(
        link->materials, n * sizeof(in_toto_artifact_t*));
    if (new_mat) {
        new_mat[link->material_count] = art;
        link->materials = new_mat;
        link->material_count = n;
    } else {
        free_artifact(art);
    }
}

void provenance_link_add_product(in_toto_link_t* link, const char* uri,
                                   const char* sha256_digest) {
    if (!link || !uri) return;
    in_toto_artifact_t* art = (in_toto_artifact_t*)calloc(1, sizeof(in_toto_artifact_t));
    if (!art) return;
    art->uri = pm_strdup(uri);
    art->digest_sha256 = pm_strdup(sha256_digest);
    size_t n = link->product_count + 1;
    in_toto_artifact_t** new_prod = (in_toto_artifact_t**)realloc(
        link->products, n * sizeof(in_toto_artifact_t*));
    if (new_prod) {
        new_prod[link->product_count] = art;
        link->products = new_prod;
        link->product_count = n;
    } else {
        free_artifact(art);
    }
}

void provenance_link_set_byproducts(in_toto_link_t* link, const char* json_byproducts) {
    if (!link) return;
    free(link->byproducts_json);
    link->byproducts_json = pm_strdup(json_byproducts);
}

void provenance_link_set_environment(in_toto_link_t* link, const char* json_env) {
    if (!link) return;
    free(link->environment_json);
    link->environment_json = pm_strdup(json_env);
}

int provenance_link_sign(in_toto_link_t* link, const char* private_key_pem,
                           const char* key_id) {
    if (!link || !private_key_pem) return -1;
    link->signing_key_id = pm_strdup(key_id);
    size_t sig_len = strlen(private_key_pem) + 256;
    link->signature_base64 = (char*)calloc(1, sig_len);
    if (!link->signature_base64) return -2;
    snprintf(link->signature_base64, sig_len,
        "LINK-SIG::%s::%s", link->link_name, private_key_pem);
    return 0;
}

int provenance_link_verify(const in_toto_link_t* link, const char* public_key_pem) {
    if (!link || !public_key_pem || !link->signature_base64) return -1;
    return 0;
}

char* provenance_link_export_json(const in_toto_link_t* link) {
    if (!link) return NULL;
    size_t cap = 8192;
    char* json = (char*)malloc(cap);
    if (!json) return NULL;
    snprintf(json, cap,
        "{\"_type\":\"link\",\"name\":\"%s\",\"functionary\":\"%s\","
        "\"command\":\"%s\",\"materials\":%zu,\"products\":%zu}",
        link->link_name ? link->link_name : "",
        link->functionary_name ? link->functionary_name : "",
        link->command ? link->command : "",
        link->material_count, link->product_count);
    return json;
}

in_toto_link_t* provenance_link_import_json(const char* json_data) {
    if (!json_data) return NULL;
    return provenance_link_create("imported-link", "unknown", "unknown");
}

void provenance_link_free(in_toto_link_t* link) {
    if (!link) return;
    free(link->link_name); free(link->functionary_name);
    free(link->byproducts_json); free(link->command);
    free(link->environment_json); free(link->signature_base64);
    free(link->signing_key_id);
    for (size_t i = 0; i < link->material_count; i++)
        free_artifact(link->materials[i]);
    free(link->materials);
    for (size_t i = 0; i < link->product_count; i++)
        free_artifact(link->products[i]);
    free(link->products);
    free(link);
}

attestation_bundle_t* provenance_bundle_create(in_toto_layout_t* layout) {
    attestation_bundle_t* bundle = (attestation_bundle_t*)
        calloc(1, sizeof(attestation_bundle_t));
    if (!bundle) return NULL;
    bundle->layout = layout;
    return bundle;
}

void provenance_bundle_add_link(attestation_bundle_t* bundle, in_toto_link_t* link) {
    if (!bundle || !link) return;
    size_t n = bundle->link_count + 1;
    in_toto_link_t** new_links = (in_toto_link_t**)realloc(
        bundle->links, n * sizeof(in_toto_link_t*));
    if (new_links) {
        new_links[bundle->link_count] = link;
        bundle->links = new_links;
        bundle->link_count = n;
    }
}

int provenance_bundle_verify(const attestation_bundle_t* bundle,
                               const char** trusted_pubkeys,
                               size_t trusted_key_count) {
    if (!bundle) return -1;
    bool all_ok = true;
    for (size_t i = 0; i < bundle->link_count; i++) {
        in_toto_link_t* link = bundle->links[i];
        if (!link || !link->signature_base64) { all_ok = false; continue; }
        bool found = false;
        for (size_t j = 0; j < trusted_key_count; j++) {
            if (trusted_pubkeys[j] &&
                provenance_link_verify(link, trusted_pubkeys[j]) == 0) {
                found = true; break;
            }
        }
        if (!found) all_ok = false;
    }
    return all_ok ? 0 : -1;
}

bool provenance_bundle_validate_layout(const attestation_bundle_t* bundle) {
    return bundle && bundle->layout && bundle->layout_verified;
}

char* provenance_bundle_export_json(const attestation_bundle_t* bundle) {
    if (!bundle) return NULL;
    size_t cap = 32768;
    char* json = (char*)malloc(cap);
    if (!json) return NULL;
    size_t len = 0;
    len += snprintf(json + len, cap - len,
        "{\"_type\":\"bundle\",\"links\":[");
    for (size_t i = 0; i < bundle->link_count; i++) {
        in_toto_link_t* link = bundle->links[i];
        len += snprintf(json + len, cap - len,
            "{\"name\":\"%s\",\"materials\":%zu,\"products\":%zu}%s",
            link->link_name ? link->link_name : "",
            link->material_count, link->product_count,
            i + 1 < bundle->link_count ? "," : "");
    }
    snprintf(json + len, cap - len, "]}");
    return json;
}

void provenance_bundle_free(attestation_bundle_t* bundle) {
    if (!bundle) return;
    for (size_t i = 0; i < bundle->link_count; i++)
        provenance_link_free(bundle->links[i]);
    free(bundle->links);
    free(bundle->verification_error);
    free(bundle);
}

slsa_predicate_t* provenance_slsa_predicate_create(const char* subject,
                                                      const char* digest,
                                                      slsa_level_t level) {
    slsa_predicate_t* pred = (slsa_predicate_t*)
        calloc(1, sizeof(slsa_predicate_t));
    if (!pred) return NULL;
    pred->predicate_type = pm_strdup("https://slsa.dev/provenance/v1");
    pred->subject_name = pm_strdup(subject);
    pred->subject_digest = pm_strdup(digest);
    pred->slsa_level = level;
    return pred;
}

void provenance_slsa_predicate_add_material(slsa_predicate_t* pred,
                                              const char* uri, const char* digest) {
    if (!pred || !uri) return;
    in_toto_artifact_t* art = (in_toto_artifact_t*)calloc(1, sizeof(in_toto_artifact_t));
    if (!art) return;
    art->uri = pm_strdup(uri);
    art->digest_sha256 = pm_strdup(digest);
    size_t n = pred->material_count + 1;
    in_toto_artifact_t** new_mat = (in_toto_artifact_t**)realloc(
        pred->materials, n * sizeof(in_toto_artifact_t*));
    if (new_mat) {
        new_mat[pred->material_count] = art;
        pred->materials = new_mat;
        pred->material_count = n;
    } else { free_artifact(art); }
}

void provenance_slsa_predicate_add_dependency(slsa_predicate_t* pred,
                                                const char* uri, const char* digest) {
    if (!pred || !uri) return;
    in_toto_artifact_t* art = (in_toto_artifact_t*)calloc(1, sizeof(in_toto_artifact_t));
    if (!art) return;
    art->uri = pm_strdup(uri);
    art->digest_sha256 = pm_strdup(digest);
    size_t n = pred->resolved_dep_count + 1;
    in_toto_artifact_t** new_dep = (in_toto_artifact_t**)realloc(
        pred->resolved_dependencies, n * sizeof(in_toto_artifact_t*));
    if (new_dep) {
        new_dep[pred->resolved_dep_count] = art;
        pred->resolved_dependencies = new_dep;
        pred->resolved_dep_count = n;
    } else { free_artifact(art); }
}

char* provenance_slsa_predicate_export_json(const slsa_predicate_t* pred) {
    if (!pred) return NULL;
    size_t cap = 8192;
    char* json = (char*)malloc(cap);
    if (!json) return NULL;
    snprintf(json, cap,
        "{\"builder\":{\"id\":\"%s\"},\"buildType\":\"custom\","
        "\"slsa_level\":%d,\"materials\":%zu,\"reproducible\":%s}",
        pred->builder_id ? pred->builder_id : "unknown",
        (int)pred->slsa_level, pred->material_count,
        pred->reproducible ? "true" : "false");
    return json;
}

void provenance_slsa_predicate_free(slsa_predicate_t* pred) {
    if (!pred) return;
    free(pred->predicate_type); free(pred->predicate_json);
    free(pred->subject_name); free(pred->subject_digest);
    free(pred->builder_id);
    for (size_t i = 0; i < pred->material_count; i++)
        free_artifact(pred->materials[i]);
    free(pred->materials);
    for (size_t i = 0; i < pred->resolved_dep_count; i++)
        free_artifact(pred->resolved_dependencies[i]);
    free(pred->resolved_dependencies);
    free(pred);
}

bin_auth_policy_t* bin_auth_policy_create(const char* binary_path) {
    bin_auth_policy_t* policy = (bin_auth_policy_t*)
        calloc(1, sizeof(bin_auth_policy_t));
    if (!policy) return NULL;
    policy->binary_path = pm_strdup(binary_path);
    policy->minimum_slsa_level = SLSA_LEVEL_2;
    return policy;
}

void bin_auth_policy_add_builder(bin_auth_policy_t* policy, const char* builder_id) {
    if (!policy || !builder_id) return;
    size_t n = policy->allowed_builder_count + 1;
    char** nb = (char**)realloc(policy->allowed_builder_ids, n * sizeof(char*));
    if (nb) {
        nb[policy->allowed_builder_count] = pm_strdup(builder_id);
        policy->allowed_builder_ids = nb;
        policy->allowed_builder_count = n;
    }
}

void bin_auth_policy_add_signer(bin_auth_policy_t* policy, const char* signer_id) {
    if (!policy || !signer_id) return;
    size_t n = policy->allowed_signer_count + 1;
    char** ns = (char**)realloc(policy->allowed_signer_ids, n * sizeof(char*));
    if (ns) {
        ns[policy->allowed_signer_count] = pm_strdup(signer_id);
        policy->allowed_signer_ids = ns;
        policy->allowed_signer_count = n;
    }
}

bin_auth_result_t* bin_auth_check_binary(const char* binary_path,
                                           const char* binary_digest,
                                           const attestation_bundle_t* bundle,
                                           const bin_auth_policy_t* policy) {
    (void)binary_path; (void)binary_digest;
    bin_auth_result_t* result = (bin_auth_result_t*)
        calloc(1, sizeof(bin_auth_result_t));
    if (!result) return NULL;
    if (!bundle || !bundle->layout) {
        result->decision = BIN_AUTH_DECISION_NEED_ATTESTATION;
        result->reason = pm_strdup("No attestation bundle provided");
        return result;
    }
    if (bundle->link_count == 0) {
        result->decision = BIN_AUTH_DECISION_DENY;
        result->reason = pm_strdup("No links in attestation bundle");
        return result;
    }
    if (policy && policy->allowed_builder_count > 0) {
        bool match = false;
        for (size_t i = 0; i < bundle->link_count && !match; i++) {
            if (!bundle->links[i] || !bundle->links[i]->functionary_name)
                continue;
            for (size_t j = 0; j < policy->allowed_builder_count; j++) {
                if (policy->allowed_builder_ids[j] &&
                    strstr(bundle->links[i]->functionary_name,
                           policy->allowed_builder_ids[j])) {
                    match = true; break;
                }
            }
        }
        if (!match) {
            result->decision = BIN_AUTH_DECISION_DENY;
            result->reason = pm_strdup("Builder not in allowed list");
            return result;
        }
    }
    result->decision = BIN_AUTH_DECISION_ALLOW;
    result->reason = pm_strdup("Binary authorized");
    result->matched_policy = policy ? pm_strdup(policy->binary_path) : NULL;
    return result;
}

void bin_auth_result_free(bin_auth_result_t* result) {
    if (!result) return;
    free(result->reason); free(result->matched_policy);
    for (size_t i = 0; i < result->missing_count; i++)
        free(result->missing_attestations[i]);
    free(result->missing_attestations);
    free(result);
}

void bin_auth_policy_free(bin_auth_policy_t* policy) {
    if (!policy) return;
    free(policy->binary_path); free(policy->binary_digest);
    for (size_t i = 0; i < policy->allowed_builder_count; i++)
        free(policy->allowed_builder_ids[i]);
    free(policy->allowed_builder_ids);
    for (size_t i = 0; i < policy->allowed_signer_count; i++)
        free(policy->allowed_signer_ids[i]);
    free(policy->allowed_signer_ids);
    for (size_t i = 0; i < policy->required_predicate_count; i++)
        free(policy->required_predicate_types[i]);
    free(policy->required_predicate_types);
    free(policy);
}

grafeas_note_t* grafeas_note_create(const char* name, const char* project,
                                      grafeas_note_kind_t kind,
                                      const char* short_desc) {
    grafeas_note_t* note = (grafeas_note_t*)calloc(1, sizeof(grafeas_note_t));
    if (!note) return NULL;
    note->note_name = pm_strdup(name);
    note->note_project = pm_strdup(project);
    note->note_kind = (kind == GRAFEAS_KIND_VULNERABILITY) ? "VULNERABILITY" :
                      (kind == GRAFEAS_KIND_BUILD) ? "BUILD" :
                      (kind == GRAFEAS_KIND_IMAGE) ? "IMAGE" :
                      (kind == GRAFEAS_KIND_PACKAGE) ? "PACKAGE" :
                      (kind == GRAFEAS_KIND_DEPLOYMENT) ? "DEPLOYMENT" :
                      (kind == GRAFEAS_KIND_ATTESTATION) ? "ATTESTATION" : "CUSTOM";
    note->note_short_description = pm_strdup(short_desc);
    note->create_time = time(NULL);
    note->update_time = note->create_time;
    return note;
}

void grafeas_note_add_url(grafeas_note_t* note, const char* url) {
    if (!note || !url) return;
    size_t n = note->related_url_count + 1;
    char** nu = (char**)realloc(note->related_urls, n * sizeof(char*));
    if (nu) {
        nu[note->related_url_count] = pm_strdup(url);
        note->related_urls = nu;
        note->related_url_count = n;
    }
}

char* grafeas_note_export_json(const grafeas_note_t* note) {
    if (!note) return NULL;
    size_t cap = 4096;
    char* json = (char*)malloc(cap);
    if (!json) return NULL;
    snprintf(json, cap,
        "{\"name\":\"%s\",\"project\":\"%s\",\"kind\":\"%s\","
        "\"description\":\"%s\"}",
        note->note_name ? note->note_name : "",
        note->note_project ? note->note_project : "",
        note->note_kind ? note->note_kind : "",
        note->note_short_description ? note->note_short_description : "");
    return json;
}

grafeas_note_t* grafeas_note_import_json(const char* json_data) {
    if (!json_data) return NULL;
    return grafeas_note_create("imported", "default", GRAFEAS_KIND_CUSTOM, "imported note");
}

void grafeas_note_free(grafeas_note_t* note) {
    if (!note) return;
    free(note->note_name); free(note->note_project);
    free(note->note_kind); free(note->note_short_description);
    free(note->note_long_description);
    for (size_t i = 0; i < note->related_url_count; i++)
        free(note->related_urls[i]);
    free(note->related_urls);
    free(note);
}

grafeas_occurrence_t* grafeas_occurrence_create(const char* name,
                                                   const char* resource_uri,
                                                   grafeas_note_kind_t kind) {
    grafeas_occurrence_t* occ = (grafeas_occurrence_t*)
        calloc(1, sizeof(grafeas_occurrence_t));
    if (!occ) return NULL;
    occ->occurrence_name = pm_strdup(name);
    occ->resource_uri = pm_strdup(resource_uri);
    occ->kind = kind;
    occ->discovered_time = time(NULL);
    return occ;
}

void grafeas_occurrence_attach_note(grafeas_occurrence_t* occurrence, const char* note_name) {
    if (!occurrence) return;
    free(occurrence->note_name);
    occurrence->note_name = pm_strdup(note_name);
}

void grafeas_occurrence_set_vulnerability(grafeas_occurrence_t* occurrence,
                                           const char* cve_id,
                                           const char* remediation) {
    if (!occurrence) return;
    free(occurrence->vulnerability_cve_id);
    free(occurrence->remediation_text);
    occurrence->vulnerability_cve_id = pm_strdup(cve_id);
    occurrence->remediation_text = pm_strdup(remediation);
}

char* grafeas_occurrence_export_json(const grafeas_occurrence_t* occurrence) {
    if (!occurrence) return NULL;
    size_t cap = 4096;
    char* json = (char*)malloc(cap);
    if (!json) return NULL;
    snprintf(json, cap,
        "{\"name\":\"%s\",\"resourceUri\":\"%s\",\"noteName\":\"%s\"}",
        occurrence->occurrence_name ? occurrence->occurrence_name : "",
        occurrence->resource_uri ? occurrence->resource_uri : "",
        occurrence->note_name ? occurrence->note_name : "");
    return json;
}

void grafeas_occurrence_free(grafeas_occurrence_t* occurrence) {
    if (!occurrence) return;
    free(occurrence->occurrence_name); free(occurrence->note_name);
    free(occurrence->resource_uri); free(occurrence->remediation_text);
    free(occurrence->vulnerability_cve_id);
    free(occurrence);
}

grafeas_project_t* grafeas_project_create(const char* name) {
    grafeas_project_t* proj = (grafeas_project_t*)
        calloc(1, sizeof(grafeas_project_t));
    if (!proj) return NULL;
    proj->project_name = pm_strdup(name);
    return proj;
}

void grafeas_project_add_note(grafeas_project_t* project, grafeas_note_t* note) {
    if (!project || !note) return;
    size_t n = project->note_count + 1;
    grafeas_note_t** nn = (grafeas_note_t**)realloc(
        project->notes, n * sizeof(grafeas_note_t*));
    if (nn) {
        nn[project->note_count] = note;
        project->notes = nn;
        project->note_count = n;
    }
}

void grafeas_project_add_occurrence(grafeas_project_t* project,
                                      grafeas_occurrence_t* occurrence) {
    if (!project || !occurrence) return;
    size_t n = project->occurrence_count + 1;
    grafeas_occurrence_t** no = (grafeas_occurrence_t**)realloc(
        project->occurrences, n * sizeof(grafeas_occurrence_t*));
    if (no) {
        no[project->occurrence_count] = occurrence;
        project->occurrences = no;
        project->occurrence_count = n;
    }
}

char* grafeas_project_export_json(const grafeas_project_t* project) {
    if (!project) return NULL;
    size_t cap = 16384;
    char* json = (char*)malloc(cap);
    if (!json) return NULL;
    snprintf(json, cap,
        "{\"project\":\"%s\",\"notes\":%zu,\"occurrences\":%zu}",
        project->project_name ? project->project_name : "",
        project->note_count, project->occurrence_count);
    return json;
}

void grafeas_project_free(grafeas_project_t* project) {
    if (!project) return;
    free(project->project_name);
    for (size_t i = 0; i < project->note_count; i++)
        grafeas_note_free(project->notes[i]);
    free(project->notes);
    for (size_t i = 0; i < project->occurrence_count; i++)
        grafeas_occurrence_free(project->occurrences[i]);
    free(project->occurrences);
    free(project);
}

kritis_policy_t* kritis_policy_create(const char* name, kritis_action_t default_action) {
    kritis_policy_t* policy = (kritis_policy_t*)
        calloc(1, sizeof(kritis_policy_t));
    if (!policy) return NULL;
    policy->policy_name = pm_strdup(name);
    policy->default_action = default_action;
    policy->minimum_slsa_level = SLSA_LEVEL_2;
    policy->max_critical_vulnerabilities = 0;
    policy->max_high_vulnerabilities = 5;
    return policy;
}

void kritis_policy_add_attestor(kritis_policy_t* policy, const char* attestor) {
    if (!policy || !attestor) return;
    size_t n = policy->required_attestor_count + 1;
    char** na = (char**)realloc(policy->required_attestors, n * sizeof(char*));
    if (na) {
        na[policy->required_attestor_count] = pm_strdup(attestor);
        policy->required_attestors = na;
        policy->required_attestor_count = n;
    }
}

void kritis_policy_add_predicate_type(kritis_policy_t* policy, const char* predicate_type) {
    if (!policy || !predicate_type) return;
    size_t n = policy->required_predicate_count + 1;
    char** np = (char**)realloc(policy->required_predicate_types, n * sizeof(char*));
    if (np) {
        np[policy->required_predicate_count] = pm_strdup(predicate_type);
        policy->required_predicate_types = np;
        policy->required_predicate_count = n;
    }
}

void kritis_policy_add_builder(kritis_policy_t* policy, const char* builder_id) {
    if (!policy || !builder_id) return;
    size_t n = policy->required_builder_count + 1;
    char** nb = (char**)realloc(policy->required_builder_ids, n * sizeof(char*));
    if (nb) {
        nb[policy->required_builder_count] = pm_strdup(builder_id);
        policy->required_builder_ids = nb;
        policy->required_builder_count = n;
    }
}

void kritis_policy_set_vulnerability_threshold(kritis_policy_t* policy,
                                                 int max_critical, int max_high) {
    if (!policy) return;
    policy->max_critical_vulnerabilities = max_critical;
    policy->max_high_vulnerabilities = max_high;
}

kritis_decision_t* kritis_evaluate(const kritis_policy_t* policy,
                                     const attestation_bundle_t* bundle,
                                     const char* image_reference) {
    (void)image_reference;
    kritis_decision_t* decision = (kritis_decision_t*)
        calloc(1, sizeof(kritis_decision_t));
    if (!decision) return NULL;
    if (!policy) {
        decision->allowed = false;
        decision->decision_reason = pm_strdup("No policy defined");
        return decision;
    }
    decision->attestation_satisfied = bundle && bundle->link_count > 0;
    decision->vulnerability_satisfied = true;
    decision->sbom_satisfied = true;
    decision->critical_vulns_found = 0;
    decision->high_vulns_found = 0;
    if (policy->required_attestor_count > 0 && !decision->attestation_satisfied) {
        decision->allowed = false;
        decision->decision_reason = pm_strdup("Required attestations not satisfied");
        return decision;
    }
    if (policy->max_critical_vulnerabilities == 0 && decision->critical_vulns_found > 0) {
        decision->allowed = false;
        decision->decision_reason = pm_strdup("Critical vulnerabilities found");
        return decision;
    }
    decision->allowed = (policy->default_action == KRITIS_ACTION_ALLOW);
    decision->decision_reason = pm_strdup(
        decision->allowed ? "Policy satisfied" : "Default deny");
    return decision;
}

bool kritis_is_allowed(const kritis_decision_t* decision) {
    return decision && decision->allowed;
}

char* kritis_decision_to_string(const kritis_decision_t* decision) {
    if (!decision) return pm_strdup("N/A");
    size_t cap = 1024;
    char* str = (char*)malloc(cap);
    if (!str) return NULL;
    snprintf(str, cap,
        "KritisDecision{allowed=%s, attestation=%s, vuln=%s, sbom=%s, "
        "critical=%d, high=%d, reason=%s}",
        decision->allowed ? "true" : "false",
        decision->attestation_satisfied ? "true" : "false",
        decision->vulnerability_satisfied ? "true" : "false",
        decision->sbom_satisfied ? "true" : "false",
        decision->critical_vulns_found, decision->high_vulns_found,
        decision->decision_reason ? decision->decision_reason : "");
    return str;
}

void kritis_decision_free(kritis_decision_t* decision) {
    if (!decision) return;
    free(decision->decision_reason);
    for (size_t i = 0; i < decision->violation_count; i++)
        free(decision->violation_reasons[i]);
    free(decision->violation_reasons);
    free(decision);
}

void kritis_policy_free(kritis_policy_t* policy) {
    if (!policy) return;
    free(policy->policy_name);
    for (size_t i = 0; i < policy->required_attestor_count; i++)
        free(policy->required_attestors[i]);
    free(policy->required_attestors);
    for (size_t i = 0; i < policy->required_predicate_count; i++)
        free(policy->required_predicate_types[i]);
    free(policy->required_predicate_types);
    for (size_t i = 0; i < policy->required_builder_count; i++)
        free(policy->required_builder_ids[i]);
    free(policy->required_builder_ids);
    free(policy);
}
