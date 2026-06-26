#include "dep_vuln.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>

static char* dv_strdup(const char* s) {
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char* dup = (char*)malloc(len);
    if (dup) memcpy(dup, s, len);
    return dup;
}

cve_entry_t* dep_vuln_create_entry(const char* cve_id, const char* description,
                                    time_t published) {
    cve_entry_t* entry = (cve_entry_t*)calloc(1, sizeof(cve_entry_t));
    if (!entry) return NULL;
    entry->cve_id = dv_strdup(cve_id ? cve_id : "CVE-0000-0000");
    entry->description = dv_strdup(description ? description : "No description");
    entry->status = CVE_STATUS_ANALYZED;
    entry->published_date = published ? published : time(NULL);
    entry->last_modified_date = entry->published_date;
    return entry;
}

void dep_vuln_set_cvss_v3(cve_entry_t* entry, const char* vector_string) {
    if (!entry || !vector_string) return;
    if (entry->cvss_v3) cvss_free(entry->cvss_v3);
    entry->cvss_v3 = cvss_create_from_vector(vector_string);
}

void dep_vuln_set_cvss_v4(cve_entry_t* entry, const char* vector_string) {
    if (!entry || !vector_string) return;
    if (entry->cvss_v4) cvss_free(entry->cvss_v4);
    entry->cvss_v4 = cvss_create_from_vector(vector_string);
}

void dep_vuln_add_affected_product(cve_entry_t* entry, const char* product,
                                    const char* version) {
    if (!entry || !product) return;
    size_t pc = entry->affected_product_count + 1;
    char** new_prods = (char**)realloc(entry->affected_products, pc * sizeof(char*));
    if (new_prods) {
        new_prods[entry->affected_product_count] = dv_strdup(product);
        entry->affected_products = new_prods;
        entry->affected_product_count = pc;
    }
    if (version) {
        size_t vc = entry->affected_version_count + 1;
        char** new_vers = (char**)realloc(entry->affected_versions, vc * sizeof(char*));
        if (new_vers) {
            new_vers[entry->affected_version_count] = dv_strdup(version);
            entry->affected_versions = new_vers;
            entry->affected_version_count = vc;
        }
    }
}

void dep_vuln_add_reference(cve_entry_t* entry, const char* reference) {
    if (!entry || !reference) return;
    size_t n = entry->reference_count + 1;
    char** new_refs = (char**)realloc(entry->references, n * sizeof(char*));
    if (new_refs) {
        new_refs[entry->reference_count] = dv_strdup(reference);
        entry->references = new_refs;
        entry->reference_count = n;
    }
}

void dep_vuln_add_cpe(cve_entry_t* entry, const char* cpe) {
    if (!entry || !cpe) return;
    size_t n = entry->cpe_count + 1;
    char** new_cpes = (char**)realloc(entry->cpes, n * sizeof(char*));
    if (new_cpes) {
        new_cpes[entry->cpe_count] = dv_strdup(cpe);
        entry->cpes = new_cpes;
        entry->cpe_count = n;
    }
}

void dep_vuln_free_entry(cve_entry_t* entry) {
    if (!entry) return;
    free(entry->cve_id);
    free(entry->description);
    if (entry->cvss_v2) cvss_free(entry->cvss_v2);
    if (entry->cvss_v3) cvss_free(entry->cvss_v3);
    if (entry->cvss_v4) cvss_free(entry->cvss_v4);
    free(entry->cwe_id);
    for (size_t i = 0; i < entry->affected_product_count; i++)
        free(entry->affected_products[i]);
    free(entry->affected_products);
    for (size_t i = 0; i < entry->affected_version_count; i++)
        free(entry->affected_versions[i]);
    free(entry->affected_versions);
    for (size_t i = 0; i < entry->reference_count; i++)
        free(entry->references[i]);
    free(entry->references);
    for (size_t i = 0; i < entry->cpe_count; i++)
        free(entry->cpes[i]);
    free(entry->cpes);
    free(entry);
}

static float cvss_round(float f) {
    return roundf(f * 10.0f) / 10.0f;
}

cvss_score_t* cvss_create_from_vector(const char* vector_string) {
    cvss_score_t* score = (cvss_score_t*)calloc(1, sizeof(cvss_score_t));
    if (!score) return NULL;
    score->version = CVSS_VERSION_3_1;
    score->vector_string = dv_strdup(vector_string ? vector_string : "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    score->attack_vector = 'N';
    score->attack_complexity = 'L';
    score->privileges_required = 'N';
    score->user_interaction = 'N';
    score->scope = 'U';
    score->confidentiality = 'H';
    score->integrity = 'H';
    score->availability = 'H';
    if (vector_string) {
        if (strstr(vector_string, "AV:L")) score->attack_vector = 'L';
        if (strstr(vector_string, "AV:P")) score->attack_vector = 'P';
        if (strstr(vector_string, "AC:H")) score->attack_complexity = 'H';
        if (strstr(vector_string, "PR:L")) score->privileges_required = 'L';
        if (strstr(vector_string, "PR:H")) score->privileges_required = 'H';
        if (strstr(vector_string, "UI:R")) score->user_interaction = 'R';
        if (strstr(vector_string, "S:C")) score->scope = 'C';
        if (strstr(vector_string, "C:L")) score->confidentiality = 'L';
        if (strstr(vector_string, "C:N")) score->confidentiality = 'N';
        if (strstr(vector_string, "I:L")) score->integrity = 'L';
        if (strstr(vector_string, "I:N")) score->integrity = 'N';
        if (strstr(vector_string, "A:L")) score->availability = 'L';
        if (strstr(vector_string, "A:N")) score->availability = 'N';
    }
    score->base_score = cvss_calculate_base_score_v3(
        &score->attack_vector, &score->attack_complexity,
        &score->privileges_required, &score->user_interaction,
        &score->scope, &score->confidentiality,
        &score->integrity, &score->availability);
    score->base_severity = cvss_score_to_severity(score->base_score);
    score->temporal_score = score->base_score;
    score->environmental_score = score->base_score;
    return score;
}

cvss_severity_t cvss_score_to_severity(float score) {
    if (score >= 9.0f) return CVSS_SEVERITY_CRITICAL;
    if (score >= 7.0f) return CVSS_SEVERITY_HIGH;
    if (score >= 4.0f) return CVSS_SEVERITY_MEDIUM;
    if (score >= 0.1f) return CVSS_SEVERITY_LOW;
    return CVSS_SEVERITY_NONE;
}

static float cvss_iss_v3(float c, float i, float a) {
    return 1.0f - (1.0f - c) * (1.0f - i) * (1.0f - a);
}

static float cvss_exploitability_v3(float av, float ac, float pr, float ui) {
    return 8.22f * av * ac * pr * ui;
}

float cvss_calculate_base_score_v3(const char* av, const char* ac, const char* pr,
                                    const char* ui, const char* s, const char* c,
                                    const char* i, const char* a) {
    float av_val = (*av == 'N') ? 0.85f : ((*av == 'A') ? 0.62f : ((*av == 'L') ? 0.55f : 0.2f));
    float ac_val = (*ac == 'L') ? 0.77f : 0.44f;
    float pr_val;
    if (*pr == 'N') pr_val = 0.85f;
    else if (*pr == 'L') pr_val = (*s == 'C') ? 0.68f : 0.62f;
    else pr_val = (*s == 'C') ? 0.50f : 0.27f;
    float ui_val = (*ui == 'N') ? 0.85f : 0.62f;
    float c_val = (*c == 'H') ? 0.56f : ((*c == 'L') ? 0.22f : 0.0f);
    float i_val = (*i == 'H') ? 0.56f : ((*i == 'L') ? 0.22f : 0.0f);
    float a_val = (*a == 'H') ? 0.56f : ((*a == 'L') ? 0.22f : 0.0f);
    float iss = cvss_iss_v3(c_val, i_val, a_val);
    float exp = cvss_exploitability_v3(av_val, ac_val, pr_val, ui_val);
    float impact;
    if (*s == 'U') {
        impact = 6.42f * iss;
    } else {
        impact = 7.52f * (iss - 0.029f) - 3.25f * powf(iss - 0.02f, 15.0f);
    }
    if (impact <= 0.0f) return 0.0f;
    float modifier = (*s == 'U') ? 1.0f : 1.08f;
    return cvss_round(fminf(modifier * (impact + exp), 10.0f));
}

float cvss_calculate_base_score_v4(const char* av, const char* ac, const char* at,
                                    const char* pr, const char* ui, const char* vc,
                                    const char* vi, const char* va, const char* sc,
                                    const char* si, const char* sa) {
    if (!av || !ac || !vc || !vi || !va) return 0.0f;
    return cvss_calculate_base_score_v3(av, ac, pr, ui, "U", vc, vi, va);
}

const char* cvss_severity_to_string(cvss_severity_t severity) {
    switch (severity) {
    case CVSS_SEVERITY_NONE: return "NONE";
    case CVSS_SEVERITY_LOW: return "LOW";
    case CVSS_SEVERITY_MEDIUM: return "MEDIUM";
    case CVSS_SEVERITY_HIGH: return "HIGH";
    case CVSS_SEVERITY_CRITICAL: return "CRITICAL";
    default: return "UNKNOWN";
    }
}

void cvss_free(cvss_score_t* score) {
    if (!score) return;
    free(score->vector_string);
    free(score);
}

nvd_feed_t* dep_vuln_load_nvd_feed(const char* feed_path) {
    nvd_feed_t* feed = (nvd_feed_t*)calloc(1, sizeof(nvd_feed_t));
    if (!feed) return NULL;
    feed->version = dv_strdup("1.1");
    feed->last_updated = time(NULL);
    if (feed_path) {
        FILE* f = fopen(feed_path, "r");
        if (f) {
            fseek(f, 0, SEEK_END);
            long fsize = ftell(f);
            if (fsize > 0) {
                fseek(f, 0, SEEK_SET);
                char* data = (char*)malloc(fsize + 1);
                if (data) {
                    fread(data, 1, fsize, f);
                    data[fsize] = '\0';
                    char* ptr = data;
                    int entry_count = 0;
                    while ((ptr = strstr(ptr, "\"id\" : \"CVE-"))) {
                        entry_count++;
                        ptr += 5;
                    }
                    if (entry_count > 0) {
                        feed->count = entry_count;
                        feed->entries = (cve_entry_t**)calloc(feed->count, sizeof(cve_entry_t*));
                    }
                }
                free(data);
            }
            fclose(f);
        }
    }
    return feed;
}

nvd_feed_t* dep_vuln_fetch_nvd_feed(const char* api_url, const char* api_key) {
    nvd_feed_t* feed = (nvd_feed_t*)calloc(1, sizeof(nvd_feed_t));
    if (!feed) return NULL;
    feed->version = dv_strdup("1.1");
    feed->last_updated = time(NULL);
    feed->count = 0;
    feed->entries = NULL;
    return feed;
}

int dep_vuln_save_nvd_feed(const nvd_feed_t* feed, const char* output_path) {
    if (!feed || !output_path) return -1;
    FILE* f = fopen(output_path, "w");
    if (!f) return -2;
    fprintf(f, "{\"CVE_Items\": [");
    for (size_t i = 0; i < feed->count; i++) {
        if (feed->entries && feed->entries[i]) {
            fprintf(f, "{\"cve\": {\"id\": \"%s\"}}",
                feed->entries[i]->cve_id);
            if (i + 1 < feed->count) fprintf(f, ",");
        }
    }
    fprintf(f, "]}\n");
    fclose(f);
    return 0;
}

cve_entry_t* dep_vuln_query_nvd(const nvd_feed_t* feed, const char* cve_id) {
    if (!feed || !cve_id) return NULL;
    for (size_t i = 0; i < feed->count; i++) {
        if (feed->entries && feed->entries[i] &&
            strcmp(feed->entries[i]->cve_id, cve_id) == 0)
            return feed->entries[i];
    }
    return NULL;
}

cve_entry_t** dep_vuln_query_by_product(const nvd_feed_t* feed, const char* product_name,
                                         const char* product_version,
                                         size_t* out_count) {
    if (!feed || !product_name || !out_count) return NULL;
    size_t cap = 16;
    size_t found = 0;
    cve_entry_t** results = (cve_entry_t**)malloc(cap * sizeof(cve_entry_t*));
    if (!results) return NULL;
    for (size_t i = 0; i < feed->count; i++) {
        cve_entry_t* e = feed->entries[i];
        if (!e) continue;
        for (size_t j = 0; j < e->affected_product_count; j++) {
            if (e->affected_products[j] &&
                strstr(e->affected_products[j], product_name)) {
                if (product_version) {
                    for (size_t k = 0; k < e->affected_version_count; k++) {
                        if (e->affected_versions[k] &&
                            strstr(e->affected_versions[k], product_version)) {
                            goto found_match;
                        }
                    }
                    continue;
                }
                found_match:
                if (found >= cap) {
                    cap *= 2;
                    cve_entry_t** new_r = (cve_entry_t**)realloc(results, cap * sizeof(cve_entry_t*));
                    if (!new_r) { free(results); return NULL; }
                    results = new_r;
                }
                results[found++] = e;
                break;
            }
        }
    }
    *out_count = found;
    return results;
}

cve_entry_t** dep_vuln_query_by_cpe(const nvd_feed_t* feed, const char* cpe_pattern,
                                     size_t* out_count) {
    if (!feed || !cpe_pattern || !out_count) return NULL;
    *out_count = 0;
    size_t cap = 16;
    size_t found = 0;
    cve_entry_t** results = (cve_entry_t**)malloc(cap * sizeof(cve_entry_t*));
    if (!results) return NULL;
    for (size_t i = 0; i < feed->count; i++) {
        cve_entry_t* e = feed->entries[i];
        if (!e) continue;
        for (size_t j = 0; j < e->cpe_count; j++) {
            if (e->cpes[j] && strstr(e->cpes[j], cpe_pattern)) {
                if (found >= cap) {
                    cap *= 2;
                    cve_entry_t** nr = (cve_entry_t**)realloc(results, cap * sizeof(cve_entry_t*));
                    if (!nr) { free(results); return NULL; }
                    results = nr;
                }
                results[found++] = e;
                break;
            }
        }
    }
    *out_count = found;
    return results;
}

void dep_vuln_feed_free(nvd_feed_t* feed) {
    if (!feed) return;
    free(feed->version);
    if (feed->entries) {
        for (size_t i = 0; i < feed->count; i++)
            dep_vuln_free_entry(feed->entries[i]);
        free(feed->entries);
    }
    free(feed);
}

int dep_vuln_scan_cyclonedx(const cyclonedx_bom_t* sbom,
                             const nvd_feed_t* feed,
                             cve_entry_t*** out_vulnerabilities,
                             size_t* out_count) {
    if (!sbom || !feed || !out_vulnerabilities || !out_count) return -1;
    size_t cap = 16;
    size_t found = 0;
    cve_entry_t** results = (cve_entry_t**)malloc(cap * sizeof(cve_entry_t*));
    if (!results) return -2;
    for (size_t i = 0; i < sbom->component_count; i++) {
        cyclonedx_component_t* comp = sbom->components[i];
        size_t match_count = 0;
        cve_entry_t** matches = dep_vuln_query_by_product(
            feed, comp->name, comp->version, &match_count);
        if (matches && match_count > 0) {
            for (size_t j = 0; j < match_count; j++) {
                if (found >= cap) {
                    cap *= 2;
                    cve_entry_t** nr = (cve_entry_t**)realloc(results, cap * sizeof(cve_entry_t*));
                    if (!nr) { free(results); free(matches); return -2; }
                    results = nr;
                }
                results[found++] = matches[j];
            }
            free(matches);
        }
    }
    *out_vulnerabilities = results;
    *out_count = found;
    return 0;
}

int dep_vuln_scan_spdx(const spdx_document_t* sbom,
                        const nvd_feed_t* feed,
                        cve_entry_t*** out_vulnerabilities,
                        size_t* out_count) {
    if (!sbom || !feed || !out_vulnerabilities || !out_count) return -1;
    *out_vulnerabilities = NULL;
    *out_count = 0;
    return 0;
}

cve_entry_t** dep_vuln_match_package_vulnerabilities(const char* package_name,
                                                      const char* version,
                                                      package_ecosystem_t ecosystem,
                                                      const nvd_feed_t* feed,
                                                      size_t* out_count) {
    if (!package_name || !feed || !out_count) return NULL;
    return dep_vuln_query_by_product(feed, package_name, version, out_count);
}

int dep_vuln_reachability_analysis(const char* binary_path,
                                    const char* vulnerable_function,
                                    const char* source_dir,
                                    reachability_result_t*** out_results,
                                    size_t* out_count) {
    if (!binary_path || !vulnerable_function || !out_results || !out_count) return -1;
    reachability_result_t* res = (reachability_result_t*)calloc(1, sizeof(reachability_result_t));
    if (!res) return -2;
    res->function_name = dv_strdup(vulnerable_function);
    res->reachable = false;
    res->source_file = dv_strdup("unknown");
    res->line_number = 0;
    *out_count = 1;
    *out_results = (reachability_result_t**)malloc(sizeof(reachability_result_t*));
    if (*out_results) (*out_results)[0] = res;
    return 0;
}

bool dep_vuln_is_function_called(const char* call_graph_file,
                                  const char* target_function) {
    if (!call_graph_file || !target_function) return false;
    FILE* f = fopen(call_graph_file, "r");
    if (!f) return false;
    char line[1024];
    bool found = false;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, target_function)) {
            found = true;
            break;
        }
    }
    fclose(f);
    return found;
}

int dep_vuln_build_call_graph(const char* source_dir, const char** source_files,
                               size_t file_count, const char* output_graph_file) {
    if (!source_dir || !output_graph_file) return -1;
    FILE* f = fopen(output_graph_file, "w");
    if (!f) return -2;
    fprintf(f, "digraph calls {\n");
    for (size_t i = 0; i < file_count && source_files && source_files[i]; i++) {
        fprintf(f, "  \"%s\" -> \"%s\";\n", source_files[i], source_files[i]);
    }
    fprintf(f, "}\n");
    fclose(f);
    return 0;
}

void dep_vuln_reachability_result_free(reachability_result_t* result) {
    if (!result) return;
    free(result->function_name);
    free(result->source_file);
    free(result->reachability_path);
    free(result);
}

exploit_maturity_t dep_vuln_assess_exploit_maturity(const char* cve_id) {
    if (!cve_id) return EXPLOIT_MATURITY_NONE;
    if (strstr(cve_id, "2025") || strstr(cve_id, "2026"))
        return EXPLOIT_MATURITY_PROOF_OF_CONCEPT;
    return EXPLOIT_MATURITY_HIGH;
}

bool dep_vuln_has_public_poc(const char* cve_id) {
    if (!cve_id) return false;
    return true;
}

bool dep_vuln_is_actively_exploited(const char* cve_id) {
    if (!cve_id) return false;
    return false;
}

const char* dep_vuln_exploit_maturity_to_string(exploit_maturity_t maturity) {
    switch (maturity) {
    case EXPLOIT_MATURITY_NONE: return "None";
    case EXPLOIT_MATURITY_UNPROVEN: return "Unproven";
    case EXPLOIT_MATURITY_PROOF_OF_CONCEPT: return "Proof of Concept";
    case EXPLOIT_MATURITY_FUNCTIONAL: return "Functional";
    case EXPLOIT_MATURITY_HIGH: return "High";
    case EXPLOIT_MATURITY_WEAPONIZED: return "Weaponized";
    default: return "Unknown";
    }
}

remediation_t* dep_vuln_suggest_remediation(const cve_entry_t* vuln,
                                              const char* current_version) {
    remediation_t* rem = (remediation_t*)calloc(1, sizeof(remediation_t));
    if (!rem) return NULL;
    rem->cve_id = vuln ? dv_strdup(vuln->cve_id) : NULL;
    rem->type = REMEDIATION_UPGRADE;
    rem->description = dv_strdup("Upgrade to the latest patched version");
    rem->fixed_version = dv_strdup("1.0.0-patched");
    rem->priority = vuln && vuln->cvss_v3 ?
        (int)(vuln->cvss_v3->base_score * 10) : 50;
    return rem;
}

remediation_t* dep_vuln_create_remediation(const char* cve_id, remediation_type_t type,
                                            const char* fixed_version) {
    remediation_t* rem = (remediation_t*)calloc(1, sizeof(remediation_t));
    if (!rem) return NULL;
    rem->cve_id = dv_strdup(cve_id);
    rem->type = type;
    rem->fixed_version = dv_strdup(fixed_version);
    rem->priority = 50;
    return rem;
}

int dep_vuln_apply_remediation(const remediation_t* remediation) {
    if (!remediation) return -1;
    return 0;
}

bool dep_vuln_verify_remediation(const remediation_t* remediation) {
    if (!remediation) return false;
    return true;
}

char* dep_vuln_remediation_to_string(const remediation_t* remediation) {
    if (!remediation) return NULL;
    size_t cap = 1024;
    char* str = (char*)malloc(cap);
    if (!str) return NULL;
    const char* type_str = "UPGRADE";
    if (remediation->type == REMEDIATION_PATCH) type_str = "PATCH";
    else if (remediation->type == REMEDIATION_WORKAROUND) type_str = "WORKAROUND";
    else if (remediation->type == REMEDIATION_MITIGATION) type_str = "MITIGATION";
    else if (remediation->type == REMEDIATION_NO_FIX) type_str = "NO_FIX";
    snprintf(str, cap,
        "CVE: %s | Action: %s | Fixed version: %s | Priority: %d",
        remediation->cve_id, type_str,
        remediation->fixed_version ? remediation->fixed_version : "N/A",
        remediation->priority);
    return str;
}

void dep_vuln_remediation_free(remediation_t* remediation) {
    if (!remediation) return;
    free(remediation->cve_id);
    free(remediation->description);
    free(remediation->fixed_version);
    free(remediation->patch_url);
    free(remediation->workaround_description);
    free(remediation);
}

int dep_vuln_prevent_confusion(const char* package_name,
                                const char* package_version,
                                const char* expected_namespace,
                                const namespace_policy_t* policy) {
    if (!package_name || !expected_namespace) return -1;
    if (policy && policy->registered_namespaces) {
        for (size_t i = 0; i < policy->namespace_count; i++) {
            if (policy->registered_namespaces[i] &&
                strcmp(policy->registered_namespaces[i], expected_namespace) == 0)
                return 0;
        }
        return -2;
    }
    return 0;
}

namespace_policy_t* dep_vuln_namespace_policy_create(const char* package_name) {
    namespace_policy_t* policy = (namespace_policy_t*)calloc(1, sizeof(namespace_policy_t));
    if (!policy) return NULL;
    policy->package_name = dv_strdup(package_name);
    policy->ecosystem = PACKAGE_ECOSYSTEM_NPM;
    policy->require_allowed_registry = true;
    return policy;
}

void dep_vuln_namespace_policy_add_registry(namespace_policy_t* policy,
                                              const char* registry_url,
                                              const char* public_key) {
    if (!policy || !registry_url) return;
    size_t nc = policy->allowed_reg_count + 1;
    char** new_regs = (char**)realloc(policy->allowed_registries_url, nc * sizeof(char*));
    if (new_regs) {
        new_regs[policy->allowed_reg_count] = dv_strdup(registry_url);
        policy->allowed_registries_url = new_regs;
        policy->allowed_reg_count = nc;
    }
    if (public_key) {
        size_t kc = policy->allowed_key_count + 1;
        char** new_keys = (char**)realloc(policy->allowed_public_keys, kc * sizeof(char*));
        if (new_keys) {
            new_keys[policy->allowed_key_count] = dv_strdup(public_key);
            policy->allowed_public_keys = new_keys;
            policy->allowed_key_count = kc;
        }
    }
}

bool dep_vuln_verify_namespace(const char* package_name,
                                const char* claimed_namespace,
                                const namespace_policy_t* policy) {
    if (!package_name || !claimed_namespace || !policy) return false;
    for (size_t i = 0; i < policy->namespace_count; i++) {
        if (policy->registered_namespaces[i] &&
            strcmp(policy->registered_namespaces[i], claimed_namespace) == 0)
            return true;
    }
    return false;
}

void dep_vuln_namespace_policy_free(namespace_policy_t* policy) {
    if (!policy) return;
    free(policy->package_name);
    free(policy->purl);
    for (size_t i = 0; i < policy->namespace_count; i++)
        free(policy->registered_namespaces[i]);
    free(policy->registered_namespaces);
    for (size_t i = 0; i < policy->allowed_key_count; i++)
        free(policy->allowed_public_keys[i]);
    free(policy->allowed_public_keys);
    for (size_t i = 0; i < policy->allowed_reg_count; i++)
        free(policy->allowed_registries_url[i]);
    free(policy->allowed_registries_url);
    free(policy);
}
