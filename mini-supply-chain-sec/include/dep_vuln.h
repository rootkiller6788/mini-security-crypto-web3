#ifndef DEP_VULN_H
#define DEP_VULN_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#include "sbom_gen.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CVSS_SEVERITY_NONE = 0,
    CVSS_SEVERITY_LOW = 1,
    CVSS_SEVERITY_MEDIUM = 2,
    CVSS_SEVERITY_HIGH = 3,
    CVSS_SEVERITY_CRITICAL = 4
} cvss_severity_t;

typedef enum {
    CVSS_VERSION_2_0,
    CVSS_VERSION_3_0,
    CVSS_VERSION_3_1,
    CVSS_VERSION_4_0
} cvss_version_t;

typedef struct {
    cvss_version_t version;
    float base_score;
    float temporal_score;
    float environmental_score;
    char* vector_string;
    cvss_severity_t base_severity;
    cvss_severity_t temporal_severity;
    cvss_severity_t environmental_severity;
    float exploitability_score;
    float impact_score;
    char attack_vector;
    char attack_complexity;
    char privileges_required;
    char user_interaction;
    char scope;
    char confidentiality;
    char integrity;
    char availability;
} cvss_score_t;

typedef enum {
    CVE_STATUS_RECEIVED,
    CVE_STATUS_ANALYZED,
    CVE_STATUS_MODIFIED,
    CVE_STATUS_REJECTED
} cve_status_t;

typedef struct {
    char* cve_id;
    char* description;
    cve_status_t status;
    time_t published_date;
    time_t last_modified_date;
    cvss_score_t* cvss_v2;
    cvss_score_t* cvss_v3;
    cvss_score_t* cvss_v4;
    char* cwe_id;
    char** affected_products;
    size_t affected_product_count;
    char** affected_versions;
    size_t affected_version_count;
    char** references;
    size_t reference_count;
    char** cpes;
    size_t cpe_count;
    bool disputed;
} cve_entry_t;

typedef enum {
    EXPLOIT_MATURITY_NONE,
    EXPLOIT_MATURITY_UNPROVEN,
    EXPLOIT_MATURITY_PROOF_OF_CONCEPT,
    EXPLOIT_MATURITY_FUNCTIONAL,
    EXPLOIT_MATURITY_HIGH,
    EXPLOIT_MATURITY_WEAPONIZED
} exploit_maturity_t;

typedef enum {
    PACKAGE_ECOSYSTEM_NPM,
    PACKAGE_ECOSYSTEM_PYPI,
    PACKAGE_ECOSYSTEM_MAVEN,
    PACKAGE_ECOSYSTEM_NUGET,
    PACKAGE_ECOSYSTEM_GO,
    PACKAGE_ECOSYSTEM_CARGO,
    PACKAGE_ECOSYSTEM_DEB,
    PACKAGE_ECOSYSTEM_RPM,
    PACKAGE_ECOSYSTEM_GEM,
    PACKAGE_ECOSYSTEM_CONAN,
    PACKAGE_ECOSYSTEM_UNKNOWN
} package_ecosystem_t;

typedef enum {
    REMEDIATION_UPGRADE,
    REMEDIATION_PATCH,
    REMEDIATION_WORKAROUND,
    REMEDIATION_MITIGATION,
    REMEDIATION_NO_FIX
} remediation_type_t;

typedef struct {
    char* cve_id;
    remediation_type_t type;
    char* description;
    char* fixed_version;
    char* patch_url;
    char* workaround_description;
    bool requires_restart;
    int priority;
} remediation_t;

typedef struct {
    char* package_name;
    char* package_version;
    char* purl;
    package_ecosystem_t ecosystem;
    char** registered_namespaces;
    size_t namespace_count;
    char** allowed_public_keys;
    size_t allowed_key_count;
    bool require_allowed_registry;
    char** allowed_registries_url;
    size_t allowed_reg_count;
} namespace_policy_t;

typedef struct {
    char* function_name;
    char* source_file;
    int line_number;
    bool reachable;
    char* reachability_path;
} reachability_result_t;

typedef struct {
    cve_entry_t** entries;
    size_t count;
    char* version;
    time_t last_updated;
} nvd_feed_t;

cve_entry_t* dep_vuln_create_entry(const char* cve_id, const char* description,
                                    time_t published);
void dep_vuln_set_cvss_v3(cve_entry_t* entry, const char* vector_string);
void dep_vuln_set_cvss_v4(cve_entry_t* entry, const char* vector_string);
void dep_vuln_add_affected_product(cve_entry_t* entry, const char* product,
                                    const char* version);
void dep_vuln_add_reference(cve_entry_t* entry, const char* reference);
void dep_vuln_add_cpe(cve_entry_t* entry, const char* cpe);
void dep_vuln_free_entry(cve_entry_t* entry);

cvss_score_t* cvss_create_from_vector(const char* vector_string);
cvss_severity_t cvss_score_to_severity(float score);
float cvss_calculate_base_score_v3(const char* av, const char* ac, const char* pr,
                                    const char* ui, const char* s, const char* c,
                                    const char* i, const char* a);
float cvss_calculate_base_score_v4(const char* av, const char* ac, const char* at,
                                    const char* pr, const char* ui, const char* vc,
                                    const char* vi, const char* va, const char* sc,
                                    const char* si, const char* sa);
const char* cvss_severity_to_string(cvss_severity_t severity);
void cvss_free(cvss_score_t* score);

nvd_feed_t* dep_vuln_load_nvd_feed(const char* feed_path);
nvd_feed_t* dep_vuln_fetch_nvd_feed(const char* api_url, const char* api_key);
int dep_vuln_save_nvd_feed(const nvd_feed_t* feed, const char* output_path);
cve_entry_t* dep_vuln_query_nvd(const nvd_feed_t* feed, const char* cve_id);
cve_entry_t** dep_vuln_query_by_product(const nvd_feed_t* feed, const char* product_name,
                                         const char* product_version,
                                         size_t* out_count);
cve_entry_t** dep_vuln_query_by_cpe(const nvd_feed_t* feed, const char* cpe_pattern,
                                     size_t* out_count);
void dep_vuln_feed_free(nvd_feed_t* feed);

int dep_vuln_scan_cyclonedx(const cyclonedx_bom_t* sbom,
                             const nvd_feed_t* feed,
                             cve_entry_t*** out_vulnerabilities,
                             size_t* out_count);
int dep_vuln_scan_spdx(const spdx_document_t* sbom,
                        const nvd_feed_t* feed,
                        cve_entry_t*** out_vulnerabilities,
                        size_t* out_count);
cve_entry_t** dep_vuln_match_package_vulnerabilities(const char* package_name,
                                                      const char* version,
                                                      package_ecosystem_t ecosystem,
                                                      const nvd_feed_t* feed,
                                                      size_t* out_count);

int dep_vuln_reachability_analysis(const char* binary_path,
                                    const char* vulnerable_function,
                                    const char* source_dir,
                                    reachability_result_t*** out_results,
                                    size_t* out_count);
bool dep_vuln_is_function_called(const char* call_graph_file,
                                  const char* target_function);
int dep_vuln_build_call_graph(const char* source_dir, const char** source_files,
                               size_t file_count, const char* output_graph_file);
void dep_vuln_reachability_result_free(reachability_result_t* result);

exploit_maturity_t dep_vuln_assess_exploit_maturity(const char* cve_id);
bool dep_vuln_has_public_poc(const char* cve_id);
bool dep_vuln_is_actively_exploited(const char* cve_id);
const char* dep_vuln_exploit_maturity_to_string(exploit_maturity_t maturity);

remediation_t* dep_vuln_suggest_remediation(const cve_entry_t* vuln,
                                              const char* current_version);
remediation_t* dep_vuln_create_remediation(const char* cve_id, remediation_type_t type,
                                            const char* fixed_version);
int dep_vuln_apply_remediation(const remediation_t* remediation);
bool dep_vuln_verify_remediation(const remediation_t* remediation);
char* dep_vuln_remediation_to_string(const remediation_t* remediation);
void dep_vuln_remediation_free(remediation_t* remediation);

int dep_vuln_prevent_confusion(const char* package_name,
                                const char* package_version,
                                const char* expected_namespace,
                                const namespace_policy_t* policy);
namespace_policy_t* dep_vuln_namespace_policy_create(const char* package_name);
void dep_vuln_namespace_policy_add_registry(namespace_policy_t* policy,
                                              const char* registry_url,
                                              const char* public_key);
bool dep_vuln_verify_namespace(const char* package_name,
                                const char* claimed_namespace,
                                const namespace_policy_t* policy);
void dep_vuln_namespace_policy_free(namespace_policy_t* policy);

#ifdef __cplusplus
}
#endif

#endif
