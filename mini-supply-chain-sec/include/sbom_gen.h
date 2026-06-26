#ifndef SBOM_GEN_H
#define SBOM_GEN_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SBOM_FORMAT_SPDX_2_3,
    SBOM_FORMAT_CYCLONEDX_1_5
} sbom_format_t;

typedef enum {
    SBOM_REL_DESCRIBES,
    SBOM_REL_DEPENDS_ON,
    SBOM_REL_CONTAINS,
    SBOM_REL_GENERATES,
    SBOM_REL_BUILD_TOOL_OF,
    SBOM_REL_PATCH_FOR
} sbom_relationship_type_t;

typedef struct {
    char* name;
    char* email;
    char* organization;
    char* tool;
} spdx_creator_t;

typedef struct {
    char* spdx_id;
    char* name;
    char* version;
    char* license_concluded;
    char* license_declared;
    char* copyright_text;
    char* supplier;
    char* download_url;
    char* checksum_sha256;
    char** external_refs;
    size_t external_ref_count;
} spdx_package_t;

typedef struct {
    char* source_spdx_id;
    char* target_spdx_id;
    sbom_relationship_type_t relationship;
    char* comment;
} spdx_relationship_t;

typedef struct {
    char* spdx_version;
    char* data_license;
    char* document_namespace;
    char* document_name;
    spdx_creator_t* creation_creator;
    time_t created;
    spdx_package_t** packages;
    size_t package_count;
    spdx_relationship_t** relationships;
    size_t relationship_count;
    char* spec_version;
} spdx_document_t;

typedef struct {
    char* type;
    char* bom_ref;
    char* name;
    char* version;
    char* purl;
    char* publisher;
    char* group;
    char* description;
    char** licenses;
    size_t license_count;
    char* sha256_hash;
    char** cpe_list;
    size_t cpe_count;
} cyclonedx_component_t;

typedef struct {
    char* ref;
    char** depends_on;
    size_t depends_on_count;
} cyclonedx_dependency_t;

typedef struct {
    char* bom_format;
    char* spec_version;
    char* serial_number;
    int version;
    cyclonedx_component_t** components;
    size_t component_count;
    cyclonedx_dependency_t** dependencies;
    size_t dependency_count;
    char* metadata_timestamp;
    char* metadata_tool;
} cyclonedx_bom_t;

typedef enum {
    VEX_STATUS_AFFECTED,
    VEX_STATUS_NOT_AFFECTED,
    VEX_STATUS_FIXED,
    VEX_STATUS_UNDER_INVESTIGATION
} vex_status_t;

typedef enum {
    VEX_JUST_COMPONENT_NOT_PRESENT,
    VEX_JUST_VULNERABLE_CODE_NOT_PRESENT,
    VEX_JUST_VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
    VEX_JUST_INLINE_MITIGATIONS_EXIST,
    VEX_JUST_PATCH_APPLIED
} vex_justification_t;

typedef struct {
    char* vulnerability_id;
    char* vulnerability_description;
    char* product_identifier;
    char* component_bom_ref;
    vex_status_t status;
    vex_justification_t justification;
    char* action_statement;
    char* release_date;
} vex_entry_t;

typedef struct {
    vex_entry_t** entries;
    size_t entry_count;
    char* document_id;
    char* author;
    time_t timestamp;
} vex_document_t;

typedef struct {
    char* predicate_type;
    char* subject_name;
    char* subject_digest_sha256;
    char* predicate_json;
    char* signature_base64;
    char* public_key_pem;
} sbom_attestation_t;

spdx_document_t* sbom_spdx_create(const char* name, const char* namespace_uri);
void sbom_spdx_add_package(spdx_document_t* doc, const char* name, const char* version,
                           const char* license, const char* supplier);
void sbom_spdx_add_relationship(spdx_document_t* doc, const char* src_id, const char* tgt_id,
                                sbom_relationship_type_t rel_type);
spdx_document_t* sbom_spdx_generate_from_build(const char* build_dir, const char* build_tool);
int sbom_spdx_parse_json(const char* json_data, spdx_document_t** out_doc);
char* sbom_spdx_export_json(const spdx_document_t* doc);
char* sbom_spdx_export_tagvalue(const spdx_document_t* doc);
void sbom_spdx_free(spdx_document_t* doc);

cyclonedx_bom_t* sbom_cyclonedx_create(const char* serial_number);
void sbom_cyclonedx_add_component(cyclonedx_bom_t* bom, const char* name, const char* version,
                                  const char* purl, const char* sha256);
void sbom_cyclonedx_add_dependency(cyclonedx_bom_t* bom, const char* ref, const char* depends_on_ref);
cyclonedx_bom_t* sbom_cyclonedx_generate_from_build(const char* build_dir,
                                                     const char* build_tool);
int sbom_cyclonedx_parse_json(const char* json_data, cyclonedx_bom_t** out_bom);
char* sbom_cyclonedx_export_json(const cyclonedx_bom_t* bom);
char* sbom_cyclonedx_export_xml(const cyclonedx_bom_t* bom);
void sbom_cyclonedx_free(cyclonedx_bom_t* bom);

vex_entry_t* vex_entry_create(const char* vuln_id, const char* product,
                              vex_status_t status, vex_justification_t justification);
vex_document_t* vex_document_create(const char* doc_id, const char* author);
void vex_document_add_entry(vex_document_t* doc, vex_entry_t* entry);
char* vex_document_export_json(const vex_document_t* doc);
int vex_document_parse_json(const char* json_data, vex_document_t** out_doc);
void vex_document_free(vex_document_t* doc);

sbom_attestation_t* sbom_attestation_create(const char* subject_name,
                                             const char* subject_digest,
                                             const char* predicate_type);
int sbom_attestation_sign(sbom_attestation_t* attestation,
                          const char* private_key_pem);
int sbom_attestation_verify(const sbom_attestation_t* attestation,
                            const char* public_key_pem);
char* sbom_attestation_export_bundle(const sbom_attestation_t* attestation);
void sbom_attestation_free(sbom_attestation_t* attestation);

typedef struct {
    char* component_name;
    char* component_version;
    char** dependents;
    size_t dependent_count;
    char** dependencies;
    size_t dep_count;
} sbom_component_node_t;

typedef struct {
    sbom_component_node_t** nodes;
    size_t node_count;
} sbom_component_graph_t;

sbom_component_graph_t* sbom_build_component_graph(const cyclonedx_bom_t* bom);
sbom_component_node_t* sbom_graph_find_node(const sbom_component_graph_t* graph,
                                             const char* name);
int sbom_graph_topological_sort(const sbom_component_graph_t* graph,
                                char*** out_sorted, size_t* out_count);
int sbom_graph_find_cycles(const sbom_component_graph_t* graph,
                           char*** out_cycles, size_t* out_count);
void sbom_component_graph_free(sbom_component_graph_t* graph);

#ifdef __cplusplus
}
#endif

#endif
