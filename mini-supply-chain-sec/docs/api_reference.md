# mini-supply-chain-sec API Reference

## Module 1: sbom_gen.h — SBOM Generation

### Types

| Type | Description |
|------|-------------|
| `sbom_format_t` | `SBOM_FORMAT_SPDX_2_3`, `SBOM_FORMAT_CYCLONEDX_1_5` |
| `spdx_creator_t` | Creator info (name, email, org, tool) |
| `spdx_package_t` | Package entry (SPDX ID, name, version, license, supplier) |
| `spdx_relationship_t` | Relationship between two SPDX elements |
| `spdx_document_t` | Full SPDX document |
| `cyclonedx_component_t` | CycloneDX component (type, name, version, purl) |
| `cyclonedx_dependency_t` | CycloneDX dependency reference |
| `cyclonedx_bom_t` | Full CycloneDX BOM |
| `vex_status_t` | `AFFECTED`, `NOT_AFFECTED`, `FIXED`, `UNDER_INVESTIGATION` |
| `vex_entry_t` | VEX entry (vuln ID, product, status, justification) |
| `vex_document_t` | Collection of VEX entries |
| `sbom_attestation_t` | in-toto SBOM attestation |
| `sbom_component_graph_t` | Component dependency graph |
| `sbom_component_node_t` | Graph node |

### Functions: SPDX

```c
spdx_document_t* sbom_spdx_create(const char* name, const char* namespace_uri);
void sbom_spdx_add_package(spdx_document_t* doc, const char* name, const char* version,
                           const char* license, const char* supplier);
void sbom_spdx_add_relationship(spdx_document_t* doc, const char* src_id,
                                const char* tgt_id, sbom_relationship_type_t rel);
spdx_document_t* sbom_spdx_generate_from_build(const char* build_dir, const char* build_tool);
int sbom_spdx_parse_json(const char* json_data, spdx_document_t** out_doc);
char* sbom_spdx_export_json(const spdx_document_t* doc);
char* sbom_spdx_export_tagvalue(const spdx_document_t* doc);
void sbom_spdx_free(spdx_document_t* doc);
```

### Functions: CycloneDX

```c
cyclonedx_bom_t* sbom_cyclonedx_create(const char* serial_number);
void sbom_cyclonedx_add_component(cyclonedx_bom_t* bom, const char* name,
                                  const char* version, const char* purl, const char* sha256);
void sbom_cyclonedx_add_dependency(cyclonedx_bom_t* bom, const char* ref, const char* dep_ref);
cyclonedx_bom_t* sbom_cyclonedx_generate_from_build(const char* build_dir, const char* tool);
int sbom_cyclonedx_parse_json(const char* json_data, cyclonedx_bom_t** out_bom);
char* sbom_cyclonedx_export_json(const cyclonedx_bom_t* bom);
char* sbom_cyclonedx_export_xml(const cyclonedx_bom_t* bom);
void sbom_cyclonedx_free(cyclonedx_bom_t* bom);
```

### Functions: VEX

```c
vex_entry_t* vex_entry_create(const char* vuln_id, const char* product,
                              vex_status_t status, vex_justification_t just);
vex_document_t* vex_document_create(const char* doc_id, const char* author);
void vex_document_add_entry(vex_document_t* doc, vex_entry_t* entry);
char* vex_document_export_json(const vex_document_t* doc);
int vex_document_parse_json(const char* json_data, vex_document_t** out_doc);
void vex_document_free(vex_document_t* doc);
```

### Functions: Attestation & Graph

```c
sbom_attestation_t* sbom_attestation_create(const char* subject, const char* digest,
                                             const char* predicate_type);
int sbom_attestation_sign(sbom_attestation_t* att, const char* private_key_pem);
int sbom_attestation_verify(const sbom_attestation_t* att, const char* public_key_pem);
char* sbom_attestation_export_bundle(const sbom_attestation_t* att);
void sbom_attestation_free(sbom_attestation_t* att);

sbom_component_graph_t* sbom_build_component_graph(const cyclonedx_bom_t* bom);
sbom_component_node_t* sbom_graph_find_node(const sbom_component_graph_t* graph, const char* name);
int sbom_graph_topological_sort(const sbom_component_graph_t* graph,
                                char*** out_sorted, size_t* out_count);
int sbom_graph_find_cycles(const sbom_component_graph_t* graph,
                           char*** out_cycles, size_t* out_count);
void sbom_component_graph_free(sbom_component_graph_t* graph);
```

## Module 2: slsa_framework.h — SLSA Levels

### Types

| Type | Description |
|------|-------------|
| `slsa_level_t` | `SLSA_LEVEL_0` through `SLSA_LEVEL_4` |
| `slsa_source_t` | Source verification state |
| `slsa_build_config_t` | Build configuration |
| `slsa_build_isolation_t` | `CONTAINER`, `VM`, `SANDBOX`, `NONE` |
| `slsa_provenance_t` | SLSA provenance attestation |
| `slsa_verification_result_t` | Verification result |
| `pipeline_t` | Declarative build pipeline |
| `pipeline_step_t` | Pipeline step |

### Functions

```c
slsa_level_t slsa_assess_source_level(const slsa_source_t* source);
slsa_level_t slsa_assess_build_level(const slsa_build_config_t* build);
slsa_level_t slsa_determine_overall_level(slsa_level_t src, slsa_level_t build);
const char* slsa_level_to_string(slsa_level_t level);
slsa_level_t slsa_level_from_string(const char* str);

slsa_source_t* slsa_source_create(const char* repo_url, const char* commit_sha);
void slsa_source_set_signed(slsa_source_t* src, const char* signer, const char* fingerprint);
bool slsa_source_verify_signature(const slsa_source_t* src, const char* pubkey);
void slsa_source_free(slsa_source_t* src);

slsa_build_config_t* slsa_build_config_create(const char* platform, const char* builder_id);
void slsa_build_config_set_hermetic(slsa_build_config_t* cfg, bool hermetic, slsa_build_isolation_t iso);
void slsa_build_config_add_input(slsa_build_config_t* cfg, const char* uri);
void slsa_build_config_add_output(slsa_build_config_t* cfg, const char* uri);
bool slsa_build_config_validate(const slsa_build_config_t* cfg, slsa_level_t target);
void slsa_build_config_free(slsa_build_config_t* cfg);

slsa_provenance_t* slsa_provenance_create(const char* subject, const char* digest, const char* pred);
void slsa_provenance_attach_source(slsa_provenance_t* prov, const slsa_source_t* src);
void slsa_provenance_attach_build(slsa_provenance_t* prov, const slsa_build_config_t* cfg);
void slsa_provenance_add_material(slsa_provenance_t* prov, const char* uri);
int slsa_provenance_sign(slsa_provenance_t* prov, const char* private_key_pem);
int slsa_provenance_export_intoto(slsa_provenance_t* prov, char** out_json);
slsa_provenance_t* slsa_provenance_import_intoto(const char* json);
slsa_verification_result_t* slsa_verify_provenance(const slsa_provenance_t* prov,
    const char* trusted_builders[], size_t count, const char* pubkey);
void slsa_provenance_free(slsa_provenance_t* prov);
void slsa_verification_result_free(slsa_verification_result_t* result);

pipeline_t* pipeline_create(const char* name, const char* version);
void pipeline_add_step(pipeline_t* p, const char* name, const char* image,
                       const char* entrypoint, bool isolated);
void pipeline_step_add_argument(pipeline_step_t* step, const char* arg);
void pipeline_step_add_environment(pipeline_step_t* step, const char* key, const char* value);
void pipeline_step_add_input(pipeline_step_t* step, const char* artifact);
void pipeline_step_add_output(pipeline_step_t* step, const char* artifact);
bool pipeline_validate_slsa(const pipeline_t* pipeline, slsa_level_t target);
char* pipeline_export_declarative(const pipeline_t* pipeline);
void pipeline_free(pipeline_t* pipeline);
```

## Module 3: sigstore_cosign.h — Sigstore/Cosign

### Types

| Type | Description |
|------|-------------|
| `oidc_identity_t` | OIDC token and identity |
| `fulcio_certificate_t` | Fulcio-issued short-lived cert |
| `rekor_entry_t` | Rekor transparency log entry |
| `cosign_signature_t` | Container image signature |
| `cosign_attestation_t` | in-toto attestation in sigstore |
| `sigstore_policy_t` | Policy controller |
| `sigstore_policy_action_t` | `ALLOW`, `DENY`, `WARN` |

### Functions: OIDC

```c
oidc_identity_t* sigstore_oidc_authenticate(const char* issuer_url, const char* client_id);
bool sigstore_oidc_validate_token(const oidc_identity_t* identity);
int sigstore_oidc_refresh_token(oidc_identity_t* identity);
void sigstore_oidc_free(oidc_identity_t* identity);
```

### Functions: Fulcio

```c
fulcio_certificate_t* sigstore_fulcio_request_certificate(const oidc_identity_t* id,
    const char* pubkey_pem, const char* fulcio_url);
int sigstore_fulcio_verify_certificate_chain(const fulcio_certificate_t* cert, const char* root_ca);
bool sigstore_fulcio_validate_cert_identity(const fulcio_certificate_t* cert, const oidc_identity_t* id);
void sigstore_fulcio_free(fulcio_certificate_t* cert);
```

### Functions: Rekor

```c
rekor_entry_t* sigstore_rekor_create_entry(const char* sig, const char* payload,
    const fulcio_certificate_t* cert, const char* rekor_url);
int sigstore_rekor_verify_entry(const rekor_entry_t* entry, const char* pubkey);
bool sigstore_rekor_check_inclusion(const rekor_entry_t* entry);
int sigstore_rekor_query_by_artifact(const char* digest, const char* url,
    rekor_entry_t*** out, size_t* count);
void sigstore_rekor_free(rekor_entry_t* entry);
```

### Functions: Cosign

```c
cosign_signature_t* cosign_sign_image(const char* image, const char* key, bool keyless);
cosign_signature_t* cosign_sign_image_keyless(const char* image, oidc_identity_t* id,
    const char* fulcio_url, const char* rekor_url);
int cosign_verify_image(const char* image, const char* pubkey, sigstore_policy_t* policy,
    cosign_signature_t*** out, size_t* count);
int cosign_verify_image_signatures(const char* image, char** pubkeys, size_t n, bool* verified);
int cosign_attach_signature(const char* image, cosign_signature_t* sig);
int cosign_clean_signatures(const char* image);
void cosign_signature_free(cosign_signature_t* sig);

cosign_attestation_t* cosign_attestation_create(const char* image, const char* pred_type,
    const char* pred_json);
int cosign_attestation_sign(cosign_attestation_t* att, const char* key, bool keyless,
    oidc_identity_t* id);
int cosign_attestation_verify(const cosign_attestation_t* att, const char* pubkey,
    sigstore_policy_t* policy);
char* cosign_attestation_export_bundle(const cosign_attestation_t* att);
void cosign_attestation_free(cosign_attestation_t* att);
```

### Functions: Policy Controller

```c
sigstore_policy_t* sigstore_policy_create(const char* name);
void sigstore_policy_add_issuer(sigstore_policy_t* p, const char* issuer);
void sigstore_policy_add_subject(sigstore_policy_t* p, const char* subject);
void sigstore_policy_add_email_domain(sigstore_policy_t* p, const char* domain);
void sigstore_policy_add_annotation(sigstore_policy_t* p, const char* annotation);
sigstore_policy_action_t sigstore_policy_evaluate(const sigstore_policy_t* p,
    const cosign_signature_t* sig, char** reason);
sigstore_policy_t* sigstore_policy_from_cue(const char* cue);
char* sigstore_policy_export_cue(const sigstore_policy_t* p);
void sigstore_policy_free(sigstore_policy_t* p);
```

## Module 4: dep_vuln.h — Dependency Vulnerabilities

### Types

| Type | Description |
|------|-------------|
| `cvss_severity_t` | `NONE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `cvss_version_t` | CVSS 2.0, 3.0, 3.1, 4.0 |
| `cvss_score_t` | CVSS vector and scores |
| `cve_entry_t` | CVE entry with metadata |
| `nvd_feed_t` | NVD database |
| `exploit_maturity_t` | Exploit maturity levels |
| `remediation_t` | Remediation suggestion |
| `reachability_result_t` | Call graph reachability |
| `namespace_policy_t` | Dependency confusion prevention |

### Functions: CVSS/CVE

```c
cve_entry_t* dep_vuln_create_entry(const char* cve_id, const char* desc, time_t published);
void dep_vuln_set_cvss_v3(cve_entry_t* entry, const char* vector_string);
void dep_vuln_set_cvss_v4(cve_entry_t* entry, const char* vector_string);
void dep_vuln_add_affected_product(cve_entry_t* entry, const char* product, const char* version);
void dep_vuln_add_reference(cve_entry_t* entry, const char* ref);
void dep_vuln_add_cpe(cve_entry_t* entry, const char* cpe);
void dep_vuln_free_entry(cve_entry_t* entry);

cvss_score_t* cvss_create_from_vector(const char* vector_string);
cvss_severity_t cvss_score_to_severity(float score);
float cvss_calculate_base_score_v3(const char* av, const char* ac, const char* pr,
    const char* ui, const char* s, const char* c, const char* i, const char* a);
float cvss_calculate_base_score_v4(const char* av, const char* ac, const char* at,
    const char* pr, const char* ui, const char* vc, const char* vi, const char* va,
    const char* sc, const char* si, const char* sa);
void cvss_free(cvss_score_t* score);
```

### Functions: NVD / Scanning

```c
nvd_feed_t* dep_vuln_load_nvd_feed(const char* feed_path);
nvd_feed_t* dep_vuln_fetch_nvd_feed(const char* api_url, const char* api_key);
int dep_vuln_save_nvd_feed(const nvd_feed_t* feed, const char* output_path);
cve_entry_t* dep_vuln_query_nvd(const nvd_feed_t* feed, const char* cve_id);
cve_entry_t** dep_vuln_query_by_product(const nvd_feed_t* feed, const char* name,
    const char* version, size_t* out_count);
cve_entry_t** dep_vuln_query_by_cpe(const nvd_feed_t* feed, const char* cpe, size_t* out_count);
int dep_vuln_scan_cyclonedx(const cyclonedx_bom_t* sbom, const nvd_feed_t* feed,
    cve_entry_t*** out, size_t* count);
int dep_vuln_scan_spdx(const spdx_document_t* sbom, const nvd_feed_t* feed,
    cve_entry_t*** out, size_t* count);
void dep_vuln_feed_free(nvd_feed_t* feed);
```

### Functions: Remediation / Reachability / Confusion

```c
int dep_vuln_reachability_analysis(const char* binary, const char* vuln_func,
    const char* src_dir, reachability_result_t*** out, size_t* count);
bool dep_vuln_is_function_called(const char* call_graph, const char* target_func);
int dep_vuln_build_call_graph(const char* src_dir, const char** files, size_t n,
    const char* out_graph);
void dep_vuln_reachability_result_free(reachability_result_t* result);

exploit_maturity_t dep_vuln_assess_exploit_maturity(const char* cve_id);
bool dep_vuln_has_public_poc(const char* cve_id);
bool dep_vuln_is_actively_exploited(const char* cve_id);

remediation_t* dep_vuln_suggest_remediation(const cve_entry_t* vuln, const char* current_ver);
remediation_t* dep_vuln_create_remediation(const char* cve_id, remediation_type_t type,
    const char* fixed_ver);
int dep_vuln_apply_remediation(const remediation_t* rem);
bool dep_vuln_verify_remediation(const remediation_t* rem);
char* dep_vuln_remediation_to_string(const remediation_t* rem);
void dep_vuln_remediation_free(remediation_t* rem);

int dep_vuln_prevent_confusion(const char* pkg_name, const char* version,
    const char* namespace, const namespace_policy_t* policy);
namespace_policy_t* dep_vuln_namespace_policy_create(const char* pkg_name);
void dep_vuln_namespace_policy_add_registry(namespace_policy_t* p, const char* url,
    const char* pubkey);
bool dep_vuln_verify_namespace(const char* pkg, const char* namespace,
    const namespace_policy_t* policy);
void dep_vuln_namespace_policy_free(namespace_policy_t* policy);
```

## Module 5: provenance_model.h — Provenance Model

### Types

| Type | Description |
|------|-------------|
| `in_toto_artifact_t` | Artifact with URI and digests |
| `in_toto_step_t` | Layout step definition |
| `in_toto_inspection_t` | Layout inspection |
| `in_toto_layout_t` | in-toto supply chain layout |
| `in_toto_link_t` | Signed link metadata |
| `attestation_bundle_t` | Bundle of links + layout |
| `slsa_predicate_t` | SLSA provenance predicate |
| `bin_auth_policy_t` | Binary authorization policy |
| `bin_auth_result_t` | Binary authorization result |
| `grafeas_note_t` | Grafeas metadata note |
| `grafeas_occurrence_t` | Grafeas occurrence |
| `grafeas_project_t` | Grafeas project |
| `kritis_policy_t` | Kritis deployment policy |
| `kritis_decision_t` | Kritis enforcement decision |

### Functions: in-toto

```c
in_toto_layout_t* provenance_layout_create(const char* name);
void provenance_layout_add_step(in_toto_layout_t* l, const char* name, const char* pubkey_id,
    const char** expected_cmd, size_t count);
void provenance_layout_add_inspection(in_toto_layout_t* l, const char* name, const char* run);
void provenance_layout_add_key(in_toto_layout_t* l, const char* key_pem);
int provenance_layout_sign(in_toto_layout_t* l, const char* private_key);
char* provenance_layout_export_json(const in_toto_layout_t* l);
in_toto_layout_t* provenance_layout_import_json(const char* json);
void provenance_layout_free(in_toto_layout_t* l);

in_toto_link_t* provenance_link_create(const char* name, const char* functionary, const char* cmd);
void provenance_link_add_material(in_toto_link_t* link, const char* uri, const char* sha256);
void provenance_link_add_product(in_toto_link_t* link, const char* uri, const char* sha256);
void provenance_link_set_byproducts(in_toto_link_t* link, const char* json);
void provenance_link_set_environment(in_toto_link_t* link, const char* json);
int provenance_link_sign(in_toto_link_t* link, const char* key, const char* key_id);
int provenance_link_verify(const in_toto_link_t* link, const char* pubkey);
char* provenance_link_export_json(const in_toto_link_t* link);
in_toto_link_t* provenance_link_import_json(const char* json);
void provenance_link_free(in_toto_link_t* link);

attestation_bundle_t* provenance_bundle_create(in_toto_layout_t* layout);
void provenance_bundle_add_link(attestation_bundle_t* b, in_toto_link_t* link);
int provenance_bundle_verify(const attestation_bundle_t* b, const char** trusted_keys, size_t n);
bool provenance_bundle_validate_layout(const attestation_bundle_t* b);
char* provenance_bundle_export_json(const attestation_bundle_t* b);
void provenance_bundle_free(attestation_bundle_t* b);

slsa_predicate_t* provenance_slsa_predicate_create(const char* subject, const char* digest,
    slsa_level_t level);
void provenance_slsa_predicate_add_material(slsa_predicate_t* p, const char* uri, const char* d);
void provenance_slsa_predicate_add_dependency(slsa_predicate_t* p, const char* uri, const char* d);
char* provenance_slsa_predicate_export_json(const slsa_predicate_t* p);
void provenance_slsa_predicate_free(slsa_predicate_t* p);
```

### Functions: Binary Auth, Grafeas, Kritis

```c
bin_auth_policy_t* bin_auth_policy_create(const char* binary_path);
void bin_auth_policy_add_builder(bin_auth_policy_t* p, const char* builder_id);
void bin_auth_policy_add_signer(bin_auth_policy_t* p, const char* signer_id);
bin_auth_result_t* bin_auth_check_binary(const char* path, const char* digest,
    const attestation_bundle_t* b, const bin_auth_policy_t* p);
void bin_auth_result_free(bin_auth_result_t* r);
void bin_auth_policy_free(bin_auth_policy_t* p);

grafeas_note_t* grafeas_note_create(const char* name, const char* project,
    grafeas_note_kind_t kind, const char* desc);
void grafeas_note_add_url(grafeas_note_t* n, const char* url);
char* grafeas_note_export_json(const grafeas_note_t* n);
grafeas_note_t* grafeas_note_import_json(const char* json);
void grafeas_note_free(grafeas_note_t* n);

grafeas_occurrence_t* grafeas_occurrence_create(const char* name, const char* resource_uri,
    grafeas_note_kind_t kind);
void grafeas_occurrence_attach_note(grafeas_occurrence_t* o, const char* note_name);
void grafeas_occurrence_set_vulnerability(grafeas_occurrence_t* o, const char* cve,
    const char* remediation);
char* grafeas_occurrence_export_json(const grafeas_occurrence_t* o);
void grafeas_occurrence_free(grafeas_occurrence_t* o);

grafeas_project_t* grafeas_project_create(const char* name);
void grafeas_project_add_note(grafeas_project_t* p, grafeas_note_t* n);
void grafeas_project_add_occurrence(grafeas_project_t* p, grafeas_occurrence_t* o);
char* grafeas_project_export_json(const grafeas_project_t* p);
void grafeas_project_free(grafeas_project_t* p);

kritis_policy_t* kritis_policy_create(const char* name, kritis_action_t default_action);
void kritis_policy_add_attestor(kritis_policy_t* p, const char* attestor);
void kritis_policy_add_predicate_type(kritis_policy_t* p, const char* pred_type);
void kritis_policy_add_builder(kritis_policy_t* p, const char* builder_id);
void kritis_policy_set_vulnerability_threshold(kritis_policy_t* p, int max_crit, int max_high);
kritis_decision_t* kritis_evaluate(const kritis_policy_t* p, const attestation_bundle_t* b,
    const char* image);
bool kritis_is_allowed(const kritis_decision_t* d);
char* kritis_decision_to_string(const kritis_decision_t* d);
void kritis_decision_free(kritis_decision_t* d);
void kritis_policy_free(kritis_policy_t* p);
```
