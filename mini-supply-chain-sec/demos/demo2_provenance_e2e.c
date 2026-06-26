#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../include/provenance_model.h"
#include "../include/sbom_gen.h"

static void section_header(const char* title) {
    printf("\n===========================================\n");
    printf("  %s\n", title);
    printf("===========================================\n");
}

static void subsection(const char* title) {
    printf("\n--- %s ---\n", title);
}

static void print_artifact(const char* label, const in_toto_artifact_t* a) {
    if (!a) return;
    printf("  %s: %s (sha256:%s)\n", label, a->uri,
           a->digest_sha256 ? a->digest_sha256 : "N/A");
}

static void print_layout_summary(const in_toto_layout_t* layout) {
    if (!layout) { printf("  Layout: NULL\n"); return; }
    printf("  Layout: %s\n", layout->layout_name);
    printf("    Steps: %zu\n", layout->step_count);
    for (size_t i = 0; i < layout->step_count; i++) {
        in_toto_step_t* s = layout->steps[i];
        printf("      [%zu] %s (pubkey=%s, commands=%zu)\n",
               i, s->step_name,
               s->pubkey_id ? s->pubkey_id : "none",
               s->expected_command_count);
    }
    printf("    Inspections: %zu\n", layout->inspection_count);
    for (size_t i = 0; i < layout->inspection_count; i++) {
        printf("      [%zu] %s (run=%s)\n", i,
               layout->inspections[i]->inspection_name,
               layout->inspections[i]->run_command);
    }
    printf("    Keys: %zu\n", layout->key_count);
    printf("    Expires: %ld\n", (long)layout->expires);
}

static void print_link_summary(const char* label, const in_toto_link_t* link) {
    if (!link) { printf("  %s: NULL\n", label); return; }
    printf("  %s: %s by %s\n", label, link->link_name,
           link->functionary_name ? link->functionary_name : "unknown");
    printf("    Command: %s\n", link->command ? link->command : "N/A");
    printf("    Materials: %zu, Products: %zu\n",
           link->material_count, link->product_count);
    for (size_t i = 0; i < link->material_count; i++) {
        printf("      MAT[%zu]: %s\n", i, link->materials[i]->uri);
    }
    for (size_t i = 0; i < link->product_count; i++) {
        printf("      PRD[%zu]: %s\n", i, link->products[i]->uri);
    }
}

static void print_kritis_decision(const kritis_decision_t* decision) {
    if (!decision) { printf("  Decision: NULL\n"); return; }
    printf("  Allowed: %s\n", decision->allowed ? "YES" : "NO");
    printf("  Reason: %s\n", decision->decision_reason ?
           decision->decision_reason : "N/A");
    printf("  Attestation satisfied: %s\n",
           decision->attestation_satisfied ? "YES" : "NO");
    printf("  Vulnerability satisfied: %s\n",
           decision->vulnerability_satisfied ? "YES" : "NO");
    printf("  SBOM satisfied: %s\n",
           decision->sbom_satisfied ? "YES" : "NO");
    printf("  CVEs found: %d critical, %d high\n",
           decision->critical_vulns_found, decision->high_vulns_found);
}

static void demo_in_toto_layout(void) {
    section_header("Demo 1: In-Toto Layout Creation & Management");

    in_toto_layout_t* layout = provenance_layout_create(
        "secure-build-pipeline-layout");
    printf("Created layout: %s\n", layout->layout_name);

    const char* clone_cmds[] = {
        "git", "clone", "--depth", "1", "$REPO_URL", "/workspace"
    };
    provenance_layout_add_step(layout, "clone-source", "developer-key-1",
                                clone_cmds, 5);
    provenance_layout_add_step(layout, "verify-signatures",
                                "security-team-key",
                                NULL, 0);
    const char* build_cmds[] = { "make", "build" };
    provenance_layout_add_step(layout, "build-artifact", "build-service-key",
                                build_cmds, 2);
    const char* test_cmds[] = { "make", "test" };
    provenance_layout_add_step(layout, "run-tests", "ci-bot-key",
                                test_cmds, 2);
    provenance_layout_add_step(layout, "sign-release", "release-manager-key",
                                NULL, 0);

    provenance_layout_add_inspection(layout, "verify-sbom-exists",
        "test -f /workspace/sbom.json");
    provenance_layout_add_inspection(layout, "verify-digests-match",
        "sha256sum -c /workspace/digests.txt");
    provenance_layout_add_inspection(layout, "check-no-secrets",
        "gitleaks detect --source /workspace --no-git");

    provenance_layout_add_key(layout, "-----BEGIN PUBLIC KEY-----\ndev-key\n-----END PUBLIC KEY-----");
    provenance_layout_add_key(layout, "-----BEGIN PUBLIC KEY-----\nbuild-key\n-----END PUBLIC KEY-----");
    provenance_layout_add_key(layout, "-----BEGIN PUBLIC KEY-----\nrelease-key\n-----END PUBLIC KEY-----");

    print_layout_summary(layout);

    char* layout_json = provenance_layout_export_json(layout);
    printf("\n  Exported JSON:\n%s\n", layout_json);
    free(layout_json);

    provenance_layout_sign(layout, "-----BEGIN PRIVATE KEY-----\nlayout-key\n-----END PRIVATE KEY-----");
    printf("  Layout signed: OK\n");

    in_toto_layout_t* imported = provenance_layout_import_json(
        "{\"name\":\"imported-test\"}");
    printf("  Imported layout: %s\n", imported ? "OK" : "FAILED");
    provenance_layout_free(imported);

    provenance_layout_free(layout);
}

static void demo_in_toto_links(void) {
    section_header("Demo 2: In-Toto Links and Attestation Bundle");

    in_toto_link_t* link_clone = provenance_link_create(
        "clone-source", "developer-alice", "git clone $REPO /workspace");
    provenance_link_add_material(link_clone,
        "git+https://github.com/org/repo.git@abc123",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    provenance_link_add_product(link_clone,
        "/workspace/src/",
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    provenance_link_set_environment(link_clone,
        "{\"CI\":\"true\",\"BUILD_ID\":\"12345\"}");
    provenance_link_set_byproducts(link_clone,
        "{\"return-code\":0,\"stderr\":\"\",\"stdout\":\"Cloning into workspace...\"}");
    provenance_link_sign(link_clone,
        "-----BEGIN PRIVATE KEY-----\nalice-key\n-----END PRIVATE KEY-----",
        "alice-key-id");
    print_link_summary("Clone link", link_clone);

    in_toto_link_t* link_build = provenance_link_create(
        "build-artifact", "build-service-github", "make build");
    provenance_link_add_material(link_build,
        "/workspace/src/",
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    provenance_link_add_material(link_build,
        "https://releases.ubuntu.com/24.04/base.tar.gz",
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    provenance_link_add_product(link_build,
        "/workspace/bin/myapp",
        "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
    provenance_link_set_byproducts(link_build,
        "{\"return-code\":0,\"build-time-ms\":45200}");
    provenance_link_sign(link_build,
        "-----BEGIN PRIVATE KEY-----\nbuild-key\n-----END PRIVATE KEY-----",
        "build-key-id");
    print_link_summary("Build link", link_build);

    in_toto_link_t* link_test = provenance_link_create(
        "run-tests", "ci-runner-01", "make test");
    provenance_link_add_material(link_test,
        "/workspace/bin/myapp",
        "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
    provenance_link_add_product(link_test,
        "/workspace/test-results.xml",
        "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
    provenance_link_set_byproducts(link_test,
        "{\"return-code\":0,\"tests-passed\":142,\"tests-failed\":0}");
    provenance_link_sign(link_test,
        "-----BEGIN PRIVATE KEY-----\nci-key\n-----END PRIVATE KEY-----",
        "ci-key-id");
    print_link_summary("Test link", link_test);

    in_toto_link_t* link_sign = provenance_link_create(
        "sign-release", "release-manager", "cosign sign $IMAGE");
    provenance_link_add_material(link_sign,
        "/workspace/bin/myapp",
        "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
    provenance_link_add_product(link_sign,
        "oci://registry.example.com/myapp:v1.0.0",
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    provenance_link_set_byproducts(link_sign,
        "{\"return-code\":0,\"signature\":\"MEUCID...\"}");
    provenance_link_sign(link_sign,
        "-----BEGIN PRIVATE KEY-----\nrelease-key\n-----END PRIVATE KEY-----",
        "release-key-id");
    print_link_summary("Sign link", link_sign);

    subsection("Attestation Bundle");
    in_toto_layout_t* bundle_layout = provenance_layout_create("release-layout");
    attestation_bundle_t* bundle = provenance_bundle_create(bundle_layout);
    provenance_bundle_add_link(bundle, link_clone);
    provenance_bundle_add_link(bundle, link_build);
    provenance_bundle_add_link(bundle, link_test);
    provenance_bundle_add_link(bundle, link_sign);
    printf("  Bundle links: %zu\n", bundle->link_count);

    const char* trusted_keys[] = {
        "-----BEGIN PUBLIC KEY-----\nalice-key\n-----END PUBLIC KEY-----",
        "-----BEGIN PUBLIC KEY-----\nbuild-key\n-----END PUBLIC KEY-----",
        "-----BEGIN PUBLIC KEY-----\nci-key\n-----END PUBLIC KEY-----",
        "-----BEGIN PUBLIC KEY-----\nrelease-key\n-----END PUBLIC KEY-----"
    };
    int verify_rc = provenance_bundle_verify(bundle, trusted_keys, 4);
    printf("  Bundle verification: %s\n", verify_rc == 0 ? "PASS" : "FAIL");

    char* bundle_json = provenance_bundle_export_json(bundle);
    printf("  Bundle JSON:\n%s\n", bundle_json);
    free(bundle_json);

    provenance_bundle_free(bundle);
}

static void demo_slsa_predicate(void) {
    section_header("Demo 3: SLSA Provenance Predicate");

    slsa_predicate_t* pred = provenance_slsa_predicate_create(
        "myapp-v1.0.0",
        "sha256:final-artifact-digest-hex-encoded-64chars",
        SLSA_LEVEL_3);
    pred->builder_id = strdup("https://github.com/slsa-framework/github-actions-generator@v2");
    pred->reproducible = true;

    provenance_slsa_predicate_add_material(pred,
        "git+https://github.com/org/app.git@abc123def456",
        "sha256:source-tree-digest-placeholder");
    provenance_slsa_predicate_add_material(pred,
        "oci://gcr.io/distroless/cc:latest@sha256:base-image-digest",
        "sha256:base-image-hash-value");
    provenance_slsa_predicate_add_dependency(pred,
        "pkg:npm/express@4.18.0",
        "sha256:express-digest-placeholder");
    provenance_slsa_predicate_add_dependency(pred,
        "pkg:npm/lodash@4.17.21",
        "sha256:lodash-digest-placeholder");

    printf("  Subject: %s\n", pred->subject_name);
    printf("  Digest: %s\n", pred->subject_digest);
    printf("  SLSA Level: %d\n", (int)pred->slsa_level);
    printf("  Builder: %s\n", pred->builder_id);
    printf("  Materials: %zu\n", pred->material_count);
    for (size_t i = 0; i < pred->material_count; i++)
        print_artifact("MAT", pred->materials[i]);
    printf("  Dependencies: %zu\n", pred->resolved_dep_count);
    for (size_t i = 0; i < pred->resolved_dep_count; i++)
        print_artifact("DEP", pred->resolved_dependencies[i]);
    printf("  Reproducible: %s\n", pred->reproducible ? "YES" : "NO");

    char* pred_json = provenance_slsa_predicate_export_json(pred);
    printf("  Predicate JSON:\n%s\n", pred_json);
    free(pred_json);

    provenance_slsa_predicate_free(pred);
}

static void demo_binary_authorization(void) {
    section_header("Demo 4: Binary Authorization");

    bin_auth_policy_t* policy = bin_auth_policy_create("/usr/bin/myapp");
    bin_auth_policy_add_builder(policy, "github-actions");
    bin_auth_policy_add_builder(policy, "cloud-build");
    bin_auth_policy_add_signer(policy, "release-manager@myorg.com");
    policy->minimum_slsa_level = SLSA_LEVEL_3;
    policy->require_reproducible_build = true;
    printf("  Policy: %s (min SLSA=%d)\n", policy->binary_path,
           (int)policy->minimum_slsa_level);
    printf("  Allowed builders: %zu\n", policy->allowed_builder_count);
    for (size_t i = 0; i < policy->allowed_builder_count; i++)
        printf("    - %s\n", policy->allowed_builder_ids[i]);
    printf("  Allowed signers: %zu\n", policy->allowed_signer_count);
    for (size_t i = 0; i < policy->allowed_signer_count; i++)
        printf("    - %s\n", policy->allowed_signer_ids[i]);

    in_toto_layout_t* auth_layout = provenance_layout_create("auth-layout");
    attestation_bundle_t* good_bundle = provenance_bundle_create(auth_layout);
    in_toto_link_t* good_link = provenance_link_create(
        "build-step", "github-actions-v2", "make build");
    provenance_bundle_add_link(good_bundle, good_link);
    good_bundle->layout_verified = true;

    bin_auth_result_t* result_good = bin_auth_check_binary(
        "/usr/bin/myapp",
        "sha256:verified-digest",
        good_bundle, policy);
    printf("\n  Good binary check:\n");
    printf("    Decision: %d (%s)\n", (int)result_good->decision,
           result_good->decision == BIN_AUTH_DECISION_ALLOW ? "ALLOW" :
           result_good->decision == BIN_AUTH_DECISION_DENY ? "DENY" : "NEED_ATTESTATION");
    printf("    Reason: %s\n", result_good->reason);
    bin_auth_result_free(result_good);

    attestation_bundle_t* bad_bundle = provenance_bundle_create(auth_layout);
    in_toto_link_t* bad_link = provenance_link_create(
        "build-step", "unknown-builder", "make build");
    provenance_bundle_add_link(bad_bundle, bad_link);
    bad_bundle->layout_verified = true;

    bin_auth_result_t* result_bad = bin_auth_check_binary(
        "/usr/bin/myapp",
        "sha256:unknown-digest",
        bad_bundle, policy);
    printf("\n  Bad binary check:\n");
    printf("    Decision: %d (%s)\n", (int)result_bad->decision,
           result_bad->decision == BIN_AUTH_DECISION_ALLOW ? "ALLOW" :
           result_bad->decision == BIN_AUTH_DECISION_DENY ? "DENY" : "NEED_ATTESTATION");
    printf("    Reason: %s\n", result_bad->reason);
    bin_auth_result_free(result_bad);

    bin_auth_result_t* result_no_bundle = bin_auth_check_binary(
        "/usr/bin/myapp", "sha256:novel-digest", NULL, policy);
    printf("\n  No bundle check:\n");
    printf("    Decision: %d (%s)\n", (int)result_no_bundle->decision,
           result_no_bundle->decision == BIN_AUTH_DECISION_ALLOW ? "ALLOW" :
           result_no_bundle->decision == BIN_AUTH_DECISION_DENY ? "DENY" : "NEED_ATTESTATION");
    printf("    Reason: %s\n", result_no_bundle->reason);
    bin_auth_result_free(result_no_bundle);

    provenance_bundle_free(good_bundle);
    provenance_bundle_free(bad_bundle);
    bin_auth_policy_free(policy);
}

static void demo_grafeas_kritis(void) {
    section_header("Demo 5: Grafeas Artifact Metadata + Kritis Policy");

    subsection("Grafeas Notes and Occurrences");
    grafeas_note_t* vuln_note = grafeas_note_create(
        "projects/my-project/notes/CVE-2024-0001",
        "my-project",
        GRAFEAS_KIND_VULNERABILITY,
        "Critical RCE vulnerability in libfoo < 2.0.0");
    grafeas_note_add_url(vuln_note, "https://nvd.nist.gov/vuln/detail/CVE-2024-0001");
    grafeas_note_add_url(vuln_note, "https://github.com/advisories/GHSA-xxxx");
    printf("  Note: %s (kind=%s)\n", vuln_note->note_name, vuln_note->note_kind);
    printf("    Description: %s\n", vuln_note->note_short_description);
    printf("    URLs: %zu\n", vuln_note->related_url_count);

    grafeas_occurrence_t* occ = grafeas_occurrence_create(
        "projects/my-project/occurrences/occ-001",
        "https://registry.example.com/myapp@sha256:abc123",
        GRAFEAS_KIND_VULNERABILITY);
    grafeas_occurrence_attach_note(occ, vuln_note->note_name);
    grafeas_occurrence_set_vulnerability(occ, "CVE-2024-0001",
        "Upgrade libfoo to >= 2.0.0 or apply vendor patch");
    printf("\n  Occurrence: %s\n", occ->occurrence_name);
    printf("    Resource: %s\n", occ->resource_uri);
    printf("    CVE: %s\n", occ->vulnerability_cve_id);
    printf("    Remediation: %s\n", occ->remediation_text);

    char* note_json = grafeas_note_export_json(vuln_note);
    printf("\n  Note JSON: %s\n", note_json);
    free(note_json);

    char* occ_json = grafeas_occurrence_export_json(occ);
    printf("  Occurrence JSON: %s\n", occ_json);
    free(occ_json);

    subsection("Grafeas Project");
    grafeas_project_t* project = grafeas_project_create("my-project");
    grafeas_project_add_note(project, vuln_note);
    grafeas_project_add_occurrence(project, occ);

    grafeas_note_t* build_note = grafeas_note_create(
        "projects/my-project/notes/build-info",
        "my-project",
        GRAFEAS_KIND_BUILD,
        "Build provenance for myapp v1.0.0");
    grafeas_project_add_note(project, build_note);
    printf("\n  Project: %s (notes=%zu, occurrences=%zu)\n",
           project->project_name,
           project->note_count, project->occurrence_count);

    char* proj_json = grafeas_project_export_json(project);
    printf("  Project JSON: %s\n", proj_json);
    free(proj_json);

    subsection("Kritis Deploy-Time Policy Enforcement");
    kritis_policy_t* kpolicy = kritis_policy_create(
        "production-deploy-policy", KRITIS_ACTION_DENY);
    kritis_policy_add_attestor(kpolicy, "security-team@myorg.com");
    kritis_policy_add_attestor(kpolicy, "build-service@github.com");
    kritis_policy_add_predicate_type(kpolicy, "https://slsa.dev/provenance/v1");
    kritis_policy_add_predicate_type(kpolicy, "https://spdx.dev/Document");
    kritis_policy_add_builder(kpolicy, "github-actions-v2");
    kritis_policy_set_vulnerability_threshold(kpolicy, 0, 3);
    kpolicy->minimum_slsa_level = SLSA_LEVEL_3;
    kpolicy->require_vulnerability_scan = true;
    kpolicy->require_sbom = true;
    kpolicy->breakglass_enabled = false;

    printf("  Policy: %s\n", kpolicy->policy_name);
    printf("    Attestors: %zu\n", kpolicy->required_attestor_count);
    printf("    Predicate types: %zu\n", kpolicy->required_predicate_count);
    printf("    Builders: %zu\n", kpolicy->required_builder_count);
    printf("    Min SLSA: %d\n", (int)kpolicy->minimum_slsa_level);
    printf("    Max critical: %d, Max high: %d\n",
           kpolicy->max_critical_vulnerabilities,
           kpolicy->max_high_vulnerabilities);
    printf("    Default action: %s\n",
           kpolicy->default_action == KRITIS_ACTION_ALLOW ? "ALLOW" : "DENY");

    in_toto_layout_t* k_layout = provenance_layout_create("kritis-eval-layout");
    attestation_bundle_t* deploy_bundle = provenance_bundle_create(k_layout);
    in_toto_link_t* deploy_link = provenance_link_create(
        "deploy", "github-actions-v2", "kubectl apply");
    provenance_bundle_add_link(deploy_bundle, deploy_link);

    kritis_decision_t* decision = kritis_evaluate(
        kpolicy, deploy_bundle,
        "gcr.io/my-project/myapp@sha256:abc123def456");
    printf("\n  Deployment decision:\n");
    print_kritis_decision(decision);
    printf("  Is allowed: %s\n", kritis_is_allowed(decision) ? "YES" : "NO");

    char* decision_str = kritis_decision_to_string(decision);
    printf("  Decision string: %s\n", decision_str);
    free(decision_str);

    kritis_decision_free(decision);
    provenance_bundle_free(deploy_bundle);
    kritis_policy_free(kpolicy);
    grafeas_project_free(project);
}

static void demo_integration_flow(void) {
    section_header("Demo 6: End-to-End Supply Chain Security Flow");

    printf("  1. Developer commits code with signed commit\n");
    printf("  2. Pipeline creates in-toto layout with steps\n");
    printf("  3. Each step produces signed link metadata\n");
    printf("  4. Links are bundled into attestation bundle\n");
    printf("  5. SLSA predicate captures provenance\n");
    printf("  6. SBOM generated for all dependencies\n");
    printf("  7. Vulnerability scan against NVD database\n");
    printf("  8. Binary authorization checks attestation bundle\n");
    printf("  9. Grafeas stores artifact metadata\n");
    printf(" 10. Kritis enforces deploy-time policy\n");
    printf("\n  Pipeline flow:\n");
    printf("    Source -> Build -> Test -> SBOM -> Scan -> Sign -> Deploy\n");
    printf("      |        |       |       |       |      |        |\n");
    printf("      v        v       v       v       v      v        v\n");
    printf("    Link    Link    Link    Link    VEX   Cosign   Kritis\n");
    printf("                                            attest   check\n");
    printf("\n");

    time_t now = time(NULL);
    printf("  Supply chain attestation complete at: %s", ctime(&now));
}

int main(void) {
    printf("==============================================================\n");
    printf("  Provenance Model - End-to-End Supply Chain Attestation Demo\n");
    printf("==============================================================\n");

    demo_in_toto_layout();
    demo_in_toto_links();
    demo_slsa_predicate();
    demo_binary_authorization();
    demo_grafeas_kritis();
    demo_integration_flow();

    printf("\n=== All Provenance Model Demos Complete ===\n");
    return 0;
}
