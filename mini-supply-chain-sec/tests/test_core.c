/*
 * mini-supply-chain-sec — Core Tests
 *
 * Unit tests for SBOM, SLSA, Sigstore/cosign, dependency vuln scanning, provenance model.
 */
#include "../include/sbom_gen.h"
#include "../include/slsa_framework.h"
#include "../include/sigstore_cosign.h"
#include "../include/dep_vuln.h"
#include "../include/provenance_model.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

static int tests_run = 0, tests_passed = 0;

#define TEST(name) do { tests_run++; printf("  TEST %s ... ", name); } while(0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); return 1; } while(0)
#define CHECK(cond, msg) if (!(cond)) FAIL(msg)

/* ── SBOM Tests ── */
static int test_spdx_create_add(void) {
    TEST("spdx_create_add");
    spdx_document_t *spdx = sbom_spdx_create("TestApp-v1.0", "https://test.example/spdx/v1");
    CHECK(spdx != NULL, "create failed");
    sbom_spdx_add_package(spdx, "libtest", "1.0.0", "MIT", "TestOrg");
    CHECK(spdx->package_count == 1, "package count wrong");
    CHECK(strcmp(spdx->packages[0].name, "libtest") == 0, "package name wrong");
    sbom_spdx_free(spdx);
    PASS();
    return 0;
}

static int test_cyclonedx_create_add(void) {
    TEST("cyclonedx_create_add");
    cyclonedx_bom_t *bom = sbom_cyclonedx_create("urn:uuid:test-123");
    CHECK(bom != NULL, "create failed");
    sbom_cyclonedx_add_component(bom, "mylib", "2.0", "pkg:npm/mylib@2.0", "sha256:abc123");
    CHECK(bom->component_count == 1, "component count wrong");
    sbom_cyclonedx_add_dependency(bom, "myapp", "mylib");
    sbom_cyclonedx_free(bom);
    PASS();
    return 0;
}

static int test_vex_create(void) {
    TEST("vex_create");
    vex_entry_t *entry = vex_entry_create("CVE-2024-0001", "libtest@1.0.0",
                                           VEX_STATUS_NOT_AFFECTED,
                                           VEX_JUST_VULNERABLE_CODE_NOT_PRESENT);
    CHECK(entry != NULL, "vex entry create failed");
    vex_document_t *vex = vex_document_create("VEX-Test-001", "sec-team");
    CHECK(vex != NULL, "vex document create failed");
    vex_document_add_entry(vex, entry);
    CHECK(vex->entry_count == 1, "vex entry count wrong");
    PASS();
    return 0;
}

/* ── SLSA Tests ── */
static int test_slsa_source_level(void) {
    TEST("slsa_source_level");
    slsa_source_t *source = slsa_source_create("https://github.com/test/repo", "abc123");
    source->signed_commit = true;
    source->two_person_review = true;
    source->protected_branch = true;
    slsa_level_t level = slsa_assess_source_level(source);
    CHECK(level >= SLSA_LEVEL_1, "source level too low");
    CHECK(level <= SLSA_LEVEL_3, "source level too high");
    slsa_source_free(source);
    PASS();
    return 0;
}

static int test_slsa_build_level(void) {
    TEST("slsa_build_level");
    slsa_build_config_t *build = slsa_build_config_create("GitHub Actions", "github-actions/v4");
    slsa_build_config_set_hermetic(build, true, SLSA_BUILD_ISOLATION_CONTAINER);
    build->reproducible = true;
    slsa_level_t level = slsa_assess_build_level(build);
    CHECK(level >= SLSA_LEVEL_1, "build level too low");
    slsa_build_config_free(build);
    PASS();
    return 0;
}

static int test_slsa_overall_level(void) {
    TEST("slsa_overall_level");
    slsa_level_t overall = slsa_determine_overall_level(SLSA_LEVEL_3, SLSA_LEVEL_3);
    CHECK(overall == SLSA_LEVEL_3, "overall should be min(L3, L3)");
    overall = slsa_determine_overall_level(SLSA_LEVEL_2, SLSA_LEVEL_3);
    CHECK(overall == SLSA_LEVEL_2, "overall should be min(L2, L3)");
    PASS();
    return 0;
}

/* ── Sigstore/Cosign Tests ── */
static int test_cosign_sign_image(void) {
    TEST("cosign_sign_image");
    cosign_signature_t *sig = cosign_sign_image("registry.example/myapp:v1.0", NULL, false);
    CHECK(sig != NULL, "sign failed");
    cosign_signature_free(sig);
    PASS();
    return 0;
}

static int test_sigstore_policy(void) {
    TEST("sigstore_policy");
    sigstore_policy_t *policy = sigstore_policy_create("test-policy");
    sigstore_policy_add_issuer(policy, "https://accounts.google.com");
    sigstore_policy_add_email_domain(policy, "example.com");
    cosign_signature_t *sig = cosign_sign_image("registry.example/myapp:v1.0", NULL, false);
    char *reason = NULL;
    sigstore_policy_action_t action = sigstore_policy_evaluate(policy, sig, &reason);
    CHECK(action == SIGSTORE_POLICY_ACTION_ALLOW || action == SIGSTORE_POLICY_ACTION_DENY, "invalid action");
    cosign_signature_free(sig);
    sigstore_policy_free(policy);
    PASS();
    return 0;
}

/* ── Dependency Vulnerability Tests ── */
static int test_cvss_score(void) {
    TEST("cvss_score");
    float score = cvss_calculate_base_score_v3("N", "L", "N", "N", "U", "H", "H", "H");
    CHECK(score > 0.0 && score <= 10.0, "cvss score out of range");
    cvss_severity_t sev = cvss_score_to_severity(score);
    CHECK(sev >= CVSS_SEVERITY_NONE && sev <= CVSS_SEVERITY_CRITICAL, "invalid severity");
    PASS();
    return 0;
}

static int test_cve_remediation(void) {
    TEST("cve_remediation");
    cve_entry_t *cve = dep_vuln_create_entry("CVE-2024-TEST", "Test vulnerability", time(NULL));
    dep_vuln_add_affected_product(cve, "testlib", "1.0.0");
    remediation_t *rem = dep_vuln_suggest_remediation(cve, "1.0.0");
    CHECK(rem != NULL, "remediation is NULL");
    CHECK(rem->type >= 0, "remediation type invalid");
    dep_vuln_free_entry(cve);
    dep_vuln_remediation_free(rem);
    PASS();
    return 0;
}

/* ── Provenance Model Tests ── */
static int test_in_toto_link(void) {
    TEST("in_toto_link");
    in_toto_link_t *link = provenance_link_create("build-step", "github-actions", "make release");
    CHECK(link != NULL, "link create failed");
    provenance_link_add_material(link, "git+https://github.com/test/repo.git", "sha256:abc123");
    provenance_link_add_product(link, "docker://myapp:v1.0", "sha256:def456");
    CHECK(link->material_count == 1, "material count wrong");
    CHECK(link->product_count == 1, "product count wrong");
    provenance_link_free(link);
    PASS();
    return 0;
}

static int test_grafeas_note_occurrence(void) {
    TEST("grafeas_note_occurrence");
    grafeas_note_t *note = grafeas_note_create("test-note", "myapp", GRAFEAS_KIND_VULNERABILITY, "Test issue");
    grafeas_note_add_url(note, "https://example.com/vuln/test");
    grafeas_occurrence_t *occ = grafeas_occurrence_create("occ-001", "docker://myapp:v1.0", GRAFEAS_KIND_VULNERABILITY);
    grafeas_occurrence_attach_note(occ, "test-note");
    CHECK(strcmp(occ->attached_note_name, "test-note") == 0, "note not attached");
    grafeas_project_t *proj = grafeas_project_create("test-project");
    grafeas_project_add_note(proj, note);
    grafeas_project_add_occurrence(proj, occ);
    CHECK(proj->note_count == 1, "project note count wrong");
    CHECK(proj->occurrence_count == 1, "project occurrence count wrong");
    grafeas_project_free(proj);
    PASS();
    return 0;
}

static int test_kritis_policy(void) {
    TEST("kritis_policy");
    kritis_policy_t *kpol = kritis_policy_create("prod-policy", KRITIS_ACTION_DENY);
    kritis_policy_add_attestor(kpol, "signer@example.com");
    kritis_policy_add_builder(kpol, "github-actions/v4");
    kritis_policy_set_vulnerability_threshold(kpol, 0, 3);
    CHECK(strcmp(kpol->policy_name, "prod-policy") == 0, "policy name wrong");
    CHECK(kpol->default_action == KRITIS_ACTION_DENY, "default action wrong");
    kritis_policy_free(kpol);
    PASS();
    return 0;
}

int main(void) {
    printf("=== mini-supply-chain-sec Unit Tests ===\n\n");

    int failed = 0;
    failed += test_spdx_create_add();
    failed += test_cyclonedx_create_add();
    failed += test_vex_create();
    failed += test_slsa_source_level();
    failed += test_slsa_build_level();
    failed += test_slsa_overall_level();
    failed += test_cosign_sign_image();
    failed += test_sigstore_policy();
    failed += test_cvss_score();
    failed += test_cve_remediation();
    failed += test_in_toto_link();
    failed += test_grafeas_note_occurrence();
    failed += test_kritis_policy();

    printf("\n=== Results: %d/%d passed, %d failed ===\n",
           tests_passed, tests_run, failed);
    return failed > 0 ? 1 : 0;
}
