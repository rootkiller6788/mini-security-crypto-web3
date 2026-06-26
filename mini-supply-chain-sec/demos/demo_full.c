/*
 * mini-supply-chain-sec — Full Demo: Supply Chain Security
 *
 * Demonstrates: SBOM (SPDX/CycloneDX/VEX), SLSA provenance,
 *               Sigstore/cosign, dependency vuln scanning, in-toto/Grafeas/Kritis.
 */
#include "../include/sbom_gen.h"
#include "../include/slsa_framework.h"
#include "../include/sigstore_cosign.h"
#include "../include/dep_vuln.h"
#include "../include/provenance_model.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

int main(void) {
    printf("=== mini-supply-chain-sec: Supply Chain Security Demo ===\n\n");

    /* Step 1: SBOM Generation */
    printf("-- Step 1: SBOM Generation --\n");

    /* SPDX */
    spdx_document_t *spdx = sbom_spdx_create("MyApp-v2.0", "https://myapp.example/spdx/v2");
    sbom_spdx_add_package(spdx, "libopenssl", "3.2.1", "Apache-2.0", "OpenSSL Foundation");
    sbom_spdx_add_package(spdx, "libcurl", "8.5.0", "MIT", "curl project");
    sbom_spdx_add_package(spdx, "json-parser", "2.1.3", "MIT", "json-org");
    sbom_spdx_add_relationship(spdx, "SPDXRef-MyApp-v2.0", "SPDXRef-libopenssl", SBOM_REL_DEPENDS_ON);
    sbom_spdx_add_relationship(spdx, "SPDXRef-MyApp-v2.0", "SPDXRef-libcurl", SBOM_REL_DEPENDS_ON);
    printf("SPDX SBOM: %s, %zu packages, %zu relationships\n",
           spdx->document_name, spdx->package_count, spdx->relationship_count);

    /* CycloneDX */
    cyclonedx_bom_t *bom = sbom_cyclonedx_create("urn:uuid:abc123-def456");
    sbom_cyclonedx_add_component(bom, "myapp", "2.0", "pkg:npm/myapp@2.0", "sha256:feedface123");
    sbom_cyclonedx_add_component(bom, "libopenssl", "3.2.1", "pkg:conan/openssl@3.2.1", "sha256:cafebabe456");
    sbom_cyclonedx_add_dependency(bom, "myapp", "libopenssl");
    printf("CycloneDX BOM: serial=%s, %zu components\n", bom->serial_number, bom->component_count);

    /* VEX */
    vex_entry_t *vex_e = vex_entry_create("CVE-2024-3094", "libopenssl@3.2.1", VEX_STATUS_NOT_AFFECTED, VEX_JUST_VULNERABLE_CODE_NOT_PRESENT);
    vex_document_t *vex = vex_document_create("VEX-MyApp-2024-001", "security-team");
    vex_document_add_entry(vex, vex_e);
    printf("VEX: %zu entries, status=%s\n", vex->entry_count, "NOT_AFFECTED");

    /* Step 2: SLSA Framework */
    printf("\n-- Step 2: SLSA Provenance --\n");
    slsa_source_t *source = slsa_source_create("https://github.com/myorg/myapp", "abc123def456789");
    slsa_source_set_signed(source, "dev@myorg.com", "SHA256:ABCD1234");
    source->two_person_review = true;
    source->protected_branch = true;

    slsa_level_t src_level = slsa_assess_source_level(source);
    printf("Source: %s (commit=%s)\n", source->repo_url, source->commit_sha);
    printf("  Signed: %s, 2-person review: %s, Protected branch: %s\n",
           source->signed_commit ? "YES" : "NO",
           source->two_person_review ? "YES" : "NO",
           source->protected_branch ? "YES" : "NO");
    printf("  Source SLSA level: %s\n", slsa_level_to_string(src_level));

    slsa_build_config_t *build = slsa_build_config_create("GitHub Actions", "github-actions/v4");
    slsa_build_config_set_hermetic(build, true, SLSA_BUILD_ISOLATION_CONTAINER);
    slsa_build_config_add_input(build, "git+https://github.com/myorg/myapp.git@abc123");
    slsa_build_config_add_output(build, "docker://myapp:v2.0");
    build->reproducible = true;

    slsa_level_t build_level = slsa_assess_build_level(build);
    printf("Build: platform=%s, hermetic=%s, reproducible=%s\n",
           build->build_platform, build->hermetic ? "YES" : "NO", build->reproducible ? "YES" : "NO");
    printf("  Build SLSA level: %s\n", slsa_level_to_string(build_level));

    slsa_level_t overall = slsa_determine_overall_level(src_level, build_level);
    printf("  Overall SLSA level: %s\n", slsa_level_to_string(overall));

    slsa_provenance_t *prov = slsa_provenance_create("myapp-v2.0", "sha256:abc123...", "https://slsa.dev/provenance/v1");
    slsa_provenance_attach_source(prov, source);
    slsa_provenance_attach_build(prov, build);
    printf("Provenance: subject=%s, in-toto predicate generated\n", prov->subject_name);

    /* Step 3: Sigstore / Cosign */
    printf("\n-- Step 3: Sigstore / Cosign --\n");
    cosign_signature_t *sig = cosign_sign_image("myregistry.io/myapp:v2.0", NULL, false);
    printf("Container signing: %s\n", sig ? "SIGNED" : "FAILED");

    sigstore_policy_t *policy = sigstore_policy_create("prod-policy");
    sigstore_policy_add_issuer(policy, "https://accounts.google.com");
    sigstore_policy_add_email_domain(policy, "myorg.com");
    char *policy_reason = NULL;
    sigstore_policy_action_t action = sigstore_policy_evaluate(policy, sig, &policy_reason);
    printf("Policy '%s': action=%s\n", policy->name,
           action == SIGSTORE_POLICY_ACTION_ALLOW ? "ALLOW" : "DENY");

    /* Step 4: Dependency Vulnerability Scanning */
    printf("\n-- Step 4: Dependency Vulnerability Scanning --\n");
    cve_entry_t *cve = dep_vuln_create_entry("CVE-2024-3094", "Malicious code in xz/liblzma", time(NULL));
    dep_vuln_set_cvss_v3(cve, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    dep_vuln_add_affected_product(cve, "xz", "5.6.0");
    dep_vuln_add_affected_product(cve, "xz", "5.6.1");
    dep_vuln_add_cpe(cve, "cpe:2.3:a:tukaani:xz:5.6.0:*:*:*:*:*:*:*");
    printf("CVE: %s (%s)\n", cve->cve_id, dep_vuln_has_public_poc("CVE-2024-3094") ? "POC public" : "no POC");

    float cvss_base = cvss_calculate_base_score_v3("N", "L", "N", "N", "U", "H", "H", "H");
    cvss_severity_t sev = cvss_score_to_severity(cvss_base);
    printf("  CVSS v3 base: %.1f (%s)\n", cvss_base, cvss_severity_to_string(sev));

    remediation_t *rem = dep_vuln_suggest_remediation(cve, "5.6.0");
    printf("  Remediation: type=%d, fixed_version=%s, priority=%d\n",
           rem->type, rem->fixed_version ? rem->fixed_version : "N/A", rem->priority);

    exploit_maturity_t mat = dep_vuln_assess_exploit_maturity("CVE-2024-3094");
    printf("  Exploit maturity: %s\n", dep_vuln_exploit_maturity_to_string(mat));

    /* Step 5: Provenance Model (in-toto, Grafeas, Kritis) */
    printf("\n-- Step 5: Provenance Model (in-toto / Grafeas / Kritis) --\n");

    /* in-toto */
    in_toto_link_t *link = provenance_link_create("build-step", "github-actions", "make release");
    provenance_link_add_material(link, "git+https://github.com/myorg/myapp.git", "sha256:abc123");
    provenance_link_add_product(link, "docker://myapp:v2.0", "sha256:def456");
    printf("in-toto link: %s by %s (%zu materials, %zu products)\n",
           link->link_name, link->functionary_name, link->material_count, link->product_count);

    /* Grafeas */
    grafeas_note_t *note = grafeas_note_create("CVE-2024-3094-note", "myapp", GRAFEAS_KIND_VULNERABILITY, "Backdoor in xz");
    grafeas_note_add_url(note, "https://nvd.nist.gov/vuln/detail/CVE-2024-3094");
    grafeas_occurrence_t *occ = grafeas_occurrence_create("occ-001", "docker://myapp:v2.0", GRAFEAS_KIND_VULNERABILITY);
    grafeas_occurrence_attach_note(occ, "CVE-2024-3094-note");
    grafeas_occurrence_set_vulnerability(occ, "CVE-2024-3094", "Update to xz 5.6.2+");
    printf("Grafeas: note=%s, occurrence=%s (CVE=%s)\n",
           note->note_name, occ->occurrence_name, occ->vulnerability_cve_id);

    grafeas_project_t *proj = grafeas_project_create("myapp-v2.0");
    grafeas_project_add_note(proj, note);
    grafeas_project_add_occurrence(proj, occ);
    printf("Grafeas project: %s (%zu notes, %zu occurrences)\n",
           proj->project_name, proj->note_count, proj->occurrence_count);

    /* Kritis */
    kritis_policy_t *kpol = kritis_policy_create("prod-admission", KRITIS_ACTION_DENY);
    kritis_policy_add_attestor(kpol, "prod-signer@myorg.com");
    kritis_policy_add_builder(kpol, "github-actions/v4");
    kritis_policy_set_vulnerability_threshold(kpol, 0, 3);
    printf("Kritis policy: %s (default=%s, max_crit=0, max_high=3)\n",
           kpol->policy_name, kpol->default_action == KRITIS_ACTION_DENY ? "DENY" : "ALLOW");

    /* Binary authorization */
    bin_auth_policy_t *bin_pol = bin_auth_policy_create("/usr/bin/myapp");
    bin_auth_policy_add_builder(bin_pol, "github-actions/v4");
    bin_auth_policy_add_signer(bin_pol, "prod-signer@myorg.com");
    bin_pol->minimum_slsa_level = SLSA_LEVEL_3;
    printf("Binary auth policy: path=%s, min SLSA=%s\n",
           bin_pol->binary_path, slsa_level_to_string(bin_pol->minimum_slsa_level));

    /* Cleanup */
    sbom_spdx_free(spdx);
    sbom_cyclonedx_free(bom);
    slsa_source_free(source);
    slsa_build_config_free(build);
    slsa_provenance_free(prov);
    dep_vuln_free_entry(cve);
    dep_vuln_remediation_free(rem);
    if (sig) cosign_signature_free(sig);
    sigstore_policy_free(policy);
    provenance_link_free(link);
    grafeas_project_free(proj);
    kritis_policy_free(kpol);
    bin_auth_policy_free(bin_pol);

    printf("\nSupply chain security demo complete!\n");
    return 0;
}
