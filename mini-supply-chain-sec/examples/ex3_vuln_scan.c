#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/dep_vuln.h"

static void print_cve(const cve_entry_t* cve) {
    if (!cve) { printf("NULL\n"); return; }
    printf("  CVE: %s\n", cve->cve_id);
    printf("    Description: %s\n", cve->description);
    printf("    Status: %d\n", (int)cve->status);
    if (cve->cvss_v3) {
        printf("    CVSS v3: %.1f (%s)\n",
               cve->cvss_v3->base_score,
               cvss_severity_to_string(cve->cvss_v3->base_severity));
        printf("    Vector: %s\n", cve->cvss_v3->vector_string);
    }
    if (cve->cvss_v4) {
        printf("    CVSS v4: %.1f (%s)\n",
               cve->cvss_v4->base_score,
               cvss_severity_to_string(cve->cvss_v4->base_severity));
    }
    printf("    Affected products: %zu\n", cve->affected_product_count);
    for (size_t i = 0; i < cve->affected_product_count; i++)
        printf("      - %s", cve->affected_products[i]);
    if (cve->affected_product_count > 0) printf("\n");
    printf("    References: %zu\n", cve->reference_count);
    printf("    CPEs: %zu\n", cve->cpe_count);
}

static void print_remediation(const remediation_t* rem) {
    if (!rem) { printf("  NULL\n"); return; }
    const char* type_str =
        rem->type == REMEDIATION_UPGRADE ? "UPGRADE" :
        rem->type == REMEDIATION_PATCH ? "PATCH" :
        rem->type == REMEDIATION_WORKAROUND ? "WORKAROUND" :
        rem->type == REMEDIATION_MITIGATION ? "MITIGATION" : "NO_FIX";
    printf("  CVE: %s\n", rem->cve_id);
    printf("  Type: %s\n", type_str);
    printf("  Description: %s\n", rem->description);
    printf("  Fixed version: %s\n", rem->fixed_version);
    printf("  Priority: %d\n", rem->priority);
}

int main(void) {
    printf("=== Dependency Vulnerability Analysis Example ===\n\n");

    printf("--- CVSS Score Calculation ---\n");
    float score_default = cvss_calculate_base_score_v3(
        "N", "L", "N", "N", "U", "H", "H", "H");
    printf("  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = %.1f (%s)\n",
           score_default, cvss_severity_to_string(cvss_score_to_severity(score_default)));

    float score_local = cvss_calculate_base_score_v3(
        "L", "H", "H", "R", "C", "N", "N", "N");
    printf("  CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:N/I:N/A:N = %.1f (%s)\n",
           score_local, cvss_severity_to_string(cvss_score_to_severity(score_local)));

    float score_adj = cvss_calculate_base_score_v3(
        "A", "L", "L", "N", "U", "H", "L", "N");
    printf("  CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N = %.1f (%s)\n",
           score_adj, cvss_severity_to_string(cvss_score_to_severity(score_adj)));

    float score_phys = cvss_calculate_base_score_v3(
        "P", "L", "L", "N", "U", "L", "L", "L");
    printf("  CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L = %.1f (%s)\n",
           score_phys, cvss_severity_to_string(cvss_score_to_severity(score_phys)));

    printf("\n--- CVSS v4 Score ---\n");
    float v4_score = cvss_calculate_base_score_v4(
        "N", "L", "N", "N", "N", "H", "H", "H", "C", "H", "H");
    printf("  CVSS v4 score: %.1f (%s)\n",
           v4_score, cvss_severity_to_string(cvss_score_to_severity(v4_score)));

    printf("\n--- CVSS From Vector String ---\n");
    cvss_score_t* cvss_crit = cvss_create_from_vector(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    printf("  Critical: %.1f - %s\n",
           cvss_crit->base_score,
           cvss_severity_to_string(cvss_crit->base_severity));
    cvss_free(cvss_crit);

    cvss_score_t* cvss_med = cvss_create_from_vector(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N");
    printf("  Medium: %.1f - %s\n",
           cvss_med->base_score,
           cvss_severity_to_string(cvss_med->base_severity));
    cvss_free(cvss_med);

    printf("\n--- CVE Entry Creation ---\n");
    cve_entry_t* cve1 = dep_vuln_create_entry(
        "CVE-2024-0001", "Remote code execution in libfoo", 0);
    cve_entry_t* cve2 = dep_vuln_create_entry(
        "CVE-2024-0002", "Denial of service in libbar", 0);
    cve_entry_t* cve3 = dep_vuln_create_entry(
        "CVE-2024-0003", "Privilege escalation via unsafe deserialization", 0);

    dep_vuln_set_cvss_v3(cve1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    dep_vuln_set_cvss_v3(cve2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
    dep_vuln_set_cvss_v3(cve3, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

    dep_vuln_add_affected_product(cve1, "libfoo", "< 2.0.0");
    dep_vuln_add_affected_product(cve1, "libfoo-devel", "< 2.0.0");
    dep_vuln_add_affected_product(cve2, "libbar", "<= 1.5.0");
    dep_vuln_add_affected_product(cve3, "libbaz", ">= 3.0.0, < 3.5.0");

    dep_vuln_add_reference(cve1, "https://nvd.nist.gov/vuln/detail/CVE-2024-0001");
    dep_vuln_add_reference(cve1, "https://github.com/advisories/GHSA-xxxx-xxxx-xxxx");
    dep_vuln_add_reference(cve2, "https://nvd.nist.gov/vuln/detail/CVE-2024-0002");

    dep_vuln_add_cpe(cve1, "cpe:2.3:a:vendor:libfoo:*:*:*:*:*:*:*:*");
    dep_vuln_add_cpe(cve2, "cpe:2.3:a:vendor:libbar:*:*:*:*:*:*:*:*");
    dep_vuln_add_cpe(cve3, "cpe:2.3:a:vendor:libbaz:*:*:*:*:*:*:*:*");

    print_cve(cve1);
    printf("\n");
    print_cve(cve2);
    printf("\n");
    print_cve(cve3);

    printf("\n--- NVD Feed ---\n");
    nvd_feed_t* feed = dep_vuln_load_nvd_feed(NULL);
    if (!feed) { fprintf(stderr, "NVD feed failed\n");
        dep_vuln_free_entry(cve3); dep_vuln_free_entry(cve2);
        dep_vuln_free_entry(cve1); return 1; }
    printf("  Feed version: %s\n", feed->version);
    printf("  Entries: %zu\n", feed->count);

    printf("\n--- SBOM Vulnerability Scan (CycloneDX) ---\n");
    cyclonedx_bom_t* bom = sbom_cyclonedx_create("scan-test");
    sbom_cyclonedx_add_component(bom, "libfoo", "1.5.0",
        "pkg:generic/libfoo@1.5.0", NULL);
    sbom_cyclonedx_add_component(bom, "libbar", "1.4.0",
        "pkg:generic/libbar@1.4.0", NULL);
    sbom_cyclonedx_add_component(bom, "libsafe", "2.0.0",
        "pkg:generic/libsafe@2.0.0", NULL);

    cve_entry_t** scan_results = NULL;
    size_t scan_count = 0;
    int scan_rc = dep_vuln_scan_cyclonedx(bom, feed, &scan_results, &scan_count);
    printf("  Scan result: %d, vulnerabilities found: %zu\n", scan_rc, scan_count);

    cve_entry_t** spdx_results = NULL;
    size_t spdx_count = 0;
    spdx_document_t* spdx = sbom_spdx_create("spdx-scan", NULL);
    sbom_spdx_add_package(spdx, "libfoo", "1.5.0", "MIT", NULL);
    int spdx_rc = dep_vuln_scan_spdx(spdx, feed, &spdx_results, &spdx_count);
    printf("  SPDX scan result: %d, vulnerabilities: %zu\n", spdx_rc, spdx_count);
    sbom_spdx_free(spdx);
    free(spdx_results);

    printf("\n--- Match Package Vulnerabilities ---\n");
    size_t match_count = 0;
    cve_entry_t** matches = dep_vuln_match_package_vulnerabilities(
        "libfoo", "1.5.0", PACKAGE_ECOSYSTEM_NPM, feed, &match_count);
    printf("  libfoo@1.5.0 matches: %zu\n", match_count);
    free(matches);

    printf("\n--- Exploit Maturity ---\n");
    const char* cve_ids[] = {"CVE-2024-0001", "CVE-2023-0001", "CVE-2025-0001"};
    for (int i = 0; i < 3; i++) {
        exploit_maturity_t mat = dep_vuln_assess_exploit_maturity(cve_ids[i]);
        printf("  %s: %s (PoC=%s, active=%s)\n", cve_ids[i],
               dep_vuln_exploit_maturity_to_string(mat),
               dep_vuln_has_public_poc(cve_ids[i]) ? "YES" : "NO",
               dep_vuln_is_actively_exploited(cve_ids[i]) ? "YES" : "NO");
    }

    printf("\n--- Remediation ---\n");
    remediation_t* rem1 = dep_vuln_suggest_remediation(cve1, "1.5.0");
    print_remediation(rem1);
    printf("\n");
    remediation_t* rem2 = dep_vuln_create_remediation(
        "CVE-2024-0002", REMEDIATION_WORKAROUND, "1.6.0-patched");
    rem2->description = strdup("Add input validation before parsing");
    rem2->workaround_description = strdup(
        "Set environment variable DISABLE_UNSAFE_FEATURE=1");
    print_remediation(rem2);

    char* rem_str = dep_vuln_remediation_to_string(rem1);
    printf("\n  To string: %s\n", rem_str);
    free(rem_str);

    printf("\n  Verify remediation: %s\n",
           dep_vuln_verify_remediation(rem1) ? "PASS" : "FAIL");

    printf("\n--- Reachability Analysis ---\n");
    reachability_result_t** reach_results = NULL;
    size_t reach_count = 0;
    int reach_rc = dep_vuln_reachability_analysis(
        "/usr/bin/myapp", "vulnerable_parse", "./src",
        &reach_results, &reach_count);
    printf("  Reachability analysis: %d, results: %zu\n", reach_rc, reach_count);
    if (reach_results && reach_count > 0) {
        printf("  Function: %s, reachable: %s\n",
               reach_results[0]->function_name,
               reach_results[0]->reachable ? "YES" : "NO");
        dep_vuln_reachability_result_free(reach_results[0]);
        free(reach_results);
    }

    printf("\n--- Call Graph ---\n");
    const char* files[] = {"main.c", "parser.c", "network.c", "crypto.c", NULL};
    dep_vuln_build_call_graph("./src", files, 4, "/tmp/callgraph.dot");
    bool called = dep_vuln_is_function_called("/tmp/callgraph.dot", "vulnerable_parse");
    printf("  Function called: %s\n", called ? "YES" : "NO");

    printf("\n--- Dependency Confusion Prevention ---\n");
    int confusion_rc = dep_vuln_prevent_confusion(
        "my-internal-lib", "1.0.0", "com.mycompany.internal", NULL);
    printf("  Confusion check (no policy): %s\n",
           confusion_rc == 0 ? "PASS" : "BLOCKED");

    namespace_policy_t* ns_policy = dep_vuln_namespace_policy_create("my-internal-lib");
    dep_vuln_namespace_policy_add_registry(ns_policy,
        "https://registry.mycompany.com", "pubkey-base64-data");
    dep_vuln_namespace_policy_add_registry(ns_policy,
        "https://internal-packages.mycompany.com", "pubkey2-base64-data");
    printf("  Namespace policy: %s (registries=%zu)\n",
           ns_policy->package_name, ns_policy->allowed_reg_count);
    bool ns_verify = dep_vuln_verify_namespace(
        "my-internal-lib", "com.mycompany.internal", ns_policy);
    printf("  Namespace verify: %s\n", ns_verify ? "PASS" : "FAIL");

    int confusion_rc2 = dep_vuln_prevent_confusion(
        "my-internal-lib", "1.0.0", "com.mycompany.internal", ns_policy);
    printf("  Confusion check (with policy): %s (0=pass)\n",
           confusion_rc2 == 0 ? "PASS" : confusion_rc2 == -2 ? "NAMESPACE MISMATCH" : "ERROR");

    dep_vuln_namespace_policy_free(ns_policy);
    dep_vuln_remediation_free(rem2);
    dep_vuln_remediation_free(rem1);
    free(scan_results);
    sbom_cyclonedx_free(bom);
    dep_vuln_feed_free(feed);
    dep_vuln_free_entry(cve3);
    dep_vuln_free_entry(cve2);
    dep_vuln_free_entry(cve1);

    printf("\n=== All vulnerability analysis examples completed ===\n");
    return 0;
}
