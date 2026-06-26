/*
 * mini-supply-chain-sec — Benchmark: SBOM, SLSA, Sigstore, dependency vuln, provenance
 *
 * Usage: bench_core [iterations]
 */
#include "../include/sbom_gen.h"
#include "../include/slsa_framework.h"
#include "../include/sigstore_cosign.h"
#include "../include/dep_vuln.h"
#include "../include/provenance_model.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now_ms(void) {
    return (double)clock() / (double)(CLOCKS_PER_SEC / 1000);
}

int main(int argc, char **argv) {
    int N = (argc > 1) ? atoi(argv[1]) : 5000;
    printf("=== mini-supply-chain-sec Benchmarks (iterations=%d) ===\n\n", N);

    /* SPDX SBOM generation */
    {
        spdx_document_t *doc = sbom_spdx_create("bench-app", "https://bench.example/ns");
        sbom_spdx_add_package(doc, "libopenssl", "3.0.0", "Apache-2.0", "OpenSSL Foundation");
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            sbom_spdx_add_package(doc, "bench-pkg", "1.0", "MIT", "bench-vendor");
        }
        double dt = now_ms() - t0;
        printf("  sbom_spdx_add_package:                %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
        sbom_spdx_free(doc);
    }

    /* CycloneDX SBOM */
    {
        cyclonedx_bom_t *bom = sbom_cyclonedx_create("bench-serial-001");
        sbom_cyclonedx_add_component(bom, "bench-lib", "2.0", "pkg:npm/bench-lib@2.0", "abcdef123456");
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            sbom_cyclonedx_add_component(bom, "bench-comp", "1.0", "pkg:pypi/comp@1.0", "deadbeef");
        }
        double dt = now_ms() - t0;
        printf("  sbom_cyclonedx_add_component:         %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
        sbom_cyclonedx_free(bom);
    }

    /* SLSA source assessment */
    {
        slsa_source_t *source = slsa_source_create("https://github.com/example/repo", "abc123def456");
        slsa_source_set_signed(source, "dev@example.com", "SHA256:fp12345");
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            slsa_assess_source_level(source);
        }
        double dt = now_ms() - t0;
        printf("  slsa_assess_source_level:             %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
        slsa_source_free(source);
    }

    /* SLSA provenance creation */
    {
        slsa_provenance_t *prov = slsa_provenance_create("bench-subject", "sha256:feedface", "https://slsa.dev/provenance/v1");
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            slsa_provenance_add_material(prov, "https://repo.example/artifact");
        }
        double dt = now_ms() - t0;
        printf("  slsa_provenance_add_material:         %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
        slsa_provenance_free(prov);
    }

    /* CVSS score calculation */
    {
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            cvss_calculate_base_score_v3("N", "L", "N", "N", "U", "H", "H", "H");
            cvss_score_to_severity(8.5f);
        }
        double dt = now_ms() - t0;
        printf("  cvss_calc_v3+severity:                %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
    }

    /* CVE entry creation + scan */
    {
        cve_entry_t *entry = dep_vuln_create_entry("CVE-2024-0001", "Test vulnerability for benchmark", time(NULL));
        dep_vuln_set_cvss_v3(entry, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
        dep_vuln_add_affected_product(entry, "bench-product", "1.0");
        dep_vuln_add_cpe(entry, "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*");
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            dep_vuln_suggest_remediation(entry, "0.9.0");
        }
        double dt = now_ms() - t0;
        printf("  dep_vuln_suggest_remediation:         %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
        dep_vuln_free_entry(entry);
    }

    /* in-toto link creation */
    {
        in_toto_link_t *link = provenance_link_create("bench-step", "bench-builder", "make build");
        provenance_link_add_material(link, "https://src.example/main.c", "sha256:abc123");
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            provenance_link_add_product(link, "https://out.example/binary", "sha256:def456");
        }
        double dt = now_ms() - t0;
        printf("  provenance_link_add_product:          %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
        provenance_link_free(link);
    }

    /* Grafeas note creation */
    {
        grafeas_note_t *note = grafeas_note_create("bench-note", "bench-proj", GRAFEAS_KIND_VULNERABILITY, "Test CVE note");
        double t0 = now_ms();
        for (int i = 0; i < N; i++) {
            grafeas_note_add_url(note, "https://nvd.nist.gov/vuln/detail/CVE-2024-0001");
        }
        double dt = now_ms() - t0;
        printf("  grafeas_note_add_url:                 %d ops in %.1f ms  (%.1f µs/op)\n",
               N, dt, dt * 1000.0 / (double)N);
        grafeas_note_free(note);
    }

    printf("\n=== Benchmarks complete ===\n");
    return 0;
}
