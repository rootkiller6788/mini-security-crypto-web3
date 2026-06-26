#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/sbom_gen.h"

static void print_spdx_doc(const spdx_document_t* doc) {
    if (!doc) { printf("NULL document\n"); return; }
    printf("=== SPDX Document ===\n");
    printf("  Name: %s\n", doc->document_name);
    printf("  Version: %s\n", doc->spdx_version);
    printf("  Namespace: %s\n", doc->document_namespace);
    printf("  License: %s\n", doc->data_license);
    printf("  Packages: %zu\n", doc->package_count);
    for (size_t i = 0; i < doc->package_count; i++) {
        const spdx_package_t* p = doc->packages[i];
        printf("    [%zu] %s v%s (%s) license=%s\n",
               i, p->name, p->version, p->spdx_id, p->license_concluded);
    }
    printf("  Relationships: %zu\n", doc->relationship_count);
    for (size_t i = 0; i < doc->relationship_count; i++) {
        const spdx_relationship_t* r = doc->relationships[i];
        printf("    %s -> %s\n", r->source_spdx_id, r->target_spdx_id);
    }
}

static void print_cyclonedx_bom(const cyclonedx_bom_t* bom) {
    if (!bom) { printf("NULL BOM\n"); return; }
    printf("=== CycloneDX BOM ===\n");
    printf("  Format: %s v%s\n", bom->bom_format, bom->spec_version);
    printf("  Serial: %s\n", bom->serial_number);
    printf("  Version: %d\n", bom->version);
    printf("  Components: %zu\n", bom->component_count);
    for (size_t i = 0; i < bom->component_count; i++) {
        const cyclonedx_component_t* c = bom->components[i];
        printf("    [%zu] %s v%s ref=%s", i, c->name, c->version, c->bom_ref);
        if (c->purl) printf(" purl=%s", c->purl);
        if (c->sha256_hash) printf(" sha256=%s", c->sha256_hash);
        printf("\n");
    }
    printf("  Dependencies: %zu\n", bom->dependency_count);
}

int main(void) {
    printf("=== SBOM Generation Example ===\n\n");

    printf("--- SPDX SBOM ---\n");
    spdx_document_t* spdx = sbom_spdx_create("my-application", "https://example.com/sbom/v1");
    if (!spdx) { fprintf(stderr, "Failed to create SPDX doc\n"); return 1; }

    sbom_spdx_add_package(spdx, "libcrypto", "3.0.0", "Apache-2.0",
                          "Organization: OpenSSL Foundation");
    sbom_spdx_add_package(spdx, "libcurl", "8.4.0", "MIT",
                          "Organization: curl project");
    sbom_spdx_add_package(spdx, "my-app", "1.0.0", "GPL-3.0-only",
                          "Organization: MyCompany");
    sbom_spdx_add_package(spdx, "libz", "1.3.0", "Zlib",
                          "Organization: zlib");

    sbom_spdx_add_relationship(spdx, "SPDXRef-DOCUMENT", "SPDXRef-pkg-2",
                               SBOM_REL_DESCRIBES);
    sbom_spdx_add_relationship(spdx, "SPDXRef-pkg-2", "SPDXRef-pkg-0",
                               SBOM_REL_DEPENDS_ON);
    sbom_spdx_add_relationship(spdx, "SPDXRef-pkg-2", "SPDXRef-pkg-1",
                               SBOM_REL_DEPENDS_ON);
    sbom_spdx_add_relationship(spdx, "SPDXRef-pkg-2", "SPDXRef-pkg-3",
                               SBOM_REL_DEPENDS_ON);

    print_spdx_doc(spdx);

    char* spdx_json = sbom_spdx_export_json(spdx);
    printf("\nSPDX JSON output:\n%s\n", spdx_json);
    free(spdx_json);

    char* spdx_tag = sbom_spdx_export_tagvalue(spdx);
    printf("SPDX Tag/Value output:\n%s\n", spdx_tag);
    free(spdx_tag);

    printf("\n--- CycloneDX SBOM ---\n");
    cyclonedx_bom_t* cdx = sbom_cyclonedx_create(NULL);
    if (!cdx) { fprintf(stderr, "Failed CycloneDX\n"); sbom_spdx_free(spdx); return 1; }

    sbom_cyclonedx_add_component(cdx, "my-app", "1.0.0",
        "pkg:npm/my-app@1.0.0", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    sbom_cyclonedx_add_component(cdx, "express", "4.18.0",
        "pkg:npm/express@4.18.0", "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    sbom_cyclonedx_add_component(cdx, "lodash", "4.17.21",
        "pkg:npm/lodash@4.17.21", "sha256:cccccccccccccccccccccccccccccccc");
    sbom_cyclonedx_add_component(cdx, "typescript", "5.3.0",
        "pkg:npm/typescript@5.3.0", "sha256:dddddddddddddddddddddddddddddddd");

    sbom_cyclonedx_add_dependency(cdx, "my-app@1.0.0", "express@4.18.0");
    sbom_cyclonedx_add_dependency(cdx, "my-app@1.0.0", "lodash@4.17.21");
    sbom_cyclonedx_add_dependency(cdx, "my-app@1.0.0", "typescript@5.3.0");

    print_cyclonedx_bom(cdx);

    char* cdx_json = sbom_cyclonedx_export_json(cdx);
    printf("\nCycloneDX JSON:\n%s\n", cdx_json);
    free(cdx_json);

    char* cdx_xml = sbom_cyclonedx_export_xml(cdx);
    printf("CycloneDX XML:\n%s\n", cdx_xml);
    free(cdx_xml);

    printf("\n--- VEX Document ---\n");
    vex_document_t* vex = vex_document_create("vex-2024-001", "security-team");
    vex_entry_t* e1 = vex_entry_create("CVE-2024-1234", "libcrypto@3.0.0",
        VEX_STATUS_AFFECTED, VEX_JUST_VULNERABLE_CODE_NOT_IN_EXECUTE_PATH);
    vex_entry_t* e2 = vex_entry_create("CVE-2024-5678", "express@4.18.0",
        VEX_STATUS_NOT_AFFECTED, VEX_JUST_COMPONENT_NOT_PRESENT);
    vex_entry_t* e3 = vex_entry_create("CVE-2023-9999", "lodash@4.17.21",
        VEX_STATUS_FIXED, VEX_JUST_PATCH_APPLIED);
    vex_document_add_entry(vex, e1);
    vex_document_add_entry(vex, e2);
    vex_document_add_entry(vex, e3);
    char* vex_json = vex_document_export_json(vex);
    printf("%s\n", vex_json);
    free(vex_json);

    printf("\n--- SBOM Attestation ---\n");
    sbom_attestation_t* att = sbom_attestation_create(
        "my-app@1.0.0",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "https://spdx.dev/Document");
    sbom_attestation_sign(att, "-----BEGIN PRIVATE KEY-----\ntest-key\n-----END PRIVATE KEY-----");
    char* att_bundle = sbom_attestation_export_bundle(att);
    printf("%s\n", att_bundle);
    free(att_bundle);

    printf("\n--- Component Graph ---\n");
    sbom_component_graph_t* graph = sbom_build_component_graph(cdx);
    printf("Graph nodes: %zu\n", graph ? graph->node_count : 0);
    char** sorted = NULL;
    size_t sorted_count = 0;
    if (graph) {
        sbom_graph_topological_sort(graph, &sorted, &sorted_count);
        printf("Topological sort: ");
        for (size_t i = 0; i < sorted_count; i++) {
            printf("%s%s", sorted[i], i + 1 < sorted_count ? " -> " : "\n");
        }
        for (size_t i = 0; i < sorted_count; i++) free(sorted[i]);
        free(sorted);
        sbom_component_graph_free(graph);
    }

    sbom_attestation_free(att);
    vex_document_free(vex);
    sbom_cyclonedx_free(cdx);
    sbom_spdx_free(spdx);

    printf("\n=== All SBOM examples completed successfully ===\n");
    return 0;
}
