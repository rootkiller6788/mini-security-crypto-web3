#include "sbom_gen.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

static char* sbom_strdup(const char* s) {
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char* dup = (char*)malloc(len);
    if (dup) memcpy(dup, s, len);
    return dup;
}

static char* sbom_json_escape(const char* s) {
    if (!s) return sbom_strdup("");
    size_t len = strlen(s);
    size_t alloc = len * 2 + 3;
    char* out = (char*)malloc(alloc);
    if (!out) return NULL;
    size_t j = 0;
    for (size_t i = 0; i < len && j < alloc - 1; i++) {
        switch (s[i]) {
        case '\"': out[j++] = '\\'; out[j++] = '\"'; break;
        case '\\': out[j++] = '\\'; out[j++] = '\\'; break;
        case '\n': out[j++] = '\\'; out[j++] = 'n'; break;
        case '\t': out[j++] = '\\'; out[j++] = 't'; break;
        case '\r': out[j++] = '\\'; out[j++] = 'r'; break;
        default: out[j++] = s[i]; break;
        }
    }
    out[j] = '\0';
    return out;
}

static char* sbom_gen_uuid(void) {
    char* uuid = (char*)malloc(37);
    if (!uuid) return NULL;
    unsigned int a = (unsigned int)time(NULL);
    unsigned int b = ((unsigned int)(uintptr_t)&uuid) ^ (a >> 4);
    unsigned int c = a ^ (b << 1);
    unsigned int d = b ^ (c << 2);
    snprintf(uuid, 37,
             "%08x-%04x-%04x-%04x-%04x%08x",
             a, (unsigned int)(b & 0xFFFF), (unsigned int)(c & 0xFFFF),
             (unsigned int)(d & 0xFFFF), (unsigned int)((a ^ d) & 0xFFFF),
             (unsigned int)((b ^ c) & 0xFFFFFFFF));
    return uuid;
}

spdx_document_t* sbom_spdx_create(const char* name, const char* namespace_uri) {
    spdx_document_t* doc = (spdx_document_t*)calloc(1, sizeof(spdx_document_t));
    if (!doc) return NULL;
    doc->spdx_version = sbom_strdup("SPDX-2.3");
    doc->data_license = sbom_strdup("CC0-1.0");
    doc->document_name = sbom_strdup(name ? name : "unnamed");
    char* ns = namespace_uri ? sbom_strdup(namespace_uri) : sbom_gen_uuid();
    size_t ns_len = strlen(ns) + 256;
    doc->document_namespace = (char*)malloc(ns_len);
    if (doc->document_namespace) {
        snprintf(doc->document_namespace, ns_len,
                 "%s#SPDXRef-DOCUMENT", ns);
    }
    free(ns);
    doc->spec_version = sbom_strdup("2.3");
    doc->created = time(NULL);
    doc->creation_creator = (spdx_creator_t*)calloc(1, sizeof(spdx_creator_t));
    if (doc->creation_creator) {
        doc->creation_creator->tool = sbom_strdup("mini-supply-chain-sec");
        doc->creation_creator->name = sbom_strdup("SBOM Generator");
    }
    doc->packages = NULL;
    doc->package_count = 0;
    doc->relationships = NULL;
    doc->relationship_count = 0;
    return doc;
}

void sbom_spdx_add_package(spdx_document_t* doc, const char* name, const char* version,
                           const char* license, const char* supplier) {
    if (!doc || !name) return;
    spdx_package_t* pkg = (spdx_package_t*)calloc(1, sizeof(spdx_package_t));
    if (!pkg) return;
    pkg->name = sbom_strdup(name);
    pkg->version = sbom_strdup(version ? version : "NOASSERTION");
    pkg->license_concluded = sbom_strdup(license ? license : "NOASSERTION");
    pkg->license_declared = sbom_strdup(license ? license : "NOASSERTION");
    pkg->supplier = supplier ? sbom_strdup(supplier) : sbom_strdup("Organization: NOASSERTION");
    pkg->copyright_text = sbom_strdup("NOASSERTION");
    char spdx_id[512];
    snprintf(spdx_id, sizeof(spdx_id), "SPDXRef-pkg-%zu", doc->package_count);
    pkg->spdx_id = sbom_strdup(spdx_id);
    size_t new_count = doc->package_count + 1;
    spdx_package_t** new_pkgs = (spdx_package_t**)realloc(
        doc->packages, new_count * sizeof(spdx_package_t*));
    if (new_pkgs) {
        new_pkgs[doc->package_count] = pkg;
        doc->packages = new_pkgs;
        doc->package_count = new_count;
    } else {
        free(pkg->name);
        free(pkg->spdx_id);
        free(pkg);
    }
}

void sbom_spdx_add_relationship(spdx_document_t* doc, const char* src_id, const char* tgt_id,
                                sbom_relationship_type_t rel_type) {
    if (!doc || !src_id || !tgt_id) return;
    spdx_relationship_t* rel = (spdx_relationship_t*)calloc(1, sizeof(spdx_relationship_t));
    if (!rel) return;
    rel->source_spdx_id = sbom_strdup(src_id);
    rel->target_spdx_id = sbom_strdup(tgt_id);
    rel->relationship = rel_type;
    size_t new_count = doc->relationship_count + 1;
    spdx_relationship_t** new_rels = (spdx_relationship_t**)realloc(
        doc->relationships, new_count * sizeof(spdx_relationship_t*));
    if (new_rels) {
        new_rels[doc->relationship_count] = rel;
        doc->relationships = new_rels;
        doc->relationship_count = new_count;
    } else {
        free(rel->source_spdx_id);
        free(rel->target_spdx_id);
        free(rel);
    }
}

static const char* sbom_rel_type_to_string(sbom_relationship_type_t t) {
    switch (t) {
    case SBOM_REL_DESCRIBES: return "DESCRIBES";
    case SBOM_REL_DEPENDS_ON: return "DEPENDS_ON";
    case SBOM_REL_CONTAINS: return "CONTAINS";
    case SBOM_REL_GENERATES: return "GENERATES";
    case SBOM_REL_BUILD_TOOL_OF: return "BUILD_TOOL_OF";
    case SBOM_REL_PATCH_FOR: return "PATCH_FOR";
    default: return "RELATED_TO";
    }
}

char* sbom_spdx_export_json(const spdx_document_t* doc) {
    if (!doc) return NULL;
    size_t cap = 65536;
    size_t len = 0;
    char* json = (char*)malloc(cap);
    if (!json) return NULL;
    len += snprintf(json + len, cap - len,
        "{\n  \"spdxVersion\": \"%s\",\n  \"dataLicense\": \"%s\",\n"
        "  \"SPDXID\": \"SPDXRef-DOCUMENT\",\n"
        "  \"name\": \"%s\",\n"
        "  \"documentNamespace\": \"%s\",\n",
        doc->spdx_version, doc->data_license,
        doc->document_name, doc->document_namespace);
    len += snprintf(json + len, cap - len,
        "  \"creationInfo\": {\n    \"created\": \"%ld\",\n"
        "    \"creators\": [\"Tool: %s\"]\n  },\n",
        (long)doc->created,
        doc->creation_creator ? doc->creation_creator->tool : "unknown");
    len += snprintf(json + len, cap - len, "  \"packages\": [\n");
    for (size_t i = 0; i < doc->package_count; i++) {
        spdx_package_t* p = doc->packages[i];
        char* name_esc = sbom_json_escape(p->name);
        char* ver_esc = sbom_json_escape(p->version);
        char* lic_esc = sbom_json_escape(p->license_concluded);
        len += snprintf(json + len, cap - len,
            "    {\"SPDXID\": \"%s\", \"name\": \"%s\","
            " \"versionInfo\": \"%s\", \"licenseConcluded\": \"%s\"}%s\n",
            p->spdx_id, name_esc, ver_esc, lic_esc,
            i + 1 < doc->package_count ? "," : "");
        free(name_esc); free(ver_esc); free(lic_esc);
    }
    len += snprintf(json + len, cap - len, "  ],\n  \"relationships\": [\n");
    for (size_t i = 0; i < doc->relationship_count; i++) {
        spdx_relationship_t* r = doc->relationships[i];
        len += snprintf(json + len, cap - len,
            "    {\"spdxElementId\": \"%s\", \"relatedSpdxElement\": \"%s\","
            " \"relationshipType\": \"%s\"}%s\n",
            r->source_spdx_id, r->target_spdx_id,
            sbom_rel_type_to_string(r->relationship),
            i + 1 < doc->relationship_count ? "," : "");
    }
    snprintf(json + len, cap - len, "  ]\n}\n");
    return json;
}

spdx_document_t* sbom_spdx_generate_from_build(const char* build_dir, const char* build_tool) {
    spdx_document_t* doc = sbom_spdx_create("build-sbom", NULL);
    if (!doc || !build_dir) return doc;
    if (doc->creation_creator) {
        free(doc->creation_creator->tool);
        doc->creation_creator->tool = sbom_strdup(build_tool ? build_tool : "make");
    }
    char info_path[1024];
    snprintf(info_path, sizeof(info_path), "%s/build_info.txt", build_dir);
    FILE* f = fopen(info_path, "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            line[strcspn(line, "\r\n")] = '\0';
            if (strlen(line) > 0) {
                sbom_spdx_add_package(doc, line, "1.0.0", "MIT", NULL);
            }
        }
        fclose(f);
    }
    sbom_spdx_add_package(doc, build_tool ? build_tool : "build-root", "1.0", "NOASSERTION",
                          "Organization: build-system");
    return doc;
}

int sbom_spdx_parse_json(const char* json_data, spdx_document_t** out_doc) {
    if (!json_data || !out_doc) return -1;
    *out_doc = sbom_spdx_create("parsed-sbom", NULL);
    if (!*out_doc) return -2;
    if (strstr(json_data, "\"name\"")) {
        const char* name_start = strstr(json_data, "\"name\"");
        if (name_start) {
            const char* val_start = strchr(name_start + 6, ':');
            if (val_start) {
                const char* q1 = strchr(val_start, '\"');
                if (q1) {
                    const char* q2 = strchr(q1 + 1, '\"');
                    if (q2 && q2 > q1 + 1) {
                        size_t nlen = q2 - q1 - 1;
                        char* dname = (char*)malloc(nlen + 1);
                        if (dname) {
                            memcpy(dname, q1 + 1, nlen);
                            dname[nlen] = '\0';
                            free((*out_doc)->document_name);
                            (*out_doc)->document_name = dname;
                        }
                    }
                }
            }
        }
    }
    return 0;
}

char* sbom_spdx_export_tagvalue(const spdx_document_t* doc) {
    if (!doc) return NULL;
    size_t cap = 32768;
    char* out = (char*)malloc(cap);
    if (!out) return NULL;
    size_t len = 0;
    len += snprintf(out + len, cap - len,
        "SPDXVersion: %s\nDataLicense: %s\nSPDXID: SPDXRef-DOCUMENT\n"
        "DocumentName: %s\nDocumentNamespace: %s\n",
        doc->spdx_version, doc->data_license,
        doc->document_name, doc->document_namespace);
    for (size_t i = 0; i < doc->package_count; i++) {
        spdx_package_t* p = doc->packages[i];
        len += snprintf(out + len, cap - len,
            "PackageName: %s\nSPDXID: %s\nPackageVersion: %s\n"
            "PackageLicenseConcluded: %s\n",
            p->name, p->spdx_id, p->version, p->license_concluded);
    }
    return out;
}

void sbom_spdx_free(spdx_document_t* doc) {
    if (!doc) return;
    free(doc->spdx_version);
    free(doc->data_license);
    free(doc->document_namespace);
    free(doc->document_name);
    free(doc->spec_version);
    if (doc->creation_creator) {
        free(doc->creation_creator->name);
        free(doc->creation_creator->email);
        free(doc->creation_creator->organization);
        free(doc->creation_creator->tool);
        free(doc->creation_creator);
    }
    for (size_t i = 0; i < doc->package_count; i++) {
        spdx_package_t* p = doc->packages[i];
        free(p->spdx_id);
        free(p->name);
        free(p->version);
        free(p->license_concluded);
        free(p->license_declared);
        free(p->copyright_text);
        free(p->supplier);
        free(p->download_url);
        free(p->checksum_sha256);
        for (size_t j = 0; j < p->external_ref_count; j++)
            free(p->external_refs[j]);
        free(p->external_refs);
        free(p);
    }
    free(doc->packages);
    for (size_t i = 0; i < doc->relationship_count; i++) {
        spdx_relationship_t* r = doc->relationships[i];
        free(r->source_spdx_id);
        free(r->target_spdx_id);
        free(r->comment);
        free(r);
    }
    free(doc->relationships);
    free(doc);
}

cyclonedx_bom_t* sbom_cyclonedx_create(const char* serial_number) {
    cyclonedx_bom_t* bom = (cyclonedx_bom_t*)calloc(1, sizeof(cyclonedx_bom_t));
    if (!bom) return NULL;
    bom->bom_format = sbom_strdup("CycloneDX");
    bom->spec_version = sbom_strdup("1.5");
    bom->serial_number = serial_number ? sbom_strdup(serial_number) : sbom_gen_uuid();
    bom->version = 1;
    bom->metadata_tool = sbom_strdup("mini-supply-chain-sec");
    return bom;
}

void sbom_cyclonedx_add_component(cyclonedx_bom_t* bom, const char* name, const char* version,
                                  const char* purl, const char* sha256) {
    if (!bom || !name) return;
    cyclonedx_component_t* comp = (cyclonedx_component_t*)calloc(1, sizeof(cyclonedx_component_t));
    if (!comp) return;
    comp->type = sbom_strdup("library");
    char ref[512];
    snprintf(ref, sizeof(ref), "%s@%s", name, version ? version : "unknown");
    comp->bom_ref = sbom_strdup(ref);
    comp->name = sbom_strdup(name);
    comp->version = sbom_strdup(version ? version : "0.0.0");
    comp->purl = purl ? sbom_strdup(purl) : NULL;
    comp->sha256_hash = sha256 ? sbom_strdup(sha256) : NULL;
    size_t nc = bom->component_count + 1;
    cyclonedx_component_t** newc = (cyclonedx_component_t**)realloc(
        bom->components, nc * sizeof(cyclonedx_component_t*));
    if (newc) {
        newc[bom->component_count] = comp;
        bom->components = newc;
        bom->component_count = nc;
    } else {
        free(comp->bom_ref); free(comp->name); free(comp->version);
        free(comp->purl); free(comp->sha256_hash); free(comp->type);
        free(comp);
    }
}

void sbom_cyclonedx_add_dependency(cyclonedx_bom_t* bom, const char* ref, const char* depends_on_ref) {
    if (!bom || !ref || !depends_on_ref) return;
    for (size_t i = 0; i < bom->dependency_count; i++) {
        if (bom->dependencies[i] && strcmp(bom->dependencies[i]->ref, ref) == 0) {
            cyclonedx_dependency_t* d = bom->dependencies[i];
            size_t nd = d->depends_on_count + 1;
            char** newdeps = (char**)realloc(d->depends_on, nd * sizeof(char*));
            if (newdeps) {
                newdeps[d->depends_on_count] = sbom_strdup(depends_on_ref);
                d->depends_on = newdeps;
                d->depends_on_count = nd;
            }
            return;
        }
    }
    cyclonedx_dependency_t* dep = (cyclonedx_dependency_t*)calloc(1, sizeof(cyclonedx_dependency_t));
    if (!dep) return;
    dep->ref = sbom_strdup(ref);
    dep->depends_on = (char**)malloc(sizeof(char*));
    if (dep->depends_on) {
        dep->depends_on[0] = sbom_strdup(depends_on_ref);
        dep->depends_on_count = 1;
    }
    size_t nd = bom->dependency_count + 1;
    cyclonedx_dependency_t** newd = (cyclonedx_dependency_t**)realloc(
        bom->dependencies, nd * sizeof(cyclonedx_dependency_t*));
    if (newd) {
        newd[bom->dependency_count] = dep;
        bom->dependencies = newd;
        bom->dependency_count = nd;
    }
}

char* sbom_cyclonedx_export_json(const cyclonedx_bom_t* bom) {
    if (!bom) return NULL;
    size_t cap = 65536;
    char* json = (char*)malloc(cap);
    if (!json) return NULL;
    size_t len = 0;
    len += snprintf(json + len, cap - len,
        "{\n  \"bomFormat\": \"%s\",\n  \"specVersion\": \"%s\",\n"
        "  \"serialNumber\": \"%s\",\n  \"version\": %d,\n"
        "  \"metadata\": {\"tools\": [{\"name\": \"%s\"}]},\n",
        bom->bom_format, bom->spec_version, bom->serial_number,
        bom->version, bom->metadata_tool);
    len += snprintf(json + len, cap - len, "  \"components\": [\n");
    for (size_t i = 0; i < bom->component_count; i++) {
        cyclonedx_component_t* c = bom->components[i];
        char* name_esc = sbom_json_escape(c->name);
        len += snprintf(json + len, cap - len,
            "    {\"type\": \"library\", \"bom-ref\": \"%s\","
            " \"name\": \"%s\", \"version\": \"%s\"",
            c->bom_ref, name_esc, c->version);
        free(name_esc);
        if (c->purl) {
            char* purl_esc = sbom_json_escape(c->purl);
            len += snprintf(json + len, cap - len,
                ", \"purl\": \"%s\"", purl_esc);
            free(purl_esc);
        }
        len += snprintf(json + len, cap - len, "}%s\n",
            i + 1 < bom->component_count ? "," : "");
    }
    len += snprintf(json + len, cap - len, "  ]\n}\n");
    return json;
}

cyclonedx_bom_t* sbom_cyclonedx_generate_from_build(const char* build_dir,
                                                     const char* build_tool) {
    cyclonedx_bom_t* bom = sbom_cyclonedx_create(NULL);
    if (!bom || !build_dir) return bom;
    if (bom->metadata_tool) {
        free(bom->metadata_tool);
        bom->metadata_tool = sbom_strdup(build_tool ? build_tool : "generic");
    }
    sbom_cyclonedx_add_component(bom, "app-root", "0.1.0",
        "pkg:generic/app-root@0.1.0", NULL);
    return bom;
}

int sbom_cyclonedx_parse_json(const char* json_data, cyclonedx_bom_t** out_bom) {
    if (!json_data || !out_bom) return -1;
    *out_bom = sbom_cyclonedx_create("parsed-cyclonedx");
    return *out_bom ? 0 : -2;
}

char* sbom_cyclonedx_export_xml(const cyclonedx_bom_t* bom) {
    if (!bom) return NULL;
    size_t cap = 32768;
    char* xml = (char*)malloc(cap);
    if (!xml) return NULL;
    size_t len = 0;
    len += snprintf(xml + len, cap - len,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<bom xmlns=\"http://cyclonedx.org/schema/bom/1.5\""
        " serialNumber=\"%s\" version=\"%d\">\n"
        "  <components>\n", bom->serial_number, bom->version);
    for (size_t i = 0; i < bom->component_count; i++) {
        cyclonedx_component_t* c = bom->components[i];
        len += snprintf(xml + len, cap - len,
            "    <component type=\"library\" bom-ref=\"%s\">\n"
            "      <name>%s</name>\n      <version>%s</version>\n"
            "    </component>\n", c->bom_ref, c->name, c->version);
    }
    snprintf(xml + len, cap - len, "  </components>\n</bom>\n");
    return xml;
}

void sbom_cyclonedx_free(cyclonedx_bom_t* bom) {
    if (!bom) return;
    free(bom->bom_format);
    free(bom->spec_version);
    free(bom->serial_number);
    free(bom->metadata_timestamp);
    free(bom->metadata_tool);
    for (size_t i = 0; i < bom->component_count; i++) {
        cyclonedx_component_t* c = bom->components[i];
        free(c->type); free(c->bom_ref); free(c->name); free(c->version);
        free(c->purl); free(c->publisher); free(c->group);
        free(c->description); free(c->sha256_hash);
        for (size_t j = 0; j < c->license_count; j++) free(c->licenses[j]);
        free(c->licenses);
        for (size_t j = 0; j < c->cpe_count; j++) free(c->cpe_list[j]);
        free(c->cpe_list);
        free(c);
    }
    free(bom->components);
    for (size_t i = 0; i < bom->dependency_count; i++) {
        cyclonedx_dependency_t* d = bom->dependencies[i];
        free(d->ref);
        for (size_t j = 0; j < d->depends_on_count; j++)
            free(d->depends_on[j]);
        free(d->depends_on);
        free(d);
    }
    free(bom->dependencies);
    free(bom);
}

vex_entry_t* vex_entry_create(const char* vuln_id, const char* product,
                              vex_status_t status, vex_justification_t justification) {
    vex_entry_t* entry = (vex_entry_t*)calloc(1, sizeof(vex_entry_t));
    if (!entry) return NULL;
    entry->vulnerability_id = sbom_strdup(vuln_id);
    entry->product_identifier = sbom_strdup(product);
    entry->status = status;
    entry->justification = justification;
    return entry;
}

vex_document_t* vex_document_create(const char* doc_id, const char* author) {
    vex_document_t* doc = (vex_document_t*)calloc(1, sizeof(vex_document_t));
    if (!doc) return NULL;
    doc->document_id = sbom_strdup(doc_id ? doc_id : "vex-doc-1");
    doc->author = sbom_strdup(author ? author : "unknown");
    doc->timestamp = time(NULL);
    return doc;
}

void vex_document_add_entry(vex_document_t* doc, vex_entry_t* entry) {
    if (!doc || !entry) return;
    size_t n = doc->entry_count + 1;
    vex_entry_t** new_e = (vex_entry_t**)realloc(doc->entries, n * sizeof(vex_entry_t*));
    if (new_e) { new_e[doc->entry_count] = entry; doc->entries = new_e; doc->entry_count = n; }
}

char* vex_document_export_json(const vex_document_t* doc) {
    if (!doc) return NULL;
    size_t cap = 16384;
    char* json = (char*)malloc(cap);
    if (!json) return NULL;
    size_t len = 0;
    len += snprintf(json + len, cap - len,
        "{\n  \"@id\": \"%s\",\n  \"author\": \"%s\",\n"
        "  \"timestamp\": \"%ld\",\n  \"entries\": [\n",
        doc->document_id, doc->author, (long)doc->timestamp);
    for (size_t i = 0; i < doc->entry_count; i++) {
        vex_entry_t* e = doc->entries[i];
        char* vid = sbom_json_escape(e->vulnerability_id);
        char* pid = sbom_json_escape(e->product_identifier);
        len += snprintf(json + len, cap - len,
            "    {\"vuln_id\": \"%s\", \"product\": \"%s\","
            " \"status\": %d}%s\n",
            vid, pid, (int)e->status,
            i + 1 < doc->entry_count ? "," : "");
        free(vid); free(pid);
    }
    snprintf(json + len, cap - len, "  ]\n}\n");
    return json;
}

int vex_document_parse_json(const char* json_data, vex_document_t** out_doc) {
    if (!json_data || !out_doc) return -1;
    *out_doc = vex_document_create("parsed-vex", "parser");
    return *out_doc ? 0 : -2;
}

void vex_document_free(vex_document_t* doc) {
    if (!doc) return;
    free(doc->document_id); free(doc->author);
    for (size_t i = 0; i < doc->entry_count; i++) {
        vex_entry_t* e = doc->entries[i];
        free(e->vulnerability_id); free(e->vulnerability_description);
        free(e->product_identifier); free(e->component_bom_ref);
        free(e->action_statement); free(e->release_date);
        free(e);
    }
    free(doc->entries);
    free(doc);
}

sbom_attestation_t* sbom_attestation_create(const char* subject_name,
                                             const char* subject_digest,
                                             const char* predicate_type) {
    sbom_attestation_t* att = (sbom_attestation_t*)calloc(1, sizeof(sbom_attestation_t));
    if (!att) return NULL;
    att->subject_name = sbom_strdup(subject_name);
    att->subject_digest_sha256 = sbom_strdup(subject_digest);
    att->predicate_type = sbom_strdup(predicate_type);
    return att;
}

int sbom_attestation_sign(sbom_attestation_t* attestation, const char* private_key_pem) {
    if (!attestation || !private_key_pem) return -1;
    size_t sig_cap = 4096;
    attestation->signature_base64 = (char*)calloc(1, sig_cap);
    if (!attestation->signature_base64) return -2;
    attestation->public_key_pem = sbom_strdup(private_key_pem);
    snprintf(attestation->signature_base64, sig_cap,
             "SIGNED:%s:%s:%s", attestation->subject_name,
             attestation->predicate_type, private_key_pem);
    return 0;
}

int sbom_attestation_verify(const sbom_attestation_t* attestation, const char* public_key_pem) {
    if (!attestation || !public_key_pem || !attestation->signature_base64) return -1;
    return 0;
}

char* sbom_attestation_export_bundle(const sbom_attestation_t* attestation) {
    if (!attestation) return NULL;
    size_t cap = 8192;
    char* bundle = (char*)malloc(cap);
    if (!bundle) return NULL;
    snprintf(bundle, cap,
        "{\"payloadType\": \"application/vnd.in-toto+json\",\n"
        " \"payload\": {\"subject\": \"%s\", \"predicateType\": \"%s\"},\n"
        " \"signature\": \"%s\"}\n",
        attestation->subject_name, attestation->predicate_type,
        attestation->signature_base64 ? attestation->signature_base64 : "");
    return bundle;
}

void sbom_attestation_free(sbom_attestation_t* attestation) {
    if (!attestation) return;
    free(attestation->predicate_type);
    free(attestation->subject_name);
    free(attestation->subject_digest_sha256);
    free(attestation->predicate_json);
    free(attestation->signature_base64);
    free(attestation->public_key_pem);
    free(attestation);
}

sbom_component_graph_t* sbom_build_component_graph(const cyclonedx_bom_t* bom) {
    if (!bom) return NULL;
    sbom_component_graph_t* graph = (sbom_component_graph_t*)
        calloc(1, sizeof(sbom_component_graph_t));
    if (!graph) return NULL;
    graph->node_count = bom->component_count;
    graph->nodes = (sbom_component_node_t**)calloc(graph->node_count,
        sizeof(sbom_component_node_t*));
    if (!graph->nodes) { free(graph); return NULL; }
    for (size_t i = 0; i < bom->component_count; i++) {
        sbom_component_node_t* node = (sbom_component_node_t*)
            calloc(1, sizeof(sbom_component_node_t));
        if (node) {
            node->component_name = sbom_strdup(bom->components[i]->name);
            node->component_version = sbom_strdup(bom->components[i]->version);
            graph->nodes[i] = node;
        }
    }
    return graph;
}

sbom_component_node_t* sbom_graph_find_node(const sbom_component_graph_t* graph,
                                             const char* name) {
    if (!graph || !name) return NULL;
    for (size_t i = 0; i < graph->node_count; i++) {
        if (graph->nodes[i] && strcmp(graph->nodes[i]->component_name, name) == 0)
            return graph->nodes[i];
    }
    return NULL;
}

int sbom_graph_topological_sort(const sbom_component_graph_t* graph,
                                char*** out_sorted, size_t* out_count) {
    if (!graph || !out_sorted || !out_count) return -1;
    *out_count = graph->node_count;
    *out_sorted = (char**)malloc(graph->node_count * sizeof(char*));
    if (!*out_sorted) return -2;
    for (size_t i = 0; i < graph->node_count; i++) {
        (*out_sorted)[i] = sbom_strdup(graph->nodes[i] ?
            graph->nodes[i]->component_name : "unknown");
    }
    return 0;
}

int sbom_graph_find_cycles(const sbom_component_graph_t* graph,
                           char*** out_cycles, size_t* out_count) {
    if (!graph || !out_cycles || !out_count) return -1;
    *out_count = 0;
    *out_cycles = NULL;
    return 0;
}

void sbom_component_graph_free(sbom_component_graph_t* graph) {
    if (!graph) return;
    for (size_t i = 0; i < graph->node_count; i++) {
        sbom_component_node_t* n = graph->nodes[i];
        if (n) {
            free(n->component_name); free(n->component_version);
            for (size_t j = 0; j < n->dependent_count; j++)
                free(n->dependents[j]);
            free(n->dependents);
            for (size_t j = 0; j < n->dep_count; j++)
                free(n->dependencies[j]);
            free(n->dependencies);
            free(n);
        }
    }
    free(graph->nodes);
    free(graph);
}
