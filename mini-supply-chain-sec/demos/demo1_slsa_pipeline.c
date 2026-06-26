#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/slsa_framework.h"

static slsa_source_t* create_source(const char* name, const char* repo,
                                      const char* commit, bool signed_commit,
                                      bool two_person, bool protected_branch) {
    slsa_source_t* src = slsa_source_create(repo, commit);
    if (!src) return NULL;
    src->branch_name = strdup("main");
    src->commit_timestamp = time(NULL) - 86400;
    if (signed_commit) {
        slsa_source_set_signed(src, name, "SHA256:fingerprint-placeholder-data");
        src->two_person_review = two_person;
        src->protected_branch = protected_branch;
        src->code_review_url = two_person ?
            strdup("https://github.com/example/review/123") : NULL;
    }
    return src;
}

static void print_source_summary(const char* label, const slsa_source_t* src) {
    if (!src) { printf("  %-12s: NULL\n", label); return; }
    slsa_level_t level = slsa_assess_source_level(src);
    printf("  %-12s: %s -> %s (signed=%s, review=%s, branch=%s)\n",
           label, src->repo_url, slsa_level_to_string(level),
           src->signed_commit ? "Y" : "N",
           src->two_person_review ? "Y" : "N",
           src->protected_branch ? "protected" : "unprotected");
}

static slsa_build_config_t* create_build(const char* platform,
                                           const char* builder,
                                           bool hermetic,
                                           bool parameterless,
                                           slsa_build_isolation_t iso,
                                           bool reproducible) {
    slsa_build_config_t* cfg = slsa_build_config_create(platform, builder);
    if (!cfg) return NULL;
    cfg->hermetic = hermetic;
    cfg->parameterless = parameterless;
    cfg->isolated = (iso != SLSA_BUILD_ISOLATION_NONE);
    cfg->isolation_type = iso;
    cfg->reproducible = reproducible;
    cfg->build_command = strdup("make build");
    char invocation[128];
    snprintf(invocation, sizeof(invocation), "inv-%lu-%p",
             (unsigned long)time(NULL), (void*)cfg);
    cfg->build_invocation_id = strdup(invocation);
    slsa_build_config_add_input(cfg, "git+https://github.com/example/repo.git");
    slsa_build_config_add_input(cfg, "https://packages.example.com/deps.tar.gz");
    slsa_build_config_add_output(cfg, "oci://registry.example.com/myapp:v1.0.0");
    return cfg;
}

static void print_build_summary(const char* label, const slsa_build_config_t* cfg) {
    if (!cfg) { printf("  %-12s: NULL\n", label); return; }
    slsa_level_t level = slsa_assess_build_level(cfg);
    printf("  %-12s: %s on %s -> %s\n", label, cfg->builder_id,
           cfg->build_platform, slsa_level_to_string(level));
    printf("    Hermetic=%s ParamLess=%s Isolated=%s(%d) Reprod=%s\n",
           cfg->hermetic ? "Y" : "N",
           cfg->parameterless ? "Y" : "N",
           cfg->isolated ? "Y" : "N",
           (int)cfg->isolation_type,
           cfg->reproducible ? "Y" : "N");
    printf("    Inputs=%zu Outputs=%zu Invocation=%s\n",
           cfg->input_count, cfg->output_count,
           cfg->build_invocation_id ? cfg->build_invocation_id : "N/A");
}

static void build_provenance_demo(void) {
    printf("\n=== SLSA Provenance Creation and Verification ===\n");
    slsa_source_t* src = create_source("dev1", "https://github.com/org/app",
        "abc123def", true, true, true);
    slsa_build_config_t* cfg = create_build("github-actions",
        "https://github.com/slsa-framework/github-actions-generator",
        true, true, SLSA_BUILD_ISOLATION_CONTAINER, true);

    slsa_provenance_t* prov = slsa_provenance_create(
        "myapp-v1.0.0", "sha256:deadbeefcafebabe",
        "https://slsa.dev/provenance/v1");
    slsa_provenance_attach_source(prov, src);
    slsa_provenance_attach_build(prov, cfg);
    slsa_provenance_add_material(prov, "git+https://github.com/org/app@abc123def");
    slsa_provenance_add_material(prov, "https://releases.ubuntu.com/24.04/base-image.tar.gz");
    slsa_provenance_add_material(prov, "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz");
    slsa_provenance_sign(prov, "-----BEGIN PRIVATE KEY-----\ndemo-key\n-----END PRIVATE KEY-----");

    char* intoto_json = NULL;
    slsa_provenance_export_intoto(prov, &intoto_json);
    printf("  In-toto statement:\n%s", intoto_json ? intoto_json : "ERROR");
    free(intoto_json);

    const char* trusted_builders[] = {
        "https://github.com/slsa-framework/github-actions-generator",
        "https://cloudbuild.googleapis.com/GoogleHostedWorker",
        "https://tekton.dev/TektonPipelineRun"
    };
    slsa_verification_result_t* result = slsa_verify_provenance(
        prov, trusted_builders, 3, "-----BEGIN PUBLIC KEY-----\ndemo-key\n-----END PUBLIC KEY-----");
    printf("\n  Verification:\n");
    printf("    Verified: %s\n", result->verified ? "YES" : "NO");
    printf("    Signature valid: %s\n", result->signature_valid ? "YES" : "NO");
    printf("    Builder trusted: %s\n", result->builder_trusted ? "YES" : "NO");
    printf("    Source integrity: %s\n", result->source_integrity_ok ? "YES" : "NO");
    printf("    Build compliant: %s\n", result->build_config_compliant ? "YES" : "NO");
    printf("    Claimed level: %s\n", slsa_level_to_string(result->claimed_level));
    printf("    Assessed level: %s\n", slsa_level_to_string(result->assessed_level));
    slsa_verification_result_free(result);

    slsa_provenance_free(prov);
    slsa_source_free(src);
    slsa_build_config_free(cfg);
}

static void declarative_pipeline_demo(void) {
    printf("\n=== Declarative Build Pipeline (Build as Code) ===\n");
    pipeline_t* pipe = pipeline_create("secure-build", "2.0.1");
    pipe->require_isolation = true;
    pipe->required_level = SLSA_LEVEL_4;
    pipe->default_image = strdup("gcr.io/distroless/cc:latest");

    pipeline_add_step(pipe, "checkout", "alpine/git:latest",
                      "git clone --depth 1 $REPO_URL /workspace", true);
    pipeline_add_step(pipe, "verify-signatures", "cosign:latest",
                      "cosign verify --key /keys/source.pub $COMMIT_SHA", true);
    pipeline_add_step(pipe, "resolve-deps", "ubuntu:24.04",
                      "apt-get update && apt-get install -y build-essential", true);
    pipeline_add_step(pipe, "compile", "gcc:13",
                      "gcc -std=c99 -O2 -Wall -Werror -o /out/app /workspace/*.c", true);
    pipeline_add_step(pipe, "test", "ubuntu:24.04",
                      "/out/test-runner --junit=/out/results.xml", true);
    pipeline_add_step(pipe, "sbom-generate", "cyclonedx:latest",
                      "cyclonedx-bom -o /out/sbom.json /out/app", true);
    pipeline_add_step(pipe, "sign-attest", "cosign:latest",
                      "cosign attest --key /keys/build.key --predicate /out/slsa.json $IMAGE", true);
    pipeline_add_step(pipe, "publish", "docker:latest",
                      "docker push $IMAGE", true);

    pipeline_step_add_argument(pipe->steps[0], "--depth");
    pipeline_step_add_argument(pipe->steps[0], "1");
    pipeline_step_add_environment(pipe->steps[0], "GIT_SSH_COMMAND",
                                  "ssh -i /secrets/deploy_key");
    pipeline_step_add_environment(pipe->steps[3], "CFLAGS", "-O2 -march=native");
    pipeline_step_add_environment(pipe->steps[3], "LDFLAGS", "-static -s");
    pipeline_step_add_input(pipe->steps[0], "git+https://github.com/org/repo.git");
    pipeline_step_add_output(pipe->steps[0], "/workspace/*");
    pipeline_step_add_input(pipe->steps[1], "/workspace/*");
    pipeline_step_add_output(pipe->steps[1], "/workspace/*");
    pipeline_step_add_input(pipe->steps[3], "/workspace/*.c");
    pipeline_step_add_output(pipe->steps[3], "/out/app");
    pipeline_step_add_input(pipe->steps[4], "/out/app");
    pipeline_step_add_output(pipe->steps[4], "/out/results.xml");
    pipeline_step_add_input(pipe->steps[5], "/out/app");
    pipeline_step_add_output(pipe->steps[5], "/out/sbom.json");
    pipeline_step_add_output(pipe->steps[7], "oci://registry.example.com/myapp:v1.0.0");

    printf("  Pipeline: %s v%s\n", pipe->pipeline_name, pipe->pipeline_version);
    printf("  Steps: %zu\n", pipe->step_count);
    for (size_t i = 0; i < pipe->step_count; i++) {
        pipeline_step_t* s = pipe->steps[i];
        printf("    [%zu] %-20s image=%-25s isolated=%s\n",
               i, s->step_name, s->container_image,
               s->isolated ? "YES" : "NO");
    }

    printf("\n  SLSA Level validation:\n");
    slsa_level_t levels[] = {SLSA_LEVEL_1, SLSA_LEVEL_2,
                              SLSA_LEVEL_3, SLSA_LEVEL_4};
    for (int i = 0; i < 4; i++) {
        bool valid = pipeline_validate_slsa(pipe, levels[i]);
        printf("    %s -> %s\n",
               slsa_level_to_string(levels[i]),
               valid ? "COMPLIANT" : "NON-COMPLIANT");
    }

    char* declarative = pipeline_export_declarative(pipe);
    printf("\n  %s", declarative);
    free(declarative);

    pipeline_free(pipe);
}

static void level_comparison_demo(void) {
    printf("\n=== SLSA Level Comparison Matrix ===\n");
    printf("\n  %-6s | %-12s | %-12s | %-12s | %s\n",
           "Level", "Source", "Build", "Overall", "Requirements");
    printf("  %s\n",
           "--------+--------------+--------------+--------------+----------------------------");

    struct {
        slsa_level_t target;
        const char* desc;
    } examples[] = {
        {SLSA_LEVEL_0, "No guarantees - ad-hoc build from any source"},
        {SLSA_LEVEL_1, "Build is scripted/automated, source version controlled"},
        {SLSA_LEVEL_2, "Build service with signed provenance, source tracked"},
        {SLSA_LEVEL_3, "Hardened build: isolated, hermetic, auditable platform"},
        {SLSA_LEVEL_4, "Two-person review + hermetic + reproducible + parameterless"},
    };

    for (int i = 0; i < 5; i++) {
        slsa_source_t* src = slsa_source_create(
            "https://github.com/example/app", "commit-sha-12345");
        src->signed_commit = (examples[i].target >= SLSA_LEVEL_2);
        src->two_person_review = (examples[i].target >= SLSA_LEVEL_4);
        src->protected_branch = (examples[i].target >= SLSA_LEVEL_3);

        slsa_build_config_t* cfg = slsa_build_config_create(
            "github-actions", "builder-id-xyz");
        cfg->hermetic = (examples[i].target >= SLSA_LEVEL_2);
        cfg->parameterless = (examples[i].target >= SLSA_LEVEL_4);
        cfg->isolated = (examples[i].target >= SLSA_LEVEL_3);
        cfg->isolation_type = (examples[i].target >= SLSA_LEVEL_3) ?
            SLSA_BUILD_ISOLATION_CONTAINER : SLSA_BUILD_ISOLATION_NONE;
        cfg->reproducible = (examples[i].target >= SLSA_LEVEL_4);

        slsa_level_t src_lvl = slsa_assess_source_level(src);
        slsa_level_t build_lvl = slsa_assess_build_level(cfg);
        slsa_level_t overall = slsa_determine_overall_level(src_lvl, build_lvl);

        printf("  %-6s | %-12s | %-12s | %-12s | %s\n",
               slsa_level_to_string(examples[i].target),
               slsa_level_to_string(src_lvl),
               slsa_level_to_string(build_lvl),
               slsa_level_to_string(overall),
               examples[i].desc);

        slsa_source_free(src);
        slsa_build_config_free(cfg);
    }
}

static void source_verification_demo(void) {
    printf("\n=== Source Integrity Verification ===\n");
    const char* test_commits[] = {
        "unsigned-commit-abc123",
        "signed-commit-def456",
        "signed-reviewed-ghi789",
    };
    const char* labels[] = {
        "Unsigned commit",
        "Signed commit",
        "Signed + reviewed commit"
    };
    for (int i = 0; i < 3; i++) {
        slsa_source_t* src = slsa_source_create(
            "https://github.com/example/repo", test_commits[i]);
        if (i >= 1) {
            slsa_source_set_signed(src, "developer@example.com",
                "SHA256:valid-key-fingerprint-placeholder");
        }
        if (i >= 2) {
            src->two_person_review = true;
            src->protected_branch = true;
            src->code_review_url = strdup("https://github.com/example/repo/pull/42");
        }
        slsa_level_t level = slsa_assess_source_level(src);
        bool sig_ok = slsa_source_verify_signature(
            src, "SHA256:valid-key-fingerprint-placeholder");
        printf("  %-30s -> %-24s (sig=%s)\n", labels[i],
               slsa_level_to_string(level),
               sig_ok ? "VERIFIED" : "FAILED");
        slsa_source_free(src);
    }
}

static void build_config_validation_demo(void) {
    printf("\n=== Build Configuration Validation ===\n");
    struct {
        const char* label;
        bool hermetic;
        bool paramless;
        slsa_build_isolation_t iso;
        bool repro;
    } configs[] = {
        {"Unsafe build",        false, false, SLSA_BUILD_ISOLATION_NONE,       false},
        {"Basic CI",            true,  false, SLSA_BUILD_ISOLATION_NONE,       false},
        {"Containerized",       true,  false, SLSA_BUILD_ISOLATION_CONTAINER,  false},
        {"VM-isolated",         true,  true,  SLSA_BUILD_ISOLATION_VM,         false},
        {"SLSA 4 compliant",    true,  true,  SLSA_BUILD_ISOLATION_SANDBOX,    true},
    };

    for (int i = 0; i < 5; i++) {
        slsa_build_config_t* cfg = slsa_build_config_create(
            "custom-platform", "custom-builder");
        cfg->hermetic = configs[i].hermetic;
        cfg->parameterless = configs[i].paramless;
        cfg->isolated = (configs[i].iso != SLSA_BUILD_ISOLATION_NONE);
        cfg->isolation_type = configs[i].iso;
        cfg->reproducible = configs[i].repro;
        slsa_level_t level = slsa_assess_build_level(cfg);
        printf("  %-20s -> %s (herm=%s param=%s iso=%s repro=%s)\n",
               configs[i].label, slsa_level_to_string(level),
               cfg->hermetic ? "Y" : "N", cfg->parameterless ? "Y" : "N",
               cfg->isolated ? "Y" : "N", cfg->reproducible ? "Y" : "N");
        slsa_build_config_free(cfg);
    }
}

static void import_export_demo(void) {
    printf("\n=== SLSA Provenance Import/Export ===\n");
    const char* sample_json =
        "{\"_type\":\"https://in-toto.io/Statement/v1\","
        "\"subject\":[{\"name\":\"test\",\"digest\":{\"sha256\":\"abc\"}}],"
        "\"predicateType\":\"https://slsa.dev/provenance/v1\"}";
    slsa_provenance_t* imported = slsa_provenance_import_intoto(sample_json);
    printf("  Imported provenance: %s\n", imported ? "OK" : "FAILED");
    if (imported) {
        printf("  Subject: %s\n", imported->subject_name);
        printf("  Digest: %s\n", imported->subject_digest_sha256);
        printf("  Predicate: %s\n", imported->predicate_type);
        slsa_provenance_free(imported);
    }

    slsa_provenance_t* export_prov = slsa_provenance_create(
        "export-test", "sha256:export123",
        "https://slsa.dev/provenance/v1");
    char* export_json = NULL;
    slsa_provenance_export_intoto(export_prov, &export_json);
    printf("  Exported: %s\n", export_json ? "OK" : "FAILED");
    free(export_json);
    slsa_provenance_free(export_prov);
}

int main(void) {
    printf("============================================\n");
    printf("  SLSA Framework - Supply Chain Levels Demo\n");
    printf("============================================\n");

    printf("\n--- SLSA Level String Conversion ---\n");
    for (slsa_level_t l = SLSA_LEVEL_0; l <= SLSA_LEVEL_4; l++) {
        const char* s = slsa_level_to_string(l);
        slsa_level_t back = slsa_level_from_string(s);
        printf("  %d -> \"%s\" -> %d %s\n", (int)l, s, (int)back,
               l == back ? "OK" : "MISMATCH");
    }
    printf("  \"SLSA_LEVEL_UNKNOWN\" -> %d\n",
           (int)slsa_level_from_string("SLSA_LEVEL_UNKNOWN"));

    printf("\n--- Source Assessment ---\n");
    slsa_source_t* src_l0 = create_source("dev", "https://example.com/repo",
        "abc", false, false, false);
    slsa_source_t* src_l2 = create_source("dev2", "https://example.com/repo2",
        "def", true, false, false);
    slsa_source_t* src_l3 = create_source("dev3", "https://example.com/repo3",
        "ghi", true, true, true);
    print_source_summary("L0 source", src_l0);
    print_source_summary("L2 source", src_l2);
    print_source_summary("L3 source", src_l3);
    slsa_source_free(src_l0);
    slsa_source_free(src_l2);
    slsa_source_free(src_l3);

    printf("\n--- Build Assessment ---\n");
    slsa_build_config_t* bld_l0 = create_build("local", "none",
        false, false, SLSA_BUILD_ISOLATION_NONE, false);
    slsa_build_config_t* bld_l2 = create_build("jenkins", "jenkins-worker",
        true, false, SLSA_BUILD_ISOLATION_NONE, false);
    slsa_build_config_t* bld_l3 = create_build("github-actions", "gha-runner",
        true, false, SLSA_BUILD_ISOLATION_CONTAINER, false);
    slsa_build_config_t* bld_l4 = create_build("cloud-build", "google-worker",
        true, true, SLSA_BUILD_ISOLATION_VM, true);
    print_build_summary("L0 build", bld_l0);
    print_build_summary("L2 build", bld_l2);
    print_build_summary("L3 build", bld_l3);
    print_build_summary("L4 build", bld_l4);
    slsa_build_config_free(bld_l0);
    slsa_build_config_free(bld_l2);
    slsa_build_config_free(bld_l3);
    slsa_build_config_free(bld_l4);

    build_provenance_demo();
    declarative_pipeline_demo();
    level_comparison_demo();
    source_verification_demo();
    build_config_validation_demo();
    import_export_demo();

    printf("\n=== SLSA Framework Demo Complete ===\n");
    return 0;
}
