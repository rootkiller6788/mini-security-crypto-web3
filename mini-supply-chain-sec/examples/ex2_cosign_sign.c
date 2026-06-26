#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/sigstore_cosign.h"

static void print_cert_info(const fulcio_certificate_t* cert) {
    if (!cert) { printf("  Certificate: NULL\n"); return; }
    printf("  Certificate:\n");
    printf("    Issuer: %s\n", cert->issuer);
    printf("    SAN: %s\n", cert->subject_alternative_name ?
           cert->subject_alternative_name : "N/A");
    printf("    Algorithm: %s (%d bits)\n",
           cert->key_algorithm ? cert->key_algorithm : "unknown",
           cert->key_size);
    printf("    Serial: %s\n", cert->serial_number ?
           cert->serial_number : "N/A");
}

static void print_rekor_entry(const rekor_entry_t* entry) {
    if (!entry) { printf("  Rekor Entry: NULL\n"); return; }
    printf("  Rekor Entry:\n");
    printf("    Log Index: %s\n", entry->log_index);
    printf("    Log ID: %.32s...\n", entry->log_id ?
           entry->log_id : "N/A");
    printf("    UUID: %s\n", entry->entry_uuid ?
           entry->entry_uuid : "N/A");
    printf("    Verified: %s\n", entry->verified ? "YES" : "NO");
}

static void print_policy(const sigstore_policy_t* policy) {
    if (!policy) { printf("  Policy: NULL\n"); return; }
    printf("  Policy: %s\n", policy->name);
    printf("    Allowed issuers: %zu\n", policy->allowed_issuer_count);
    for (size_t i = 0; i < policy->allowed_issuer_count; i++)
        printf("      - %s\n", policy->allowed_issuers[i]);
    printf("    Allowed subjects: %zu\n", policy->allowed_subject_count);
    for (size_t i = 0; i < policy->allowed_subject_count; i++)
        printf("      - %s\n", policy->allowed_subjects[i]);
    printf("    Allowed domains: %zu\n", policy->allowed_domain_count);
    for (size_t i = 0; i < policy->allowed_domain_count; i++)
        printf("      - %s\n", policy->allowed_email_domains[i]);
    printf("    Require Rekor: %s\n", policy->require_rekor_entry ? "YES" : "NO");
    printf("    Require Fulcio: %s\n", policy->require_fulcio_cert ? "YES" : "NO");
    printf("    Default action: %s\n",
           policy->default_action == SIGSTORE_POLICY_ACTION_ALLOW ? "ALLOW" :
           policy->default_action == SIGSTORE_POLICY_ACTION_DENY ? "DENY" : "WARN");
}

int main(void) {
    printf("=== Sigstore / Cosign Example ===\n\n");

    printf("--- OIDC Authentication ---\n");
    oidc_identity_t* identity = sigstore_oidc_authenticate(
        "https://oauth2.sigstore.dev/auth", "sigstore-client");
    if (!identity) { fprintf(stderr, "OIDC auth failed\n"); return 1; }
    printf("  Issuer: %s\n", identity->issuer_url);
    printf("  Subject: %s\n", identity->subject);
    printf("  Email: %s\n", identity->email);
    printf("  Token valid: %s\n",
           sigstore_oidc_validate_token(identity) ? "YES" : "NO");

    printf("\n--- Fulcio Certificate ---\n");
    fulcio_certificate_t* cert = sigstore_fulcio_request_certificate(
        identity, "fake-public-key-pem", "https://fulcio.sigstore.dev");
    if (!cert) { fprintf(stderr, "Fulcio cert request failed\n");
        sigstore_oidc_free(identity); return 1; }
    print_cert_info(cert);

    bool cert_identity_ok = sigstore_fulcio_validate_cert_identity(cert, identity);
    printf("  Identity match: %s\n", cert_identity_ok ? "YES" : "NO");
    int chain_verify = sigstore_fulcio_verify_certificate_chain(cert,
        "-----BEGIN CERTIFICATE-----\nfake-root-ca\n-----END CERTIFICATE-----");
    printf("  Chain verification: %s\n", chain_verify == 0 ? "OK" : "FAILED");

    printf("\n--- Rekor Transparency Log ---\n");
    rekor_entry_t* rekor = sigstore_rekor_create_entry(
        "base64signaturedata", "artifact-payload-data", cert,
        "https://rekor.sigstore.dev");
    if (!rekor) { fprintf(stderr, "Rekor entry failed\n");
        sigstore_fulcio_free(cert); sigstore_oidc_free(identity); return 1; }
    print_rekor_entry(rekor);
    printf("  Inclusion verified: %s\n",
           sigstore_rekor_check_inclusion(rekor) ? "YES" : "NO");

    printf("\n--- Cosign: Sign Container Image ---\n");
    cosign_signature_t* sig_keyless = cosign_sign_image_keyless(
        "index.docker.io/myorg/myapp:v1.0.0",
        identity, "https://fulcio.sigstore.dev", "https://rekor.sigstore.dev");
    if (!sig_keyless) { fprintf(stderr, "Keyless sign failed\n");
        sigstore_rekor_free(rekor); sigstore_fulcio_free(cert);
        sigstore_oidc_free(identity); return 1; }
    printf("  Image: %s\n", sig_keyless->image_reference);
    printf("  Digest: %s\n", sig_keyless->image_digest);
    printf("  Has cert: %s\n", sig_keyless->certificate ? "YES" : "NO");
    printf("  Has rekor: %s\n", sig_keyless->rekor_entry ? "YES" : "NO");
    printf("  Signature: %.32s...\n", sig_keyless->signature_base64 ?
           sig_keyless->signature_base64 : "N/A");

    cosign_signature_t* sig_keyed = cosign_sign_image(
        "index.docker.io/myorg/myapp:v1.0.0",
        "-----BEGIN PRIVATE KEY-----\nkeyed-test-key\n-----END PRIVATE KEY-----",
        false);
    printf("\n  Keyed signing image: %s\n",
           sig_keyed ? sig_keyed->image_reference : "FAILED");

    printf("\n--- Cosign: Verify Image ---\n");
    cosign_signature_t** out_sigs = NULL;
    size_t out_count = 0;
    int verify_rc = cosign_verify_image(
        "index.docker.io/myorg/myapp:v1.0.0",
        "-----BEGIN PUBLIC KEY-----\ntest-pubkey\n-----END PUBLIC KEY-----",
        NULL, &out_sigs, &out_count);
    printf("  Verify result: %s\n", verify_rc == 0 ? "OK" : "FAILED");
    printf("  Found %zu signatures\n", out_count);
    if (out_sigs) { cosign_signature_free(out_sigs[0]); free(out_sigs); }

    bool verified = false;
    char* allowed_keys[] = {"pubkey1", "pubkey2"};
    cosign_verify_image_signatures("index.docker.io/myorg/myapp:v1.0.0",
        allowed_keys, 2, &verified);
    printf("  Multi-key verify: %s\n", verified ? "VERIFIED" : "NOT VERIFIED");

    printf("\n--- Sigstore Policy Controller ---\n");
    sigstore_policy_t* policy = sigstore_policy_create("production-policy");
    sigstore_policy_add_issuer(policy, "https://oauth2.sigstore.dev/auth");
    sigstore_policy_add_subject(policy, "user@example.com");
    sigstore_policy_add_subject(policy, "ci-bot@myorg.com");
    sigstore_policy_add_email_domain(policy, "myorg.com");
    sigstore_policy_add_email_domain(policy, "trusted.org");
    sigstore_policy_add_annotation(policy, "environment=production");
    policy->default_action = SIGSTORE_POLICY_ACTION_DENY;
    print_policy(policy);

    char* reason = NULL;
    sigstore_policy_action_t action = sigstore_policy_evaluate(
        policy, sig_keyless, &reason);
    printf("  Evaluation: %s\n",
           action == SIGSTORE_POLICY_ACTION_ALLOW ? "ALLOW" :
           action == SIGSTORE_POLICY_ACTION_DENY ? "DENY" : "WARN");
    printf("  Reason: %s\n", reason ? reason : "N/A");
    free(reason);

    char* cue_policy = sigstore_policy_export_cue(policy);
    printf("\n  CUE Policy:\n%s", cue_policy);
    free(cue_policy);

    sigstore_policy_t* from_cue = sigstore_policy_from_cue("dummy-cue");
    printf("  From CUE: %s\n", from_cue ? from_cue->name : "FAILED");
    sigstore_policy_free(from_cue);

    printf("\n--- Cosign In-Toto Attestation ---\n");
    cosign_attestation_t* att = cosign_attestation_create(
        "index.docker.io/myorg/myapp@sha256:abc123",
        "https://slsa.dev/provenance/v1",
        "{\"builder\":{\"id\":\"github-actions\"}}");
    printf("  Subject: %s\n", att->subject);
    printf("  Predicate type: %s\n", att->predicate_type);

    int att_sign_rc = cosign_attestation_sign(att,
        "-----BEGIN PRIVATE KEY-----\ntest-key\n-----END PRIVATE KEY-----",
        true, identity);
    printf("  Attestation sign: %s\n", att_sign_rc == 0 ? "OK" : "FAILED");

    int att_verify_rc = cosign_attestation_verify(att,
        "-----BEGIN PUBLIC KEY-----\ntest-pub\n-----END PUBLIC KEY-----",
        policy);
    printf("  Attestation verify: %s\n", att_verify_rc == 0 ? "OK" : "FAILED");

    char* bundle = cosign_attestation_export_bundle(att);
    printf("  Bundle: %s\n", bundle);
    free(bundle);

    cosign_attestation_free(att);
    cosign_signature_free(sig_keyed);
    cosign_signature_free(sig_keyless);
    sigstore_policy_free(policy);
    sigstore_rekor_free(rekor);
    sigstore_fulcio_free(cert);
    sigstore_oidc_free(identity);

    printf("\n=== All Sigstore/Cosign examples completed successfully ===\n");
    return 0;
}
