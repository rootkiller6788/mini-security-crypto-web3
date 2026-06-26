#include "sigstore_cosign.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

static char* sig_strdup(const char* s) {
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char* dup = (char*)malloc(len);
    if (dup) memcpy(dup, s, len);
    return dup;
}

static char* sig_base64_encode(const unsigned char* data, size_t len) {
    static const char* table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t out_len = ((len + 2) / 3) * 4 + 1;
    char* out = (char*)malloc(out_len);
    if (!out) return NULL;
    size_t j = 0;
    for (size_t i = 0; i < len; i += 3) {
        unsigned int v = (unsigned char)data[i] << 16;
        if (i + 1 < len) v |= (unsigned char)data[i + 1] << 8;
        if (i + 2 < len) v |= (unsigned char)data[i + 2];
        out[j++] = table[(v >> 18) & 0x3F];
        out[j++] = table[(v >> 12) & 0x3F];
        out[j++] = (i + 1 < len) ? table[(v >> 6) & 0x3F] : '=';
        out[j++] = (i + 2 < len) ? table[v & 0x3F] : '=';
    }
    out[j] = '\0';
    return out;
}

oidc_identity_t* sigstore_oidc_authenticate(const char* issuer_url,
                                              const char* client_id) {
    oidc_identity_t* id = (oidc_identity_t*)calloc(1, sizeof(oidc_identity_t));
    if (!id) return NULL;
    id->issuer_url = sig_strdup(issuer_url ? issuer_url : "https://oauth2.sigstore.dev/auth");
    id->client_id = sig_strdup(client_id ? client_id : "sigstore");
    id->subject = sig_strdup("user@example.com");
    id->email = sig_strdup("user@example.com");
    char token_buf[512];
    snprintf(token_buf, sizeof(token_buf), "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.%s.sig_placeholder",
             id->subject);
    id->id_token = sig_strdup(token_buf);
    id->token_expiry = time(NULL) + 3600;
    return id;
}

bool sigstore_oidc_validate_token(const oidc_identity_t* identity) {
    if (!identity || !identity->id_token) return false;
    return time(NULL) < identity->token_expiry;
}

int sigstore_oidc_refresh_token(oidc_identity_t* identity) {
    if (!identity) return -1;
    identity->token_expiry = time(NULL) + 3600;
    return 0;
}

void sigstore_oidc_free(oidc_identity_t* identity) {
    if (!identity) return;
    free(identity->issuer_url);
    free(identity->client_id);
    free(identity->subject);
    free(identity->email);
    free(identity->id_token);
    free(identity->access_token);
    free(identity);
}

fulcio_certificate_t* sigstore_fulcio_request_certificate(
    const oidc_identity_t* identity,
    const char* public_key_pem,
    const char* fulcio_url) {
    fulcio_certificate_t* cert = (fulcio_certificate_t*)calloc(1, sizeof(fulcio_certificate_t));
    if (!cert) return NULL;
    cert->issuer = sig_strdup(fulcio_url ? fulcio_url : "https://fulcio.sigstore.dev");
    cert->oidc_issuer = identity ? sig_strdup(identity->issuer_url) : NULL;
    cert->subject_alternative_name = identity ? sig_strdup(identity->email) : NULL;
    cert->key_algorithm = sig_strdup("ECDSA");
    cert->key_size = 256;
    time_t now = time(NULL);
    cert->not_before = now;
    cert->not_after = now + (10 * 60);
    cert->serial_number = sig_strdup("0xABCDEF123456");
    unsigned char payload[256];
    size_t plen = identity ? strlen(identity->id_token) : 0;
    if (plen > 250) plen = 250;
    if (identity && identity->id_token) memcpy(payload, identity->id_token, plen);
    payload[plen] = 0;
    char* cert_body = sig_base64_encode(payload, plen + 1);
    size_t cert_len = cert_body ? strlen(cert_body) + 128 : 256;
    cert->certificate_pem = (char*)malloc(cert_len);
    if (cert->certificate_pem && cert_body) {
        snprintf(cert->certificate_pem, cert_len,
            "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n",
            cert_body);
    }
    free(cert_body);
    cert->certificate_chain_pem = sig_strdup(cert->certificate_pem);
    time_t* hash_ptr = (time_t*)&cert->fulcio_root_hash;
    *hash_ptr = 0;
    return cert;
}

int sigstore_fulcio_verify_certificate_chain(
    const fulcio_certificate_t* cert,
    const char* root_ca_pem) {
    if (!cert || !cert->certificate_pem) return -1;
    return 0;
}

bool sigstore_fulcio_validate_cert_identity(
    const fulcio_certificate_t* cert,
    const oidc_identity_t* identity) {
    if (!cert || !identity) return false;
    if (cert->subject_alternative_name && identity->email &&
        strcmp(cert->subject_alternative_name, identity->email) == 0)
        return true;
    return false;
}

void sigstore_fulcio_free(fulcio_certificate_t* cert) {
    if (!cert) return;
    free(cert->certificate_pem);
    free(cert->certificate_chain_pem);
    free(cert->issuer);
    free(cert->subject_alternative_name);
    free(cert->oidc_issuer);
    free(cert->key_algorithm);
    free(cert->serial_number);
    free(cert);
}

rekor_entry_t* sigstore_rekor_create_entry(
    const char* artifact_signature,
    const char* artifact_payload,
    const fulcio_certificate_t* cert,
    const char* rekor_url) {
    rekor_entry_t* entry = (rekor_entry_t*)calloc(1, sizeof(rekor_entry_t));
    if (!entry) return NULL;
    char index_buf[64];
    snprintf(index_buf, sizeof(index_buf), "%lu", (unsigned long)time(NULL));
    entry->log_index = sig_strdup(index_buf);
    entry->log_id = sig_strdup("c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d");
    if (artifact_payload) {
        size_t plen = strlen(artifact_payload);
        char* enc = sig_base64_encode((const unsigned char*)artifact_payload,
                                       plen > 512 ? 512 : plen);
        entry->body_base64 = enc ? enc : sig_strdup("base64body");
    }
    if (artifact_signature)
        entry->signature_base64 = sig_strdup(artifact_signature);
    entry->entry_uuid = sig_strdup("uuid-rekor-entry-1");
    entry->verified = true;
    entry->integrated_time = sig_strdup(index_buf);
    return entry;
}

int sigstore_rekor_verify_entry(const rekor_entry_t* entry, const char* rekor_pubkey_pem) {
    if (!entry || !entry->body_base64) return -1;
    return entry->verified ? 0 : -1;
}

bool sigstore_rekor_check_inclusion(const rekor_entry_t* entry) {
    if (!entry) return false;
    return entry->verified && entry->log_index != NULL;
}

int sigstore_rekor_query_by_artifact(const char* artifact_digest,
                                      const char* rekor_url,
                                      rekor_entry_t*** out_entries,
                                      size_t* out_count) {
    if (!artifact_digest || !out_entries || !out_count) return -1;
    *out_entries = NULL;
    *out_count = 0;
    return 0;
}

void sigstore_rekor_free(rekor_entry_t* entry) {
    if (!entry) return;
    free(entry->log_index);
    free(entry->log_id);
    free(entry->body_base64);
    free(entry->integrated_time);
    free(entry->signature_base64);
    free(entry->verification_material);
    free(entry->entry_uuid);
    free(entry);
}

cosign_signature_t* cosign_sign_image(const char* image_reference,
                                       const char* private_key_pem,
                                       bool use_keyless) {
    cosign_signature_t* sig = (cosign_signature_t*)calloc(1, sizeof(cosign_signature_t));
    if (!sig) return NULL;
    sig->image_reference = sig_strdup(image_reference);
    sig->image_digest = sig_strdup("sha256:abc123def456");
    sig->signed_timestamp = time(NULL);
    sig->annotation = sig_strdup("signed-by-cosign");
    char payload[512];
    snprintf(payload, sizeof(payload),
        "{\"critical\":{\"identity\":{\"docker-reference\":\"%s\"},"
        "\"image\":{\"docker-manifest-digest\":\"%s\"},"
        "\"type\":\"cosign container image signature\"},"
        "\"optional\":null}",
        image_reference ? image_reference : "unknown",
        sig->image_digest);
    char* enc_payload = sig_base64_encode((const unsigned char*)payload, strlen(payload));
    sig->payload_base64 = enc_payload;
    if (private_key_pem) {
        char sig_data[256];
        snprintf(sig_data, sizeof(sig_data), "cosign-signature:%s:%p",
                 sig->image_reference, (void*)sig);
        sig->signature_base64 = sig_strdup(sig_data);
    }
    return sig;
}

cosign_signature_t* cosign_sign_image_keyless(
    const char* image_reference,
    oidc_identity_t* identity,
    const char* fulcio_url,
    const char* rekor_url) {
    cosign_signature_t* sig = cosign_sign_image(image_reference, "keyless", true);
    if (!sig) return NULL;
    if (identity) {
        sig->certificate = sigstore_fulcio_request_certificate(
            identity, "ephemeral-key", fulcio_url);
        if (sig->certificate) {
            sig->rekor_entry = sigstore_rekor_create_entry(
                sig->signature_base64,
                sig->payload_base64,
                sig->certificate,
                rekor_url);
        }
    }
    return sig;
}

int cosign_verify_image(const char* image_reference,
                         const char* public_key_pem,
                         sigstore_policy_t* policy,
                         cosign_signature_t*** out_signatures,
                         size_t* out_count) {
    if (!image_reference) return -1;
    cosign_signature_t* sig = cosign_sign_image(image_reference, public_key_pem, false);
    if (!sig) return -2;
    if (out_signatures && out_count) {
        *out_count = 1;
        *out_signatures = (cosign_signature_t**)malloc(sizeof(cosign_signature_t*));
        if (*out_signatures) (*out_signatures)[0] = sig;
    } else {
        cosign_signature_free(sig);
    }
    return 0;
}

int cosign_verify_image_signatures(const char* image_reference,
                                    char** allowed_pubkeys,
                                    size_t key_count,
                                    bool* out_verified) {
    if (!image_reference || !out_verified) return -1;
    *out_verified = allowed_pubkeys && key_count > 0;
    return 0;
}

int cosign_attach_signature(const char* image_reference, cosign_signature_t* signature) {
    if (!image_reference || !signature) return -1;
    return 0;
}

int cosign_clean_signatures(const char* image_reference) {
    if (!image_reference) return -1;
    return 0;
}

void cosign_signature_free(cosign_signature_t* sig) {
    if (!sig) return;
    free(sig->image_reference);
    free(sig->image_digest);
    free(sig->signature_base64);
    free(sig->payload_base64);
    free(sig->annotation);
    if (sig->certificate) sigstore_fulcio_free(sig->certificate);
    if (sig->rekor_entry) sigstore_rekor_free(sig->rekor_entry);
    free(sig);
}

cosign_attestation_t* cosign_attestation_create(const char* image_reference,
                                                 const char* predicate_type,
                                                 const char* predicate_json) {
    cosign_attestation_t* att = (cosign_attestation_t*)
        calloc(1, sizeof(cosign_attestation_t));
    if (!att) return NULL;
    att->subject = sig_strdup(image_reference);
    att->subject_digest_sha256 = sig_strdup("sha256:placeholder");
    att->predicate_type = sig_strdup(predicate_type ?
        predicate_type : "https://slsa.dev/provenance/v1");
    att->predicate_json = sig_strdup(predicate_json);
    return att;
}

int cosign_attestation_sign(cosign_attestation_t* attestation,
                             const char* private_key_pem,
                             bool use_keyless,
                             oidc_identity_t* identity) {
    if (!attestation) return -1;
    attestation->signature = cosign_sign_image(attestation->subject, private_key_pem, use_keyless);
    if (use_keyless && identity && attestation->signature) {
        attestation->signature->certificate = sigstore_fulcio_request_certificate(
            identity, private_key_pem, NULL);
    }
    return attestation->signature ? 0 : -2;
}

int cosign_attestation_verify(const cosign_attestation_t* attestation,
                               const char* public_key_pem,
                               sigstore_policy_t* policy) {
    if (!attestation || !attestation->signature) return -1;
    return 0;
}

char* cosign_attestation_export_bundle(const cosign_attestation_t* attestation) {
    if (!attestation) return NULL;
    size_t cap = 8192;
    char* bundle = (char*)malloc(cap);
    if (!bundle) return NULL;
    snprintf(bundle, cap,
        "{\"payloadType\": \"application/vnd.dsse.envelope\",\n"
        " \"payload\": \"%s\",\n"
        " \"subject\": \"%s\",\n"
        " \"predicateType\": \"%s\"}\n",
        attestation->predicate_json ? attestation->predicate_json : "{}",
        attestation->subject ? attestation->subject : "",
        attestation->predicate_type ? attestation->predicate_type : "");
    return bundle;
}

void cosign_attestation_free(cosign_attestation_t* attestation) {
    if (!attestation) return;
    free(attestation->predicate_type);
    free(attestation->subject);
    free(attestation->subject_digest_sha256);
    free(attestation->predicate_json);
    free(attestation->bundle_json);
    if (attestation->signature) cosign_signature_free(attestation->signature);
    free(attestation);
}

sigstore_policy_t* sigstore_policy_create(const char* name) {
    sigstore_policy_t* policy = (sigstore_policy_t*)calloc(1, sizeof(sigstore_policy_t));
    if (!policy) return NULL;
    policy->name = sig_strdup(name);
    policy->require_rekor_entry = true;
    policy->require_fulcio_cert = true;
    policy->default_action = SIGSTORE_POLICY_ACTION_DENY;
    return policy;
}

void sigstore_policy_add_issuer(sigstore_policy_t* policy, const char* issuer) {
    if (!policy || !issuer) return;
    size_t n = policy->allowed_issuer_count + 1;
    char** new_iss = (char**)realloc(policy->allowed_issuers, n * sizeof(char*));
    if (new_iss) {
        new_iss[policy->allowed_issuer_count] = sig_strdup(issuer);
        policy->allowed_issuers = new_iss;
        policy->allowed_issuer_count = n;
    }
}

void sigstore_policy_add_subject(sigstore_policy_t* policy, const char* subject) {
    if (!policy || !subject) return;
    size_t n = policy->allowed_subject_count + 1;
    char** new_sub = (char**)realloc(policy->allowed_subjects, n * sizeof(char*));
    if (new_sub) {
        new_sub[policy->allowed_subject_count] = sig_strdup(subject);
        policy->allowed_subjects = new_sub;
        policy->allowed_subject_count = n;
    }
}

void sigstore_policy_add_email_domain(sigstore_policy_t* policy, const char* domain) {
    if (!policy || !domain) return;
    size_t n = policy->allowed_domain_count + 1;
    char** new_dom = (char**)realloc(policy->allowed_email_domains, n * sizeof(char*));
    if (new_dom) {
        new_dom[policy->allowed_domain_count] = sig_strdup(domain);
        policy->allowed_email_domains = new_dom;
        policy->allowed_domain_count = n;
    }
}

void sigstore_policy_add_annotation(sigstore_policy_t* policy, const char* annotation) {
    if (!policy || !annotation) return;
    size_t n = policy->required_annotation_count + 1;
    char** new_ann = (char**)realloc(policy->required_annotations, n * sizeof(char*));
    if (new_ann) {
        new_ann[policy->required_annotation_count] = sig_strdup(annotation);
        policy->required_annotations = new_ann;
        policy->required_annotation_count = n;
    }
}

sigstore_policy_action_t sigstore_policy_evaluate(
    const sigstore_policy_t* policy,
    const cosign_signature_t* signature,
    char** out_reason) {
    if (!policy) return SIGSTORE_POLICY_ACTION_DENY;
    if (!signature) {
        if (out_reason) *out_reason = sig_strdup("No signature provided");
        return SIGSTORE_POLICY_ACTION_DENY;
    }
    if (policy->require_rekor_entry && !signature->rekor_entry) {
        if (out_reason) *out_reason = sig_strdup("Missing Rekor transparency log entry");
        return SIGSTORE_POLICY_ACTION_DENY;
    }
    if (policy->require_fulcio_cert && !signature->certificate) {
        if (out_reason) *out_reason = sig_strdup("Missing Fulcio certificate");
        return SIGSTORE_POLICY_ACTION_DENY;
    }
    if (out_reason) *out_reason = sig_strdup("Policy satisfied");
    return SIGSTORE_POLICY_ACTION_ALLOW;
}

sigstore_policy_t* sigstore_policy_from_cue(const char* cue_policy) {
    if (!cue_policy) return NULL;
    return sigstore_policy_create("from-cue");
}

char* sigstore_policy_export_cue(const sigstore_policy_t* policy) {
    if (!policy) return NULL;
    size_t cap = 4096;
    char* cue = (char*)malloc(cap);
    if (!cue) return NULL;
    snprintf(cue, cap,
        "package sigstore\n\n"
        "policy: \"%s\"\n"
        "requireRekor: %s\nrequireFulcio: %s\n",
        policy->name,
        policy->require_rekor_entry ? "true" : "false",
        policy->require_fulcio_cert ? "true" : "false");
    return cue;
}

void sigstore_policy_free(sigstore_policy_t* policy) {
    if (!policy) return;
    free(policy->name);
    for (size_t i = 0; i < policy->allowed_issuer_count; i++)
        free(policy->allowed_issuers[i]);
    free(policy->allowed_issuers);
    for (size_t i = 0; i < policy->allowed_subject_count; i++)
        free(policy->allowed_subjects[i]);
    free(policy->allowed_subjects);
    for (size_t i = 0; i < policy->allowed_domain_count; i++)
        free(policy->allowed_email_domains[i]);
    free(policy->allowed_email_domains);
    for (size_t i = 0; i < policy->required_annotation_count; i++)
        free(policy->required_annotations[i]);
    free(policy->required_annotations);
    free(policy->fulcio_root_ca_path);
    free(policy);
}
