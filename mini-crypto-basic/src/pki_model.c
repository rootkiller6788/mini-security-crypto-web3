#include "pki_model.h"
#include "hash_func.h"
#include "asymmetric_cipher.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* ─── CSR ───────────────────────────────────────────────────── */

void csr_init(CsrRequest *csr, const char *cn, const char *org, const char *country) {
    memset(csr, 0, sizeof(CsrRequest));
    strncpy(csr->common_name, cn, CSR_MAX_CN_LEN - 1);
    strncpy(csr->organization, org, 127);
    strncpy(csr->country, country, 3);
}

void csr_set_rsa_key(CsrRequest *csr, const uint8_t *pub_key, size_t pub_key_len) {
    csr->public_key_type = 0;
    csr->public_key_len = pub_key_len < sizeof(csr->public_key) ? pub_key_len : sizeof(csr->public_key);
    memcpy(csr->public_key, pub_key, csr->public_key_len);
}

void csr_set_ec_key(CsrRequest *csr, const uint8_t *pub_key, size_t pub_key_len) {
    csr->public_key_type = 1;
    csr->public_key_len = pub_key_len < sizeof(csr->public_key) ? pub_key_len : sizeof(csr->public_key);
    memcpy(csr->public_key, pub_key, csr->public_key_len);
}

bool csr_sign(CsrRequest *csr, const void *priv_key, size_t key_bits) {
    uint8_t hash[32];
    sha256_hash((const uint8_t *)csr, sizeof(CsrRequest) - sizeof(csr->der_encoded), hash);
    memcpy(csr->der_encoded, hash, 32);
    csr->der_len = 32;
    return true;
}

bool csr_verify(const CsrRequest *csr) {
    return csr->der_len >= 32;
}

/* ─── Certificate Issuance ──────────────────────────────────── */

bool ca_issue_certificate(const CaConfig *ca,
                          const CsrRequest *csr,
                          X509Certificate *cert,
                          uint64_t valid_days) {
    if (!ca || !csr || !cert) return false;
    memset(cert, 0, sizeof(X509Certificate));
    cert->version = 2;
    cert->sig_algo = SIG_RSA_PSS;
    cert->serial[0] = (uint8_t)(rand() % 256);
    cert->serial[1] = (uint8_t)(rand() % 256);
    cert->serial_len = 2;
    strncpy(cert->issuer.common_name, ca->name, X509_MAX_CN_LEN - 1);
    strncpy(cert->issuer.organization, "CA Organization", X509_MAX_O_LEN - 1);
    strncpy(cert->issuer.country, "US", 3);
    strncpy(cert->subject.common_name, csr->common_name, X509_MAX_CN_LEN - 1);
    strncpy(cert->subject.organization, csr->organization, X509_MAX_O_LEN - 1);
    strncpy(cert->subject.country, csr->country, 3);
    cert->not_before = (uint64_t)time(NULL);
    cert->not_after = cert->not_before + valid_days * 86400ULL;
    cert->key_usage = X509_KU_DIGITAL_SIGNATURE | X509_KU_KEY_ENCIPHERMENT;
    cert->ext_key_usage = X509_EKU_SERVER_AUTH;
    cert->basic_constraints.is_ca = false;
    cert->basic_constraints.path_len_constraint = -1;
    cert->pub_key_type = csr->public_key_type;
    cert->pub_key_len = csr->public_key_len < sizeof(cert->pub_key_data)
                        ? csr->public_key_len : sizeof(cert->pub_key_data);
    memcpy(cert->pub_key_data, csr->public_key, cert->pub_key_len);
    uint8_t tbs_hash[32];
    sha256_hash((const uint8_t *)&cert->subject, sizeof(X509Name) + sizeof(uint64_t) * 2, tbs_hash);
    memcpy(cert->signature, tbs_hash, 32);
    cert->sig_len = 32;
    return true;
}

bool ca_self_sign_root(CaConfig *ca, X509Certificate *cert) {
    if (!ca || !cert) return false;
    memset(cert, 0, sizeof(X509Certificate));
    cert->version = 2;
    cert->serial[0] = 0x01;
    cert->serial_len = 1;
    strncpy(cert->issuer.common_name, ca->name, X509_MAX_CN_LEN - 1);
    strncpy(cert->issuer.organization, "Root CA Org", X509_MAX_O_LEN - 1);
    strncpy(cert->issuer.country, "US", 3);
    strncpy(cert->subject.common_name, ca->name, X509_MAX_CN_LEN - 1);
    strncpy(cert->subject.organization, "Root CA Org", X509_MAX_O_LEN - 1);
    strncpy(cert->subject.country, "US", 3);
    cert->not_before = (uint64_t)time(NULL);
    cert->not_after = cert->not_before + (3650ULL * 86400ULL);
    cert->key_usage = X509_KU_CERT_SIGN | X509_KU_CRL_SIGN;
    cert->basic_constraints.is_ca = true;
    cert->basic_constraints.path_len_constraint = 0;
    ca->is_root = true;
    uint8_t tbs_hash[32];
    sha256_hash((const uint8_t *)&cert->subject, sizeof(X509Name) + sizeof(uint64_t) * 2, tbs_hash);
    memcpy(cert->signature, tbs_hash, 32);
    cert->sig_len = 32;
    return true;
}

/* ─── Trust Store ───────────────────────────────────────────── */

void trust_store_init(TrustStore *store) {
    memset(store, 0, sizeof(TrustStore));
}

bool trust_store_add(TrustStore *store, const X509Certificate *cert) {
    if (store->count >= TRUST_STORE_MAX_CERTS) return false;
    store->certs[store->count++] = *cert;
    return true;
}

bool trust_store_remove(TrustStore *store, const uint8_t *serial, size_t serial_len) {
    size_t i;
    for (i = 0; i < store->count; i++) {
        X509Certificate *c = &store->certs[i];
        if (c->serial_len == serial_len && memcmp(c->serial, serial, serial_len) == 0) {
            if (i < store->count - 1)
                memmove(&store->certs[i], &store->certs[i + 1],
                        (store->count - i - 1) * sizeof(X509Certificate));
            store->count--;
            return true;
        }
    }
    return false;
}

const X509Certificate *trust_store_find_by_subject(const TrustStore *store, const char *cn) {
    size_t i;
    for (i = 0; i < store->count; i++) {
        if (strcmp(store->certs[i].subject.common_name, cn) == 0)
            return &store->certs[i];
    }
    return NULL;
}

bool trust_store_verify_chain(const TrustStore *store,
                              const X509Certificate *cert,
                              const CertificateRevocationList *crl,
                              uint64_t verify_time) {
    uint64_t now = (uint64_t)time(NULL);
    uint64_t vt = verify_time > 0 ? verify_time : now;
    if (!x509_is_valid_at_time(cert, vt)) return false;
    if (crl && crl_is_revoked(crl, cert->serial, cert->serial_len)) return false;
    const X509Certificate *issuer = trust_store_find_by_subject(store, cert->issuer.common_name);
    if (!issuer) return false;
    if (!x509_is_valid_at_time(issuer, vt)) return false;
    return x509_verify_signature(cert, issuer);
}

/* ─── ACME Simulation ───────────────────────────────────────── */

void acme_account_create(AcmeAccount *acc, const char *contact) {
    memset(acc, 0, sizeof(AcmeAccount));
    strncpy(acc->contact, contact, 127);
    snprintf(acc->account_id, sizeof(acc->account_id), "acct-%08x", (unsigned int)rand());
    int i;
    for (i = 0; i < 32; i++) acc->private_key[i] = (uint8_t)(rand() % 251 + 1);
    acc->private_key_len = 32;
    acc->key_type = 1;
    acc->accepted_tos = true;
}

bool acme_new_order(AcmeOrder *order, const char *domain) {
    memset(order, 0, sizeof(AcmeOrder));
    snprintf(order->order_id, sizeof(order->order_id), "order-%08x", (unsigned int)rand());
    strncpy(order->domain, domain, 255);
    strncpy(order->status, "pending", 31);
    order->challenges[0].type = ACME_CHALLENGE_HTTP01;
    snprintf(order->challenges[0].token, sizeof(order->challenges[0].token),
             "tok-%04x-%04x", (unsigned int)rand(), (unsigned int)rand());
    snprintf(order->challenges[0].url, sizeof(order->challenges[0].url),
             "http://%s/.well-known/acme-challenge/%s", domain, order->challenges[0].token);
    order->challenges[1].type = ACME_CHALLENGE_DNS01;
    snprintf(order->challenges[1].token, sizeof(order->challenges[1].token),
             "dns-%04x-%04x", (unsigned int)rand(), (unsigned int)rand());
    snprintf(order->challenges[1].url, sizeof(order->challenges[1].url),
             "_acme-challenge.%s", domain);
    order->challenge_count = 2;
    return true;
}

bool acme_submit_challenge_response(AcmeOrder *order, size_t chall_idx,
                                     const char *response) {
    if (chall_idx >= order->challenge_count) return false;
    strncpy(order->challenges[chall_idx].key_auth, response, 255);
    order->challenges[chall_idx].validated = true;
    bool all_valid = true;
    size_t i;
    for (i = 0; i < order->challenge_count; i++) {
        if (!order->challenges[i].validated) { all_valid = false; break; }
    }
    if (all_valid) strncpy(order->status, "ready", 31);
    return true;
}

bool acme_finalize_order(AcmeOrder *order, const CsrRequest *csr) {
    if (strcmp(order->status, "ready") != 0) return false;
    if (csr) order->csr = *csr;
    strncpy(order->status, "valid", 31);
    uint8_t der[4096];
    memset(der, 0, sizeof(der));
    memcpy(der, "SIMULATED-CERT", 14);
    int i;
    for (i = 0; i < 32; i++) der[14 + i] = (uint8_t)(rand() % 256);
    order->cert_len = 46;
    memcpy(order->certificate_der, der, order->cert_len);
    return true;
}

bool acme_download_certificate(AcmeOrder *order, uint8_t *der, size_t *der_len) {
    if (strcmp(order->status, "valid") != 0) return false;
    if (order->cert_len == 0) return false;
    *der_len = order->cert_len;
    memcpy(der, order->certificate_der, order->cert_len);
    return true;
}

void acme_renew_certificate(AcmeOrder *order, uint8_t *der, size_t *der_len) {
    order->cert_len = 46;
    int i;
    for (i = 0; i < 32; i++) order->certificate_der[14 + i] = (uint8_t)(rand() % 256);
    *der_len = order->cert_len;
    memcpy(der, order->certificate_der, order->cert_len);
    strncpy(order->status, "valid", 31);
}

/* ─── OCSP Stapling ─────────────────────────────────────────── */

bool ocsp_request_build(const uint8_t *serial, size_t serial_len,
                        uint8_t *der, size_t *der_len) {
    size_t pos = 0;
    der[pos++] = 0x30;
    der[pos++] = (uint8_t)(serial_len + 8);
    der[pos++] = 0x30;
    der[pos++] = 0x06;
    der[pos++] = 0x02;
    der[pos++] = (uint8_t)serial_len;
    memcpy(der + pos, serial, serial_len);
    pos += serial_len;
    *der_len = pos;
    return true;
}

bool ocsp_response_parse(const uint8_t *der, size_t der_len, OcspResponse *resp) {
    if (!der || der_len < 4) return false;
    memset(resp, 0, sizeof(OcspResponse));
    sha256_hash(der, der_len, resp->responder_id_hash);
    resp->produced_at = (uint64_t)time(NULL) - 60;
    resp->responses[0].cert_status = OCSP_STATUS_GOOD;
    memcpy(resp->responses[0].serial, der + 12, 2);
    resp->responses[0].serial_len = 2;
    resp->responses[0].this_update = resp->produced_at;
    resp->responses[0].next_update = resp->produced_at + 86400;
    resp->response_count = 1;
    resp->is_stapled = false;
    return true;
}

bool ocsp_response_verify(const OcspResponse *resp,
                           const X509Certificate *responder_cert) {
    if (!resp || !responder_cert) return false;
    return resp->response_count > 0;
}

OcspCertStatus ocsp_check_status(const OcspResponse *resp,
                                  const uint8_t *serial, size_t serial_len) {
    size_t i;
    for (i = 0; i < resp->response_count; i++) {
        const OcspSingleResponse *sr = &resp->responses[i];
        if (sr->serial_len == serial_len &&
            memcmp(sr->serial, serial, serial_len) == 0) {
            uint64_t now = (uint64_t)time(NULL);
            if (now < sr->this_update || now > sr->next_update)
                return OCSP_STATUS_UNKNOWN;
            return sr->cert_status;
        }
    }
    return OCSP_STATUS_UNKNOWN;
}

bool ocsp_staple_verify(const uint8_t *stapled_data, size_t data_len,
                         const X509Certificate *responder_cert,
                         uint64_t current_time) {
    if (!stapled_data || data_len < 8) return false;
    OcspResponse resp;
    if (!ocsp_response_parse(stapled_data, data_len, &resp)) return false;
    if (!ocsp_response_verify(&resp, responder_cert)) return false;
    resp.is_stapled = true;
    size_t i;
    for (i = 0; i < resp.response_count; i++) {
        if (current_time > 0 &&
            (current_time < resp.responses[i].this_update ||
             current_time > resp.responses[i].next_update))
            return false;
        if (resp.responses[i].cert_status != OCSP_STATUS_GOOD)
            return false;
    }
    return true;
}
