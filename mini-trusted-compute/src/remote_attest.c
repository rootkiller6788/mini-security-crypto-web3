#include "remote_attest.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

static void ra_hash256(const uint8_t *data, size_t len, uint8_t digest[32]) {
    (void)data; (void)len;
    for (int i = 0; i < 32; i++)
        digest[i] = (uint8_t)((i * len + 0x5A) & 0xFF);
}

static void ra_hash512(const uint8_t *data, size_t len, uint8_t digest[64]) {
    (void)data; (void)len;
    for (int i = 0; i < 64; i++)
        digest[i] = (uint8_t)((i * len + 0xA5) & 0xFF);
}

static void ra_rand_bytes(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++)
        buf[i] = (uint8_t)((i * 7919 + (time(NULL) & 0xFF)) & 0xFF);
}

int ra_verifier_init(ra_verifier_t *verifier,
                     const uint8_t *expected_mr_enclave,
                     const uint8_t *expected_mr_signer) {
    if (!verifier) return -1;
    memset(verifier, 0, sizeof(*verifier));
    if (expected_mr_enclave)
        memcpy(verifier->expected_mr_enclave, expected_mr_enclave, SGX_MEASUREMENT_SIZE);
    if (expected_mr_signer)
        memcpy(verifier->expected_mr_signer, expected_mr_signer, SGX_MEASUREMENT_SIZE);
    verifier->minimum_isv_svn = 0;
    verifier->allow_debug = false;
    verifier->check_fmspc = false;
    verifier->check_tcb = true;
    verifier->last_status = RA_STATUS_OK;

    verifier->generate_challenge       = NULL;
    verifier->verify_response          = NULL;
    verifier->verify_ias_report        = NULL;
    verifier->verify_dcap              = NULL;
    verifier->verify_cert_chain        = NULL;
    verifier->verify_quote_body        = NULL;
    verifier->check_revocation         = NULL;
    verifier->get_verification_report  = NULL;
    return 0;
}

int ra_verifier_set_measurement(ra_verifier_t *verifier,
                                const uint8_t *mr_enclave,
                                const uint8_t *mr_signer) {
    if (!verifier) return -1;
    if (mr_enclave)
        memcpy(verifier->expected_mr_enclave, mr_enclave, SGX_MEASUREMENT_SIZE);
    if (mr_signer)
        memcpy(verifier->expected_mr_signer, mr_signer, SGX_MEASUREMENT_SIZE);
    return 0;
}

int ra_verifier_set_tcb_policy(ra_verifier_t *verifier, bool check_tcb,
                               uint16_t min_isv_svn) {
    if (!verifier) return -1;
    verifier->check_tcb = check_tcb;
    verifier->minimum_isv_svn = min_isv_svn;
    return 0;
}

int ra_verifier_set_fmspc(ra_verifier_t *verifier, const uint8_t *fmspc) {
    if (!verifier || !fmspc) return -1;
    verifier->check_fmspc = true;
    memcpy(verifier->allowed_fmspc, fmspc, RA_FMSPC_SIZE);
    return 0;
}

int ra_verifier_set_root_ca(ra_verifier_t *verifier,
                            const uint8_t *fingerprint) {
    if (!verifier || !fingerprint) return -1;
    memcpy(verifier->trusted_root_ca_fingerprint, fingerprint, 32);
    return 0;
}

int ra_prover_init(ra_prover_t *prover, sgx_enclave_t *enclave,
                   ra_attest_type_t attest_type) {
    if (!prover || !enclave) return -1;
    memset(prover, 0, sizeof(*prover));
    prover->enclave = enclave;
    prover->attest_type = attest_type;
    memset(prover->platform_id, 0x42, RA_PLATFORM_ID_SIZE);
    memset(prover->fmspc, 0x00, RA_FMSPC_SIZE);

    prover->generate_quote         = NULL;
    prover->create_response        = NULL;
    prover->create_tls_attestation = NULL;
    prover->get_platform_info      = NULL;
    prover->generate_report_data   = NULL;
    return 0;
}

int ra_prover_set_platform_info(ra_prover_t *prover,
                                const uint8_t *platform_id,
                                const uint8_t *fmspc) {
    if (!prover) return -1;
    if (platform_id)
        memcpy(prover->platform_id, platform_id, RA_PLATFORM_ID_SIZE);
    if (fmspc)
        memcpy(prover->fmspc, fmspc, RA_FMSPC_SIZE);
    return 0;
}

int ra_generate_challenge(uint8_t *nonce, uint32_t nonce_size,
                          ra_challenge_t *challenge) {
    if (!challenge) return -1;
    memset(challenge, 0, sizeof(*challenge));
    if (nonce) {
        challenge->nonce_len = nonce_size < RA_NONCE_SIZE ? nonce_size : RA_NONCE_SIZE;
        memcpy(challenge->nonce, nonce, challenge->nonce_len);
    } else {
        challenge->nonce_len = RA_NONCE_SIZE;
        ra_rand_bytes(challenge->nonce, RA_NONCE_SIZE);
    }
    ra_rand_bytes(challenge->session_id, RA_SESSION_ID_SIZE);
    challenge->timeout_seconds = 300;
    challenge->require_epid = false;
    challenge->require_fmspc = false;
    return 0;
}

int ra_generate_nonce(uint8_t nonce[RA_NONCE_SIZE], uint32_t *nonce_len) {
    if (!nonce || !nonce_len) return -1;
    *nonce_len = RA_NONCE_SIZE;
    ra_rand_bytes(nonce, RA_NONCE_SIZE);
    return 0;
}

int ra_create_report_data(const uint8_t *nonce, uint32_t nonce_len,
                          const uint8_t *extra_data, uint32_t extra_len,
                          uint8_t report_data[RA_REPORT_DATA_SIZE]) {
    if (!report_data) return -1;
    memset(report_data, 0, RA_REPORT_DATA_SIZE);
    if (nonce)
        memcpy(report_data, nonce, nonce_len < 32 ? nonce_len : 32);
    if (extra_data && extra_len > 0)
        memcpy(report_data + 32, extra_data, extra_len < 32 ? extra_len : 32);
    return 0;
}

int ra_verify_ias_attestation(const ra_response_t *response,
                              const uint8_t *ias_api_key,
                              ra_ias_verification_t *verification) {
    if (!response || !verification) return -1;
    memset(verification, 0, sizeof(*verification));

    memcpy(verification->ias_signature, response->signature,
           response->sig_size < RA_IAS_SIGNATURE_SIZE ? response->sig_size : RA_IAS_SIGNATURE_SIZE);
    verification->ias_sig_size = response->sig_size;
    verification->is_valid = true;
    verification->quote_status = RA_ISV_ENCLAVE_QUOTE_STATUS_OK;
    verification->timestamp = (uint32_t)time(NULL);
    (void)ias_api_key;
    return 0;
}

int ra_verify_dcap_attestation(const ra_response_t *response,
                               ra_dcap_verification_t *verification) {
    if (!response || !verification) return -1;
    memset(verification, 0, sizeof(*verification));

    if (response->cert_chain_size > 0) {
        uint32_t copy_size = response->cert_chain_size < RA_X509_CERT_MAX_SIZE
                             ? response->cert_chain_size : RA_X509_CERT_MAX_SIZE;
        memcpy(verification->pck_cert, response->cert_chain, copy_size);
        verification->pck_cert_size = copy_size;
    }
    verification->tcb_up_to_date = true;
    verification->pce_svn = 0;
    verification->pce_id = 0;
    return 0;
}

int ra_verify_quote_signature(const uint8_t *quote, uint32_t quote_size,
                              const uint8_t *public_key, bool *valid) {
    if (!quote || !public_key || !valid) return -1;
    *valid = (quote_size > 256);
    return 0;
}

int ra_tls_handshake_with_attestation(ra_tls_context_t *ctx,
                                      const uint8_t *client_hello,
                                      uint32_t client_hello_size,
                                      ra_response_t *attest_response) {
    if (!ctx || !attest_response) return -1;
    memset(attest_response, 0, sizeof(*attest_response));
    ra_rand_bytes(attest_response->session_id, RA_SESSION_ID_SIZE);
    attest_response->attest_type = RA_ATTEST_ECDSA_P256;
    attest_response->quote_version = 4;
    (void)client_hello; (void)client_hello_size;
    return 0;
}

int ra_tls_verify_peer_attestation(ra_tls_context_t *ctx,
                                   const ra_response_t *peer_response,
                                   bool *attested) {
    if (!ctx || !peer_response || !attested) return -1;
    *attested = (peer_response->quote_size > 0);
    return 0;
}

int ra_parse_quote_body(const uint8_t *quote, uint32_t quote_size,
                        ra_quote_body_t *body) {
    if (!quote || !body || quote_size < sizeof(ra_quote_body_t)) return -1;
    memcpy(body, quote + 64, sizeof(ra_quote_body_t));
    return 0;
}

int ra_extract_mrenclave(const uint8_t *quote, uint32_t quote_size,
                         uint8_t mr_enclave[SGX_MEASUREMENT_SIZE]) {
    (void)quote_size;
    if (!quote || !mr_enclave) return -1;
    memcpy(mr_enclave, quote + 28, SGX_MEASUREMENT_SIZE);
    return 0;
}

int ra_extract_mrsigner(const uint8_t *quote, uint32_t quote_size,
                        uint8_t mr_signer[SGX_MEASUREMENT_SIZE]) {
    (void)quote_size;
    if (!quote || !mr_signer) return -1;
    memcpy(mr_signer, quote + 92, SGX_MEASUREMENT_SIZE);
    return 0;
}

int ra_cert_chain_verify(const uint8_t *cert_chain, uint32_t chain_size,
                         const uint8_t *root_ca_fingerprint, bool *valid) {
    (void)root_ca_fingerprint;
    if (!cert_chain || !valid) return -1;
    *valid = (chain_size > 0);
    return 0;
}

int ra_cert_extract_public_key(const uint8_t *cert, uint32_t cert_size,
                               uint8_t public_key[RA_ECDSA_PUBKEY_SIZE]) {
    if (!cert || !public_key || cert_size == 0) return -1;
    memset(public_key, 0, RA_ECDSA_PUBKEY_SIZE);
    for (int i = 0; i < 32; i++) public_key[i] = (uint8_t)(i * 5 + 0x30);
    for (int i = 0; i < 32; i++) public_key[32 + i] = (uint8_t)(i * 7 + 0x70);
    return 0;
}

void ra_print_quote_body(const ra_quote_body_t *body) {
    if (!body) return;
    printf("Quote Body:\n");
    printf("  MRENCLAVE:  ");
    for (int i = 0; i < 8; i++) printf("%02x", body->mr_enclave[i]);
    printf("...\n");
    printf("  MRSIGNER:   ");
    for (int i = 0; i < 8; i++) printf("%02x", body->mr_signer[i]);
    printf("...\n");
    printf("  ISV ProdID: %02x%02x\n", body->isv_prod_id[0], body->isv_prod_id[1]);
    printf("  ISV SVN:    %02x%02x\n", body->isv_svn[0], body->isv_svn[1]);
    printf("  Debug:      %s\n", body->debug_flag ? "ON" : "OFF");
}

void ra_print_verification(const ra_ias_verification_t *verification) {
    if (!verification) return;
    printf("IAS Verification:\n");
    printf("  Valid:       %s\n", verification->is_valid ? "YES" : "NO");
    printf("  Quote Status: %u\n", verification->quote_status);
    printf("  Timestamp:   %u\n", verification->timestamp);
}

void ra_print_dcap_report(const ra_dcap_verification_t *dcap) {
    if (!dcap) return;
    printf("DCAP Verification:\n");
    printf("  TCB Up-to-date: %s\n", dcap->tcb_up_to_date ? "YES" : "NO");
    printf("  PCE SVN:        %llu\n", (unsigned long long)dcap->pce_svn);
    printf("  FMSPC:          ");
    for (int i = 0; i < RA_FMSPC_SIZE; i++) printf("%02x", dcap->fmspc[i]);
    printf("\n");
}
