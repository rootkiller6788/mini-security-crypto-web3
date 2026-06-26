#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sgx_enclave.h"
#include "remote_attest.h"
#include "confidential_comp.h"

static void print_separator(const char *title) {
    printf("\n========== %s ==========\n", title);
}

static void demo_remote_attestation_flow(void) {
    print_separator("Remote Attestation Demo");

    printf("Step 1: Initialize SGX Enclave (Prover side)\n");
    sgx_enclave_t enclave;
    sgx_enclave_init(&enclave, 1024 * 1024, false);
    sgx_enclave_create(&enclave);

    uint8_t code[4096];
    memset(code, 0xCD, sizeof(code));
    sgx_enclave_add_page(&enclave, enclave.identity.base_addr,
                         code, sizeof(code),
                         SGX_SECINFO_R | SGX_SECINFO_W | SGX_SECINFO_X,
                         SGX_PAGE_REGULAR);
    sgx_enclave_initialize(&enclave);

    ra_prover_t prover;
    ra_prover_init(&prover, &enclave, RA_ATTEST_ECDSA_P256);
    printf("  Prover initialized: attest_type=ECDSA_P256\n");

    print_separator("Step 2: Initialize Verifier (Relying Party)");
    ra_verifier_t verifier;
    ra_verifier_init(&verifier,
                     enclave.identity.mr_enclave,
                     enclave.identity.mr_signer);
    ra_verifier_set_tcb_policy(&verifier, true, 1);
    printf("  Verifier initialized with expected MRENCLAVE/MRSIGNER\n");

    print_separator("Step 3: Generate Challenge (Verifier -> Prover)");
    ra_challenge_t challenge;
    ra_generate_challenge(NULL, 0, &challenge);
    printf("  Challenge generated:\n");
    printf("    Session ID: ");
    for (int i = 0; i < 8; i++) printf("%02x", challenge.session_id[i]);
    printf("...\n");
    printf("    Nonce len:  %u\n", challenge.nonce_len);
    printf("    Timeout:    %u sec\n", challenge.timeout_seconds);

    print_separator("Step 4: Generate Quote (Prover)");
    uint8_t report_data[RA_REPORT_DATA_SIZE];
    ra_create_report_data(challenge.nonce, challenge.nonce_len,
                          NULL, 0, report_data);

    ra_response_t response;
    memset(&response, 0, sizeof(response));
    response.attest_type = RA_ATTEST_ECDSA_P256;
    response.quote_version = 4;

    sgx_quote_v3_t quote_buf[1];
    uint32_t qsize;
    sgx_enclave_create_quote(&enclave, report_data, SGX_ATTEST_ECDSA,
                             (sgx_quote_v3_t *)quote_buf, &qsize);
    memcpy(response.quote, quote_buf, qsize < RA_QUOTE_MAX_SIZE ? qsize : RA_QUOTE_MAX_SIZE);
    response.quote_size = qsize;

    memcpy(response.session_id, challenge.session_id, RA_SESSION_ID_SIZE);
    printf("  Quote generated: %u bytes\n", response.quote_size);

    print_separator("Step 5: Verify Quote (Verifier)");
    ra_quote_body_t body;
    if (ra_parse_quote_body(response.quote, response.quote_size, &body) == 0) {
        printf("  Quote body parsed successfully\n");
        ra_print_quote_body(&body);
    }

    bool verify_body = false;
    (void)verify_body;
    verifier.verify_quote_body = NULL;
    printf("  MRENCLAVE match: %s\n",
           memcmp(body.mr_enclave, verifier.expected_mr_enclave,
                  SGX_MEASUREMENT_SIZE) == 0 ? "YES" : "NO");
    printf("  ISV SVN check:   %u >= %u -> %s\n",
           (unsigned)body.isv_svn[0], verifier.minimum_isv_svn,
           body.isv_svn[0] >= verifier.minimum_isv_svn ? "PASS" : "FAIL");
    printf("  Debug flag:      %s -> %s\n",
           body.debug_flag ? "ON" : "OFF",
           (!body.debug_flag || verifier.allow_debug) ? "OK" : "REJECTED");

    print_separator("Step 6: IAS Verification (simulated)");
    ra_ias_verification_t ias;
    ra_verify_ias_attestation(&response, NULL, &ias);
    ra_print_verification(&ias);

    print_separator("Step 7: DCAP Verification (simulated)");
    ra_dcap_verification_t dcap;
    ra_verify_dcap_attestation(&response, &dcap);
    ra_print_dcap_report(&dcap);

    print_separator("Step 8: Certificate Chain Verification");
    uint8_t cert_chain[1024];
    memset(cert_chain, 0xCE, sizeof(cert_chain));
    bool chain_valid;
    ra_cert_chain_verify(cert_chain, sizeof(cert_chain), NULL, &chain_valid);
    printf("  Certificate chain: %s\n", chain_valid ? "VALID" : "INVALID");

    uint8_t pubkey[RA_ECDSA_PUBKEY_SIZE];
    ra_cert_extract_public_key(cert_chain, sizeof(cert_chain), pubkey);
    printf("  Extracted public key (first 16 bytes): ");
    for (int i = 0; i < 16; i++) printf("%02x", pubkey[i]);
    printf("\n");

    print_separator("Step 9: TLS Integration with Attestation");
    ra_tls_context_t tls_ctx;
    memset(&tls_ctx, 0, sizeof(tls_ctx));
    tls_ctx.attestation_required = true;
    tls_ctx.mutual_attestation = true;
    tls_ctx.tls_version = 0x0304;

    ra_response_t tls_attest;
    uint8_t client_hello[256];
    memset(client_hello, 0x16, sizeof(client_hello));
    ra_tls_handshake_with_attestation(&tls_ctx, client_hello,
                                      sizeof(client_hello), &tls_attest);
    printf("  TLS handshake with attestation completed\n");
    printf("  Peer attestation quote size: %u\n", tls_attest.quote_size);

    bool peer_attested;
    ra_tls_verify_peer_attestation(&tls_ctx, &tls_attest, &peer_attested);
    printf("  Peer attestation verified: %s\n", peer_attested ? "YES" : "NO");

    sgx_enclave_destroy(&enclave);
    sgx_enclave_free(&enclave);
    printf("\n[Remote Attestation Demo Complete]\n");
}

static void demo_confidential_computing(void) {
    print_separator("Confidential Computing Demo");

    printf("Step 1: Initialize Confidential Computing Context\n");
    cc_confidential_ctx_t cc;
    cc_init(&cc);
    printf("  Context initialized\n");

    printf("\nStep 2: Probe Platform Capabilities\n");
    cc_trust_boundary_t boundary;
    cc_probe_platform(&cc, &boundary);
    cc_print_trust_boundary(&boundary);

    bool sgx_ok, tdx_ok, sev_ok, tme_ok;
    cc_is_sgx_supported(&cc, &sgx_ok);
    cc_is_tdx_supported(&cc, &tdx_ok);
    cc_is_sev_supported(&cc, &sev_ok);
    cc_is_tme_supported(&cc, &tme_ok);
    printf("  Feature check: SGX=%c TDX=%c SEV=%c TME=%c\n",
           sgx_ok ? 'Y' : 'N', tdx_ok ? 'Y' : 'N',
           sev_ok ? 'Y' : 'N', tme_ok ? 'Y' : 'N');

    printf("\nStep 3: Enable TME (Total Memory Encryption)\n");
    uint8_t tme_key[CC_TME_KEY_SIZE];
    for (int i = 0; i < CC_TME_KEY_SIZE; i++) tme_key[i] = (uint8_t)(i * 7 + 0x33);
    cc_enable_tme(&cc, tme_key);
    printf("  TME enabled (active_mode=%d)\n", cc.mem_encryption.active_mode);

    printf("\nStep 4: Register Encrypted Memory Regions\n");
    cc_register_encrypted_region(&cc, 0x1000000, 0x2000000,
                                 CC_MEM_MODE_TME, tme_key);
    cc_register_encrypted_region(&cc, 0x3000000, 0x4000000,
                                 CC_MEM_MODE_MKTME, NULL);
    printf("  Registered %u encrypted regions\n", cc.trust_boundary.region_count);

    printf("\nStep 5: Vulnerability Assessment\n");
    bool vuln_present;
    cc_check_vulnerability(&cc, CC_VULN_LVI, &vuln_present);
    printf("  LVI present: %s\n", vuln_present ? "YES" : "NO");
    cc_check_vulnerability(&cc, CC_VULN_SGAXE, &vuln_present);
    printf("  SGAxe present: %s\n", vuln_present ? "YES" : "NO");
    cc_check_vulnerability(&cc, CC_VULN_PLUNDERVOLT, &vuln_present);
    printf("  Plundervolt present: %s\n", vuln_present ? "YES" : "NO");

    cc_vuln_database_t sgx_db;
    cc_get_sgx_vulnerabilities(&cc, &sgx_db);
    printf("\n  --- SGX Vulnerabilities ---\n");
    cc_print_vuln_database(&sgx_db);

    cc_vuln_database_t sev_db;
    cc_get_sev_vulnerabilities(&cc, &sev_db);
    printf("\n  --- SEV Vulnerabilities ---\n");
    cc_print_vuln_database(&sev_db);

    printf("\nStep 6: Side-Channel Mitigations\n");
    cc_cache_layout_t cache_layout;
    memset(&cache_layout, 0, sizeof(cache_layout));
    cache_layout.cache_sets = 2048;
    cache_layout.cache_ways = 16;
    cache_layout.cache_line_size = 64;
    cache_layout.cache_level = 3;

    cc_mitigate_cache_side_channel(&cc, &cache_layout, 0);
    printf("  Cache side-channel mitigation enabled\n");
    printf("  Cache: %u sets x %u ways x %u bytes (L%u)\n",
           cache_layout.cache_sets, cache_layout.cache_ways,
           cache_layout.cache_line_size, cache_layout.cache_level);
    printf("  Partitioned: %s\n", cache_layout.partitioned ? "YES" : "NO");

    cc_mitigate_page_fault_channel(&cc);
    printf("  Page-fault channel mitigation enabled\n");

    printf("\nStep 7: Mitigate Known Vulnerabilities\n");
    cc_enable_patch_for_vuln(&cc, CC_VULN_LVI);
    cc_enable_patch_for_vuln(&cc, CC_VULN_SGAXE);
    cc_is_mitigated(&cc, CC_VULN_LVI, &vuln_present);
    printf("  LVI mitigated: %s\n", vuln_present ? "YES" : "NO");

    printf("\nStep 8: Constant-Time Crypto Operations\n");
    uint8_t buf_a[CC_CONST_TIME_BUFFER_SIZE];
    uint8_t buf_b[CC_CONST_TIME_BUFFER_SIZE];
    for (int i = 0; i < CC_CONST_TIME_BUFFER_SIZE; i++) {
        buf_a[i] = (uint8_t)(i & 0xFF);
        buf_b[i] = (uint8_t)(i & 0xFF);
    }

    int cmp_result = cc_constant_time_compare(buf_a, buf_b, 64);
    printf("  ct_compare(identical): %d (expected 0)\n", cmp_result);

    buf_b[32] ^= 0x01;
    cmp_result = cc_constant_time_compare(buf_a, buf_b, 64);
    printf("  ct_compare(different): %d (expected -1)\n", cmp_result);
    buf_b[32] ^= 0x01;

    bool is_zero, is_equal;
    cc_constant_time_is_zero(buf_a, 16, &is_zero);
    printf("  ct_is_zero: %s\n", is_zero ? "YES" : "NO");

    cc_constant_time_equal(buf_a, buf_b, 64, &is_equal);
    printf("  ct_equal: %s\n", is_equal ? "YES" : "NO");

    uint8_t ct_result[64];
    cc_constant_time_select(true, buf_a, buf_b, ct_result, 64);
    printf("  ct_select(true): first byte = %02x\n", ct_result[0]);

    cc_constant_time_increment(buf_a, 32);
    printf("  ct_increment: first byte now %02x\n", buf_a[0]);

    printf("\nStep 9: Secure I/O\n");
    cc_secure_io_t secure_io;
    uint8_t peer_pubkey[32];
    memset(peer_pubkey, 0xDD, 32);
    cc_secure_io_negotiate(&cc, peer_pubkey, &secure_io);
    printf("  Secure I/O session established: %s\n",
           secure_io.established ? "YES" : "NO");

    const char *io_msg = "Secure channel message (encrypted)";
    cc_secure_io_send(&cc, (const uint8_t *)io_msg,
                      strlen(io_msg) + 1, &secure_io);
    printf("  Data sent: %u bytes\n", secure_io.source_size);

    uint8_t io_recv[CC_SECURE_IO_BUFFER_SIZE];
    size_t io_recv_size;
    cc_secure_io_receive(&cc, io_recv, &io_recv_size, &secure_io);
    printf("  Data received: %zu bytes\n", io_recv_size);

    printf("\nStep 10: State Sealing\n");
    size_t sealed_size;
    uint8_t sealed_buf[sizeof(cc_confidential_ctx_t)];
    cc_seal_entire_state(&cc, sealed_buf, &sealed_size);
    printf("  State sealed: %zu bytes\n", sealed_size);

    cc_unseal_entire_state(&cc, sealed_buf, sealed_size);
    printf("  State unsealed successfully\n");

    printf("\nStep 11: Key Rotation\n");
    cc_rotate_encryption_keys(&cc);
    cc_rotate_encryption_keys(&cc);
    printf("  Keys rotated: epoch=%u\n", cc.epoch);

    printf("\nStep 12: Platform Attestation\n");
    uint8_t evidence[512];
    size_t evidence_size;
    cc_attest_platform(&cc, evidence, &evidence_size);
    printf("  Platform evidence: %zu bytes\n", evidence_size);

    bool att_valid;
    cc_verify_attestation(&cc, evidence, evidence_size, &att_valid);
    printf("  Attestation verification: %s\n", att_valid ? "VALID" : "INVALID");

    cc_free(&cc);
    printf("\n[Confidential Computing Demo Complete]\n");
}

int main(void) {
    printf("=== mini-trusted-compute — Remote Attestation & Confidential Computing Demo ===\n");

    demo_remote_attestation_flow();
    demo_confidential_computing();

    printf("\n=== All Demos Complete ===\n");
    return 0;
}
