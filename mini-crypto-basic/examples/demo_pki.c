#include "pki_model.h"
#include "asymmetric_cipher.h"
#include "hash_func.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

static void print_hex(const uint8_t *data, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) printf("%02x", data[i]);
}

int main(void) {
    srand((unsigned int)time(NULL));
    printf("=== mini-crypto-basic PKI Demo ===\n\n");

    /* ── CA Setup ─────────────────────────────── */
    printf("--- Certificate Authority Setup ---\n");

    CaConfig root_ca;
    memset(&root_ca, 0, sizeof(root_ca));
    strncpy(root_ca.name, "Root CA", 127);

    X509Certificate root_cert;
    if (ca_self_sign_root(&root_ca, &root_cert)) {
        printf("Root CA self-signed certificate created.\n");
        x509_print_certificate(&root_cert);
    }

    CaConfig inter_ca;
    memset(&inter_ca, 0, sizeof(inter_ca));
    strncpy(inter_ca.name, "Intermediate CA", 127);

    X509Certificate inter_cert;
    memset(&inter_cert, 0, sizeof(inter_cert));

    /* ── CSR ───────────────────────────────────── */
    printf("\n--- Certificate Signing Request ---\n");

    CsrRequest csr;
    csr_init(&csr, "example.com", "Example Inc", "US");
    printf("CSR: CN=%s, O=%s, C=%s\n", csr.common_name, csr.organization, csr.country);

    RsaPublicKey pub;
    RsaPrivateKey priv;
    rsa_keygen(&priv, &pub, 1024);

    csr_sign(&csr, &priv, 1024);
    printf("CSR signed: %s\n", csr_verify(&csr) ? "OK" : "FAIL");

    /* ── Certificate Issuance ──────────────────── */
    printf("\n--- Certificate Issuance ---\n");

    X509Certificate leaf_cert;
    if (ca_issue_certificate(&inter_ca, &csr, &leaf_cert, 365)) {
        printf("Leaf certificate issued (365 days).\n");
        x509_print_certificate(&leaf_cert);
    }

    /* ── Trust Store ───────────────────────────── */
    printf("\n--- Trust Store ---\n");

    TrustStore store;
    trust_store_init(&store);
    trust_store_add(&store, &root_cert);
    trust_store_add(&store, &inter_cert);
    printf("Trust store: %zu certificates\n", store.count);

    const X509Certificate *found =
        trust_store_find_by_subject(&store, "Root CA");
    printf("Find 'Root CA': %s\n", found ? "FOUND" : "NOT FOUND");

    /* ── Certificate Chain ─────────────────────── */
    printf("\n--- Certificate Chain Verification ---\n");

    CertChain chain;
    chain.depth = 1;
    chain.certs[0] = leaf_cert;

    uint64_t now = (uint64_t)time(NULL);
    bool chain_valid = cert_chain_verify(&chain, &root_cert, now);
    printf("Chain verify: %s\n", chain_valid ? "OK" : "FAIL");

    /* ── CRL ───────────────────────────────────── */
    printf("\n--- Certificate Revocation List ---\n");

    CertificateRevocationList crl;
    memset(&crl, 0, sizeof(crl));
    crl.entry_count = 1;
    crl.entries[0].serial_len = 2;
    crl.entries[0].serial[0] = 0xaa;
    crl.entries[0].serial[1] = 0xbb;
    crl.entries[0].revocation_date = now - 86400;
    crl.entries[0].reason = 1; /* keyCompromise */

    uint8_t test_serial[2] = {0xaa, 0xbb};
    printf("Revoked serial aa:bb: %s\n",
           crl_is_revoked(&crl, test_serial, 2) ? "YES" : "NO");

    uint8_t good_serial[2] = {0x01, 0x02};
    printf("Good serial 01:02: %s\n",
           crl_is_revoked(&crl, good_serial, 2) ? "Revoked" : "Not revoked");

    /* ── ACME ──────────────────────────────────── */
    printf("\n--- ACME (Let's Encrypt Simulation) ---\n");

    AcmeAccount acc;
    acme_account_create(&acc, "admin@example.com");
    printf("Account: %s (contact=%s)\n", acc.account_id, acc.contact);

    AcmeOrder order;
    if (acme_new_order(&order, "myblog.example.com")) {
        printf("Order: %s (domain=%s, status=%s)\n",
               order.order_id, order.domain, order.status);

        printf("  Challenge HTTP-01:\n");
        printf("    Token: %s\n", order.challenges[0].token);
        printf("    URL: %s\n", order.challenges[0].url);

        printf("  Challenge DNS-01:\n");
        printf("    Token: %s\n", order.challenges[1].token);
        printf("    URL: %s\n", order.challenges[1].url);

        acme_submit_challenge_response(&order, 0, "valid-key-auth");
        acme_submit_challenge_response(&order, 1, "valid-dns-auth");
        printf("  Status: %s\n", order.status);

        if (acme_finalize_order(&order, &csr)) {
            uint8_t cert_der[4096];
            size_t cert_len;
            if (acme_download_certificate(&order, cert_der, &cert_len)) {
                printf("  Certificate downloaded: %zu bytes\n", cert_len);
            }
        }
    }

    /* ── OCSP ──────────────────────────────────── */
    printf("\n--- OCSP Stapling ---\n");

    uint8_t req[256];
    size_t req_len;
    uint8_t serial[2] = {0x01, 0x00};
    ocsp_request_build(serial, 2, req, &req_len);
    printf("OCSP request: %zu bytes\n", req_len);

    OcspResponse resp;
    if (ocsp_response_parse(req, req_len, &resp)) {
        printf("OCSP status: %s\n",
               ocsp_check_status(&resp, serial, 2) == OCSP_STATUS_GOOD
               ? "GOOD" : "REVOKED/UNKNOWN");
    }

    /* ── Digital Signature ─────────────────────── */
    printf("\n--- Hash-then-Sign ---\n");

    Signer signer;
    signer.algo = SIG_ECDSA;
    EcKey ec_signer;
    ecdh_generate_keypair(&ec_signer);
    signer.key.ec_priv = ec_signer.priv;
    signer.key_bits = 256;

    Verifier verifier;
    verifier.algo = SIG_ECDSA;
    verifier.key.ec_pub = &ec_signer.pub;
    verifier.key_bits = 256;

    const char *msg_to_sign = "PKI demo message";
    uint8_t signature[256];
    size_t sig_len;
    if (hash_then_sign(&signer, (const uint8_t *)msg_to_sign,
                       strlen(msg_to_sign), signature, &sig_len)) {
        printf("Signed: \"%s\" (%zu bytes)\n", msg_to_sign, sig_len);
        bool ok = hash_then_verify(&verifier, (const uint8_t *)msg_to_sign,
                                    strlen(msg_to_sign), signature, sig_len);
        printf("Verify: %s\n", ok ? "OK" : "FAIL");
    }

    printf("\n=== PKI Demo Complete ===\n");
    return 0;
}
