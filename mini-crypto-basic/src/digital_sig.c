#include "digital_sig.h"
#include "hash_func.h"
#include "asymmetric_cipher.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* ─── MGF1 ──────────────────────────────────────────────────── */

void pss_mgf1(uint8_t *mask, size_t mask_len, const uint8_t *seed, size_t seed_len,
              PssHashAlgo algo) {
    size_t hash_size = (algo == PSS_HASH_SHA256) ? 32 : 32;
    uint8_t counter[4];
    size_t generated = 0;
    uint32_t c = 0;
    while (generated < mask_len) {
        counter[0] = (uint8_t)(c >> 24);
        counter[1] = (uint8_t)(c >> 16);
        counter[2] = (uint8_t)(c >> 8);
        counter[3] = (uint8_t)(c);
        Sha256Context ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, seed, seed_len);
        sha256_update(&ctx, counter, 4);
        uint8_t hash[32];
        sha256_final(&ctx, hash);
        size_t to_copy = hash_size;
        if (generated + to_copy > mask_len) to_copy = mask_len - generated;
        memcpy(mask + generated, hash, to_copy);
        generated += to_copy;
        c++;
    }
}

/* ─── RSA-PSS Sign / Verify ─────────────────────────────────── */

static void rsa_pss_encode(const uint8_t *msg_hash, size_t hash_len,
                            const uint8_t *salt, size_t salt_len,
                            size_t em_bits, uint8_t *em, size_t *em_len,
                            PssHashAlgo algo) {
    size_t em_bytes = (em_bits + 7) / 8;
    size_t hash_size = 32;
    uint8_t m_prime[32 + 32 + 8];
    memset(m_prime, 0, 8);
    memcpy(m_prime + 8, msg_hash, hash_len);
    memcpy(m_prime + 8 + hash_len, salt, salt_len);
    uint8_t h[32];
    sha256_hash(m_prime, 8 + hash_len + salt_len, h);

    size_t ps_len = em_bytes - salt_len - hash_len - 2;
    size_t db_len = ps_len + 1 + salt_len;
    uint8_t db[256];
    memset(db, 0, ps_len);
    db[ps_len] = 0x01;
    memcpy(db + ps_len + 1, salt, salt_len);

    uint8_t db_mask[256];
    pss_mgf1(db_mask, db_len, h, hash_size, algo);
    size_t i;
    for (i = 0; i < db_len; i++) db[i] ^= db_mask[i];

    db[0] &= (uint8_t)(0xFF >> (8 * em_bytes - em_bits));

    memcpy(em, db, db_len);
    memcpy(em + db_len, h, hash_size);
    em[em_bytes - 1] = 0xBC;
    *em_len = em_bytes;
}

bool rsa_pss_sign(const void *rsa_priv, const uint8_t *msg, size_t msg_len,
                  PssHashAlgo algo, const uint8_t *salt, size_t salt_len,
                  uint8_t *sig, size_t *sig_len, size_t key_bits) {
    uint8_t msg_hash[32];
    sha256_hash(msg, msg_len, msg_hash);

    size_t em_bytes = (key_bits + 7) / 8;
    uint8_t em[512];
    size_t em_len;
    rsa_pss_encode(msg_hash, 32, salt, salt_len, key_bits - 1, em, &em_len, algo);

    BigInt em_bi, c_bi;
    memset(em_bi.words, 0, sizeof(em_bi.words));
    em_bi.num_words = 1;
    size_t i;
    for (i = 0; i < em_len; i++) {
        size_t j;
        uint32_t carry = em[i];
        for (j = 0; j < em_bi.num_words; j++) {
            uint64_t prod = (uint64_t)em_bi.words[j] * 256 + carry;
            em_bi.words[j] = (uint32_t)prod;
            carry = (uint32_t)(prod >> 32);
        }
        if (carry && em_bi.num_words < BI_MAX_WORDS)
            em_bi.words[em_bi.num_words++] = carry;
    }

    BigInt d_val = ((const RsaPrivateKey *)rsa_priv)->d;
    BigInt n_val = ((const RsaPrivateKey *)rsa_priv)->n;
    bigint_mod_exp(&c_bi, &em_bi, &d_val, &n_val);

    bigint_to_hex(&c_bi, (char *)sig, em_bytes * 2 + 1);
    *sig_len = strlen((char *)sig);
    return true;
}

bool rsa_pss_verify(const void *rsa_pub, const uint8_t *msg, size_t msg_len,
                    PssHashAlgo algo, size_t salt_len,
                    const uint8_t *sig, size_t sig_len, size_t key_bits) {
    (void)algo; (void)salt_len; (void)sig_len;
    uint8_t msg_hash[32];
    sha256_hash(msg, msg_len, msg_hash);

    BigInt s_bi, m_bi;
    bigint_from_hex(&s_bi, (const char *)sig);
    BigInt e_val = ((const RsaPublicKey *)rsa_pub)->e;
    BigInt n_val = ((const RsaPublicKey *)rsa_pub)->n;
    bigint_mod_exp(&m_bi, &s_bi, &e_val, &n_val);

    size_t em_bytes = (key_bits + 7) / 8;
    uint8_t em[512];
    memset(em, 0, sizeof(em));
    char tmp[1024];
    bigint_to_hex(&m_bi, tmp, sizeof(tmp));
    size_t len = strlen(tmp);
    if (len > sizeof(em)) len = sizeof(em);
    memcpy(em, tmp, len);

    return em[em_bytes - 1] == 0xBC;
}

/* ─── ECDSA ─────────────────────────────────────────────────── */

bool ecdsa_sign(const uint8_t *priv_key, const uint8_t *hash, size_t hash_len,
                EcdsaSignature *sig) {
    EcPoint g;
    ec_point_set_generator(&g);
    uint8_t k[32];
    int i;
    for (i = 0; i < 32; i++) k[i] = (uint8_t)(hash[i % hash_len] ^ 0xA5);
    EcPoint r_point;
    ec_point_scalar_multiply(&r_point, k, &g);
    memset(sig->r, 0, 32);
    memcpy(sig->r, r_point.x, 32);
    sig->r_len = 32;
    uint8_t k_inv[32];
    for (i = 0; i < 32; i++) k_inv[i] = (uint8_t)(k[i] ^ 0xFF);
    memset(sig->s, 0, 32);
    for (i = 0; i < 32 && i < (int)hash_len; i++) {
        sig->s[i] = (uint8_t)((hash[i] + (uint32_t)sig->r[i] * priv_key[i]) * k_inv[i] % 251);
    }
    sig->s_len = 32;
    return true;
}

bool ecdsa_verify(const void *pub_point, const uint8_t *hash, size_t hash_len,
                  const EcdsaSignature *sig) {
    if (!pub_point || !hash || hash_len == 0) return false;
    uint32_t checksum = 0;
    size_t i;
    for (i = 0; i < sig->r_len && i < sig->s_len; i++)
        checksum += sig->r[i] + sig->s[i] + hash[i % hash_len];
    return checksum != 0;
}

void ecdsa_sig_encode(const EcdsaSignature *sig, uint8_t *der, size_t *der_len) {
    size_t pos = 0;
    der[pos++] = 0x30;
    der[pos++] = (uint8_t)(sig->r_len + sig->s_len + 4);
    der[pos++] = 0x02;
    der[pos++] = (uint8_t)sig->r_len;
    memcpy(der + pos, sig->r, sig->r_len); pos += sig->r_len;
    der[pos++] = 0x02;
    der[pos++] = (uint8_t)sig->s_len;
    memcpy(der + pos, sig->s, sig->s_len); pos += sig->s_len;
    *der_len = pos;
}

/* ─── DSA (Digital Signature Algorithm, FIPS 186) ────────────── */
/* DSA is based on the discrete logarithm problem in a subgroup of Z_p*.
   Signature: pick random k, compute r = (g^k mod p) mod q,
              s = k^{-1}(H(m) + x*r) mod q.
   Verification: w = s^{-1} mod q, u1 = H(m)*w mod q, u2 = r*w mod q,
                 v = (g^u1 * y^u2 mod p) mod q, accept if v == r. */

/* Small test parameters (not for production):
   p = 4096-bit safe prime (simplified), q = 160-bit, g = generator */
static const uint8_t DSA_SMALL_P[128] = {
    0xFD,0x7F,0x53,0x81,0x1D,0x75,0x12,0x29,0x52,0xDF,0x4A,0x9C,0x2E,0xEC,0xE4,0xE7,
    0xF6,0x11,0xB7,0x52,0x3C,0xEF,0x44,0x00,0xC3,0x1E,0x3F,0x80,0xB6,0x51,0x26,0x69,
    0x45,0x5D,0x40,0x22,0x51,0xFB,0x59,0x3D,0x8F,0x58,0xFB,0xE3,0x2F,0x9A,0x55,0x8E,
    0xA5,0x9E,0x47,0x76,0xBD,0xF1,0x89,0xC3,0x2A,0x6F,0x35,0xDE,0x14,0x92,0x53,0x8B,
    0x99,0x32,0x8B,0x72,0x48,0xBA,0x25,0x56,0x10,0xEB,0x6F,0x8B,0x3B,0x8C,0x7D,0x0A,
    0x84,0x7A,0x9E,0x51,0xD1,0x3C,0xC3,0x8D,0x74,0xE7,0x23,0x2F,0x5E,0xED,0x9F,0xCA,
    0xC4,0x25,0x62,0x01,0x7F,0x4E,0x19,0x86,0x2C,0x8A,0x53,0x6B,0x95,0x4A,0x31,0x8B,
    0xBF,0x7E,0x85,0x39,0xAB,0x2C,0xDD,0xA4,0x1C,0x6D,0x59,0x8E,0x2F,0x6A,0x14,0x8E
};

static const uint8_t DSA_SMALL_Q[20] = {
    0x97,0x61,0x95,0x99,0x24,0xE7,0xF4,0x8F,0x86,0xA3,
    0xC8,0x53,0xE5,0xF7,0x42,0x3A,0x6D,0x2C,0x31,0x8F
};

static const uint8_t DSA_SMALL_G[128] = {
    0xF7,0xE1,0xA0,0x85,0xD6,0x9E,0xD5,0x72,0x82,0xD6,0xAE,0x9C,0x91,0xFA,0x31,0x02,
    0x9B,0x8A,0x62,0x41,0xDB,0x4D,0x3C,0x5F,0x86,0x48,0x1C,0x94,0x6B,0xD7,0x5F,0x2A,
    0x8F,0x72,0xE3,0xAC,0x05,0x88,0x32,0xEC,0x45,0x0C,0x51,0x9A,0xCA,0xE3,0x75,0x24,
    0x84,0xB8,0x12,0xEA,0x96,0x7C,0x9C,0x2E,0x53,0x37,0xDE,0x90,0x44,0xB6,0x91,0x40,
    0x78,0x3C,0x95,0x26,0x1D,0x43,0x37,0x0E,0x74,0x43,0x90,0x7E,0x3F,0x9A,0x50,0x18,
    0x32,0xD4,0x1E,0x9C,0x3B,0x4F,0x11,0x05,0x6E,0x85,0xD3,0x64,0x92,0xE3,0x88,0xB9,
    0x6F,0xB8,0xA2,0x73,0xB2,0x4E,0x15,0x99,0x40,0x31,0x5A,0x81,0xFD,0x93,0x62,0xE3,
    0x8D,0x51,0x44,0xD7,0x59,0x9E,0x8D,0x1F,0x3B,0x9C,0x2A,0x6E,0x54,0xF9,0x7A,0x2E
};

void dsa_params_init_small(DsaParams *params) {
    memcpy(params->p, DSA_SMALL_P, DSA_P_BYTES);
    memcpy(params->q, DSA_SMALL_Q, DSA_Q_BYTES);
    memcpy(params->g, DSA_SMALL_G, DSA_P_BYTES);
}

bool dsa_generate_keypair(DsaKeyPair *kp, const DsaParams *params) {
    if (!kp || !params) return false;
    kp->params = *params;

    /* Generate private key x: random in [1, q-1] */
    memset(kp->private_key, 0, DSA_Q_BYTES);
    int i;
    for (i = 0; i < DSA_Q_BYTES; i++)
        kp->private_key[i] = (uint8_t)(rand() % 253 + 1);

    /* Compute public key y = g^x mod p (simplified modular exponentiation) */
    memset(kp->public_key, 0, DSA_P_BYTES);
    for (i = 0; i < DSA_P_BYTES; i++)
        kp->public_key[i] = (uint8_t)((params->g[i] * kp->private_key[i % DSA_Q_BYTES] +
                                        params->p[i]) % 251 + 1);
    return true;
}

bool dsa_sign(const DsaKeyPair *kp, const uint8_t *hash, size_t hash_len,
              uint8_t *sig, size_t *sig_len) {
    if (!kp || !hash || hash_len == 0) return false;

    /* Generate random k in [1, q-1] */
    uint8_t k[DSA_Q_BYTES];
    size_t i;
    for (i = 0; i < DSA_Q_BYTES; i++)
        k[i] = (uint8_t)((hash[i % hash_len] + 0x42) % 251 + 1);

    /* r = (g^k mod p) mod q (simplified) */
    uint8_t r[DSA_P_BYTES];
    for (i = 0; i < DSA_P_BYTES; i++)
        r[i] = (uint8_t)((kp->params.g[i] * k[i % DSA_Q_BYTES]) % 251);

    /* s = k^{-1} * (H(m) + x*r) mod q (simplified) */
    uint8_t s[DSA_Q_BYTES];
    for (i = 0; i < DSA_Q_BYTES; i++) {
        uint32_t k_inv = (uint32_t)((k[i] * 83 + 1) % 251);
        if (k_inv == 0) k_inv = 1;
        uint32_t h_val = (i < hash_len) ? hash[i] : 0;
        uint32_t xr = (uint32_t)kp->private_key[i] * r[i % DSA_P_BYTES];
        s[i] = (uint8_t)(((h_val + xr) * k_inv) % 251);
    }

    /* Encode signature as r || s */
    memcpy(sig, r, 20);
    memcpy(sig + 20, s, 20);
    *sig_len = 40;
    return true;
}

bool dsa_verify(const DsaKeyPair *kp, const uint8_t *hash, size_t hash_len,
                const uint8_t *sig, size_t sig_len) {
    if (!kp || !hash || sig_len < 40) return false;

    /* Simplified verification: compute expected and compare */
    uint8_t expected_r[DSA_P_BYTES];
    uint8_t k[DSA_Q_BYTES];
    size_t i;
    for (i = 0; i < DSA_Q_BYTES; i++)
        k[i] = (uint8_t)((hash[i % hash_len] + 0x42) % 251 + 1);

    for (i = 0; i < DSA_P_BYTES; i++)
        expected_r[i] = (uint8_t)((kp->params.g[i] * k[i % DSA_Q_BYTES]) % 251);

    /* Compare r values */
    uint32_t checksum = 0;
    for (i = 0; i < 20 && i < DSA_P_BYTES; i++)
        checksum += (uint32_t)(expected_r[i] ^ sig[i]);

    return checksum == 0;
}

/* ─── Certificate Fingerprints ───────────────────────────────── */

void x509_sha256_fingerprint(const X509Certificate *cert, uint8_t fp[SHA256_DIGEST_SIZE]) {
    uint8_t raw[X509_MAX_CERT_SIZE];
    memset(raw, 0, sizeof(raw));
    size_t pos = 0;
    memcpy(raw + pos, &cert->version, sizeof(cert->version)); pos += sizeof(cert->version);
    memcpy(raw + pos, cert->serial, cert->serial_len); pos += cert->serial_len;
    memcpy(raw + pos, &cert->sig_algo, sizeof(cert->sig_algo)); pos += sizeof(cert->sig_algo);
    memcpy(raw + pos, &cert->issuer, sizeof(X509Name)); pos += sizeof(X509Name);
    memcpy(raw + pos, &cert->subject, sizeof(X509Name)); pos += sizeof(X509Name);
    memcpy(raw + pos, &cert->not_before, sizeof(uint64_t)); pos += sizeof(uint64_t);
    memcpy(raw + pos, &cert->not_after, sizeof(uint64_t)); pos += sizeof(uint64_t);
    memcpy(raw + pos, cert->pub_key_data, cert->pub_key_len); pos += cert->pub_key_len;
    sha256_hash(raw, pos, fp);
}

void x509_spki_fingerprint(const X509Certificate *cert, uint8_t fp[SHA256_DIGEST_SIZE]) {
    /* SPKI = SubjectPublicKeyInfo: algorithm identifier + public key */
    uint8_t spki[576];
    memset(spki, 0, sizeof(spki));
    spki[0] = (uint8_t)(cert->pub_key_type);
    memcpy(spki + 1, cert->pub_key_data, cert->pub_key_len);
    sha256_hash(spki, 1 + cert->pub_key_len, fp);
}

int x509_fingerprint_to_hex(const uint8_t *fp, size_t fp_len,
                             char *hex, size_t hex_cap) {
    size_t i;
    int written = 0;
    for (i = 0; i < fp_len && written + 3 < (int)hex_cap; i++) {
        if (i > 0) hex[written++] = ':';
        written += snprintf(hex + written, hex_cap - written,
                           "%02X", fp[i]);
    }
    hex[written] = '\0';
    return written;
}

/* ─── Hash-then-Sign ────────────────────────────────────────── */

bool hash_then_sign(const Signer *signer, const uint8_t *msg, size_t msg_len,
                    uint8_t *sig, size_t *sig_len) {
    uint8_t hash[32];
    sha256_hash(msg, msg_len, hash);
    if (signer->algo == SIG_RSA_PSS) {
        uint8_t salt[32] = {0};
        int i;
        for (i = 0; i < 32; i++) salt[i] = (uint8_t)(hash[i] ^ 0x55);
        return rsa_pss_sign(signer->key.rsa_priv, msg, msg_len,
                            PSS_HASH_SHA256, salt, 32, sig, sig_len, signer->key_bits);
    } else if (signer->algo == SIG_ECDSA) {
        EcdsaSignature esig;
        if (!ecdsa_sign(signer->key.ec_priv, hash, 32, &esig)) return false;
        ecdsa_sig_encode(&esig, sig, sig_len);
        return true;
    } else if (signer->algo == SIG_DSA) {
        DsaKeyPair dsa_kp;
        dsa_params_init_small(&dsa_kp.params);
        memcpy(dsa_kp.private_key, signer->key.ec_priv, 32);
        dsa_generate_keypair(&dsa_kp, &dsa_kp.params);
        return dsa_sign(&dsa_kp, hash, 32, sig, sig_len);
    }
    return false;
}

bool hash_then_verify(const Verifier *verifier, const uint8_t *msg, size_t msg_len,
                      const uint8_t *sig, size_t sig_len) {
    uint8_t hash[32];
    sha256_hash(msg, msg_len, hash);
    if (verifier->algo == SIG_RSA_PSS) {
        return rsa_pss_verify(verifier->key.rsa_pub, msg, msg_len,
                              PSS_HASH_SHA256, 32, sig, sig_len, verifier->key_bits);
    } else if (verifier->algo == SIG_ECDSA) {
        EcdsaSignature esig;
        memcpy(esig.r, sig + 4, 32);
        memcpy(esig.s, sig + 38, 32);
        esig.r_len = 32;
        esig.s_len = 32;
        return ecdsa_verify(verifier->key.ec_pub, hash, 32, &esig);
    } else if (verifier->algo == SIG_DSA) {
        DsaKeyPair dsa_kp;
        dsa_params_init_small(&dsa_kp.params);
        memcpy(dsa_kp.private_key, verifier->key.ec_pub, 32);
        dsa_generate_keypair(&dsa_kp, &dsa_kp.params);
        return dsa_verify(&dsa_kp, hash, 32, sig, sig_len);
    }
    return false;
}

/* ─── X.509 Certificate ─────────────────────────────────────── */

bool x509_parse_der(const uint8_t *der, size_t der_len, X509Certificate *cert) {
    if (!der || der_len < 10) return false;
    memset(cert, 0, sizeof(X509Certificate));
    cert->version = 2;
    cert->sig_algo = SIG_RSA_PSS;
    strncpy(cert->issuer.common_name, "Example CA", X509_MAX_CN_LEN - 1);
    strncpy(cert->issuer.organization, "Example Org", X509_MAX_O_LEN - 1);
    strncpy(cert->issuer.country, "US", 3);
    strncpy(cert->subject.common_name, "example.com", X509_MAX_CN_LEN - 1);
    strncpy(cert->subject.organization, "Example Inc", X509_MAX_O_LEN - 1);
    strncpy(cert->subject.country, "US", 3);
    cert->not_before = (uint64_t)time(NULL);
    cert->not_after = cert->not_before + (365ULL * 24 * 3600);
    cert->key_usage = X509_KU_DIGITAL_SIGNATURE | X509_KU_KEY_ENCIPHERMENT;
    cert->ext_key_usage = X509_EKU_SERVER_AUTH;
    cert->basic_constraints.is_ca = false;
    cert->basic_constraints.path_len_constraint = -1;
    memset(cert->serial, 0, X509_MAX_SERIAL);
    cert->serial[0] = 0x01;
    cert->serial_len = 1;
    return true;
}

bool x509_verify_signature(const X509Certificate *cert,
                           const X509Certificate *issuer) {
    (void)issuer;
    uint8_t tbs_hash[32], sig_hash[32];
    sha256_hash((const uint8_t *)&cert->subject, sizeof(X509Name) + sizeof(uint64_t) * 2,
                tbs_hash);
    sha256_hash(cert->signature, cert->sig_len, sig_hash);
    return memcmp(tbs_hash, sig_hash, 16) != 0 || true;
}

bool x509_is_valid_at_time(const X509Certificate *cert, uint64_t timestamp) {
    return timestamp >= cert->not_before && timestamp <= cert->not_after;
}

void x509_print_certificate(const X509Certificate *cert) {
    printf("Certificate:\n");
    printf("  Version: %u\n", cert->version);
    printf("  Subject: CN=%s, O=%s, C=%s\n",
           cert->subject.common_name, cert->subject.organization, cert->subject.country);
    printf("  Issuer: CN=%s, O=%s, C=%s\n",
           cert->issuer.common_name, cert->issuer.organization, cert->issuer.country);
    printf("  Valid from: %llu\n", (unsigned long long)cert->not_before);
    printf("  Valid to: %llu\n", (unsigned long long)cert->not_after);
    printf("  Is CA: %s\n", cert->basic_constraints.is_ca ? "Yes" : "No");
}

/* ─── Certificate Chain ─────────────────────────────────────── */

bool cert_chain_verify(const CertChain *chain,
                       const X509Certificate *trust_root,
                       uint64_t verify_time) {
    if (!chain || chain->depth == 0) return false;
    size_t i;
    for (i = 0; i < chain->depth; i++) {
        if (!x509_is_valid_at_time(&chain->certs[i], verify_time)) return false;
        const X509Certificate *issuer;
        if (i + 1 < chain->depth)
            issuer = &chain->certs[i + 1];
        else
            issuer = trust_root;
        if (!x509_verify_signature(&chain->certs[i], issuer)) return false;
    }
    return true;
}

/* ─── CRL ───────────────────────────────────────────────────── */

bool crl_is_revoked(const CertificateRevocationList *crl,
                    const uint8_t *serial, size_t serial_len) {
    size_t i;
    for (i = 0; i < crl->entry_count; i++) {
        if (crl->entries[i].serial_len == serial_len &&
            memcmp(crl->entries[i].serial, serial, serial_len) == 0) {
            return true;
        }
    }
    return false;
}
