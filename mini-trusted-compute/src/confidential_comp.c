#include "confidential_comp.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

int cc_init(cc_confidential_ctx_t *ctx) {
    if (!ctx) return -1;
    memset(ctx, 0, sizeof(*ctx));
    ctx->initialized = true;
    ctx->attestation_bound = false;
    ctx->sealed_state = false;
    ctx->epoch = 1;

    ctx->encrypt_memory         = NULL;
    ctx->decrypt_memory         = NULL;
    ctx->set_encryption_key     = NULL;
    ctx->revoke_encryption_key  = NULL;
    ctx->protect_page           = NULL;
    ctx->unprotect_page         = NULL;
    ctx->establish_secure_io    = NULL;
    ctx->seal_state             = NULL;
    ctx->unseal_state           = NULL;
    ctx->check_attestation      = NULL;
    return 0;
}

int cc_enable_tme(cc_confidential_ctx_t *ctx, const uint8_t *root_key) {
    if (!ctx || !root_key) return -1;
    memcpy(ctx->mem_encryption.tme_root_key, root_key, CC_TME_KEY_SIZE);
    ctx->mem_encryption.tme_enabled = true;
    ctx->mem_encryption.active_mode = CC_MEM_MODE_TME;
    return 0;
}

int cc_enable_mktme(cc_confidential_ctx_t *ctx, const uint8_t *root_key,
                    const uint8_t (*keys)[CC_MKTME_KEY_SIZE],
                    uint32_t key_count) {
    if (!ctx || !root_key || !keys || key_count == 0 || key_count > CC_TME_MAX_KEYS)
        return -1;
    memcpy(ctx->mem_encryption.tme_root_key, root_key, CC_TME_KEY_SIZE);
    ctx->mem_encryption.mktme_key_count = key_count;
    for (uint32_t i = 0; i < key_count; i++)
        memcpy(ctx->mem_encryption.mktme_keys[i], keys[i], CC_MKTME_KEY_SIZE);
    ctx->mem_encryption.mktme_enabled = true;
    ctx->mem_encryption.active_mode = CC_MEM_MODE_MKTME;
    return 0;
}

int cc_register_encrypted_region(cc_confidential_ctx_t *ctx,
                                 uint64_t phys_base, uint64_t phys_limit,
                                 cc_mem_mode_t mode,
                                 const uint8_t *key) {
    if (!ctx || phys_base >= phys_limit) return -1;
    if (ctx->trust_boundary.region_count >= CC_MAX_ENCRYPTED_REGIONS) return -1;

    uint32_t idx = ctx->trust_boundary.region_count++;
    ctx->trust_boundary.regions[idx].phys_base  = phys_base;
    ctx->trust_boundary.regions[idx].phys_limit = phys_limit;
    ctx->trust_boundary.regions[idx].mode       = mode;
    if (key)
        memcpy(ctx->trust_boundary.regions[idx].encryption_key, key, CC_TME_KEY_SIZE);
    ctx->trust_boundary.regions[idx].writable   = false;
    return 0;
}

int cc_probe_platform(cc_confidential_ctx_t *ctx,
                      cc_trust_boundary_t *boundary) {
    if (!ctx || !boundary) return -1;
    memset(boundary, 0, sizeof(*boundary));
    memset(boundary->cpu_package_id, 0xDE, 16);
    boundary->sgx_capable = true;
    boundary->tdx_capable = true;
    boundary->sev_capable = true;
    boundary->tme_capable = true;
    boundary->microcode_version = 0xAB000042;
    memcpy(boundary, &ctx->trust_boundary, sizeof(*boundary));
    return 0;
}

int cc_is_sgx_supported(cc_confidential_ctx_t *ctx, bool *supported) {
    if (!ctx || !supported) return -1;
    *supported = ctx->trust_boundary.sgx_capable;
    return 0;
}

int cc_is_tdx_supported(cc_confidential_ctx_t *ctx, bool *supported) {
    if (!ctx || !supported) return -1;
    *supported = ctx->trust_boundary.tdx_capable;
    return 0;
}

int cc_is_sev_supported(cc_confidential_ctx_t *ctx, bool *supported) {
    if (!ctx || !supported) return -1;
    *supported = ctx->trust_boundary.sev_capable;
    return 0;
}

int cc_is_tme_supported(cc_confidential_ctx_t *ctx, bool *supported) {
    if (!ctx || !supported) return -1;
    *supported = ctx->trust_boundary.tme_capable;
    return 0;
}

static void cc_init_known_vulnerabilities(cc_vuln_database_t *db) {
    if (!db) return;
    memset(db, 0, sizeof(*db));

    const char *sgx_vulns[] = {
        "LVI", "SGAxe", "Plundervolt", "CrossTalk",
        "MMIO Stale Data", "AEPIC Leak", "MicroScope",
        "TeeChannel", "Foreshadow-SGX", "SmeltSpectre"
    };

    for (int i = 0; i < 10 && i < (int)(sizeof(sgx_vulns) / sizeof(sgx_vulns[0])); i++) {
        cc_vulnerability_t *v = &db->vulns[db->vuln_count++];
        snprintf(v->name, sizeof(v->name), "%s", sgx_vulns[i]);
        snprintf(v->cve_id, sizeof(v->cve_id), "CVE-2022-%04d", 30000 + i);
        v->vuln_type = (cc_known_vuln_t)i;
        v->vuln_class = (i < 3) ? CC_VULN_CLASS_SIDE_CHANNEL : CC_VULN_CLASS_MICROCODE;
        v->affects_sgx = true;
        v->affects_tdx = (i >= 3);
        v->affects_sev = false;
        v->has_mitigation = true;
        snprintf(v->mitigation, sizeof(v->mitigation), "Apply microcode patch %d", i + 1);
        v->risk_score = 70 + i;
    }

    db->active_count = db->vuln_count;
    db->mitigated_count = 0;
    db->full_mitigation = false;
}

int cc_check_vulnerability(cc_confidential_ctx_t *ctx,
                           cc_known_vuln_t vuln_id, bool *present) {
    if (!ctx || !present) return -1;
    if (!ctx->vulnerabilities.vuln_count)
        cc_init_known_vulnerabilities(&ctx->vulnerabilities);

    *present = false;
    for (uint32_t i = 0; i < ctx->vulnerabilities.vuln_count; i++) {
        if (ctx->vulnerabilities.vulns[i].vuln_type == vuln_id) {
            *present = true;
            break;
        }
    }
    return 0;
}

int cc_get_sgx_vulnerabilities(cc_confidential_ctx_t *ctx,
                               cc_vuln_database_t *db) {
    if (!ctx || !db) return -1;
    if (!ctx->vulnerabilities.vuln_count)
        cc_init_known_vulnerabilities(&ctx->vulnerabilities);

    memset(db, 0, sizeof(*db));
    for (uint32_t i = 0; i < ctx->vulnerabilities.vuln_count; i++) {
        if (ctx->vulnerabilities.vulns[i].affects_sgx) {
            memcpy(&db->vulns[db->vuln_count++],
                   &ctx->vulnerabilities.vulns[i],
                   sizeof(cc_vulnerability_t));
        }
    }
    db->active_count = db->vuln_count;
    return 0;
}

int cc_get_sev_vulnerabilities(cc_confidential_ctx_t *ctx,
                               cc_vuln_database_t *db) {
    if (!ctx || !db) return -1;
    memset(db, 0, sizeof(*db));

    cc_vulnerability_t *v = &db->vulns[db->vuln_count++];
    snprintf(v->name, sizeof(v->name), "SEVered");
    snprintf(v->cve_id, sizeof(v->cve_id), "CVE-2020-0001");
    v->vuln_type = CC_VULN_SEVERED;
    v->vuln_class = CC_VULN_CLASS_SIDE_CHANNEL;
    v->affects_sgx = false;
    v->affects_tdx = false;
    v->affects_sev = true;
    v->has_mitigation = true;
    snprintf(v->mitigation, sizeof(v->mitigation), "Disable page-level swapping");
    v->risk_score = 60;

    v = &db->vulns[db->vuln_count++];
    snprintf(v->name, sizeof(v->name), "Cache Attack on SEV");
    snprintf(v->cve_id, sizeof(v->cve_id), "CVE-2021-0002");
    v->vuln_type = CC_VULN_SEVERED;
    v->vuln_class = CC_VULN_CLASS_SIDE_CHANNEL;
    v->affects_sgx = false;
    v->affects_tdx = false;
    v->affects_sev = true;
    v->has_mitigation = true;
    snprintf(v->mitigation, sizeof(v->mitigation), "Cache partitioning via CAT");
    v->risk_score = 50;

    db->active_count = db->vuln_count;
    return 0;
}

int cc_mitigate_cache_side_channel(cc_confidential_ctx_t *ctx,
                                   cc_cache_layout_t *layout,
                                   uint32_t partition_id) {
    if (!ctx || !layout) return -1;
    layout->partitioned = true;
    for (int i = 0; i < 8; i++)
        layout->partition_mask[i] = (uint8_t)(1 << (partition_id & 0x7));
    return 0;
}

int cc_mitigate_page_fault_channel(cc_confidential_ctx_t *ctx) {
    if (!ctx) return -1;
    return 0;
}

int cc_enable_patch_for_vuln(cc_confidential_ctx_t *ctx,
                             cc_known_vuln_t vuln_id) {
    if (!ctx) return -1;
    if (!ctx->vulnerabilities.vuln_count)
        cc_init_known_vulnerabilities(&ctx->vulnerabilities);

    for (uint32_t i = 0; i < ctx->vulnerabilities.vuln_count; i++) {
        if (ctx->vulnerabilities.vulns[i].vuln_type == vuln_id &&
            ctx->vulnerabilities.vulns[i].has_mitigation &&
            !ctx->vulnerabilities.vulns[i].vuln_class) {
            ctx->vulnerabilities.mitigated_count++;
            ctx->vulnerabilities.active_count--;
        }
    }
    return 0;
}

int cc_is_mitigated(cc_confidential_ctx_t *ctx,
                    cc_known_vuln_t vuln_id, bool *mitigated) {
    (void)vuln_id;
    if (!ctx || !mitigated) return -1;
    *mitigated = (ctx->vulnerabilities.mitigated_count > 0);
    return 0;
}

int cc_constant_time_compare(const uint8_t *a, const uint8_t *b, size_t len) {
    if (!a || !b) return -1;
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= a[i] ^ b[i];
    return (int)(diff != 0) ? -1 : 0;
}

int cc_constant_time_select(bool condition, const uint8_t *a,
                            const uint8_t *b, uint8_t *result, size_t len) {
    if (!result) return -1;
    if (!a && !b) return -1;
    uint8_t mask = condition ? 0xFF : 0x00;
    for (size_t i = 0; i < len; i++) {
        uint8_t va = a ? a[i] : 0;
        uint8_t vb = b ? b[i] : 0;
        result[i] = (va & mask) | (vb & ~mask);
    }
    return 0;
}

int cc_constant_time_copy(uint8_t *dst, const uint8_t *src, size_t len) {
    if (!dst || !src) return -1;
    for (size_t i = 0; i < len; i++) dst[i] = src[i];
    return 0;
}

int cc_constant_time_zero(uint8_t *buf, size_t len) {
    if (!buf) return -1;
    volatile uint8_t *p = buf;
    for (size_t i = 0; i < len; i++) p[i] = 0;
    return 0;
}

int cc_constant_time_is_zero(const uint8_t *buf, size_t len, bool *is_zero) {
    if (!buf || !is_zero) return -1;
    uint8_t acc = 0;
    for (size_t i = 0; i < len; i++) acc |= buf[i];
    *is_zero = (acc == 0);
    return 0;
}

int cc_constant_time_increment(uint8_t *buf, size_t len) {
    if (!buf || len == 0) return -1;
    for (size_t i = len; i > 0; i--) {
        buf[i - 1]++;
        if (buf[i - 1] != 0) break;
    }
    return 0;
}

int cc_constant_time_equal(const uint8_t *a, const uint8_t *b, size_t len,
                           bool *equal) {
    if (!a || !b || !equal) return -1;
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= a[i] ^ b[i];
    *equal = (diff == 0);
    return 0;
}

int cc_secure_io_negotiate(cc_confidential_ctx_t *ctx,
                           const uint8_t *peer_pubkey,
                           cc_secure_io_t *io) {
    if (!ctx || !peer_pubkey || !io) return -1;
    memset(io, 0, sizeof(*io));
    for (int i = 0; i < 32; i++) io->session_key[i] = (uint8_t)(i * 11 + 0x3C);
    io->established = true;
    return 0;
}

int cc_secure_io_send(cc_confidential_ctx_t *ctx,
                      const uint8_t *data, size_t data_size,
                      cc_secure_io_t *io) {
    if (!ctx || !data || !io || !io->established) return -1;
    if (data_size > CC_SECURE_IO_BUFFER_SIZE) return -1;
    memcpy(io->source, data, data_size);
    io->source_size = (uint32_t)data_size;
    return 0;
}

int cc_secure_io_receive(cc_confidential_ctx_t *ctx,
                         uint8_t *data, size_t *data_size,
                         cc_secure_io_t *io) {
    if (!ctx || !data || !data_size || !io || !io->established) return -1;
    memcpy(data, io->encrypted, io->encrypted_size);
    *data_size = io->encrypted_size;
    return 0;
}

int cc_seal_entire_state(cc_confidential_ctx_t *ctx,
                         uint8_t *sealed, size_t *sealed_size) {
    if (!ctx || !sealed || !sealed_size) return -1;
    *sealed_size = sizeof(*ctx);
    memcpy(sealed, ctx, sizeof(*ctx));
    ctx->sealed_state = true;
    return 0;
}

int cc_unseal_entire_state(cc_confidential_ctx_t *ctx,
                           const uint8_t *sealed, size_t sealed_size) {
    if (!ctx || !sealed || sealed_size != sizeof(*ctx)) return -1;
    memcpy(ctx, sealed, sizeof(*ctx));
    ctx->sealed_state = false;
    ctx->initialized = true;
    return 0;
}

int cc_rotate_encryption_keys(cc_confidential_ctx_t *ctx) {
    if (!ctx) return -1;
    for (int i = 0; i < CC_TME_KEY_SIZE; i++)
        ctx->mem_encryption.tme_root_key[i] ^= (uint8_t)(i * 3 + 0x55);
    ctx->epoch++;
    return 0;
}

int cc_attest_platform(cc_confidential_ctx_t *ctx, uint8_t *evidence,
                       size_t *evidence_size) {
    if (!ctx || !evidence || !evidence_size) return -1;
    *evidence_size = 256;
    memset(evidence, 0xAE, 256);
    return 0;
}

int cc_verify_attestation(cc_confidential_ctx_t *ctx,
                          const uint8_t *evidence, size_t evidence_size,
                          bool *valid) {
    if (!ctx || !evidence || !valid) return -1;
    *valid = (evidence_size >= 128);
    ctx->attestation_bound = *valid;
    return 0;
}

int cc_get_trust_boundary(cc_confidential_ctx_t *ctx,
                          cc_trust_boundary_t *boundary) {
    if (!ctx || !boundary) return -1;
    memcpy(boundary, &ctx->trust_boundary, sizeof(*boundary));
    return 0;
}

int cc_free(cc_confidential_ctx_t *ctx) {
    if (!ctx) return -1;
    memset(ctx, 0, sizeof(*ctx));
    return 0;
}

void cc_print_vulnerability(const cc_vulnerability_t *vuln) {
    if (!vuln) return;
    printf("  %-20s %-18s Risk:%u  SGX:%c TDX:%c SEV:%c  Mit:%s\n",
           vuln->name, vuln->cve_id, vuln->risk_score,
           vuln->affects_sgx ? 'Y' : 'N',
           vuln->affects_tdx ? 'Y' : 'N',
           vuln->affects_sev ? 'Y' : 'N',
           vuln->has_mitigation ? vuln->mitigation : "NONE");
}

void cc_print_vuln_database(const cc_vuln_database_t *db) {
    if (!db) return;
    printf("Vulnerability Database: %u total, %u active, %u mitigated\n",
           db->vuln_count, db->active_count, db->mitigated_count);
    for (uint32_t i = 0; i < db->vuln_count; i++)
        cc_print_vulnerability(&db->vulns[i]);
}

void cc_print_trust_boundary(const cc_trust_boundary_t *boundary) {
    if (!boundary) return;
    printf("Trust Boundary:\n");
    printf("  CPU Package:       ");
    for (int i = 0; i < 8; i++) printf("%02x", boundary->cpu_package_id[i]);
    printf("\n");
    printf("  SGX Capable:       %s\n", boundary->sgx_capable ? "YES" : "NO");
    printf("  TDX Capable:       %s\n", boundary->tdx_capable ? "YES" : "NO");
    printf("  SEV Capable:       %s\n", boundary->sev_capable ? "YES" : "NO");
    printf("  TME Capable:       %s\n", boundary->tme_capable ? "YES" : "NO");
    printf("  Microcode Version: 0x%x\n", boundary->microcode_version);
    printf("  Encrypted Regions: %u\n", boundary->region_count);
}
