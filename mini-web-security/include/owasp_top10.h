#ifndef OWASP_TOP10_H
#define OWASP_TOP10_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── OWASP Top 10 Categories (2021) ──────────────────────────────── */

typedef enum {
    OWASP_A01_BROKEN_ACCESS_CONTROL,
    OWASP_A02_CRYPTOGRAPHIC_FAILURES,
    OWASP_A03_INJECTION,
    OWASP_A04_INSECURE_DESIGN,
    OWASP_A05_SECURITY_MISCONFIGURATION,
    OWASP_A06_VULNERABLE_COMPONENTS,
    OWASP_A07_AUTH_FAILURES,
    OWASP_A08_SOFTWARE_DATA_INTEGRITY,
    OWASP_A09_LOGGING_MONITORING,
    OWASP_A10_SSRF
} owasp_category_t;

const char* owasp_category_name(owasp_category_t category);

const char* owasp_category_desc(owasp_category_t category);

/* ── Risk Assessment ─────────────────────────────────────────────── */

typedef enum {
    RISK_NONE,
    RISK_LOW,
    RISK_MEDIUM,
    RISK_HIGH,
    RISK_CRITICAL
} risk_level_t;

typedef struct {
    owasp_category_t category;
    risk_level_t      risk;
    const char*       detail;
    const char*       remediation;
} owasp_finding_t;

typedef struct {
    owasp_finding_t findings[32];
    int             count;
} owasp_report_t;

void owasp_report_init(owasp_report_t* report);

int  owasp_report_add(owasp_report_t* report, owasp_category_t cat,
                      risk_level_t risk, const char* detail, const char* fix);

/* ── A01: Broken Access Control ──────────────────────────────────── */

bool idor_check(const char* resource_id, const char* user_id, const char* owner_id);

bool idor_validate_ownership(const char* requested_id, const char** owned_ids, int count);

int  access_control_validate(const char* role, const char* resource, const char* action,
                             const char** allowed_roles, int role_count);

/* ── A02: Cryptographic Failures ─────────────────────────────────── */

typedef enum {
    CIPHER_MD5,
    CIPHER_SHA1,
    CIPHER_DES,
    CIPHER_RC4,
    CIPHER_3DES,
    CIPHER_AES128,
    CIPHER_AES256,
    CIPHER_SHA256,
    CIPHER_CHACHA20
} cipher_algorithm_t;

bool crypto_is_weak(cipher_algorithm_t algo);

bool crypto_check_key_length(cipher_algorithm_t algo, size_t key_len);

bool crypto_is_hardcoded_secret(const char* secret);

/* ── A10: SSRF ───────────────────────────────────────────────────── */

typedef struct {
    bool    is_blocked;
    bool    is_internal;
    int     risk_score;
    char    resolved_host[256];
    int     port;
    char    path[1024];
} ssrf_analysis_t;

int  ssrf_analyze_url(const char* url, ssrf_analysis_t* result);

bool ssrf_is_internal_ip(const char* host);

bool ssrf_is_loopback(const char* host);

bool ssrf_is_private_range(const char* host);

/* ── File Inclusion (LFI/RFI) ────────────────────────────────────── */

typedef enum {
    FI_NONE,
    FI_LFI,     /* Local File Inclusion */
    FI_RFI      /* Remote File Inclusion */
} file_inclusion_type_t;

typedef struct {
    file_inclusion_type_t type;
    bool                  detected;
    const char*           pattern;
    risk_level_t          risk;
} fi_result_t;

void fi_detect(const char* path_input, fi_result_t* result);

bool fi_is_lfi_payload(const char* path);

bool fi_is_rfi_payload(const char* path);

int  fi_sanitize_path(const char* input, char* output, size_t out_size);

/* ── Directory Traversal ─────────────────────────────────────────── */

typedef struct {
    bool    detected;
    int     depth_attempted;
    bool    null_byte;
    bool    encoding_abuse;
} dt_result_t;

void dt_detect(const char* path, dt_result_t* result);

int  dt_sanitize(const char* input, char* output, size_t out_size);

bool dt_is_traversal(const char* path);

char* dt_canonicalize(const char* path, char* output, size_t out_size);

/* ── Security Misconfiguration (A05) ─────────────────────────────── */

bool secmis_detect_debug_endpoint(const char* path);

bool secmis_detect_directory_listing(const char* response);

bool secmis_detect_default_credentials(const char* username, const char* password);

bool secmis_header_check(const char* header_name, const char* value);

/* ── Logging & Monitoring (A09) ──────────────────────────────────── */

typedef enum {
    LOG_AUDIT,
    LOG_AUTH,
    LOG_ACCESS,
    LOG_ERROR,
    LOG_INTRUSION
} log_event_type_t;

typedef struct {
    log_event_type_t type;
    time_t           timestamp;
    const char*      user;
    const char*      action;
    const char*      detail;
    const char*      source_ip;
} log_event_t;

void log_event_init(log_event_t* event, log_event_type_t type);

int  log_event_format(const log_event_t* event, char* output, size_t out_size);

bool log_monitor_anomaly(int event_count, time_t window_seconds, int threshold);

/* ── General OWASP Risk Scanning ─────────────────────────────────── */

int  owasp_scan_headers(const char** headers, int count, owasp_report_t* report);

int  owasp_scan_url(const char* url, owasp_report_t* report);

int  owasp_scan_response(const char* response, owasp_report_t* report);

#ifdef __cplusplus
}
#endif

#endif /* OWASP_TOP10_H */
