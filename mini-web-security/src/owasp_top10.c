#include "owasp_top10.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

const char* owasp_category_name(owasp_category_t category) {
    switch (category) {
    case OWASP_A01_BROKEN_ACCESS_CONTROL:   return "A01: Broken Access Control";
    case OWASP_A02_CRYPTOGRAPHIC_FAILURES:   return "A02: Cryptographic Failures";
    case OWASP_A03_INJECTION:                return "A03: Injection";
    case OWASP_A04_INSECURE_DESIGN:          return "A04: Insecure Design";
    case OWASP_A05_SECURITY_MISCONFIGURATION:return "A05: Security Misconfiguration";
    case OWASP_A06_VULNERABLE_COMPONENTS:    return "A06: Vulnerable & Outdated Components";
    case OWASP_A07_AUTH_FAILURES:            return "A07: Identification & Authentication Failures";
    case OWASP_A08_SOFTWARE_DATA_INTEGRITY:  return "A08: Software & Data Integrity Failures";
    case OWASP_A09_LOGGING_MONITORING:       return "A09: Security Logging & Monitoring Failures";
    case OWASP_A10_SSRF:                     return "A10: Server-Side Request Forgery";
    }
    return "Unknown";
}

const char* owasp_category_desc(owasp_category_t category) {
    switch (category) {
    case OWASP_A01_BROKEN_ACCESS_CONTROL:
        return "Restrictions on authenticated users not properly enforced";
    case OWASP_A02_CRYPTOGRAPHIC_FAILURES:
        return "Sensitive data exposed due to weak or missing cryptography";
    case OWASP_A03_INJECTION:
        return "User-supplied data interpreted as commands or queries";
    case OWASP_A04_INSECURE_DESIGN:
        return "Missing or ineffective control design flaws";
    case OWASP_A05_SECURITY_MISCONFIGURATION:
        return "Missing security hardening across the application stack";
    case OWASP_A06_VULNERABLE_COMPONENTS:
        return "Using unsupported, outdated, or vulnerable software";
    case OWASP_A07_AUTH_FAILURES:
        return "Weaknesses in authentication and session management";
    case OWASP_A08_SOFTWARE_DATA_INTEGRITY:
        return "Code and infrastructure not protected against integrity violations";
    case OWASP_A09_LOGGING_MONITORING:
        return "Insufficient logging, detection, monitoring, and response";
    case OWASP_A10_SSRF:
        return "Server fetches URL without validating the target";
    }
    return "Unknown";
}

void owasp_report_init(owasp_report_t* report) {
    if (!report) return;
    memset(report, 0, sizeof(*report));
}

int owasp_report_add(owasp_report_t* report, owasp_category_t cat,
                     risk_level_t risk, const char* detail, const char* fix) {
    if (!report || report->count >= 32) return -1;
    report->findings[report->count].category = cat;
    report->findings[report->count].risk = risk;
    report->findings[report->count].detail = detail;
    report->findings[report->count].remediation = fix;
    report->count++;
    return 0;
}

bool idor_check(const char* resource_id, const char* user_id, const char* owner_id) {
    if (!resource_id || !user_id || !owner_id) return false;
    return strcmp(user_id, owner_id) == 0;
}

bool idor_validate_ownership(const char* requested_id, const char** owned_ids, int count) {
    if (!requested_id || !owned_ids) return false;
    for (int i = 0; i < count; i++) {
        if (owned_ids[i] && strcmp(requested_id, owned_ids[i]) == 0) return true;
    }
    return false;
}

int access_control_validate(const char* role, const char* resource, const char* action,
                            const char** allowed_roles, int role_count) {
    if (!role || !allowed_roles) return -1;
    for (int i = 0; i < role_count; i++) {
        if (allowed_roles[i] && strcmp(role, allowed_roles[i]) == 0) return 1;
    }
    (void)resource; (void)action;
    return 0;
}

bool crypto_is_weak(cipher_algorithm_t algo) {
    switch (algo) {
    case CIPHER_MD5:  case CIPHER_SHA1: case CIPHER_DES:
    case CIPHER_RC4:  case CIPHER_3DES: return true;
    default: return false;
    }
}

bool crypto_check_key_length(cipher_algorithm_t algo, size_t key_len) {
    switch (algo) {
    case CIPHER_AES128: return key_len >= 16;
    case CIPHER_AES256: return key_len >= 32;
    case CIPHER_SHA256: return key_len >= 16;
    case CIPHER_CHACHA20: return key_len == 32;
    case CIPHER_DES: return key_len == 8;
    case CIPHER_3DES: return key_len == 24;
    default: return key_len >= 16;
    }
}

bool crypto_is_hardcoded_secret(const char* secret) {
    if (!secret) return true;
    const char* weak[] = {"password", "123456", "admin", "secret",
                           "changeme", "default", "test", "qwerty", NULL};
    for (int i = 0; weak[i]; i++) {
        if (strcmp(secret, weak[i]) == 0) return true;
    }
    return strlen(secret) < 8;
}

static bool is_ipv4_digit(const char* s) {
    while (*s) { if (!isdigit((unsigned char)*s) && *s != '.') return false; s++; }
    return true;
}

static bool is_ipv6_char(const char* s) {
    while (*s) {
        if (!isxdigit((unsigned char)*s) && *s != ':' && *s != '.') return false;
        s++;
    }
    return true;
}

int ssrf_analyze_url(const char* url, ssrf_analysis_t* result) {
    if (!result) return -1;
    memset(result, 0, sizeof(*result));
    if (!url) return -1;
    const char* p = url;
    if (strncmp(p, "http://", 7) == 0) p += 7;
    else if (strncmp(p, "https://", 8) == 0) p += 8;
    else if (strncmp(p, "ftp://", 6) == 0) p += 6;
    else return -1;
    const char* host_start = p;
    size_t host_len = 0;
    while (*p && *p != ':' && *p != '/' && *p != '?' && *p != '#') { p++; host_len++; }
    if (host_len >= sizeof(result->resolved_host)) host_len = sizeof(result->resolved_host) - 1;
    memcpy(result->resolved_host, host_start, host_len);
    result->resolved_host[host_len] = '\0';
    if (*p == ':') { p++; result->port = atoi(p); }
    if (result->port == 0) result->port = 80;
    while (*p && *p != '/' && *p != '?' && *p != '#') p++;
    if (*p == '/') {
        const char* path_start = p;
        size_t plen = 0;
        while (*p) { p++; plen++; }
        if (plen >= sizeof(result->path)) plen = sizeof(result->path) - 1;
        memcpy(result->path, path_start, plen);
        result->path[plen] = '\0';
    }
    result->is_internal = ssrf_is_internal_ip(result->resolved_host) ||
                          ssrf_is_loopback(result->resolved_host);
    result->is_blocked = result->is_internal;
    result->risk_score = result->is_internal ? 90 : 10;
    return 0;
}

bool ssrf_is_internal_ip(const char* host) {
    if (!host) return false;
    if (ssrf_is_loopback(host)) return true;
    if (ssrf_is_private_range(host)) return true;
    return false;
}

bool ssrf_is_loopback(const char* host) {
    if (!host) return false;
    if (strcmp(host, "localhost") == 0 || strcmp(host, "127.0.0.1") == 0 ||
        strcmp(host, "0.0.0.0") == 0 || strcmp(host, "::1") == 0) return true;
    return strncmp(host, "127.", 4) == 0 && is_ipv4_digit(host);
}

bool ssrf_is_private_range(const char* host) {
    if (!host || !is_ipv4_digit(host)) return false;
    unsigned int a = 0, b = 0, c = 0, d = 0;
    if (sscanf(host, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return false;
    if (a == 10) return true;
    if (a == 172 && b >= 16 && b <= 31) return true;
    if (a == 192 && b == 168) return true;
    if (a == 169 && b == 254) return true;
    if (a >= 224) return true;
    return false;
}

void fi_detect(const char* path_input, fi_result_t* result) {
    if (!result) return;
    memset(result, 0, sizeof(*result));
    if (!path_input) return;
    if (fi_is_rfi_payload(path_input)) {
        result->type = FI_RFI;
        result->detected = true;
        result->risk = RISK_CRITICAL;
        return;
    }
    if (fi_is_lfi_payload(path_input)) {
        result->type = FI_LFI;
        result->detected = true;
        result->risk = RISK_HIGH;
    }
}

bool fi_is_lfi_payload(const char* path) {
    if (!path) return false;
    const char* patterns[] = {"../", "..\\", "/etc/passwd", "/etc/shadow",
                               "/etc/hosts", "C:\\Windows\\", "C:\\boot.ini",
                               "/proc/self/", "php://filter", "file://",
                               "expect://", "data://", "zip://", NULL};
    for (int i = 0; patterns[i]; i++) {
        if (strstr(path, patterns[i])) return true;
    }
    return false;
}

bool fi_is_rfi_payload(const char* path) {
    if (!path) return false;
    if (strstr(path, "http://") || strstr(path, "https://") ||
        strstr(path, "ftp://")) return true;
    return false;
}

int fi_sanitize_path(const char* input, char* output, size_t out_size) {
    if (!input || !output || out_size == 0) return 0;
    size_t out_pos = 0;
    for (size_t i = 0; input[i] && out_pos < out_size - 1; i++) {
        if (isalnum((unsigned char)input[i]) || input[i] == '_' || input[i] == '-' ||
            input[i] == '.' || input[i] == '/') {
            output[out_pos++] = input[i];
        }
    }
    output[out_pos] = '\0';
    return (int)out_pos;
}

void dt_detect(const char* path, dt_result_t* result) {
    if (!result) return;
    memset(result, 0, sizeof(*result));
    if (!path) return;
    if (strstr(path, "../") || strstr(path, "..\\")) {
        result->detected = true;
        const char* p = path;
        while ((p = strstr(p, "..")) != NULL) { result->depth_attempted++; p += 2; }
    }
    if (strchr(path, '\0') && strchr(path, '.')) result->null_byte = true;
    if (strstr(path, "%2e%2e") || strstr(path, "%252e")) result->encoding_abuse = true;
}

int dt_sanitize(const char* input, char* output, size_t out_size) {
    if (!input || !output || out_size == 0) return 0;
    size_t out_pos = 0;
    for (size_t i = 0; input[i] && out_pos < out_size - 1; i++) {
        if (input[i] == '.' && input[i+1] == '.' && out_pos > 0) {
            if (out_pos > 0 && output[out_pos-1] == '/' ) {
                out_pos--;
                while (out_pos > 0 && output[out_pos-1] != '/') out_pos--;
            }
            i++;
            continue;
        }
        if (isalnum((unsigned char)input[i]) || input[i] == '_' || input[i] == '-' ||
            input[i] == '.') {
            output[out_pos++] = input[i];
        }
        if (input[i] == '/' || input[i] == '\\') output[out_pos++] = '/';
    }
    output[out_pos] = '\0';
    return (int)out_pos;
}

bool dt_is_traversal(const char* path) {
    if (!path) return false;
    return strstr(path, "../") || strstr(path, "..\\") ||
           strstr(path, "%2e%2e") || strstr(path, "%252e");
}

char* dt_canonicalize(const char* path, char* output, size_t out_size) {
    dt_sanitize(path, output, out_size);
    return output;
}

bool secmis_detect_debug_endpoint(const char* path) {
    if (!path) return false;
    const char* debug_paths[] = {"/debug", "/debug/", "/phpinfo.php", "/info.php",
                                  "/test", "/admin/console", "/.env", "/wp-admin",
                                  "/api/debug", "/actuator", "/swagger", NULL};
    for (int i = 0; debug_paths[i]; i++) {
        if (strstr(path, debug_paths[i])) return true;
    }
    return false;
}

bool secmis_detect_directory_listing(const char* response) {
    if (!response) return false;
    return strstr(response, "Index of /") || strstr(response, "Directory Listing") ||
           strstr(response, "Parent Directory");
}

bool secmis_detect_default_credentials(const char* username, const char* password) {
    const char* defaults[] = {"admin:admin", "admin:password", "root:root",
                               "guest:guest", "admin:123456", "user:user", NULL};
    if (!username || !password) return false;
    char combo[128];
    snprintf(combo, sizeof(combo), "%s:%s", username, password);
    for (int i = 0; defaults[i]; i++) {
        if (strcmp(combo, defaults[i]) == 0) return true;
    }
    return false;
}

bool secmis_header_check(const char* header_name, const char* value) {
    if (!header_name || !value) return false;
    if (strcmp(header_name, "X-Frame-Options") == 0) return strlen(value) > 0;
    if (strcmp(header_name, "X-Content-Type-Options") == 0)
        return strcmp(value, "nosniff") == 0;
    if (strcmp(header_name, "Strict-Transport-Security") == 0)
        return strstr(value, "max-age") != NULL;
    if (strcmp(header_name, "X-XSS-Protection") == 0) return true;
    return true;
}

void log_event_init(log_event_t* event, log_event_type_t type) {
    if (!event) return;
    memset(event, 0, sizeof(*event));
    event->type = type;
    event->timestamp = time(NULL);
}

int log_event_format(const log_event_t* event, char* output, size_t out_size) {
    if (!event || !output) return 0;
    char time_buf[32];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", localtime(&event->timestamp));
    const char* type_str = "UNKNOWN";
    switch (event->type) {
    case LOG_AUDIT: type_str = "AUDIT"; break;
    case LOG_AUTH: type_str = "AUTH"; break;
    case LOG_ACCESS: type_str = "ACCESS"; break;
    case LOG_ERROR: type_str = "ERROR"; break;
    case LOG_INTRUSION: type_str = "INTRUSION"; break;
    }
    return snprintf(output, out_size, "[%s] [%s] user=%s action=%s ip=%s detail=%s",
                    time_buf, type_str,
                    event->user ? event->user : "-",
                    event->action ? event->action : "-",
                    event->source_ip ? event->source_ip : "-",
                    event->detail ? event->detail : "-");
}

bool log_monitor_anomaly(int event_count, time_t window_seconds, int threshold) {
    if (window_seconds <= 0 || threshold <= 0) return false;
    return event_count > threshold;
}

int owasp_scan_headers(const char** headers, int count, owasp_report_t* report) {
    if (!report) return 0;
    int found = 0;
    bool has_hsts = false, has_xfo = false, has_cto = false, has_csp = false;
    for (int i = 0; i < count && headers[i]; i++) {
        if (strncmp(headers[i], "Strict-Transport-Security", 25) == 0) has_hsts = true;
        if (strncmp(headers[i], "X-Frame-Options", 15) == 0) has_xfo = true;
        if (strncmp(headers[i], "X-Content-Type-Options", 22) == 0) has_cto = true;
        if (strncmp(headers[i], "Content-Security-Policy", 22) == 0) has_csp = true;
    }
    if (!has_hsts)
        owasp_report_add(report, OWASP_A05_SECURITY_MISCONFIGURATION, RISK_MEDIUM,
                         "Missing HSTS header", "Add Strict-Transport-Security header");
    if (!has_xfo)
        owasp_report_add(report, OWASP_A05_SECURITY_MISCONFIGURATION, RISK_HIGH,
                         "Missing X-Frame-Options", "Add X-Frame-Options: DENY");
    if (!has_csp)
        owasp_report_add(report, OWASP_A05_SECURITY_MISCONFIGURATION, RISK_MEDIUM,
                         "Missing CSP header", "Add Content-Security-Policy header");
    found = (!has_hsts) + (!has_xfo) + (!has_csp);
    (void)has_cto;
    return found;
}

int owasp_scan_url(const char* url, owasp_report_t* report) {
    if (!report) return 0;
    int found = 0;
    if (strstr(url, "admin") || strstr(url, "config") || strstr(url, "backup")) {
        owasp_report_add(report, OWASP_A01_BROKEN_ACCESS_CONTROL, RISK_MEDIUM,
                         "Sensitive path in URL", "Restrict access with authentication");
        found++;
    }
    if (strstr(url, "password=") || strstr(url, "token=") || strstr(url, "key=")) {
        owasp_report_add(report, OWASP_A02_CRYPTOGRAPHIC_FAILURES, RISK_HIGH,
                         "Sensitive data in URL query", "Use POST with encrypted body");
        found++;
    }
    return found;
}

int owasp_scan_response(const char* response, owasp_report_t* report) {
    if (!response || !report) return 0;
    int found = 0;
    if (strstr(response, "MySQL error") || strstr(response, "SQL syntax") ||
        strstr(response, "ORA-") || strstr(response, "PostgreSQL")) {
        owasp_report_add(report, OWASP_A03_INJECTION, RISK_HIGH,
                         "Database error exposed in response", "Use generic error messages");
        found++;
    }
    if (strstr(response, "Stack trace") || strstr(response, "at ")) {
        owasp_report_add(report, OWASP_A05_SECURITY_MISCONFIGURATION, RISK_MEDIUM,
                         "Stack trace exposed", "Disable debug mode in production");
        found++;
    }
    return found;
}
