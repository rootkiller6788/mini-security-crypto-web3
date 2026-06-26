#ifndef XSS_CSRF_H
#define XSS_CSRF_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── XSS Types ───────────────────────────────────────────────────── */

typedef enum {
    XSS_TYPE_REFLECTED,
    XSS_TYPE_STORED,
    XSS_TYPE_DOM_BASED,
    XSS_TYPE_UNKNOWN
} xss_type_t;

typedef struct {
    xss_type_t type;
    const char* source;
    const char* payload;
    bool detected;
} xss_report_t;

/* ── HTML Entity Encoding ────────────────────────────────────────── */

typedef struct {
    const char  raw;
    const char* entity;
} html_entity_t;

size_t html_encode(const char* input, char* output, size_t out_size);
size_t html_attribute_encode(const char* input, char* output, size_t out_size);
size_t js_string_encode(const char* input, char* output, size_t out_size);

bool html_decode(const char* input, char* output, size_t out_size);

/* ── XSS Detection & Sanitization ────────────────────────────────── */

void xss_detect_reflected(const char* input, const char* context, xss_report_t* report);
void xss_detect_stored(const char* db_content, xss_report_t* report);
void xss_detect_dom(const char* js_sink, const char* source, xss_report_t* report);

int  xss_sanitize_html(const char* input, char* output, size_t out_size);
int  xss_sanitize_attribute(const char* input, char* output, size_t out_size);
int  xss_sanitize_javascript(const char* input, char* output, size_t out_size);
int  xss_sanitize_url(const char* input, char* output, size_t out_size);

/* ── Content Security Policy (CSP) ───────────────────────────────── */

typedef enum {
    CSP_SRC_DEFAULT,
    CSP_SRC_SCRIPT,
    CSP_SRC_STYLE,
    CSP_SRC_IMG,
    CSP_SRC_CONNECT,
    CSP_SRC_FONT,
    CSP_SRC_OBJECT,
    CSP_SRC_MEDIA,
    CSP_SRC_FRAME,
    CSP_SRC_WORKER,
    CSP_SRC_MANIFEST,
    CSP_SRC_FORM_ACTION,
    CSP_SRC_BASE_URI,
    CSP_SRC_FRAME_ANCESTORS
} csp_source_t;

typedef struct {
    csp_source_t source;
    const char*  value;
} csp_directive_t;

typedef struct {
    csp_directive_t directives[16];
    int             count;
    bool            report_only;
    const char*     report_uri;
} csp_policy_t;

void csp_init(csp_policy_t* policy, bool report_only);

int  csp_add_directive(csp_policy_t* policy, csp_source_t src, const char* value);

int  csp_generate_header(const csp_policy_t* policy, char* output, size_t out_size);

void csp_generate_nonce(char* output, size_t out_size);
void csp_generate_hash(const char* content, char* output, size_t out_size);

/* ── CSRF Protection ─────────────────────────────────────────────── */

typedef struct {
    unsigned char data[32];
    size_t        len;
} csrf_token_t;

bool csrf_token_generate(csrf_token_t* token);
bool csrf_token_validate(const csrf_token_t* token, const csrf_token_t* expected);
void csrf_token_to_hex(const csrf_token_t* token, char* output, size_t out_size);
bool csrf_token_from_hex(const char* hex, csrf_token_t* token);

typedef enum {
    SAMESITE_LAX,
    SAMESITE_STRICT,
    SAMESITE_NONE
} samesite_t;

int csrf_set_cookie_header(const char* name, const char* value,
                           bool http_only, bool secure, samesite_t same_site,
                           int max_age, const char* path,
                           char* output, size_t out_size);

bool csrf_check_origin(const char* origin, const char* target_host);
bool csrf_check_referer(const char* referer, const char* target_host);
bool csrf_same_origin(const char* url_a, const char* url_b);

#ifdef __cplusplus
}
#endif

#endif /* XSS_CSRF_H */
