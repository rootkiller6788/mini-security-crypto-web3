#include "xss_csrf.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <time.h>

static const html_entity_t g_entities[] = {
    {'&',  "&amp;"},   {'<',  "&lt;"},    {'>',  "&gt;"},
    {'"',  "&quot;"},  {'\'', "&#x27;"},  {'/',  "&#x2F;"},
    {'`',  "&#x60;"},  {'=',  "&#x3D;"},
    {0, NULL}
};

static const char* g_xss_patterns[] = {
    "<script", "javascript:", "onerror=", "onload=", "onclick=",
    "eval(", "document.cookie", "document.write",
    "<img", "<iframe", "<svg", "<object", "<embed",
    "expression(", "vbscript:", "data:text/html",
    NULL
};

size_t html_encode(const char* input, char* output, size_t out_size) {
    if (!input || !output || out_size == 0) return 0;
    size_t out_pos = 0;
    for (size_t i = 0; input[i] && out_pos < out_size - 1; i++) {
        bool matched = false;
        for (int e = 0; g_entities[e].raw != 0; e++) {
            if (input[i] == g_entities[e].raw) {
                size_t elen = strlen(g_entities[e].entity);
                if (out_pos + elen < out_size - 1) {
                    memcpy(output + out_pos, g_entities[e].entity, elen);
                    out_pos += elen;
                }
                matched = true;
                break;
            }
        }
        if (!matched && out_pos < out_size - 1) {
            output[out_pos++] = input[i];
        }
    }
    output[out_pos] = '\0';
    return out_pos;
}

size_t html_attribute_encode(const char* input, char* output, size_t out_size) {
    if (!input || !output || out_size == 0) return 0;
    size_t out_pos = 0;
    for (size_t i = 0; input[i] && out_pos < out_size - 1; i++) {
        unsigned char c = (unsigned char)input[i];
        if (c < 32 || c == '"' || c == '\'' || c == '&' || c == '<' || c == '>') {
            int needed = snprintf(output + out_pos, out_size - out_pos, "&#x%02X;", c);
            if (needed > 0) out_pos += (size_t)needed;
        } else {
            output[out_pos++] = input[i];
        }
    }
    output[out_pos] = '\0';
    return out_pos;
}

size_t js_string_encode(const char* input, char* output, size_t out_size) {
    if (!input || !output || out_size == 0) return 0;
    size_t out_pos = 0;
    for (size_t i = 0; input[i] && out_pos < out_size - 2; i++) {
        unsigned char c = (unsigned char)input[i];
        switch (c) {
        case '\\': output[out_pos++] = '\\'; output[out_pos++] = '\\'; break;
        case '\"': output[out_pos++] = '\\'; output[out_pos++] = '\"'; break;
        case '\'': output[out_pos++] = '\\'; output[out_pos++] = '\''; break;
        case '\n': output[out_pos++] = '\\'; output[out_pos++] = 'n';  break;
        case '\r': output[out_pos++] = '\\'; output[out_pos++] = 'r';  break;
        case '\t': output[out_pos++] = '\\'; output[out_pos++] = 't';  break;
        case '/':  output[out_pos++] = '\\'; output[out_pos++] = '/';  break;
        case '<':  case '>':
            snprintf(output + out_pos, out_size - out_pos, "\\u%04X", c);
            out_pos += 6;
            break;
        default:
            if (c < 32 || c > 126) {
                snprintf(output + out_pos, out_size - out_pos, "\\x%02X", c);
                out_pos += 4;
            } else {
                output[out_pos++] = input[i];
            }
        }
    }
    output[out_pos] = '\0';
    return out_pos;
}

bool html_decode(const char* input, char* output, size_t out_size) {
    if (!input || !output || out_size == 0) return false;
    size_t in_len = strlen(input);
    size_t out_pos = 0;
    for (size_t i = 0; i < in_len && out_pos < out_size - 1; i++) {
        if (input[i] == '&') {
            for (int e = 0; g_entities[e].raw != 0; e++) {
                size_t elen = strlen(g_entities[e].entity);
                if (i + elen <= in_len && strncmp(input + i, g_entities[e].entity, elen) == 0) {
                    output[out_pos++] = g_entities[e].raw;
                    i += elen - 1;
                    goto next_char;
                }
            }
            if (input[i + 1] == '#') {
                int codepoint = 0;
                if (input[i + 2] == 'x' || input[i + 2] == 'X') {
                    sscanf(input + i + 3, "%x", &codepoint);
                } else {
                    sscanf(input + i + 2, "%d", &codepoint);
                }
                if (codepoint > 0 && codepoint < 256) {
                    output[out_pos++] = (char)codepoint;
                }
                while (input[i] && input[i] != ';') i++;
                goto next_char;
            }
        }
        output[out_pos++] = input[i];
    next_char:;
    }
    output[out_pos] = '\0';
    return true;
}

static bool has_pattern(const char* input, const char* pattern) {
    if (!input || !pattern) return false;
    size_t ilen = strlen(input), plen = strlen(pattern);
    if (plen > ilen) return false;
    for (size_t i = 0; i <= ilen - plen; i++) {
        bool match = true;
        for (size_t j = 0; j < plen; j++) {
            if (tolower((unsigned char)input[i + j]) != tolower((unsigned char)pattern[j])) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

void xss_detect_reflected(const char* input, const char* context, xss_report_t* report) {
    if (!report) return;
    report->type = XSS_TYPE_REFLECTED;
    report->source = context;
    report->payload = input;
    report->detected = false;
    if (!input) return;
    for (int i = 0; g_xss_patterns[i]; i++) {
        if (has_pattern(input, g_xss_patterns[i])) {
            report->detected = true;
            return;
        }
    }
}

void xss_detect_stored(const char* db_content, xss_report_t* report) {
    if (!report) return;
    report->type = XSS_TYPE_STORED;
    report->source = "database";
    report->payload = db_content;
    report->detected = false;
    if (!db_content) return;
    for (int i = 0; g_xss_patterns[i]; i++) {
        if (has_pattern(db_content, g_xss_patterns[i])) {
            report->detected = true;
            return;
        }
    }
}

void xss_detect_dom(const char* js_sink, const char* source, xss_report_t* report) {
    if (!report) return;
    report->type = XSS_TYPE_DOM_BASED;
    report->source = source;
    report->payload = js_sink;
    report->detected = false;
    if (!js_sink) return;
    const char* dom_sinks[] = {"innerHTML", "document.write", "eval", "setTimeout",
                                "setInterval", "location", "outerHTML", "insertAdjacentHTML", NULL};
    for (int i = 0; dom_sinks[i]; i++) {
        if (has_pattern(js_sink, dom_sinks[i])) {
            report->detected = true;
            return;
        }
    }
}

int xss_sanitize_html(const char* input, char* output, size_t out_size) {
    return (int)html_encode(input, output, out_size);
}

int xss_sanitize_attribute(const char* input, char* output, size_t out_size) {
    return (int)html_attribute_encode(input, output, out_size);
}

int xss_sanitize_javascript(const char* input, char* output, size_t out_size) {
    return (int)js_string_encode(input, output, out_size);
}

int xss_sanitize_url(const char* input, char* output, size_t out_size) {
    if (!input || !output || out_size == 0) return 0;
    size_t out_pos = 0;
    for (size_t i = 0; input[i] && out_pos < out_size - 1; i++) {
        unsigned char c = (unsigned char)input[i];
        if (isalnum(c) || c == '/' || c == '.' || c == '-' || c == '_' ||
            c == '?' || c == '=' || c == '&' || c == '#' || c == ':' || c == '%') {
            output[out_pos++] = input[i];
        } else {
            int n = snprintf(output + out_pos, out_size - out_pos, "%%%02X", c);
            if (n > 0) out_pos += (size_t)n;
        }
    }
    output[out_pos] = '\0';
    return (int)out_pos;
}

void csp_init(csp_policy_t* policy, bool report_only) {
    if (!policy) return;
    memset(policy, 0, sizeof(*policy));
    policy->report_only = report_only;
}

int csp_add_directive(csp_policy_t* policy, csp_source_t src, const char* value) {
    if (!policy || !value || policy->count >= 16) return -1;
    policy->directives[policy->count].source = src;
    policy->directives[policy->count].value = value;
    policy->count++;
    return 0;
}

static const char* csp_source_str(csp_source_t src) {
    switch (src) {
    case CSP_SRC_DEFAULT:        return "default-src";
    case CSP_SRC_SCRIPT:         return "script-src";
    case CSP_SRC_STYLE:          return "style-src";
    case CSP_SRC_IMG:            return "img-src";
    case CSP_SRC_CONNECT:        return "connect-src";
    case CSP_SRC_FONT:           return "font-src";
    case CSP_SRC_OBJECT:         return "object-src";
    case CSP_SRC_MEDIA:          return "media-src";
    case CSP_SRC_FRAME:          return "frame-src";
    case CSP_SRC_WORKER:         return "worker-src";
    case CSP_SRC_MANIFEST:       return "manifest-src";
    case CSP_SRC_FORM_ACTION:    return "form-action";
    case CSP_SRC_BASE_URI:       return "base-uri";
    case CSP_SRC_FRAME_ANCESTORS:return "frame-ancestors";
    }
    return "default-src";
}

int csp_generate_header(const csp_policy_t* policy, char* output, size_t out_size) {
    if (!policy || !output || out_size == 0) return 0;
    size_t pos = 0;
    const char* prefix = policy->report_only
        ? "Content-Security-Policy-Report-Only: " : "Content-Security-Policy: ";
    size_t plen = strlen(prefix);
    if (pos + plen < out_size) { memcpy(output + pos, prefix, plen); pos += plen; }
    for (int i = 0; i < policy->count; i++) {
        if (i > 0 && pos < out_size) output[pos++] = ';';
        int n = snprintf(output + pos, out_size - pos, "%s %s",
                         csp_source_str(policy->directives[i].source),
                         policy->directives[i].value);
        if (n > 0) pos += (size_t)n;
    }
    if (pos < out_size) output[pos] = '\0';
    return (int)pos;
}

void csp_generate_nonce(char* output, size_t out_size) {
    if (!output || out_size < 25) return;
    static const char base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    unsigned char rand_bytes[16];
    for (int i = 0; i < 16; i++) rand_bytes[i] = (unsigned char)(rand() & 0xFF);
    size_t pos = 0;
    for (int i = 0; i < 16 && pos + 1 < out_size; i += 3) {
        uint32_t v = ((uint32_t)rand_bytes[i] << 16)
                   | ((i+1 < 16 ? (uint32_t)rand_bytes[i+1] : 0) << 8)
                   | (i+2 < 16 ? (uint32_t)rand_bytes[i+2] : 0);
        output[pos++] = base64[(v >> 18) & 0x3F];
        output[pos++] = base64[(v >> 12) & 0x3F];
        if (pos < out_size) output[pos++] = (i + 1 < 16) ? base64[(v >> 6) & 0x3F] : '=';
        if (pos < out_size) output[pos++] = (i + 2 < 16) ? base64[v & 0x3F] : '=';
    }
    output[pos] = '\0';
}

void csp_generate_hash(const char* content, char* output, size_t out_size) {
    if (!content || !output || out_size < 8) return;
    unsigned long hash = 5381;
    while (*content) { hash = ((hash << 5) + hash) + (unsigned char)*content; content++; }
    snprintf(output, out_size, "'sha256-%lx'", hash);
}

static void hex_to_bytes(const char* hex, unsigned char* bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        unsigned int byte;
        sscanf(hex + i * 2, "%2x", &byte);
        bytes[i] = (unsigned char)byte;
    }
}

bool csrf_token_generate(csrf_token_t* token) {
    if (!token) return false;
    token->len = 32;
    for (size_t i = 0; i < token->len; i++)
        token->data[i] = (unsigned char)(((unsigned int)rand() ^ (unsigned int)time(NULL)) & 0xFF);
    return true;
}

bool csrf_token_validate(const csrf_token_t* token, const csrf_token_t* expected) {
    if (!token || !expected) return false;
    if (token->len != expected->len) return false;
    unsigned char result = 0;
    for (size_t i = 0; i < token->len; i++)
        result |= token->data[i] ^ expected->data[i];
    return result == 0;
}

void csrf_token_to_hex(const csrf_token_t* token, char* output, size_t out_size) {
    if (!token || !output || out_size < token->len * 2 + 1) return;
    for (size_t i = 0; i < token->len; i++)
        snprintf(output + i * 2, 3, "%02x", token->data[i]);
    output[token->len * 2] = '\0';
}

bool csrf_token_from_hex(const char* hex, csrf_token_t* token) {
    if (!hex || !token) return false;
    token->len = strlen(hex) / 2;
    if (token->len > 32) return false;
    hex_to_bytes(hex, token->data, token->len);
    return true;
}

int csrf_set_cookie_header(const char* name, const char* value,
                           bool http_only, bool secure, samesite_t same_site,
                           int max_age, const char* path,
                           char* output, size_t out_size) {
    if (!name || !value || !output) return 0;
    const char* site_str = "Lax";
    if (same_site == SAMESITE_STRICT) site_str = "Strict";
    else if (same_site == SAMESITE_NONE) site_str = "None";
    int n = snprintf(output, out_size,
                     "Set-Cookie: %s=%s; Path=%s; Max-Age=%d; SameSite=%s%s%s",
                     name, value, path ? path : "/", max_age, site_str,
                     http_only ? "; HttpOnly" : "", secure ? "; Secure" : "");
    return n;
}

static bool extract_host(const char* url, char* host_out, size_t out_size) {
    if (!url || !host_out) return false;
    const char* start = url;
    if (strncmp(start, "http://", 7) == 0) start += 7;
    else if (strncmp(start, "https://", 8) == 0) start += 8;
    size_t i;
    for (i = 0; start[i] && start[i] != '/' && start[i] != ':' && start[i] != '?' && i < out_size - 1; i++)
        host_out[i] = start[i];
    host_out[i] = '\0';
    return i > 0;
}

bool csrf_check_origin(const char* origin, const char* target_host) {
    if (!origin || !target_host) return false;
    char origin_host[256];
    if (!extract_host(origin, origin_host, sizeof(origin_host))) return false;
    size_t tlen = strlen(target_host);
    size_t olen = strlen(origin_host);
    if (olen == tlen && memcmp(origin_host, target_host, tlen) == 0) return true;
    if (olen > tlen + 1 && origin_host[olen - tlen - 1] == '.' &&
        memcmp(origin_host + olen - tlen, target_host, tlen) == 0) return true;
    return false;
}

bool csrf_check_referer(const char* referer, const char* target_host) {
    return csrf_check_origin(referer, target_host);
}

bool csrf_same_origin(const char* url_a, const char* url_b) {
    char host_a[256], host_b[256];
    if (!extract_host(url_a, host_a, sizeof(host_a))) return false;
    if (!extract_host(url_b, host_b, sizeof(host_b))) return false;
    return strcmp(host_a, host_b) == 0;
}
