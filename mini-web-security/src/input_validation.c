#include "input_validation.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

void ival_list_init(ival_list_t* list, const char** items, int count, bool case_sensitive) {
    if (!list) return;
    list->items = items;
    list->count = count;
    list->case_sensitive = case_sensitive;
}

bool ival_allowlist(const char* input, const ival_list_t* allowed) {
    if (!input || !allowed || !allowed->items) return false;
    for (int i = 0; i < allowed->count; i++) {
        if (!allowed->items[i]) continue;
        bool match = allowed->case_sensitive
            ? (strcmp(input, allowed->items[i]) == 0)
            : (strcasecmp(input, allowed->items[i]) == 0);
        if (match) return true;
    }
    return false;
}

bool ival_blocklist(const char* input, const ival_list_t* blocked) {
    if (!input || !blocked || !blocked->items) return true;
    for (int i = 0; i < blocked->count; i++) {
        if (!blocked->items[i]) continue;
        if (strstr(input, blocked->items[i])) return false;
    }
    return true;
}

static bool regex_simple(const char* input, const char* pattern) {
    if (!input || !pattern) return false;
    if (strcmp(pattern, "^[a-zA-Z]+$") == 0) return ival_is_alpha(input);
    if (strcmp(pattern, "^[a-zA-Z0-9]+$") == 0) return ival_is_alphanum(input);
    if (strcmp(pattern, "^[0-9]+$") == 0) return ival_is_integer(input);
    return strstr(input, pattern) != NULL;
}

bool ival_match_regex(const char* input, const char* pattern) {
    return regex_simple(input, pattern);
}

bool ival_check_type(const char* input, ival_type_t type) {
    if (!input) return false;
    switch (type) {
    case IVAL_TYPE_INT:      return ival_is_integer(input);
    case IVAL_TYPE_FLOAT:    return ival_is_float(input);
    case IVAL_TYPE_ALPHA:    return ival_is_alpha(input);
    case IVAL_TYPE_ALPHANUM: return ival_is_alphanum(input);
    case IVAL_TYPE_PRINTABLE:return ival_is_printable(input);
    case IVAL_TYPE_HEX:      return ival_match_regex(input, "^[0-9a-fA-F]+$");
    case IVAL_TYPE_BASE64:   return ival_is_base64(input);
    }
    return false;
}

bool ival_is_integer(const char* input) {
    if (!input || !*input) return false;
    if (*input == '-') input++;
    if (!*input) return false;
    while (*input) { if (!isdigit((unsigned char)*input)) return false; input++; }
    return true;
}

bool ival_is_float(const char* input) {
    if (!input || !*input) return false;
    if (*input == '-') input++;
    bool has_dot = false, has_digit = false;
    while (*input) {
        if (*input == '.' && !has_dot) { has_dot = true; input++; continue; }
        if (!isdigit((unsigned char)*input)) return false;
        has_digit = true;
        input++;
    }
    return has_digit;
}

bool ival_is_alpha(const char* input) {
    if (!input || !*input) return false;
    while (*input) { if (!isalpha((unsigned char)*input)) return false; input++; }
    return true;
}

bool ival_is_alphanum(const char* input) {
    if (!input || !*input) return false;
    while (*input) { if (!isalnum((unsigned char)*input)) return false; input++; }
    return true;
}

bool ival_is_printable(const char* input) {
    if (!input) return false;
    while (*input) { if (!isprint((unsigned char)*input) && *input != '\n') return false; input++; }
    return true;
}

bool ival_is_base64(const char* input) {
    if (!input || !*input) return false;
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    while (*input) {
        if (!strchr(b64, *input)) return false;
        input++;
    }
    return true;
}

bool ival_check_length(const char* input, ival_length_t limits) {
    if (!input) return limits.min_len == 0;
    size_t len = strlen(input);
    return len >= limits.min_len && len <= limits.max_len;
}

bool ival_check_range(int64_t value, int64_t min_val, int64_t max_val) {
    return value >= min_val && value <= max_val;
}

bool ival_validate_email(const char* email) {
    if (!email) return false;
    const char* at = strchr(email, '@');
    if (!at || at == email) return false;
    const char* dot = strrchr(at, '.');
    if (!dot || dot == at + 1 || dot[1] == '\0') return false;
    for (const char* p = email; p < at; p++) {
        if (!isalnum((unsigned char)*p) && *p != '.' && *p != '_' && *p != '-' && *p != '+') return false;
    }
    return true;
}

bool ival_validate_url(const char* url) {
    if (!url) return false;
    if (strncmp(url, "http://", 7) != 0 && strncmp(url, "https://", 8) != 0) return false;
    const char* p = (url[4] == 's') ? url + 8 : url + 7;
    const char* host_start = p;
    while (*p && *p != '/' && *p != '?' && *p != '#') p++;
    size_t host_len = (size_t)(p - host_start);
    if (host_len < 1 || host_len > 253) return false;
    return true;
}

static int luhn_sum(const char* num) {
    int sum = 0, alt = 0;
    size_t len = strlen(num);
    for (size_t i = len; i > 0; i--) {
        int d = num[i - 1] - '0';
        if (alt) { d *= 2; if (d > 9) d -= 9; }
        sum += d;
        alt = !alt;
    }
    return sum;
}

bool ival_validate_credit_card(const char* number) {
    if (!number) return false;
    size_t len = strlen(number);
    if (len < 13 || len > 19) return false;
    for (size_t i = 0; i < len; i++)
        if (!isdigit((unsigned char)number[i])) return false;
    return luhn_sum(number) % 10 == 0;
}

bool ival_validate_phone(const char* phone) {
    if (!phone) return false;
    bool has_digit = false;
    while (*phone) {
        if (isdigit((unsigned char)*phone)) has_digit = true;
        else if (*phone != '+' && *phone != '-' && *phone != ' ' && *phone != '(' && *phone != ')')
            return false;
        phone++;
    }
    return has_digit;
}

bool ival_validate_date(const char* date) {
    if (!date || strlen(date) != 10) return false;
    if (date[4] != '-' || date[7] != '-') return false;
    for (int i = 0; i < 10; i++)
        if (i != 4 && i != 7 && !isdigit((unsigned char)date[i])) return false;
    int y = atoi(date), m = atoi(date + 5), d = atoi(date + 8);
    if (y < 1900 || y > 2100 || m < 1 || m > 12 || d < 1 || d > 31) return false;
    return true;
}

bool ival_validate_ipv4(const char* ip) {
    if (!ip) return false;
    int a, b, c, d;
    char tail;
    if (sscanf(ip, "%d.%d.%d.%d%c", &a, &b, &c, &d, &tail) != 4) return false;
    return a >= 0 && a <= 255 && b >= 0 && b <= 255 && c >= 0 && c <= 255 && d >= 0 && d <= 255;
}

bool ival_validate_ipv6(const char* ip) {
    if (!ip) return false;
    int colons = 0;
    for (size_t i = 0; ip[i]; i++) {
        if (ip[i] == ':') colons++;
        else if (!isxdigit((unsigned char)ip[i])) return false;
    }
    return colons >= 2 && colons <= 7;
}

int ival_validate_password(const char* password, int min_len,
                           bool require_upper, bool require_digit, bool require_special) {
    if (!password) return 0;
    size_t len = strlen(password);
    if ((int)len < min_len) return -1;
    bool has_upper = false, has_digit = false, has_special = false;
    for (size_t i = 0; i < len; i++) {
        if (isupper((unsigned char)password[i])) has_upper = true;
        if (isdigit((unsigned char)password[i])) has_digit = true;
        if (!isalnum((unsigned char)password[i])) has_special = true;
    }
    if (require_upper && !has_upper) return -2;
    if (require_digit && !has_digit) return -3;
    if (require_special && !has_special) return -4;
    return 1;
}

bool utf8_validate(const char* input, size_t len) {
    if (!input) return len == 0;
    size_t i = 0;
    while (i < len && input[i]) {
        unsigned char c = (unsigned char)input[i];
        int bytes;
        if (c <= 0x7F) bytes = 1;
        else if (c >= 0xC2 && c <= 0xDF) bytes = 2;
        else if (c >= 0xE0 && c <= 0xEF) bytes = 3;
        else if (c >= 0xF0 && c <= 0xF4) bytes = 4;
        else return false;
        if (i + (size_t)bytes > len) return false;
        for (int j = 1; j < bytes; j++) {
            unsigned char cont = (unsigned char)input[i + j];
            if ((cont & 0xC0) != 0x80) return false;
        }
        if (bytes == 3 && c == 0xE0 && (unsigned char)input[i+1] < 0xA0) return false;
        if (bytes == 4 && c == 0xF0 && (unsigned char)input[i+1] < 0x90) return false;
        i += (size_t)bytes;
    }
    return true;
}

int utf8_codepoint_count(const char* input) {
    if (!input) return 0;
    int count = 0;
    while (*input) {
        unsigned char c = (unsigned char)*input;
        if (c <= 0x7F || c >= 0xC0) count++;
        input++;
    }
    return count;
}

bool utf8_is_valid_multibyte(uint8_t lead, const uint8_t* continuation, int len) {
    if (lead <= 0x7F) return true;
    if (lead < 0xC2 || lead > 0xF4) return false;
    int expected = (lead >= 0xF0) ? 4 : (lead >= 0xE0) ? 3 : 2;
    if (len + 1 < expected) return false;
    for (int i = 0; i < expected - 1; i++)
        if ((continuation[i] & 0xC0) != 0x80) return false;
    return true;
}

bool utf8_is_overlong(const uint8_t* bytes, int len) {
    if (len == 2 && bytes[0] == 0xC0 && bytes[1] < 0xA0) return true;
    if (len >= 3 && bytes[0] == 0xE0 && bytes[1] < 0xA0) return true;
    if (len >= 4 && bytes[0] == 0xF0 && bytes[1] < 0x90) return true;
    return false;
}

int ival_canonicalize(const char* input, char* output, size_t out_size) {
    if (!input || !output || out_size == 0) return 0;
    size_t out_pos = 0;
    for (size_t i = 0; input[i] && out_pos < out_size - 1; i++) {
        unsigned char c = (unsigned char)input[i];
        if (c >= 32 && c < 127) output[out_pos++] = input[i];
    }
    output[out_pos] = '\0';
    return (int)out_pos;
}

int ival_canonicalize_path(const char* path, char* output, size_t out_size) {
    if (!path || !output || out_size == 0) return 0;
    size_t out_pos = 0;
    for (size_t i = 0; path[i] && out_pos < out_size - 1; i++) {
        if (path[i] == '\\') output[out_pos++] = '/';
        else if ((unsigned char)path[i] >= 32 && (unsigned char)path[i] < 127)
            output[out_pos++] = path[i];
    }
    output[out_pos] = '\0';
    return (int)out_pos;
}

int ival_canonicalize_url(const char* url, char* output, size_t out_size) {
    return ival_canonicalize(url, output, out_size);
}

static int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

void double_enc_detect(const char* input, double_enc_t* result) {
    if (!result) return;
    memset(result, 0, sizeof(*result));
    if (!input) return;
    int pos_count = 0;
    for (size_t i = 0; input[i]; i++) {
        if (input[i] == '%' && hex_digit(input[i+1]) >= 0 && hex_digit(input[i+2]) >= 0) {
            if (pos_count < 8) result->positions[pos_count++] = (int)i;
        }
    }
    if (pos_count > 0) {
        result->detected = double_enc_is_encoded(input);
        if (result->detected) {
            result->depth = 1;
            double_enc_decode_once(input, result->decoded, sizeof(result->decoded));
            if (double_enc_is_encoded(result->decoded)) result->depth = 2;
        }
    }
}

bool double_enc_is_encoded(const char* input) {
    if (!input) return false;
    for (size_t i = 0; input[i]; i++)
        if (input[i] == '%' && hex_digit(input[i+1]) >= 0 && hex_digit(input[i+2]) >= 0)
            return true;
    return false;
}

int double_enc_decode_once(const char* input, char* output, size_t out_size) {
    if (!input || !output || out_size == 0) return 0;
    size_t out_pos = 0;
    for (size_t i = 0; input[i] && out_pos < out_size - 1; i++) {
        if (input[i] == '%' && hex_digit(input[i+1]) >= 0 && hex_digit(input[i+2]) >= 0) {
            int hi = hex_digit(input[i+1]), lo = hex_digit(input[i+2]);
            output[out_pos++] = (char)((hi << 4) | lo);
            i += 2;
        } else if (input[i] == '+') {
            output[out_pos++] = ' ';
        } else {
            output[out_pos++] = input[i];
        }
    }
    output[out_pos] = '\0';
    return (int)out_pos;
}

void param_pollution_init(param_pollution_t* pp) {
    if (!pp) return;
    memset(pp, 0, sizeof(*pp));
}

int param_pollution_parse(const char* query_string, param_pollution_t* pp) {
    if (!query_string || !pp) return 0;
    char buf[4096];
    strncpy(buf, query_string, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    char* token = buf;
    while (*token) {
        char* eq = strchr(token, '=');
        if (!eq) break;
        *eq = '\0';
        char* name = token;
        char* value = eq + 1;
        char* amp = strchr(value, '&');
        if (amp) *amp = '\0';
        bool found = false;
        for (int i = 0; i < pp->count; i++) {
            if (strcmp(pp->params[i].name, name) == 0 && pp->params[i].count < 8) {
                pp->params[i].values[pp->params[i].count++] = value;
                found = true;
                break;
            }
        }
        if (!found && pp->count < 32) {
            pp->params[pp->count].name = name;
            pp->params[pp->count].values[0] = value;
            pp->params[pp->count].count = 1;
            pp->count++;
        }
        token = amp ? amp + 1 : token + strlen(token);
    }
    return pp->count;
}

int param_pollution_detect(const param_pollution_t* pp) {
    if (!pp) return 0;
    int polluted = 0;
    for (int i = 0; i < pp->count; i++)
        if (pp->params[i].count > 1) polluted++;
    return polluted;
}

const char* param_pollution_get_first(const param_pollution_t* pp, const char* name) {
    if (!pp || !name) return NULL;
    for (int i = 0; i < pp->count; i++)
        if (strcmp(pp->params[i].name, name) == 0 && pp->params[i].count > 0)
            return pp->params[i].values[0];
    return NULL;
}

int param_pollution_get_all(const param_pollution_t* pp, const char* name,
                            const char** output, int max_output) {
    if (!pp || !name || !output) return 0;
    for (int i = 0; i < pp->count; i++) {
        if (strcmp(pp->params[i].name, name) == 0) {
            int n = pp->params[i].count;
            if (n > max_output) n = max_output;
            for (int j = 0; j < n; j++) output[j] = pp->params[i].values[j];
            return n;
        }
    }
    return 0;
}

void mass_assign_init(mass_assignment_t* ma, const char** fields, int count) {
    if (!ma) return;
    ma->allowed_fields = fields;
    ma->count = count;
}

bool mass_assign_validate(const mass_assignment_t* ma, const char* field) {
    if (!ma || !ma->allowed_fields || !field) return false;
    for (int i = 0; i < ma->count; i++)
        if (ma->allowed_fields[i] && strcmp(ma->allowed_fields[i], field) == 0) return true;
    return false;
}

int mass_assign_filter(const mass_assignment_t* ma,
                       const char** input_fields, int input_count,
                       const char** output, int max_output) {
    if (!ma || !input_fields || !output) return 0;
    int found = 0;
    for (int i = 0; i < input_count && found < max_output; i++) {
        if (mass_assign_validate(ma, input_fields[i])) {
            output[found++] = input_fields[i];
        }
    }
    return found;
}
