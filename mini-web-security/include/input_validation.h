#ifndef INPUT_VALIDATION_H
#define INPUT_VALIDATION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Allowlist / Blocklist Validation ────────────────────────────── */

typedef struct {
    const char** items;
    int          count;
    bool         case_sensitive;
} ival_list_t;

void ival_list_init(ival_list_t* list, const char** items, int count, bool case_sensitive);

bool ival_allowlist(const char* input, const ival_list_t* allowed);

bool ival_blocklist(const char* input, const ival_list_t* blocked);

bool ival_match_regex(const char* input, const char* pattern);

/* ── Type Checking ───────────────────────────────────────────────── */

typedef enum {
    IVAL_TYPE_INT,
    IVAL_TYPE_FLOAT,
    IVAL_TYPE_ALPHA,
    IVAL_TYPE_ALPHANUM,
    IVAL_TYPE_PRINTABLE,
    IVAL_TYPE_HEX,
    IVAL_TYPE_BASE64
} ival_type_t;

bool ival_check_type(const char* input, ival_type_t type);

bool ival_is_integer(const char* input);

bool ival_is_float(const char* input);

bool ival_is_alpha(const char* input);

bool ival_is_alphanum(const char* input);

bool ival_is_printable(const char* input);

bool ival_is_base64(const char* input);

/* ── Length Limits ───────────────────────────────────────────────── */

typedef struct {
    size_t min_len;
    size_t max_len;
} ival_length_t;

bool ival_check_length(const char* input, ival_length_t limits);

bool ival_check_range(int64_t value, int64_t min_val, int64_t max_val);

/* ── Format Validation ───────────────────────────────────────────── */

bool ival_validate_email(const char* email);

bool ival_validate_url(const char* url);

bool ival_validate_credit_card(const char* number);

bool ival_validate_phone(const char* phone);

bool ival_validate_date(const char* date);

bool ival_validate_ipv4(const char* ip);

bool ival_validate_ipv6(const char* ip);

int  ival_validate_password(const char* password, int min_len,
                            bool require_upper, bool require_digit, bool require_special);

/* ── Encoding & Validation ───────────────────────────────────────── */

bool utf8_validate(const char* input, size_t len);

int  utf8_codepoint_count(const char* input);

bool utf8_is_valid_multibyte(uint8_t lead, const uint8_t* continuation, int len);

bool utf8_is_overlong(const uint8_t* bytes, int len);

/* ── Canonicalization ────────────────────────────────────────────── */

int  ival_canonicalize(const char* input, char* output, size_t out_size);

int  ival_canonicalize_path(const char* path, char* output, size_t out_size);

int  ival_canonicalize_url(const char* url, char* output, size_t out_size);

/* ── Double Encoding Detection ───────────────────────────────────── */

typedef struct {
    bool detected;
    int  depth;
    int  positions[8];
    char decoded[1024];
} double_enc_t;

void double_enc_detect(const char* input, double_enc_t* result);

bool double_enc_is_encoded(const char* input);

int  double_enc_decode_once(const char* input, char* output, size_t out_size);

/* ── Parameter Pollution ─────────────────────────────────────────── */

typedef struct {
    const char* name;
    const char* values[8];
    int         count;
} param_t;

typedef struct {
    param_t params[32];
    int     count;
} param_pollution_t;

void param_pollution_init(param_pollution_t* pp);

int  param_pollution_parse(const char* query_string, param_pollution_t* pp);

int  param_pollution_detect(const param_pollution_t* pp);

const char* param_pollution_get_first(const param_pollution_t* pp, const char* name);

int  param_pollution_get_all(const param_pollution_t* pp, const char* name,
                             const char** output, int max_output);

/* ── Mass Assignment Protection ──────────────────────────────────── */

typedef struct {
    const char** allowed_fields;
    int          count;
} mass_assignment_t;

void mass_assign_init(mass_assignment_t* ma, const char** fields, int count);

bool mass_assign_validate(const mass_assignment_t* ma, const char* field);

int  mass_assign_filter(const mass_assignment_t* ma,
                        const char** input_fields, int input_count,
                        const char** output, int max_output);

#ifdef __cplusplus
}
#endif

#endif /* INPUT_VALIDATION_H */
