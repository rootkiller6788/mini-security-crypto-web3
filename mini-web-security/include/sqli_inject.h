#ifndef SQLI_INJECT_H
#define SQLI_INJECT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── SQL Injection Types ─────────────────────────────────────────── */

typedef enum {
    SQLI_CLASSIC,       /* ' OR 1=1-- */
    SQLI_UNION_BASED,   /* ' UNION SELECT ... */
    SQLI_BLIND_BOOLEAN, /* AND 1=1 vs AND 1=2 */
    SQLI_BLIND_TIME,    /* SLEEP(5) / WAITFOR DELAY */
    SQLI_STACKED,       /* ; DROP TABLE */
    SQLI_ERROR_BASED,   /* extractvalue / updatexml */
    SQLI_OUT_OF_BAND,   /* DNS/HTTP exfiltration */
    SQLI_NONE
} sqli_type_t;

typedef struct {
    sqli_type_t type;
    int         risk_score;    /* 0-100 */
    size_t      match_offset;
    const char* matched_pattern;
} sqli_detect_result_t;

/* ── SQL Injection Detection ─────────────────────────────────────── */

void sqli_detect(const char* input, sqli_detect_result_t* result);

int  sqli_scan_simple(const char* input, sqli_detect_result_t results[], int max_results);

bool sqli_is_suspicious_char(char c);

const char* sqli_type_name(sqli_type_t type);

/* ── SQL Injection Patterns (recognition) ────────────────────────── */

typedef struct {
    const char* pattern;
    sqli_type_t type;
} sqli_pattern_t;

bool sqli_match_pattern(const char* input, const sqli_pattern_t* pattern, size_t* match_offset);

bool sqli_detect_classic(const char* input, size_t* offset);
bool sqli_detect_union(const char* input, size_t* offset);
bool sqli_detect_boolean_blind(const char* input, size_t* offset);
bool sqli_detect_time_blind(const char* input, size_t* offset);

/* ── Prepared Statement Helpers ──────────────────────────────────── */

typedef struct {
    char   name;
    size_t len;
    char   data_buf[256];
} sqli_param_t;

typedef struct {
    const char* query_template;
    sqli_param_t params[16];
    int          param_count;
    char         sanitized_query[2048];
} sqli_prepared_t;

void sqli_prepared_init(sqli_prepared_t* stmt, const char* template_sql);

int  sqli_prepared_bind_int(sqli_prepared_t* stmt, int64_t value);

int  sqli_prepared_bind_float(sqli_prepared_t* stmt, double value);

int  sqli_prepared_bind_text(sqli_prepared_t* stmt, const char* value);

int  sqli_prepared_bind_null(sqli_prepared_t* stmt);

int  sqli_prepared_build(sqli_prepared_t* stmt);

/* ── Input Sanitization for SQL ──────────────────────────────────── */

int  sqli_sanitize(const char* input, char* output, size_t out_size);

int  sqli_escape_string(const char* input, char* output, size_t out_size);

bool sqli_is_safe_identifier(const char* identifier);

bool sqli_is_safe_integer(const char* input);

int  sqli_whitelist_columns(const char* column, const char** allowed, int allowed_count);

/* ── NoSQL Injection (MongoDB) ───────────────────────────────────── */

typedef enum {
    NOSQLI_NONE,
    NOSQLI_GT_NE,       /* {$gt: ''}, {$ne: null} */
    NOSQLI_REGEX,       /* {$regex: ...} */
    NOSQLI_WHERE,       /* $where JavaScript */
    NOSQLI_OPERATOR     /* Other $ operators */
} nosqli_type_t;

nosqli_type_t nosqli_detect(const char* input);

int  nosqli_sanitize(const char* input, char* output, size_t out_size);

bool nosqli_is_operator_injection(const char* input);

/* ── ORM Protection ──────────────────────────────────────────────── */

bool orm_validate_model(const char* field, const char** allowed_fields, int count);

bool orm_validate_type(const char* value, const char* expected_type);

/* ── Second-Order SQL Injection ──────────────────────────────────── */

typedef struct {
    const char* stored_value;
    const char* storage_context;
    time_t      stored_at;
    bool        flagged;
} second_order_tracker_t;

void second_order_track(second_order_tracker_t* tracker, const char* value);

bool second_order_check(second_order_tracker_t* tracker, const char* usage_context);

#ifdef __cplusplus
}
#endif

#endif /* SQLI_INJECT_H */
