#include "sqli_inject.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

static const char* g_sqli_keywords[] = {
    "SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP", "ALTER",
    "CREATE", "TRUNCATE", "EXEC", "EXECUTE", "WAITFOR", "SLEEP",
    "BENCHMARK", "LOAD_FILE", "INTO OUTFILE", "INTO DUMPFILE",
    "INFORMATION_SCHEMA", "OR 1=1", "AND 1=1", "OR '1'='1",
    NULL
};

static const sqli_pattern_t g_sqli_patterns[] = {
    {"' OR '1'='1",       SQLI_CLASSIC},
    {"' OR 1=1--",        SQLI_CLASSIC},
    {"\" OR \"1\"=\"1",   SQLI_CLASSIC},
    {"' UNION SELECT",    SQLI_UNION_BASED},
    {"' UNION ALL SELECT",SQLI_UNION_BASED},
    {" AND SLEEP(",       SQLI_BLIND_TIME},
    {" WAITFOR DELAY",    SQLI_BLIND_TIME},
    {" AND 1=1",          SQLI_BLIND_BOOLEAN},
    {" AND 1=2",          SQLI_BLIND_BOOLEAN},
    {"; DROP TABLE",      SQLI_STACKED},
    {"extractvalue(",     SQLI_ERROR_BASED},
    {"updatexml(",        SQLI_ERROR_BASED},
    {"UTL_HTTP.REQUEST",  SQLI_OUT_OF_BAND},
    {NULL, SQLI_NONE}
};

void sqli_detect(const char* input, sqli_detect_result_t* result) {
    if (!result) return;
    memset(result, 0, sizeof(*result));
    result->type = SQLI_NONE;
    if (!input) return;
    for (int i = 0; g_sqli_patterns[i].pattern; i++) {
        size_t offset;
        if (sqli_match_pattern(input, &g_sqli_patterns[i], &offset)) {
            result->type = g_sqli_patterns[i].type;
            result->match_offset = offset;
            result->matched_pattern = g_sqli_patterns[i].pattern;
            result->risk_score = 70;
            return;
        }
    }
    for (int i = 0; g_sqli_keywords[i]; i++) {
        if (sqli_match_pattern(input, &(sqli_pattern_t){g_sqli_keywords[i], SQLI_CLASSIC}, NULL)) {
            result->type = SQLI_CLASSIC;
            result->risk_score = 40;
            result->matched_pattern = g_sqli_keywords[i];
            return;
        }
    }
}

int sqli_scan_simple(const char* input, sqli_detect_result_t results[], int max_results) {
    if (!input || !results || max_results <= 0) return 0;
    int found = 0;
    for (int i = 0; g_sqli_patterns[i].pattern && found < max_results; i++) {
        size_t offset;
        if (sqli_match_pattern(input, &g_sqli_patterns[i], &offset)) {
            results[found].type = g_sqli_patterns[i].type;
            results[found].risk_score = 70;
            results[found].match_offset = offset;
            results[found].matched_pattern = g_sqli_patterns[i].pattern;
            found++;
            if (found >= max_results) break;
        }
    }
    return found;
}

bool sqli_is_suspicious_char(char c) {
    return c == '\'' || c == '"' || c == ';' || c == '-' || c == '#' || c == '\\';
}

const char* sqli_type_name(sqli_type_t type) {
    switch (type) {
    case SQLI_CLASSIC:       return "Classic SQL Injection";
    case SQLI_UNION_BASED:   return "UNION-based SQL Injection";
    case SQLI_BLIND_BOOLEAN: return "Boolean Blind SQL Injection";
    case SQLI_BLIND_TIME:    return "Time-based Blind SQL Injection";
    case SQLI_STACKED:       return "Stacked Queries";
    case SQLI_ERROR_BASED:   return "Error-based SQL Injection";
    case SQLI_OUT_OF_BAND:   return "Out-of-Band SQL Injection";
    default:                 return "None";
    }
}

bool sqli_match_pattern(const char* input, const sqli_pattern_t* pattern, size_t* match_offset) {
    if (!input || !pattern || !pattern->pattern) return false;
    size_t ilen = strlen(input), plen = strlen(pattern->pattern);
    if (plen > ilen) return false;
    for (size_t i = 0; i <= ilen - plen; i++) {
        bool match = true;
        for (size_t j = 0; j < plen; j++) {
            if (toupper((unsigned char)input[i + j]) != toupper((unsigned char)pattern->pattern[j])) {
                match = false;
                break;
            }
        }
        if (match) {
            if (match_offset) *match_offset = i;
            return true;
        }
    }
    return false;
}

bool sqli_detect_classic(const char* input, size_t* offset) {
    return sqli_match_pattern(input, &(sqli_pattern_t){"' OR '1'='1", SQLI_CLASSIC}, offset) ||
           sqli_match_pattern(input, &(sqli_pattern_t){"' OR 1=1--", SQLI_CLASSIC}, offset);
}

bool sqli_detect_union(const char* input, size_t* offset) {
    return sqli_match_pattern(input, &(sqli_pattern_t){" UNION SELECT", SQLI_UNION_BASED}, offset);
}

bool sqli_detect_boolean_blind(const char* input, size_t* offset) {
    return sqli_match_pattern(input, &(sqli_pattern_t){" AND 1=1", SQLI_BLIND_BOOLEAN}, offset) ||
           sqli_match_pattern(input, &(sqli_pattern_t){" AND 1=2", SQLI_BLIND_BOOLEAN}, offset);
}

bool sqli_detect_time_blind(const char* input, size_t* offset) {
    return sqli_match_pattern(input, &(sqli_pattern_t){" SLEEP(", SQLI_BLIND_TIME}, offset) ||
           sqli_match_pattern(input, &(sqli_pattern_t){" BENCHMARK(", SQLI_BLIND_TIME}, offset) ||
           sqli_match_pattern(input, &(sqli_pattern_t){" WAITFOR DELAY", SQLI_BLIND_TIME}, offset);
}

void sqli_prepared_init(sqli_prepared_t* stmt, const char* template_sql) {
    if (!stmt) return;
    memset(stmt, 0, sizeof(*stmt));
    stmt->query_template = template_sql;
}

int sqli_prepared_bind_int(sqli_prepared_t* stmt, int64_t value) {
    if (!stmt || stmt->param_count >= 16) return -1;
    stmt->params[stmt->param_count].name = '0' + (char)stmt->param_count;
    int n = snprintf(stmt->params[stmt->param_count].data_buf, 256, "%lld", (long long)value);
    if (n < 0) return -1;
    stmt->params[stmt->param_count].len = (size_t)n;
    stmt->param_count++;
    return 0;
}

int sqli_prepared_bind_float(sqli_prepared_t* stmt, double value) {
    if (!stmt || stmt->param_count >= 16) return -1;
    stmt->params[stmt->param_count].name = '0' + (char)stmt->param_count;
    int n = snprintf(stmt->params[stmt->param_count].data_buf, 256, "%g", value);
    if (n < 0) return -1;
    stmt->params[stmt->param_count].len = (size_t)n;
    stmt->param_count++;
    return 0;
}

int sqli_prepared_bind_text(sqli_prepared_t* stmt, const char* value) {
    if (!stmt || !value || stmt->param_count >= 16) return -1;
    stmt->params[stmt->param_count].name = '0' + (char)stmt->param_count;
    size_t len = strlen(value);
    if (len >= 255) len = 254;
    stmt->params[stmt->param_count].data_buf[0] = '\'';
    char escaped[512];
    sqli_escape_string(value, escaped, sizeof(escaped));
    size_t elen = strlen(escaped);
    if (elen + 2 > 255) elen = 253;
    memcpy(stmt->params[stmt->param_count].data_buf + 1, escaped, elen);
    stmt->params[stmt->param_count].data_buf[elen + 1] = '\'';
    stmt->params[stmt->param_count].data_buf[elen + 2] = '\0';
    stmt->params[stmt->param_count].len = elen + 2;
    stmt->param_count++;
    return 0;
}

int sqli_prepared_bind_null(sqli_prepared_t* stmt) {
    if (!stmt || stmt->param_count >= 16) return -1;
    stmt->params[stmt->param_count].name = '0' + (char)stmt->param_count;
    strcpy(stmt->params[stmt->param_count].data_buf, "NULL");
    stmt->params[stmt->param_count].len = 4;
    stmt->param_count++;
    return 0;
}

int sqli_prepared_build(sqli_prepared_t* stmt) {
    if (!stmt || !stmt->query_template) return -1;
    const char* tmpl = stmt->query_template;
    size_t tlen = strlen(tmpl);
    size_t qpos = 0;
    int param_idx = 0;
    for (size_t i = 0; i < tlen && qpos < sizeof(stmt->sanitized_query) - 1; i++) {
        if (tmpl[i] == '?' && param_idx < stmt->param_count) {
            size_t plen = stmt->params[param_idx].len;
            if (qpos + plen < sizeof(stmt->sanitized_query) - 1) {
                memcpy(stmt->sanitized_query + qpos, stmt->params[param_idx].data_buf, plen);
                qpos += plen;
            }
            param_idx++;
        } else {
            stmt->sanitized_query[qpos++] = tmpl[i];
        }
    }
    stmt->sanitized_query[qpos] = '\0';
    return 0;
}

int sqli_sanitize(const char* input, char* output, size_t out_size) {
    return sqli_escape_string(input, output, out_size);
}

int sqli_escape_string(const char* input, char* output, size_t out_size) {
    if (!input || !output || out_size == 0) return 0;
    size_t out_pos = 0;
    for (size_t i = 0; input[i] && out_pos < out_size - 3; i++) {
        switch (input[i]) {
        case '\'': output[out_pos++] = '\\'; output[out_pos++] = '\''; break;
        case '"':  output[out_pos++] = '\\'; output[out_pos++] = '"';  break;
        case '\\': output[out_pos++] = '\\'; output[out_pos++] = '\\'; break;
        case '\0': output[out_pos++] = '\\'; output[out_pos++] = '0';  break;
        case '\n': output[out_pos++] = '\\'; output[out_pos++] = 'n';  break;
        case '\r': output[out_pos++] = '\\'; output[out_pos++] = 'r';  break;
        default:   output[out_pos++] = input[i]; break;
        }
    }
    output[out_pos] = '\0';
    return (int)out_pos;
}

bool sqli_is_safe_identifier(const char* identifier) {
    if (!identifier || !*identifier) return false;
    if (!isalpha((unsigned char)*identifier) && *identifier != '_') return false;
    for (size_t i = 1; identifier[i]; i++) {
        if (!isalnum((unsigned char)identifier[i]) && identifier[i] != '_') return false;
    }
    return true;
}

bool sqli_is_safe_integer(const char* input) {
    if (!input || !*input) return false;
    for (size_t i = 0; input[i]; i++) {
        if (i == 0 && input[i] == '-') continue;
        if (!isdigit((unsigned char)input[i])) return false;
    }
    return true;
}

int sqli_whitelist_columns(const char* column, const char** allowed, int allowed_count) {
    if (!column || !allowed) return -1;
    for (int i = 0; i < allowed_count; i++) {
        if (allowed[i] && strcmp(column, allowed[i]) == 0) return i;
    }
    return -1;
}

nosqli_type_t nosqli_detect(const char* input) {
    if (!input) return NOSQLI_NONE;
    const char* operators[] = {"$gt", "$ne", "$lt", "$gte", "$lte",
                                "$regex", "$where", "$exists", "$in", "$nin",
                                "$or", "$and", "$not", "$nor", "$set", "$unset",
                                "$push", "$pull", "$inc", "$rename", NULL};
    for (int i = 0; operators[i]; i++) {
        if (strstr(input, operators[i])) {
            return (strcmp(operators[i], "$where") == 0) ? NOSQLI_WHERE : NOSQLI_GT_NE;
        }
    }
    return NOSQLI_NONE;
}

int nosqli_sanitize(const char* input, char* output, size_t out_size) {
    if (!input || !output || out_size == 0) return 0;
    size_t out_pos = 0;
    for (size_t i = 0; input[i] && out_pos < out_size - 1; i++) {
        if (input[i] == '$' || input[i] == '{' || input[i] == '}') {
            if (out_pos + 2 < out_size) {
                output[out_pos++] = '\\';
                output[out_pos++] = input[i];
            }
        } else {
            output[out_pos++] = input[i];
        }
    }
    output[out_pos] = '\0';
    return (int)out_pos;
}

bool nosqli_is_operator_injection(const char* input) {
    return nosqli_detect(input) != NOSQLI_NONE;
}

bool orm_validate_model(const char* field, const char** allowed_fields, int count) {
    if (!field || !allowed_fields) return false;
    for (int i = 0; i < count; i++) {
        if (allowed_fields[i] && strcmp(field, allowed_fields[i]) == 0) return true;
    }
    return false;
}

bool orm_validate_type(const char* value, const char* expected_type) {
    if (!value || !expected_type) return false;
    if (strcmp(expected_type, "int") == 0) {
        char* end;
        strtol(value, &end, 10);
        return *end == '\0';
    }
    if (strcmp(expected_type, "float") == 0) {
        char* end;
        strtod(value, &end);
        return *end == '\0';
    }
    if (strcmp(expected_type, "alphanum") == 0) {
        for (size_t i = 0; value[i]; i++)
            if (!isalnum((unsigned char)value[i])) return false;
        return true;
    }
    return true;
}

void second_order_track(second_order_tracker_t* tracker, const char* value) {
    if (!tracker) return;
    tracker->stored_value = value;
    tracker->storage_context = "database";
    tracker->stored_at = time(NULL);
    tracker->flagged = false;
    if (value) {
        for (int i = 0; g_sqli_patterns[i].pattern; i++) {
            if (strstr(value, g_sqli_patterns[i].pattern)) {
                tracker->flagged = true;
                break;
            }
        }
    }
}

bool second_order_check(second_order_tracker_t* tracker, const char* usage_context) {
    if (!tracker) return false;
    if (tracker->flagged) return true;
    if (tracker->stored_value && strstr(tracker->stored_value, "'")) return true;
    (void)usage_context;
    return false;
}
