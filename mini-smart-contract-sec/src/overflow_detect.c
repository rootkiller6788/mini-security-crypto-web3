#include "overflow_detect.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

void od_init(od_analyzer_t *a) {
    memset(a, 0, sizeof(od_analyzer_t));
}

bool od_add_overflow(uint64_t a, uint64_t b, uint64_t *result) {
    if (a > 0 && b > UINT64_MAX - a) {
        *result = 0;
        return true;
    }
    *result = a + b;
    return false;
}

bool od_sub_underflow(uint64_t a, uint64_t b, uint64_t *result) {
    if (b > a) {
        *result = 0;
        return true;
    }
    *result = a - b;
    return false;
}

bool od_mul_overflow(uint64_t a, uint64_t b, uint64_t *result) {
    if (a == 0 || b == 0) {
        *result = 0;
        return false;
    }
    if (a > UINT64_MAX / b) {
        *result = 0;
        return true;
    }
    *result = a * b;
    return false;
}

bool od_div_safe(uint64_t a, uint64_t b, uint64_t *result) {
    if (b == 0) {
        *result = 0;
        return false;
    }
    *result = a / b;
    return true;
}

od_result_t od_check_operation(od_analyzer_t *a, const char *op,
                                uint64_t lhs, uint64_t rhs, uint64_t result,
                                int line) {
    od_result_t r = OD_OK;
    uint64_t safe_result = 0;
    (void)result; /* result is the user-reported value, not used here */

    if (strcmp(op, "+") == 0 || strcmp(op, "add") == 0) {
        if (od_add_overflow(lhs, rhs, &safe_result))
            r = OD_OVERFLOW;
    } else if (strcmp(op, "-") == 0 || strcmp(op, "sub") == 0) {
        if (od_sub_underflow(lhs, rhs, &safe_result))
            r = OD_UNDERFLOW;
    } else if (strcmp(op, "*") == 0 || strcmp(op, "mul") == 0) {
        if (od_mul_overflow(lhs, rhs, &safe_result))
            r = OD_OVERFLOW;
    } else if (strcmp(op, "/") == 0 || strcmp(op, "div") == 0) {
        if (rhs == 0)
            r = OD_DIV_ZERO;
    }

    if (r != OD_OK) {
        char expr[256], detail[256];
        snprintf(expr, sizeof(expr), "%llu %s %llu",
                 (unsigned long long)lhs, op, (unsigned long long)rhs);
        snprintf(detail, sizeof(detail),
                 r == OD_OVERFLOW ? "overflow detected" :
                 r == OD_UNDERFLOW ? "underflow detected" : "division by zero");
        od_add_finding(a, r, line, expr, detail);
        if (r == OD_OVERFLOW) a->overflow_count++;
        if (r == OD_UNDERFLOW) a->underflow_count++;
    }

    return r;
}

od_result_t od_check_timestamp(od_analyzer_t *a, uint64_t ts, int line) {
    if (ts > 0xFFFFFFFF) {
        od_add_finding(a, OD_TIMESTAMP, line, "timestamp",
                       "timestamp exceeds uint32; potential overflow in 32-bit casts");
        return OD_TIMESTAMP;
    }
    return OD_OK;
}

od_result_t od_check_block_number(od_analyzer_t *a, uint64_t block, int line) {
    if (block > 0xFFFFFFFF) {
        od_add_finding(a, OD_BLOCK_OVER, line, "block.number",
                       "block number exceeds uint32 range");
        return OD_BLOCK_OVER;
    }
    return OD_OK;
}

od_result_t od_check_truncation(od_analyzer_t *a, int from_bits, int to_bits,
                                 int line) {
    if (to_bits < from_bits) {
        uint64_t max_val = (to_bits >= 64) ? UINT64_MAX : ((1ULL << to_bits) - 1);
        char detail[256];
        snprintf(detail, sizeof(detail),
                 "truncation from %d bits to %d bits (max safe value: %llu)",
                 from_bits, to_bits, (unsigned long long)max_val);
        od_add_finding(a, OD_TRUNCATION, line, "type-cast", detail);
        a->truncation_count++;
        return OD_TRUNCATION;
    }
    return OD_OK;
}

od_fixed_t od_fixed_from_int(uint64_t v, int decimals) {
    od_fixed_t f;
    f.value = v;
    f.decimals = decimals;
    f.valid = true;
    return f;
}

od_fixed_t od_fixed_add(od_fixed_t a, od_fixed_t b) {
    od_fixed_t r = {0, 0, false};
    if (a.decimals != b.decimals) return r;
    if (od_add_overflow(a.value, b.value, &r.value)) return r;
    r.decimals = a.decimals;
    r.valid = true;
    return r;
}

od_fixed_t od_fixed_sub(od_fixed_t a, od_fixed_t b) {
    od_fixed_t r = {0, 0, false};
    if (a.decimals != b.decimals) return r;
    if (od_sub_underflow(a.value, b.value, &r.value)) return r;
    r.decimals = a.decimals;
    r.valid = true;
    return r;
}

od_fixed_t od_fixed_mul(od_fixed_t a, od_fixed_t b) {
    od_fixed_t r = {0, 0, false};
    if (od_mul_overflow(a.value, b.value, &r.value)) return r;
    r.decimals = a.decimals + b.decimals;
    r.valid = true;
    return r;
}

od_result_t od_check_fixed_op(od_analyzer_t *a, const od_fixed_t *x,
                               const od_fixed_t *y, const char *desc, int line) {
    if (!x->valid || !y->valid) {
        od_add_finding(a, OD_FIXED_POINT, line, desc, "invalid fixed-point operand");
        return OD_FIXED_POINT;
    }
    if (x->decimals != y->decimals) {
        od_add_finding(a, OD_FIXED_POINT, line, desc,
                       "fixed-point decimal mismatch");
        return OD_FIXED_POINT;
    }
    return OD_OK;
}

void od_add_finding(od_analyzer_t *a, od_result_t type, int line,
                    const char *expr, const char *detail) {
    if (a->count >= 128) return;
    a->findings[a->count].type = type;
    a->findings[a->count].line = line;
    strncpy(a->findings[a->count].expression, expr, 255);
    a->findings[a->count].expression[255] = '\0';
    strncpy(a->findings[a->count].detail, detail, 255);
    a->findings[a->count].detail[255] = '\0';
    a->count++;
}

void od_print_report(const od_analyzer_t *a) {
    printf("\n========== Overflow/Underflow Analysis Report ==========\n");
    printf("Total issues:       %d\n", a->count);
    printf("  Overflow:         %d\n", a->overflow_count);
    printf("  Underflow:        %d\n", a->underflow_count);
    printf("  Div by Zero:      %d\n", a->truncation_count);
    printf("SafeMath used:      %s\n", a->safe_math_used ? "yes" : "no");
    printf("Has critical:       %s\n", od_has_critical(a) ? "YES" : "no");

    if (a->count > 0) {
        printf("\n--- Findings ---\n");
        for (int i = 0; i < a->count; i++) {
            static const char *types[] = {
                "OK", "OVERFLOW", "UNDERFLOW", "DIV_ZERO",
                "TRUNCATION", "TIMESTAMP", "BLOCK_OVER", "FIXED_POINT"
            };
            printf("  [L%d] %-12s | %s | %s\n",
                   a->findings[i].line,
                   types[a->findings[i].type],
                   a->findings[i].expression,
                   a->findings[i].detail);
        }
    }
    printf("=========================================================\n");
}

int od_total_issues(const od_analyzer_t *a) {
    return a->count;
}

bool od_has_critical(const od_analyzer_t *a) {
    for (int i = 0; i < a->count; i++) {
        if (a->findings[i].type == OD_OVERFLOW ||
            a->findings[i].type == OD_UNDERFLOW) {
            return true;
        }
    }
    return false;
}

void od_safe_math_init(void) {
    /* no-op: SafeMath is purely a static analysis concept in this library */
}
