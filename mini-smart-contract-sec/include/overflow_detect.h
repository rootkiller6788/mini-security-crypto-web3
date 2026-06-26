#ifndef OVERFLOW_DETECT_H
#define OVERFLOW_DETECT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define OD_MAX_VARS  64

typedef enum {
    OD_OK           = 0,
    OD_OVERFLOW     = 1,
    OD_UNDERFLOW    = 2,
    OD_DIV_ZERO     = 3,
    OD_TRUNCATION   = 4,
    OD_TIMESTAMP    = 5,
    OD_BLOCK_OVER   = 6,
    OD_FIXED_POINT  = 7
} od_result_t;

typedef struct {
    od_result_t     type;
    int             line;
    char            expression[256];
    char            detail[256];
} od_finding_t;

typedef struct {
    od_finding_t findings[128];
    int          count;
    bool         safe_math_used;
    int          overflow_count;
    int          underflow_count;
    int          truncation_count;
} od_analyzer_t;

void od_init(od_analyzer_t *a);

bool od_add_overflow(uint64_t a, uint64_t b, uint64_t *result);
bool od_sub_underflow(uint64_t a, uint64_t b, uint64_t *result);
bool od_mul_overflow(uint64_t a, uint64_t b, uint64_t *result);
bool od_div_safe(uint64_t a, uint64_t b, uint64_t *result);

od_result_t od_check_operation(od_analyzer_t *a, const char *op,
                                uint64_t lhs, uint64_t rhs, uint64_t result,
                                int line);

od_result_t od_check_timestamp(od_analyzer_t *a, uint64_t ts, int line);
od_result_t od_check_block_number(od_analyzer_t *a, uint64_t block, int line);

od_result_t od_check_truncation(od_analyzer_t *a, int from_bits, int to_bits,
                                 int line);

typedef struct {
    uint64_t value;
    int      decimals;
    bool     valid;
} od_fixed_t;

od_fixed_t od_fixed_from_int(uint64_t v, int decimals);
od_fixed_t od_fixed_add(od_fixed_t a, od_fixed_t b);
od_fixed_t od_fixed_sub(od_fixed_t a, od_fixed_t b);
od_fixed_t od_fixed_mul(od_fixed_t a, od_fixed_t b);
od_result_t od_check_fixed_op(od_analyzer_t *a, const od_fixed_t *x,
                               const od_fixed_t *y, const char *desc, int line);

void od_add_finding(od_analyzer_t *a, od_result_t type, int line,
                    const char *expr, const char *detail);

void od_print_report(const od_analyzer_t *a);
int  od_total_issues(const od_analyzer_t *a);
bool od_has_critical(const od_analyzer_t *a);

void od_safe_math_init(void);

#endif
