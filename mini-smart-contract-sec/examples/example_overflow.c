#include "overflow_detect.h"
#include <stdio.h>
#include <stdint.h>

int main(void) {
    od_analyzer_t analyzer;
    od_init(&analyzer);

    printf("=== Integer Overflow Detection Example ===\n\n");

    uint64_t max_val = UINT64_MAX;

    printf("1. Addition overflow check:\n");
    printf("   %llu + 1 = ", (unsigned long long)max_val);
    uint64_t r1;
    bool ov1 = od_add_overflow(max_val, 1, &r1);
    printf("%llu (overflow=%d)\n", (unsigned long long)r1, ov1);
    od_check_operation(&analyzer, "+", max_val, 1, r1, 10);

    printf("\n2. Subtraction underflow check:\n");
    printf("   5 - 10 = ");
    uint64_t r2;
    bool uf1 = od_sub_underflow(5, 10, &r2);
    printf("%llu (underflow=%d)\n", (unsigned long long)r2, uf1);
    od_check_operation(&analyzer, "-", 5, 10, r2, 20);

    printf("\n3. Multiplication overflow check:\n");
    printf("   %llu * 2 = ", (unsigned long long)(UINT64_MAX / 2 + 1));
    uint64_t r3;
    bool ov2 = od_mul_overflow(UINT64_MAX / 2 + 1, 2, &r3);
    printf("%llu (overflow=%d)\n", (unsigned long long)r3, ov2);
    od_check_operation(&analyzer, "*", UINT64_MAX / 2 + 1, 2, r3, 30);

    printf("\n4. Division by zero check:\n");
    uint64_t r4;
    bool dz = od_div_safe(100, 0, &r4);
    printf("   100 / 0 = %llu (valid=%d)\n", (unsigned long long)r4, dz);

    printf("\n5. Safe operations (no overflow):\n");
    uint64_t safe_r;
    od_add_overflow(1000, 2000, &safe_r);
    printf("   1000 + 2000 = %llu\n", (unsigned long long)safe_r);

    od_sub_underflow(5000, 3000, &safe_r);
    printf("   5000 - 3000 = %llu\n", (unsigned long long)safe_r);

    od_mul_overflow(100, 200, &safe_r);
    printf("   100 * 200 = %llu\n", (unsigned long long)safe_r);

    printf("\n6. Timestamp check (year 2106+ problem):\n");
    uint64_t future_ts = 0x100000000ULL;
    od_check_timestamp(&analyzer, future_ts, 40);
    printf("   timestamp %llu > uint32 max\n", (unsigned long long)future_ts);

    printf("\n7. Truncation check:\n");
    od_check_truncation(&analyzer, 64, 32, 50);
    printf("   64-bit -> 32-bit truncation risk\n");

    printf("\n8. Fixed-point math check:\n");
    od_fixed_t f1 = od_fixed_from_int(150, 2);
    od_fixed_t f2 = od_fixed_from_int(250, 2);
    od_fixed_t sum = od_fixed_add(f1, f2);
    printf("   1.50 + 2.50 = %llu (decimals=%d, valid=%d)\n",
           (unsigned long long)sum.value, sum.decimals, sum.valid);

    od_check_fixed_op(&analyzer, &f1, &f2, "fixed_add", 60);

    printf("\n9. Fixed-point decimal mismatch:\n");
    od_fixed_t f3 = od_fixed_from_int(100, 18);
    od_fixed_t f4 = od_fixed_from_int(200, 6);
    od_check_fixed_op(&analyzer, &f3, &f4, "fixed_cross_decimals", 65);
    printf("   decimals %d vs %d mismatch\n", f3.decimals, f4.decimals);

    od_print_report(&analyzer);

    printf("\n=== Summary ===\n");
    printf("Total issues:  %d\n", od_total_issues(&analyzer));
    printf("Has critical:  %s\n", od_has_critical(&analyzer) ? "YES" : "no");

    return 0;
}
