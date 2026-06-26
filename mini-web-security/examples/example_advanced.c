#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "xss_csrf.h"
#include "sqli_inject.h"
#include "owasp_top10.h"
#include "input_validation.h"
#include "auth_session.h"

static void simulate_login_flow(void) {
    printf("=== Full Login Flow with Session Fixation Protection ===\n");

    session_fixation_t sf;
    session_fix_init(&sf);

    const char* pre_login_sid = "attacker_provided_session_id_abc123";
    session_fix_prelogin(&sf, pre_login_sid);
    printf("  [Step 1] Pre-login session ID captured: %.32s...\n", sf.original_id);

    session_fix_postlogin(&sf);
    printf("  [Step 2] Post-login: session rotated\n");
    printf("           New session ID: %.32s...\n", sf.new_id);
    printf("           Rotation count: %u\n", sf.login_count);

    printf("  [Step 3] Validate old session: %s\n",
           session_fix_validate(&sf, pre_login_sid) ? "ACCEPTED (BUG!)" : "REJECTED (OK)");
    printf("  [Step 3] Validate new session: %s\n",
           session_fix_validate(&sf, sf.new_id) ? "ACCEPTED (OK)" : "REJECTED (BUG!)");
    printf("\n");
}

static void simulate_idor_attack(void) {
    printf("=== IDOR (Insecure Direct Object Reference) Detection ===\n");

    const char* resource_id = "order_1337";
    const char* actual_owner = "user_42";
    const char* attacker = "user_99";

    printf("  Order '%s' owned by '%s'\n", resource_id, actual_owner);
    printf("  Attacker '%s' tries to access\n", attacker);
    printf("  Access granted: %s\n",
           idor_check(resource_id, attacker, actual_owner) ? "YES (VULN!)" : "NO (OK)");

    const char* owned_ids[] = {"order_100", "order_200", "order_300"};
    printf("  User owns: order_100, order_200, order_300\n");
    printf("  Request order_100: %s\n",
           idor_validate_ownership("order_100", owned_ids, 3) ? "ALLOWED" : "DENIED");
    printf("  Request order_1337: %s\n",
           idor_validate_ownership("order_1337", owned_ids, 3) ? "ALLOWED" : "DENIED");
    printf("\n");
}

static void simulate_ssrf_scan(void) {
    printf("=== SSRF URL Scanner ===\n");

    const char* urls[] = {
        "http://127.0.0.1/admin",
        "http://localhost:8080/debug",
        "http://192.168.1.1/config",
        "http://10.0.0.5/internal",
        "http://169.254.169.254/latest/meta-data/",
        "https://example.com/api/data",
        "http://0.0.0.0:80",
        NULL
    };
    for (int i = 0; urls[i]; i++) {
        ssrf_analysis_t analysis;
        ssrf_analyze_url(urls[i], &analysis);
        printf("  %-50s internal=%s risk=%d\n",
               urls[i],
               analysis.is_internal ? "YES" : "NO",
               analysis.risk_score);
    }
    printf("\n");
}

static void simulate_comprehensive_xss(void) {
    printf("=== Comprehensive XSS Detection & Sanitization ===\n");

    struct {
        const char* payload;
        const char* context;
        int encoding;
    } tests[] = {
        {"<script>alert(1)</script>",   "body",     0},
        {"javascript:alert(1)",          "href",     1},
        {"';alert(document.cookie);//",  "script",   2},
        {"<img src=x onerror=alert(1)>","body",     0},
        {"'onmouseover='alert(1)",       "attribute",1},
        {NULL, NULL, 0}
    };
    for (int i = 0; tests[i].payload; i++) {
        char sanitized[512];
        int result = 0;
        int enc = tests[i].encoding;
        if (enc == 0) result = xss_sanitize_html(tests[i].payload, sanitized, sizeof(sanitized));
        else if (enc == 1) result = xss_sanitize_attribute(tests[i].payload, sanitized, sizeof(sanitized));
        else if (enc == 2) result = xss_sanitize_javascript(tests[i].payload, sanitized, sizeof(sanitized));
        printf("  Context: %-10s | Raw: %-30s -> %s\n",
               tests[i].context, tests[i].payload, sanitized);
        (void)result;
    }
    printf("\n");
}

static void simulate_sqli_scan(void) {
    printf("=== SQL Injection Pattern Scan ===\n");

    struct {
        const char* input;
        const char* description;
    } tests[] = {
        {"admin' OR '1'='1",           "Classic login bypass"},
        {"1' UNION SELECT user,pass FROM users--", "UNION-based data extraction"},
        {"1 AND 1=1",                  "Boolean blind test"},
        {"1; DROP TABLE users;--",     "Stacked query kill"},
        {"1' AND SLEEP(5)--",          "Time-based blind"},
        {"999 UNION SELECT username, password FROM users", "UNION attempt"},
        {"normal_search_term",         "Legitimate input"},
        {NULL, NULL}
    };
    for (int i = 0; tests[i].input; i++) {
        sqli_detect_result_t results[4];
        int found = sqli_scan_simple(tests[i].input, results, 4);
        printf("  [%s] ", tests[i].description);
        if (found == 0) printf("CLEAN");
        else {
            printf("FOUND %d issue(s): ", found);
            for (int j = 0; j < found && j < 4; j++)
                printf("%s ", sqli_type_name(results[j].type));
        }
        printf("\n");
    }
    printf("\n");
}

static void simulate_password_reset_flow(void) {
    printf("=== Password Reset Flow (Token Security) ===\n");

    password_reset_t reset;
    pwd_reset_generate(&reset, "user@example.com", 900);
    printf("  Reset token generated for: %s\n", reset.user_id);
    printf("  Token (64 hex): %.64s\n", reset.token);
    printf("  Entropy:         %d bits\n", pwd_reset_entropy_bits(reset.token));
    printf("  Expires at:      %s", ctime(&reset.expires_at));
    printf("  Validate correct token: %s\n",
           pwd_reset_validate(&reset, reset.token) ? "OK" : "FAIL");
    printf("  Validate wrong token:   %s\n",
           pwd_reset_validate(&reset, "0000000000000000") ? "OK" : "FAIL");
    printf("\n");
}

static void simulate_csrf_defense(void) {
    printf("=== CSRF Defense Matrix ===\n");

    printf("  --- Origin/Referer Checks ---\n");
    printf("  Origin 'https://mysite.com' vs host 'mysite.com':        %s\n",
           csrf_check_origin("https://mysite.com/page", "mysite.com") ? "OK" : "FAIL");
    printf("  Origin 'https://evil.com' vs host 'mysite.com':          %s\n",
           csrf_check_origin("https://evil.com/fake", "mysite.com") ? "OK" : "FAIL");
    printf("  Origin 'https://sub.mysite.com' vs host 'mysite.com':    %s\n",
           csrf_check_origin("https://sub.mysite.com", "mysite.com") ? "OK" : "FAIL");

    printf("\n  --- CSRF Token ---\n");
    csrf_token_t tok1, tok2;
    csrf_token_generate(&tok1);
    memcpy(&tok2, &tok1, sizeof(csrf_token_t));
    printf("  Token match:    %s\n",
           csrf_token_validate(&tok1, &tok2) ? "YES" : "NO");
    csrf_token_generate(&tok2);
    printf("  Tokens differ:  %s\n",
           csrf_token_validate(&tok1, &tok2) ? "NO (same)" : "YES (different)");

    printf("\n  --- SameSite Cookie ---\n");
    char cookie[512];
    csrf_set_cookie_header("session", "abc123def", true, true,
                           SAMESITE_STRICT, 3600, "/", cookie, sizeof(cookie));
    printf("  %s\n\n", cookie);
}

static void simulate_orm_protection(void) {
    printf("=== ORM / Mass Assignment Protection ===\n");

    const char* user_fields[] = {"id", "username", "email", "bio", "avatar_url"};
    int field_count = 5;

    printf("  Allowed fields:");
    for (int i = 0; i < field_count; i++) printf(" %s", user_fields[i]);
    printf("\n");

    const char* test_fields[] = {"username", "email", "is_admin", "password_hash", "role"};
    for (int i = 0; i < 5; i++) {
        printf("  Field '%s': %s\n", test_fields[i],
               orm_validate_model(test_fields[i], user_fields, field_count)
               ? "ALLOWED" : "BLOCKED (mass assignment)");
    }
    printf("\n");
}

static void simulate_second_order_sqli(void) {
    printf("=== Second-Order SQL Injection Awareness ===\n");

    second_order_tracker_t tracker;

    const char* safe_input = "John Doe";
    second_order_track(&tracker, safe_input);
    printf("  Stored 'John Doe':      flagged=%s\n", tracker.flagged ? "YES" : "NO");

    const char* evil_input = "admin' OR 1=1--";
    second_order_track(&tracker, evil_input);
    printf("  Stored 'admin' OR 1=1': flagged=%s\n", tracker.flagged ? "YES" : "NO");

    printf("  Second-order check (query): %s\n",
           second_order_check(&tracker, "SELECT * FROM users WHERE name=?") ? "DANGER" : "OK");
    printf("\n");
}

static void simulate_owasp_comprehensive(void) {
    printf("=== OWASP Top 10 Comprehensive Report ===\n");

    owasp_report_t report;
    owasp_report_init(&report);

    owasp_report_add(&report, OWASP_A01_BROKEN_ACCESS_CONTROL, RISK_HIGH,
                     "GET /api/users/42 exposes user data without ownership check",
                     "Add ownership validation middleware");
    owasp_report_add(&report, OWASP_A03_INJECTION, RISK_CRITICAL,
                     "SQL injection in /search endpoint via 'q' parameter",
                     "Use prepared statements for all queries");
    owasp_report_add(&report, OWASP_A05_SECURITY_MISCONFIGURATION, RISK_MEDIUM,
                     "Server header exposes Apache/2.4.41 version",
                     "Configure ServerTokens Prod in httpd.conf");
    owasp_report_add(&report, OWASP_A07_AUTH_FAILURES, RISK_HIGH,
                     "Password reset token does not expire",
                     "Add 15-minute expiry to password reset tokens");
    owasp_report_add(&report, OWASP_A09_LOGGING_MONITORING, RISK_MEDIUM,
                     "Failed login attempts not rate-limited",
                     "Implement rate limiting with 5 attempts per 15 minutes");

    printf("  Total findings: %d\n", report.count);
    for (int i = 0; i < report.count; i++) {
        const char* risk_str = "LOW";
        if (report.findings[i].risk == RISK_HIGH) risk_str = "HIGH";
        else if (report.findings[i].risk == RISK_CRITICAL) risk_str = "CRITICAL";
        else if (report.findings[i].risk == RISK_MEDIUM) risk_str = "MEDIUM";
        printf("  [%s] %s\n", risk_str, owasp_category_name(report.findings[i].category));
        printf("        Issue: %s\n", report.findings[i].detail);
        printf("        Fix:   %s\n", report.findings[i].remediation);
    }
    printf("\n");
}

int main(void) {
    srand((unsigned)time(NULL));
    printf("========================================\n");
    printf("  mini-web-security: Advanced Example\n");
    printf("========================================\n\n");

    simulate_login_flow();
    simulate_idor_attack();
    simulate_ssrf_scan();
    simulate_comprehensive_xss();
    simulate_sqli_scan();
    simulate_password_reset_flow();
    simulate_csrf_defense();
    simulate_orm_protection();
    simulate_second_order_sqli();
    simulate_owasp_comprehensive();

    printf("========================================\n");
    printf("  All advanced examples completed.\n");
    printf("========================================\n");
    return 0;
}
