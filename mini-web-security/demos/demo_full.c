/*
 * mini-web-security — Full Demo: Web Application Security
 *
 * Demonstrates: XSS detection/sanitization, CSP, CSRF, SQLi detection,
 *               input validation, auth (PBKDF2/TOTP/sessions/JWT/OAuth2), OWASP scanning.
 */
#include "../include/xss_csrf.h"
#include "../include/sqli_inject.h"
#include "../include/owasp_top10.h"
#include "../include/input_validation.h"
#include "../include/auth_session.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

int main(void) {
    printf("╔══════════════════════════════════════════╗\n");
    printf("║   mini-web-security: Web App Security   ║\n");
    printf("╚══════════════════════════════════════════╝\n\n");

    /* Step 1: XSS Detection & Sanitization */
    printf("── Step 1: XSS Detection & CSP ──\n");
    char encoded[256];
    html_encode("<script>alert('xss')</script>", encoded, sizeof(encoded));
    printf("HTML encoded: \"%s\"\n", encoded);

    xss_report_t xss_report;
    xss_detect_reflected("<img src=x onerror=alert(1)>", "/search?q=", &xss_report);
    printf("XSS detection: type=%d, detected=%s\n", xss_report.type, xss_report.detected ? "YES" : "NO");

    char sanitized[256];
    xss_sanitize_html("<b>Hello</b><script>evil()</script>", sanitized, sizeof(sanitized));
    printf("XSS sanitized: \"%s\"\n", sanitized);

    csp_policy_t csp;
    csp_init(&csp, false);
    csp_add_directive(&csp, CSP_SRC_DEFAULT, "'self'");
    csp_add_directive(&csp, CSP_SRC_SCRIPT, "'self' 'nonce-random123'");
    csp_add_directive(&csp, CSP_SRC_STYLE, "'self' 'unsafe-inline'");
    char csp_header[512];
    csp_generate_header(&csp, csp_header, sizeof(csp_header));
    printf("CSP header: %s\n", csp_header);

    /* Step 2: CSRF Protection */
    printf("\n── Step 2: CSRF Protection ──\n");
    csrf_token_t csrf_tok;
    csrf_token_generate(&csrf_tok);
    char tok_hex[65];
    csrf_token_to_hex(&csrf_tok, tok_hex, sizeof(tok_hex));
    printf("CSRF token: %s\n", tok_hex);

    bool origin_ok = csrf_check_origin("https://app.example.com", "app.example.com");
    printf("Origin check (https://app.example.com): %s\n", origin_ok ? "PASS" : "FAIL");

    char cookie[256];
    csrf_set_cookie_header("session", "abc123", true, true, SAMESITE_LAX, 3600, "/", cookie, sizeof(cookie));
    printf("Set-Cookie: %s\n", cookie);

    /* Step 3: SQL Injection Detection */
    printf("\n── Step 3: SQL Injection Detection ──\n");
    const char *attacks[] = {
        "' OR '1'='1' --",
        "1' UNION SELECT username,password FROM users--",
        "1' AND 1=1--",
        "1'; WAITFOR DELAY '00:00:05'--",
        "1'; DROP TABLE users;--"
    };
    for (int i = 0; i < 5; i++) {
        sqli_detect_result_t r;
        sqli_detect(attacks[i], &r);
        printf("SQLi [%s]: type=%s, risk=%d/100\n",
               attacks[i], sqli_type_name(r.type), r.risk_score);
    }

    char safe_query[256];
    sqli_sanitize("SELECT * FROM users WHERE name='admin'--'", safe_query, sizeof(safe_query));
    printf("Sanitized query: %s\n", safe_query);

    /* Step 4: Input Validation */
    printf("\n── Step 4: Input Validation ──\n");
    printf("Email 'user@example.com': %s\n", ival_validate_email("user@example.com") ? "valid" : "invalid");
    printf("Email '../etc/passwd': %s\n", ival_validate_email("../etc/passwd") ? "valid" : "invalid");
    printf("Integer '12345': %s\n", ival_is_integer("12345") ? "yes" : "no");
    printf("Alphanum 'abc123': %s\n", ival_is_alphanum("abc123") ? "yes" : "no");
    printf("IPv4 '192.168.1.1': %s\n", ival_validate_ipv4("192.168.1.1") ? "valid" : "invalid");

    double_enc_t denc;
    double_enc_detect("%252fetc%252fpasswd", &denc);
    printf("Double encoding: detected=%s, depth=%d\n", denc.detected ? "YES" : "NO", denc.depth);

    /* Step 5: Authentication */
    printf("\n── Step 5: Authentication & Sessions ──\n");
    auth_password_t pw;
    auth_password_hash("MySecurePassword123!", &pw);
    printf("PBKDF2 hash: iterations=%d\n", pw.iterations);
    bool pw_ok = auth_password_verify("MySecurePassword123!", &pw);
    bool pw_bad = auth_password_verify("WrongPassword", &pw);
    printf("Password verify (correct): %s\n", pw_ok ? "PASS" : "FAIL");
    printf("Password verify (wrong):   %s\n", pw_bad ? "PASS (unexpected)" : "REJECTED");

    totp_config_t totp_cfg;
    totp_init(&totp_cfg, 6, 30);
    char totp_secret[64];
    totp_generate_secret(totp_secret, sizeof(totp_secret));
    uint32_t code = totp_generate_code(&totp_cfg, time(NULL));
    printf("TOTP: secret=%s, code=%06u\n", totp_secret, code);

    session_t sess;
    session_init(&sess);
    session_generate_id(&sess);
    printf("Session: id=%s, active=%s\n", sess.id, sess.is_active ? "yes" : "no");

    jwt_token_t jwt;
    jwt_init(&jwt);
    const char *jwt_str = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature";
    jwt_parse(jwt_str, &jwt);
    printf("JWT: parsed=%s, alg=%d\n", jwt.parsed ? "yes" : "no", jwt.algorithm);

    /* Step 6: OWASP Top 10 Scan */
    printf("\n── Step 6: OWASP Top 10 Scanning ──\n");
    owasp_report_t owasp;
    owasp_report_init(&owasp);
    const char *headers[] = {
        "Server: nginx/1.18.0",
        "X-XSS-Protection: 0",
        "X-Content-Type-Options: nosniff"
    };
    owasp_scan_headers(headers, 3, &owasp);
    printf("OWASP scan: %d findings\n", owasp.count);
    for (int i = 0; i < owasp.count && i < 3; i++) {
        printf("  [%s] risk=%d: %s\n",
               owasp_category_name(owasp.findings[i].category),
               owasp.findings[i].risk, owasp.findings[i].detail);
    }

    /* Step 7: SSRF / File Inclusion */
    printf("\n── Step 7: SSRF & File Inclusion ──\n");
    ssrf_analysis_t ssrf;
    ssrf_analyze_url("http://169.254.169.254/latest/meta-data/", &ssrf);
    printf("SSRF: internal=%s, risk=%d\n", ssrf.is_internal ? "YES" : "NO", ssrf.risk_score);

    fi_result_t fi_res;
    fi_detect("../../etc/passwd", &fi_res);
    printf("File inclusion: type=%d, detected=%s\n", fi_res.type, fi_res.detected ? "YES" : "NO");

    dt_result_t dt_res;
    dt_detect("....//....//etc/passwd", &dt_res);
    printf("Directory traversal: detected=%s, depth=%d\n",
           dt_res.detected ? "YES" : "NO", dt_res.depth_attempted);

    printf("\n✓ Full web security demo complete!\n");
    return 0;
}
