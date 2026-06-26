#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include "xss_csrf.h"
#include "sqli_inject.h"
#include "owasp_top10.h"
#include "input_validation.h"
#include "auth_session.h"

typedef enum {
    MODE_XSS_TEST,
    MODE_SQLI_TEST,
    MODE_OWASP_SCAN,
    MODE_VALIDATE_INPUT,
    MODE_PASSWORD_TEST,
    MODE_TOTP_TEST,
    MODE_JWT_ANALYZE,
    MODE_CSRF_TEST,
    MODE_SSRF_TEST,
    MODE_RATE_LIMIT,
    MODE_ALL,
    MODE_HELP
} cli_mode_t;

static void print_banner(void) {
    printf("\n");
    printf("  ╔═══════════════════════════════════════════════╗\n");
    printf("  ║  mini-web-security CLI                        ║\n");
    printf("  ║  Web Security Testing & Analysis Toolkit      ║\n");
    printf("  ╚═══════════════════════════════════════════════╝\n\n");
}

static void print_usage(void) {
    printf("Usage: demo_cli [OPTIONS] [INPUT]\n\n");
    printf("Options:\n");
    printf("  --xss INPUT        Test INPUT for XSS vulnerabilities\n");
    printf("  --sqli INPUT       Test INPUT for SQL injection\n");
    printf("  --owasp            Run OWASP Top 10 scan\n");
    printf("  --validate INPUT   Validate input type (email, url, etc.)\n");
    printf("  --validate-type T  Specify type: email|url|cc|ipv4|ipv6|password\n");
    printf("  --password PASS    Analyze password strength\n");
    printf("  --hash PASS        Generate password hash\n");
    printf("  --verify PASS HASH Verify password against hash\n");
    printf("  --totp             Generate TOTP secret and code\n");
    printf("  --jwt TOKEN        Analyze JWT token for vulnerabilities\n");
    printf("  --csrf             Generate CSRF token\n");
    printf("  --ssrf URL         Test URL for SSRF vulnerability\n");
    printf("  --ratelimit N      Simulate rate limiting (N attempts)\n");
    printf("  --all              Run all tests on INPUT\n");
    printf("  --help             Show this help\n\n");
    printf("Examples:\n");
    printf("  demo_cli --xss \"<script>alert(1)</script>\"\n");
    printf("  demo_cli --sqli \"admin' OR 1=1--\"\n");
    printf("  demo_cli --validate --validate-type email user@example.com\n");
    printf("  demo_cli --password \"MyP@ssw0rd\"\n");
    printf("  demo_cli --ssrf \"http://127.0.0.1/admin\"\n");
    printf("  demo_cli --all \"<script>alert(1)</script>\"\n\n");
}

static void test_xss(const char* input) {
    printf("=== XSS Vulnerability Test ===\n");
    printf("Input: \"%s\"\n\n", input);

    xss_report_t rpt;
    xss_detect_reflected(input, "query_param", &rpt);
    printf("[Reflected XSS]  Detected: %-5s | Source: %s\n",
           rpt.detected ? "YES" : "NO", rpt.source);

    xss_detect_stored(input, &rpt);
    printf("[Stored XSS]     Detected: %-5s\n", rpt.detected ? "YES" : "NO");

    xss_detect_dom(input, "location.hash", &rpt);
    printf("[DOM-based XSS]  Detected: %-5s\n", rpt.detected ? "YES" : "NO");

    printf("\n--- Sanitized Output ---\n");
    char sanitized[512];
    xss_sanitize_html(input, sanitized, sizeof(sanitized));
    printf("HTML encode:       %s\n", sanitized);
    xss_sanitize_attribute(input, sanitized, sizeof(sanitized));
    printf("Attribute encode:  %s\n", sanitized);
    xss_sanitize_javascript(input, sanitized, sizeof(sanitized));
    printf("JavaScript encode: %s\n", sanitized);
    xss_sanitize_url(input, sanitized, sizeof(sanitized));
    printf("URL sanitize:      %s\n\n", sanitized);
}

static void test_sqli(const char* input) {
    printf("=== SQL Injection Test ===\n");
    printf("Input: \"%s\"\n\n", input);

    sqli_detect_result_t main_result;
    sqli_detect(input, &main_result);
    printf("Primary detection: %s (risk: %d/100)\n",
           sqli_type_name(main_result.type), main_result.risk_score);

    printf("\n--- Specific Pattern Tests ---\n");
    size_t off;
    printf("Classic (' OR 1=1):   %s\n", sqli_detect_classic(input, &off) ? "DETECTED" : "Clear");
    printf("UNION-based:          %s\n", sqli_detect_union(input, &off) ? "DETECTED" : "Clear");
    printf("Boolean blind:        %s\n", sqli_detect_boolean_blind(input, &off) ? "DETECTED" : "Clear");
    printf("Time-based blind:     %s\n", sqli_detect_time_blind(input, &off) ? "DETECTED" : "Clear");

    printf("\n--- NoSQL Injection ---\n");
    nosqli_type_t nosql = nosqli_detect(input);
    const char* nosql_name = "NONE";
    if (nosql == NOSQLI_GT_NE) nosql_name = "GT/NE operators";
    else if (nosql == NOSQLI_REGEX) nosql_name = "REGEX injection";
    else if (nosql == NOSQLI_WHERE) nosql_name = "$where JavaScript";
    else if (nosql == NOSQLI_OPERATOR) nosql_name = "Other operators";
    printf("NoSQL detection:      %s\n", nosql_name);

    printf("\n--- Sanitized Output ---\n");
    char escaped[512];
    sqli_escape_string(input, escaped, sizeof(escaped));
    printf("SQL escaped:  %s\n\n", escaped);
}

static void test_owasp(void) {
    printf("=== OWASP Top 10 Categories ===\n\n");
    for (int i = 0; i <= OWASP_A10_SSRF; i++) {
        owasp_category_t cat = (owasp_category_t)i;
        printf("[%s]\n", owasp_category_name(cat));
        printf("  %s\n\n", owasp_category_desc(cat));
    }
    printf("--- Cryptographic Failure Detection ---\n");
    cipher_algorithm_t algos[] = {CIPHER_MD5, CIPHER_SHA1, CIPHER_DES, CIPHER_RC4,
                                   CIPHER_3DES, CIPHER_AES128, CIPHER_AES256};
    const char* algo_names[] = {"MD5","SHA1","DES","RC4","3DES","AES128","AES256"};
    for (int i = 0; i < 7; i++) {
        printf("  %-6s: weak=%s, min_key=%zu\n", algo_names[i],
               crypto_is_weak(algos[i]) ? "YES" : "NO",
               crypto_is_weak(algos[i]) ? 0 : (algos[i] == CIPHER_AES128 ? 16 : 32));
    }

    printf("\n--- Hardcoded Secret Detection ---\n");
    const char* secrets[] = {"password", "MyV3ryS3cur3K3y!!2024", "123456", "changeme"};
    for (int i = 0; i < 4; i++)
        printf("  \"%s\": %s\n", secrets[i],
               crypto_is_hardcoded_secret(secrets[i]) ? "WEAK/HARDCODED" : "OK");
    printf("\n");
}

static void test_validate(const char* input, const char* type) {
    printf("=== Input Validation: %s ===\n", type ? type : "auto");
    printf("Input: \"%s\"\n\n", input);
    if (!type || strcmp(type, "email") == 0)
        printf("Email:        %s\n", ival_validate_email(input) ? "valid" : "INVALID");
    if (!type || strcmp(type, "url") == 0)
        printf("URL:          %s\n", ival_validate_url(input) ? "valid" : "INVALID");
    if (!type || strcmp(type, "cc") == 0)
        printf("Credit Card:  %s\n", ival_validate_credit_card(input) ? "valid (Luhn)" : "INVALID");
    if (!type || strcmp(type, "ipv4") == 0)
        printf("IPv4:         %s\n", ival_validate_ipv4(input) ? "valid" : "INVALID");
    if (!type || strcmp(type, "ipv6") == 0)
        printf("IPv6:         %s\n", ival_validate_ipv6(input) ? "valid" : "INVALID");
    if (!type || strcmp(type, "password") == 0) {
        int pw = ival_validate_password(input, 8, true, true, true);
        printf("Password:     %s", pw > 0 ? "strong" :
               pw == -1 ? "too short" : pw == -2 ? "missing uppercase" :
               pw == -3 ? "missing digit" : "missing special char");
        printf(" (score: %d/100)\n", auth_password_strength(input));
    }
    printf("Length:       %zu chars\n", strlen(input));
    printf("UTF-8:        %s\n", utf8_validate(input, strlen(input)) ? "valid" : "INVALID");
    printf("\n");
}

static void test_password(const char* pass) {
    printf("=== Password Analysis ===\n");
    printf("Password: \"%s\"\n\n", pass);
    printf("Strength:     %d/100\n", auth_password_strength(pass));
    int pw_check = ival_validate_password(pass, 8, true, true, true);
    printf("Policy:       %s\n",
           pw_check > 0 ? "PASS" : pw_check == -1 ? "FAIL: too short" :
           pw_check == -2 ? "FAIL: needs uppercase" : pw_check == -3 ? "FAIL: needs digit" :
           "FAIL: needs special char");
    printf("\n--- PBKDF2-SHA256 Hash ---\n");
    auth_password_t pw_hash;
    if (auth_password_hash(pass, &pw_hash)) {
        printf("Salt:         ");
        for (int i = 0; i < 8; i++) printf("%02x", pw_hash.salt[i]);
        printf("...\n");
        printf("Hash:         ");
        for (int i = 0; i < 8; i++) printf("%02x", pw_hash.hash[i]);
        printf("...\n");
        printf("Iterations:   %d\n", pw_hash.iterations);
        char b64[256];
        auth_password_to_base64(&pw_hash, b64, sizeof(b64));
        printf("Base64:       %s\n", b64);
    }
    printf("\n");
}

static void test_totp(void) {
    printf("=== TOTP (Time-based One-Time Password) ===\n\n");
    totp_config_t cfg;
    totp_init(&cfg, 6, 30);
    char secret[32];
    totp_generate_secret(secret, sizeof(secret));
    strncpy(cfg.secret_base32, secret, sizeof(cfg.secret_base32) - 1);
    printf("Secret (Base32): %s\n", cfg.secret_base32);
    printf("Period:          %ds\n", cfg.period);
    printf("Digits:          %d\n", cfg.digits);
    time_t now = time(NULL);
    uint32_t code = totp_generate_code(&cfg, now);
    printf("\nCurrent time:    %s", ctime(&now));
    printf("TOTP Code:       %06u\n", (unsigned)code);
    printf("Validate code:   %s\n", totp_validate_code(&cfg, now, code) ? "VALID" : "INVALID");
    printf("Window test:     %s\n\n", totp_validate_window(&cfg, now, code, 1) ? "PASS" : "FAIL");
}

static void test_jwt(const char* token_str) {
    printf("=== JWT Analysis ===\n");
    printf("Token: \"%s\"\n\n", token_str);
    jwt_token_t token;
    if (jwt_parse(token_str, &token)) {
        printf("Parsed:         OK\n");
        printf("Header:         %s\n", token.header);
        printf("Payload:        %s\n", token.payload);
        printf("Algorithm:      ");
        switch (token.algorithm) {
        case JWT_ALG_NONE: printf("NONE (DANGER!)\n"); break;
        case JWT_ALG_HS256: printf("HS256\n"); break;
        case JWT_ALG_HS384: printf("HS384\n"); break;
        case JWT_ALG_HS512: printf("HS512\n"); break;
        default: printf("Unknown\n");
        }
    } else {
        printf("Parse:          FAILED\n");
    }
    printf("\n--- Vulnerability Checks ---\n");
    printf("none algorithm: %s\n", jwt_none_attack_check(token_str) ? "VULNERABLE!" : "OK");
    uint8_t key[64];
    memset(key, 0x41, 8);
    printf("8-byte key:     %s\n",
           jwt_weak_key_check(key, 8, JWT_ALG_HS256) ? "WEAK KEY!" : "OK");
    memset(key, 0x41, 32);
    printf("32-byte key:    %s\n\n",
           jwt_weak_key_check(key, 32, JWT_ALG_HS256) ? "WEAK KEY!" : "OK");
}

static void test_csrf(void) {
    printf("=== CSRF Protection Test ===\n\n");
    printf("--- Token Generation ---\n");
    csrf_token_t tok;
    csrf_token_generate(&tok);
    char hex[65];
    csrf_token_to_hex(&tok, hex, sizeof(hex));
    printf("Token (hex):  %.64s\n\n", hex);

    printf("--- Origin Validation ---\n");
    printf("mysite.com / mysite.com:        %s\n",
           csrf_check_origin("https://mysite.com", "mysite.com") ? "OK" : "FAIL");
    printf("evil.com / mysite.com:          %s\n",
           csrf_check_origin("https://evil.com", "mysite.com") ? "OK" : "FAIL");
    printf("sub.mysite.com / mysite.com:    %s\n",
           csrf_check_origin("https://sub.mysite.com", "mysite.com") ? "OK" : "FAIL");

    printf("\n--- SameSite Cookie ---\n");
    char cookie[512];
    csrf_set_cookie_header("csrf_token", hex, true, true, SAMESITE_STRICT, 3600, "/",
                           cookie, sizeof(cookie));
    printf("%s\n", cookie);

    printf("\n--- Same Origin Check ---\n");
    printf("URLs same host: %s\n\n",
           csrf_same_origin("https://mysite.com/a", "https://mysite.com/b") ? "YES" : "NO");
}

static void test_ssrf(const char* url) {
    printf("=== SSRF Analysis ===\n");
    printf("URL: \"%s\"\n\n", url);

    ssrf_analysis_t analysis;
    if (ssrf_analyze_url(url, &analysis) == 0) {
        printf("Resolved host:  %s\n", analysis.resolved_host);
        printf("Port:           %d\n", analysis.port);
        printf("Path:           %s\n", analysis.path);
        printf("Internal IP:    %s\n", analysis.is_internal ? "YES (DANGER!)" : "NO");
        printf("Loopback:       %s\n", ssrf_is_loopback(analysis.resolved_host) ? "YES" : "NO");
        printf("Private range:  %s\n", ssrf_is_private_range(analysis.resolved_host) ? "YES" : "NO");
        printf("Blocked:        %s\n", analysis.is_blocked ? "YES" : "NO");
        printf("Risk score:     %d/100\n", analysis.risk_score);
    } else {
        printf("ERROR: Could not parse URL\n");
    }
    printf("\n");
}

static void test_rate_limit(int attempts) {
    printf("=== Rate Limiting Simulation ===\n");
    printf("Configuration: %d attempts max per 60s, 300s block\n\n", attempts);
    rate_limiter_t rl;
    ratelimit_init(&rl, attempts, 60, 300);
    int passed = 0;
    for (int i = 1; i <= attempts + 3; i++) {
        bool ok = ratelimit_check(&rl);
        if (ok) passed++;
        printf("Attempt %-3d: %-7s (remaining: %d)\n",
               i, ok ? "ALLOWED" : "BLOCKED", ratelimit_remaining(&rl));
    }
    printf("\nResult: %d/%d attempts passed\n", passed, attempts + 3);
    printf("Blocked: %s\n\n", ratelimit_is_blocked(&rl) ? "YES" : "NO");
}

static void test_all(const char* input) {
    printf("═══════════════════════════════════════════════════\n");
    printf("  COMPREHENSIVE SECURITY ANALYSIS\n");
    printf("  Input: \"%s\"\n", input);
    printf("═══════════════════════════════════════════════════\n\n");
    test_xss(input);
    test_sqli(input);
    test_validate(input, NULL);
    test_ssrf(strncmp(input, "http", 4) == 0 ? input : "https://example.com");
    printf("═══════════════════════════════════════════════════\n");
    printf("  Analysis complete.\n");
    printf("═══════════════════════════════════════════════════\n\n");
}

int main(int argc, char* argv[]) {
    srand((unsigned)time(NULL));
    if (argc < 2) {
        print_banner();
        print_usage();
        return 0;
    }
    print_banner();
    const char* input = argc > 2 ? argv[2] : NULL;
    const char* validate_type = NULL;
    cli_mode_t mode = MODE_HELP;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage();
            return 0;
        } else if (strcmp(argv[i], "--xss") == 0) {
            mode = MODE_XSS_TEST; if (i + 1 < argc) input = argv[++i];
        } else if (strcmp(argv[i], "--sqli") == 0) {
            mode = MODE_SQLI_TEST; if (i + 1 < argc) input = argv[++i];
        } else if (strcmp(argv[i], "--owasp") == 0) {
            mode = MODE_OWASP_SCAN;
        } else if (strcmp(argv[i], "--validate") == 0) {
            mode = MODE_VALIDATE_INPUT; if (i + 1 < argc) input = argv[++i];
        } else if (strcmp(argv[i], "--validate-type") == 0) {
            if (i + 1 < argc) validate_type = argv[++i];
        } else if (strcmp(argv[i], "--password") == 0) {
            mode = MODE_PASSWORD_TEST; if (i + 1 < argc) input = argv[++i];
        } else if (strcmp(argv[i], "--totp") == 0) {
            mode = MODE_TOTP_TEST;
        } else if (strcmp(argv[i], "--jwt") == 0) {
            mode = MODE_JWT_ANALYZE; if (i + 1 < argc) input = argv[++i];
        } else if (strcmp(argv[i], "--csrf") == 0) {
            mode = MODE_CSRF_TEST;
        } else if (strcmp(argv[i], "--ssrf") == 0) {
            mode = MODE_SSRF_TEST; if (i + 1 < argc) input = argv[++i];
        } else if (strcmp(argv[i], "--ratelimit") == 0) {
            mode = MODE_RATE_LIMIT; if (i + 1 < argc) input = argv[++i];
        } else if (strcmp(argv[i], "--all") == 0) {
            mode = MODE_ALL; if (i + 1 < argc) input = argv[++i];
        }
    }
    switch (mode) {
    case MODE_XSS_TEST:          test_xss(input); break;
    case MODE_SQLI_TEST:         test_sqli(input); break;
    case MODE_OWASP_SCAN:        test_owasp(); break;
    case MODE_VALIDATE_INPUT:    test_validate(input, validate_type); break;
    case MODE_PASSWORD_TEST:     test_password(input); break;
    case MODE_TOTP_TEST:         test_totp(); break;
    case MODE_JWT_ANALYZE:       test_jwt(input); break;
    case MODE_CSRF_TEST:         test_csrf(); break;
    case MODE_SSRF_TEST:         test_ssrf(input); break;
    case MODE_RATE_LIMIT:        test_rate_limit(input ? atoi(input) : 5); break;
    case MODE_ALL:               test_all(input); break;
    default:                     print_usage(); break;
    }
    return 0;
}
