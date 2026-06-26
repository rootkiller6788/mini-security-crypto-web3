#include "waf_rules.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    printf("=== WAF Rules Engine Demo ===\n\n");

    waf_state_t state;
    waf_init_state(&state);
    waf_add_managed_groups(&state);
    printf("[1] Initialized WAF with %d managed rule groups\n\n", state.group_count);

    printf("--- Custom Rule Group ---\n");
    waf_rule_group_t *custom = waf_create_rule_group("CustomSecurityRules",
        WAF_GROUP_CUSTOM, WAF_ACTION_ALLOW);

    waf_rule_t *r1 = waf_add_rule(custom, "BlockX-Attack", 1, WAF_ACTION_BLOCK);
    waf_rule_add_condition(r1, WAF_COND_STRING_MATCH, "header:X-Attack", "true");

    waf_rule_t *r2 = waf_add_rule(custom, "GeoBlock", 2, WAF_ACTION_BLOCK);
    waf_rule_add_geo_condition(r2, "CN");
    waf_rule_add_geo_condition(r2, "RU");

    waf_rule_t *r3 = waf_add_rule(custom, "IPBlocklist", 3, WAF_ACTION_BLOCK);
    waf_rule_add_ip_condition(r3, "192.168.1.0/24");

    waf_rule_t *r4 = waf_add_rule(custom, "URITraversal", 4, WAF_ACTION_BLOCK);
    waf_rule_add_condition(r4, WAF_COND_STRING_MATCH, "uri", "../");

    state.groups[state.group_count++] = *custom;
    free(custom);

    printf("  BlockX-Attack: blocks requests with X-Attack header\n");
    printf("  GeoBlock: blocks CN+RU traffic\n");
    printf("  IPBlocklist: blocks 192.168.1.0/24\n");
    printf("  URITraversal: blocks path traversal\n\n");

    printf("--- Request Evaluation Tests ---\n\n");
    waf_request_t requests[8];

    memset(&requests[0], 0, sizeof(waf_request_t));
    strcpy(requests[0].method, "GET");
    strcpy(requests[0].uri, "/api/users");
    strcpy(requests[0].client_ip, "10.0.0.1");
    strcpy(requests[0].body, "{\"name\":\"test\"}");
    strcpy(requests[0].client_country, "US");
    requests[0].query_string = "id=42";

    memset(&requests[1], 0, sizeof(waf_request_t));
    strcpy(requests[1].method, "POST");
    strcpy(requests[1].uri, "/api/login");
    strcpy(requests[1].client_ip, "10.0.0.2");
    strcpy(requests[1].body, "username=admin' OR '1'='1");
    strcpy(requests[1].client_country, "US");
    requests[1].query_string = NULL;

    memset(&requests[2], 0, sizeof(waf_request_t));
    strcpy(requests[2].method, "GET");
    strcpy(requests[2].uri, "/search");
    strcpy(requests[2].client_ip, "10.0.0.3");
    strcpy(requests[2].body, "");
    strcpy(requests[2].client_country, "US");
    requests[2].query_string = "q=<script>alert(1)</script>";

    memset(&requests[3], 0, sizeof(waf_request_t));
    strcpy(requests[3].method, "GET");
    strcpy(requests[3].uri, "/../../../etc/passwd");
    strcpy(requests[3].client_ip, "10.0.0.4");
    strcpy(requests[3].body, "");
    strcpy(requests[3].client_country, "US");
    requests[3].query_string = NULL;

    memset(&requests[4], 0, sizeof(waf_request_t));
    strcpy(requests[4].method, "GET");
    strcpy(requests[4].uri, "/api/data");
    strcpy(requests[4].client_ip, "192.168.1.100");
    strcpy(requests[4].body, "");
    strcpy(requests[4].client_country, "US");
    requests[4].query_string = NULL;

    memset(&requests[5], 0, sizeof(waf_request_t));
    strcpy(requests[5].method, "GET");
    strcpy(requests[5].uri, "/api/data");
    strcpy(requests[5].client_ip, "10.0.0.5");
    strcpy(requests[5].body, "");
    strcpy(requests[5].client_country, "CN");
    requests[5].query_string = NULL;

    memset(&requests[6], 0, sizeof(waf_request_t));
    strcpy(requests[6].method, "POST");
    strcpy(requests[6].uri, "/api/upload");
    strcpy(requests[6].client_ip, "10.0.0.6");
    strcpy(requests[6].body, "DROP TABLE users");
    strcpy(requests[6].client_country, "US");
    requests[6].query_string = NULL;

    memset(&requests[7], 0, sizeof(waf_request_t));
    strcpy(requests[7].method, "POST");
    strcpy(requests[7].uri, "/api/comment");
    strcpy(requests[7].client_ip, "10.0.0.7");
    strcpy(requests[7].body, "Nice post! <script>alert(document.cookie)</script>");
    strcpy(requests[7].client_country, "US");
    requests[7].query_string = NULL;

    const char *descriptions[] = {
        "Normal GET /api/users (US)",
        "SQL Injection login (body)",
        "XSS in query string",
        "Path traversal attempt",
        "IP Blocklist (192.168.1.100)",
        "Geo Block (CN)",
        "SQLi: DROP TABLE in body",
        "XSS: script tag in body"
    };

    for (int i = 0; i < 8; i++) {
        waf_action_t result = waf_evaluate_all(&state, &requests[i]);
        printf("[%d] %s\n    -> %s\n", i + 1, descriptions[i], waf_action_name(result));
    }

    printf("\n--- SQL Injection Detection ---\n");
    const char *sqli_tests[] = {
        "SELECT * FROM users",
        "normal text",
        "1' OR '1'='1",
        "UNION SELECT password FROM users",
        "hello world",
        "DROP TABLE customers; --",
        "; cat /etc/passwd",
        "EXEC xp_cmdshell('dir')",
        "1' AND 1=1--",
        NULL
    };
    for (int i = 0; sqli_tests[i]; i++) {
        printf("  [%s] => SQLi=%s, CmdInj=%s\n", sqli_tests[i],
               waf_check_sql_injection(sqli_tests[i]) ? "YES" : "no",
               waf_check_command_injection(sqli_tests[i]) ? "YES" : "no");
    }

    printf("\n--- XSS Detection ---\n");
    const char *xss_tests[] = {
        "<script>alert('xss')</script>",
        "normal input",
        "<img src=x onerror=alert(1)>",
        "<body onload=alert('hi')>",
        "javascript:void(0)",
        "hello <b>world</b>",
        "document.cookie",
        "eval('alert(1)')",
        NULL
    };
    for (int i = 0; xss_tests[i]; i++) {
        printf("  [%s] => XSS=%s\n", xss_tests[i],
               waf_check_xss(xss_tests[i]) ? "YES" : "no");
    }

    printf("\n--- Rate Limiting Simulation ---\n");
    waf_rate_reset(&state);
    for (int i = 0; i < 10; i++) {
        int exceeded = waf_rate_check(&state, "10.255.255.1");
        printf("  Request #%d from 10.255.255.1 => %s\n", i + 1,
               exceeded ? "RATE EXCEEDED" : "ok");
    }

    printf("\n--- IP CIDR Matching ---\n");
    printf("  10.0.0.5 in 10.0.0.0/8: %s\n",
           waf_ip_in_cidr("10.0.0.5", "10.0.0.0/8") ? "yes" : "no");
    printf("  192.168.5.1 in 192.168.1.0/24: %s\n",
           waf_ip_in_cidr("192.168.5.1", "192.168.1.0/24") ? "yes" : "no");
    printf("  172.16.0.1 in 172.16.0.0/12: %s\n",
           waf_ip_in_cidr("172.16.0.1", "172.16.0.0/12") ? "yes" : "no");
    printf("  8.8.8.8 in 0.0.0.0/0: %s\n",
           waf_ip_in_cidr("8.8.8.8", "0.0.0.0/0") ? "yes" : "no");

    printf("\n");
    waf_print_stats(&state);

    printf("\nAll WAF tests complete.\n");
    return 0;
}
