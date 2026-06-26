#include "waf_rules.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static int g_next_rule_id = 1;
static int g_next_group_id = 1;

static const char *SQLI_PATTERNS[] = {
    "UNION SELECT", "UNION ALL SELECT", "' OR '1'='1", "\" OR \"1\"=\"1",
    "OR 1=1", "OR '1'='1'", "--", "DROP TABLE", "ALTER TABLE",
    "INSERT INTO", "DELETE FROM", "UPDATE", "SELECT * FROM",
    "EXEC xp_cmdshell", "INFORMATION_SCHEMA", "SLEEP(", "BENCHMARK(",
    "WAITFOR DELAY", "0x", "' OR 1=1--", "' OR 'a'='a", ") OR ('a'='a",
    NULL
};

static const char *XSS_PATTERNS[] = {
    "<script", "</script>", "javascript:", "onerror=", "onload=",
    "onclick=", "onmouseover=", "onfocus=", "eval(", "document.cookie",
    "alert(", "prompt(", "confirm(", "<img", "<iframe", "<svg",
    "expression(", "<body onload=", "vbscript:", "<embed",
    "<object", "<link", "<meta", "data:text/html", "&#x",
    NULL
};

static int pattern_match_any(const char *input, const char **patterns) {
    if (!input) return 0;
    size_t len = strlen(input);
    char *lower = malloc(len + 1);
    if (!lower) return 0;
    for (size_t i = 0; i < len; i++) lower[i] = (char)toupper((unsigned char)input[i]);
    lower[len] = '\0';
    for (int i = 0; patterns[i] != NULL; i++) {
        size_t plen = strlen(patterns[i]);
        char *pupper = malloc(plen + 1);
        if (!pupper) continue;
        for (size_t j = 0; j < plen; j++) pupper[j] = (char)toupper((unsigned char)patterns[i][j]);
        pupper[plen] = '\0';
        if (strstr(lower, pupper)) { free(pupper); free(lower); return 1; }
        free(pupper);
    }
    free(lower);
    return 0;
}

waf_rule_group_t* waf_create_rule_group(const char *name,
                                         waf_rule_group_type_t type,
                                         waf_action_t default_action) {
    waf_rule_group_t *g = malloc(sizeof(waf_rule_group_t));
    if (!g) return NULL;
    memset(g, 0, sizeof(waf_rule_group_t));
    g->id = g_next_group_id++;
    if (name) strncpy(g->name, name, WAF_HEADER_MAX_LEN - 1);
    g->type = type;
    g->default_action = default_action;
    g->enabled = 1;
    return g;
}

waf_rule_t* waf_add_rule(waf_rule_group_t *group, const char *name,
                          int priority, waf_action_t action) {
    if (!group || group->rule_count >= WAF_MAX_RULES) return NULL;
    waf_rule_t *r = &group->rules[group->rule_count++];
    memset(r, 0, sizeof(waf_rule_t));
    r->id = g_next_rule_id++;
    if (name) strncpy(r->name, name, WAF_HEADER_MAX_LEN - 1);
    r->priority = priority;
    r->action = action;
    r->enabled = 1;
    return r;
}

void waf_rule_add_condition(waf_rule_t *rule, waf_condition_type_t type,
                              const char *target, const char *value) {
    if (!rule || rule->condition_count >= WAF_MAX_CONDITIONS) return;
    waf_condition_t *c = &rule->conditions[rule->condition_count++];
    memset(c, 0, sizeof(waf_condition_t));
    c->type = type;
    if (target) strncpy(c->target_field, target, WAF_HEADER_MAX_LEN - 1);
    if (value) strncpy(c->match_value, value, WAF_URI_MAX_LEN - 1);
}

void waf_rule_add_ip_condition(waf_rule_t *rule, const char *cidr) {
    if (!rule || !cidr) return;
    waf_condition_t *c = &rule->conditions[rule->condition_count++];
    memset(c, 0, sizeof(waf_condition_t));
    c->type = WAF_COND_IP_MATCH;
    strncpy(c->ip_cidr, cidr, WAF_IP_MAX_LEN - 1);
}

void waf_rule_add_regex_condition(waf_rule_t *rule, const char *field,
                                    const char *pattern) {
    if (!rule || !field || !pattern) return;
    waf_condition_t *c = &rule->conditions[rule->condition_count++];
    memset(c, 0, sizeof(waf_condition_t));
    c->type = WAF_COND_REGEX_MATCH;
    strncpy(c->target_field, field, WAF_HEADER_MAX_LEN - 1);
    strncpy(c->regex_pattern, pattern, WAF_URI_MAX_LEN - 1);
}

void waf_rule_add_geo_condition(waf_rule_t *rule, const char *country_code) {
    if (!rule || !country_code) return;
    waf_condition_t *c = &rule->conditions[rule->condition_count++];
    memset(c, 0, sizeof(waf_condition_t));
    c->type = WAF_COND_GEO_MATCH;
    strncpy(c->geo_country, country_code, 7);
}

void waf_rule_set_rate_limit(waf_rule_t *rule, int threshold, int window_sec) {
    if (!rule) return;
    waf_condition_t *c = &rule->conditions[rule->condition_count++];
    memset(c, 0, sizeof(waf_condition_t));
    c->type = WAF_COND_RATE_LIMIT;
    c->rate_threshold = threshold > 0 ? threshold : WAF_RATE_THRESHOLD;
    c->rate_window_sec = window_sec > 0 ? window_sec : WAF_RATE_WINDOW_SEC;
}

int waf_check_sql_injection(const char *input) {
    return pattern_match_any(input, SQLI_PATTERNS);
}

int waf_check_xss(const char *input) {
    return pattern_match_any(input, XSS_PATTERNS);
}

int waf_check_path_traversal(const char *input) {
    if (!input) return 0;
    return (strstr(input, "../") != NULL) ||
           (strstr(input, "..\\") != NULL) ||
           (strstr(input, "/etc/passwd") != NULL) ||
           (strstr(input, "C:\\Windows\\") != NULL);
}

int waf_check_command_injection(const char *input) {
    if (!input) return 0;
    const char *cmds[] = {";", "&&", "||", "|", "`", "$(", "$", ">", "<", NULL};
    for (int i = 0; cmds[i]; i++) {
        if (strstr(input, cmds[i])) return 1;
    }
    return 0;
}

unsigned int ip_to_uint(const char *ip) {
    unsigned int a = 0, b = 0, c = 0, d = 0;
    if (sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 0;
    return (a << 24) | (b << 16) | (c << 8) | d;
}

int waf_ip_in_cidr(const char *ip, const char *cidr) {
    if (!ip || !cidr) return 0;
    char tmp[WAF_IP_MAX_LEN];
    strncpy(tmp, cidr, WAF_IP_MAX_LEN - 1);
    tmp[WAF_IP_MAX_LEN - 1] = '\0';
    char *slash = strchr(tmp, '/');
    int prefix = 32;
    if (slash) {
        *slash = '\0';
        prefix = atoi(slash + 1);
    }
    unsigned int ip_int = ip_to_uint(ip);
    unsigned int cidr_int = ip_to_uint(tmp);
    if (prefix == 0) return 1;
    unsigned int mask = (prefix == 32) ? 0xFFFFFFFF : (0xFFFFFFFF << (32 - prefix));
    return (ip_int & mask) == (cidr_int & mask);
}

waf_action_t waf_evaluate_rule(const waf_rule_t *rule,
                                const waf_request_t *req,
                                waf_state_t *state) {
    if (!rule || !rule->enabled || !req) return WAF_ACTION_ALLOW;
    int matched = rule->condition_count == 0;

    for (int i = 0; i < rule->condition_count; i++) {
        const waf_condition_t *c = &rule->conditions[i];
        switch (c->type) {
            case WAF_COND_IP_MATCH:
                if (!waf_ip_in_cidr(req->client_ip, c->ip_cidr)) goto next_rule;
                matched = 1;
                break;
            case WAF_COND_STRING_MATCH:
                if (strstr(req->body, c->match_value) ||
                    (req->uri && strstr(req->uri, c->match_value))) {
                    matched = 1;
                } else goto next_rule;
                break;
            case WAF_COND_REGEX_MATCH: {
                const char *search =
                    strcmp(c->target_field, "body") == 0 ? req->body :
                    strcmp(c->target_field, "uri") == 0 ? req->uri :
                    req->query_string;
                if (!search || !strstr(search, c->regex_pattern)) goto next_rule;
                matched = 1;
                break;
            }
            case WAF_COND_GEO_MATCH:
                if (strcmp(req->client_country, c->geo_country) != 0) goto next_rule;
                matched = 1;
                break;
            case WAF_COND_SQL_INJECTION:
                if (!waf_check_sql_injection(req->body) &&
                    !waf_check_sql_injection(req->uri) &&
                    !waf_check_sql_injection(req->query_string)) goto next_rule;
                matched = 1;
                if (state) state->sql_injection_detected++;
                break;
            case WAF_COND_XSS:
                if (!waf_check_xss(req->body) &&
                    !waf_check_xss(req->uri) &&
                    !waf_check_xss(req->query_string)) goto next_rule;
                matched = 1;
                if (state) state->xss_detected++;
                break;
            case WAF_COND_HEADER_MATCH:
                matched = 1;
                break;
            case WAF_COND_RATE_LIMIT:
                if (waf_rate_check(state, req->client_ip)) {
                    matched = 1;
                } else goto next_rule;
                break;
            default:
                break;
        }
    }

    next_rule:
    if (matched) {
        rule->metric_counter++;
        return rule->action;
    }
    return WAF_ACTION_ALLOW;
}

waf_action_t waf_evaluate_group(const waf_rule_group_t *group,
                                 const waf_request_t *req,
                                 waf_state_t *state) {
    if (!group || !group->enabled) return WAF_ACTION_ALLOW;
    for (int i = 0; i < group->rule_count; i++) {
        waf_action_t a = waf_evaluate_rule(&group->rules[i], req, state);
        if (a != WAF_ACTION_ALLOW) return a;
    }
    return group->default_action;
}

waf_action_t waf_evaluate_all(waf_state_t *state, const waf_request_t *req) {
    if (!state || !req) return WAF_ACTION_ALLOW;
    state->total_requests++;
    waf_action_t final_action = WAF_ACTION_ALLOW;
    for (int i = 0; i < state->group_count; i++) {
        waf_action_t r = waf_evaluate_group(&state->groups[i], req, state);
        if (r == WAF_ACTION_BLOCK) {
            state->total_blocked++;
            for (int j = 0; j < state->rate_entry_count; j++) {
                if (strcmp(state->rate_entries[j].ip, req->client_ip) == 0) {
                    state->rate_entries[j].blocked = 1;
                }
            }
            return WAF_ACTION_BLOCK;
        }
        if (r == WAF_ACTION_COUNT) final_action = WAF_ACTION_COUNT;
    }
    state->total_allowed++;
    return final_action;
}

void waf_rate_reset(waf_state_t *state) {
    if (!state) return;
    state->rate_entry_count = 0;
}

int waf_rate_check(waf_state_t *state, const char *ip) {
    if (!state || !ip) return 0;
    time_t now = time(NULL);
    for (int i = 0; i < state->rate_entry_count; i++) {
        if (strcmp(state->rate_entries[i].ip, ip) == 0) {
            if (now - state->rate_entries[i].first_request > WAF_RATE_WINDOW_SEC) {
                state->rate_entries[i].first_request = now;
                state->rate_entries[i].request_count = 1;
            } else {
                state->rate_entries[i].request_count++;
            }
            if (state->rate_entries[i].request_count > WAF_RATE_THRESHOLD) {
                return 1;
            }
            return 0;
        }
    }
    if (state->rate_entry_count < WAF_RATE_MAX_TRACKED) {
        waf_rate_entry_t *e = &state->rate_entries[state->rate_entry_count++];
        memset(e, 0, sizeof(waf_rate_entry_t));
        strncpy(e->ip, ip, WAF_IP_MAX_LEN - 1);
        e->first_request = now;
        e->request_count = 1;
    }
    return 0;
}

int waf_managed_rule_sqli(const waf_request_t *req) {
    if (!req) return 0;
    return waf_check_sql_injection(req->body) ||
           waf_check_sql_injection(req->uri) ||
           waf_check_sql_injection(req->query_string);
}

int waf_managed_rule_xss(const waf_request_t *req) {
    if (!req) return 0;
    return waf_check_xss(req->body) ||
           waf_check_xss(req->uri) ||
           waf_check_xss(req->query_string);
}

void waf_init_state(waf_state_t *state) {
    if (!state) return;
    memset(state, 0, sizeof(waf_state_t));
    state->start_time = time(NULL);
}

void waf_add_managed_groups(waf_state_t *state) {
    if (!state) return;
    waf_rule_group_t *api = waf_create_rule_group("AWS-AWSManagedRulesSQLiRuleSet",
                                                    WAF_GROUP_MANAGED_SQL,
                                                    WAF_ACTION_COUNT);
    waf_rule_t *sql = waf_add_rule(api, "SQLi_Body", 1, WAF_ACTION_BLOCK);
    waf_rule_add_condition(sql, WAF_COND_SQL_INJECTION, "body", "");
    waf_rule_t *sqlor = waf_add_rule(api, "SQLi_QueryString", 2, WAF_ACTION_BLOCK);
    waf_rule_add_condition(sqlor, WAF_COND_SQL_INJECTION, "querystring", "");
    state->groups[state->group_count++] = *api;
    free(api);

    waf_rule_group_t *xss = waf_create_rule_group("AWS-AWSManagedRulesXSSRuleSet",
                                                    WAF_GROUP_MANAGED_XSS,
                                                    WAF_ACTION_COUNT);
    waf_rule_t *xssr = waf_add_rule(xss, "XSS_Body", 1, WAF_ACTION_BLOCK);
    waf_rule_add_condition(xssr, WAF_COND_XSS, "body", "");
    waf_rule_t *xssu = waf_add_rule(xss, "XSS_URI", 2, WAF_ACTION_BLOCK);
    waf_rule_add_condition(xssu, WAF_COND_XSS, "uri", "");
    state->groups[state->group_count++] = *xss;
    free(xss);

    waf_rule_group_t *rate = waf_create_rule_group("AWS-AWSManagedRulesRateBasedRuleSet",
                                                     WAF_GROUP_RATE_BASED,
                                                     WAF_ACTION_COUNT);
    waf_rule_t *rr = waf_add_rule(rate, "RateLimit_2000_5min", 1, WAF_ACTION_BLOCK);
    waf_rule_set_rate_limit(rr, 2000, 300);
    state->groups[state->group_count++] = *rate;
    free(rate);
}

const char* waf_action_name(waf_action_t a) {
    switch (a) {
        case WAF_ACTION_ALLOW: return "ALLOW";
        case WAF_ACTION_BLOCK: return "BLOCK";
        case WAF_ACTION_COUNT: return "COUNT";
        case WAF_ACTION_CHALLENGE: return "CHALLENGE";
        case WAF_ACTION_CAPTCHA: return "CAPTCHA";
        default: return "UNKNOWN";
    }
}

void waf_print_stats(const waf_state_t *state) {
    if (!state) return;
    printf("WAF Statistics:\n");
    printf("  Total Requests:  %d\n", state->total_requests);
    printf("  Allowed:         %d\n", state->total_allowed);
    printf("  Blocked:         %d\n", state->total_blocked);
    printf("  SQLi Detected:   %d\n", state->sql_injection_detected);
    printf("  XSS Detected:    %d\n", state->xss_detected);
    printf("  Rule Groups:     %d\n", state->group_count);
    printf("  Traffic Tracked: %d IPs\n", state->rate_entry_count);
}
