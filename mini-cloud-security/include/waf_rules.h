#ifndef WAF_RULES_H
#define WAF_RULES_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define WAF_MAX_RULES           32
#define WAF_MAX_RULE_GROUPS      8
#define WAF_MAX_CONDITIONS      16
#define WAF_MAX_IP_SETS         32
#define WAF_MAX_REGEX_PATTERNS  64
#define WAF_HEADER_MAX_LEN     128
#define WAF_URI_MAX_LEN        1024
#define WAF_BODY_MAX_LEN       4096
#define WAF_IP_MAX_LEN          45
#define WAF_RATE_WINDOW_SEC    300
#define WAF_RATE_THRESHOLD     2000
#define WAF_RATE_MAX_TRACKED    256

typedef enum {
    WAF_ACTION_ALLOW = 0,
    WAF_ACTION_BLOCK = 1,
    WAF_ACTION_COUNT = 2,
    WAF_ACTION_CHALLENGE = 3,
    WAF_ACTION_CAPTCHA  = 4
} waf_action_t;

typedef enum {
    WAF_COND_NONE          = 0,
    WAF_COND_IP_MATCH      = 1,
    WAF_COND_STRING_MATCH  = 2,
    WAF_COND_REGEX_MATCH   = 3,
    WAF_COND_GEO_MATCH     = 4,
    WAF_COND_SIZE_CONSTRAINT = 5,
    WAF_COND_SQL_INJECTION = 6,
    WAF_COND_XSS           = 7,
    WAF_COND_HEADER_MATCH  = 8,
    WAF_COND_URI_MATCH     = 9,
    WAF_COND_METHOD_MATCH  = 10,
    WAF_COND_BODY_MATCH    = 11,
    WAF_COND_RATE_LIMIT    = 12
} waf_condition_type_t;

typedef enum {
    WAF_MATCH_CONTAINS     = 0,
    WAF_MATCH_EXACT        = 1,
    WAF_MATCH_STARTS_WITH  = 2,
    WAF_MATCH_ENDS_WITH    = 3,
    WAF_MATCH_IP_CIDR      = 4
} waf_match_mode_t;

typedef enum {
    WAF_GROUP_MANAGED_SQL  = 0,
    WAF_GROUP_MANAGED_XSS  = 1,
    WAF_GROUP_MANAGED_PHP  = 2,
    WAF_GROUP_MANAGED_LINUX= 3,
    WAF_GROUP_MANAGED_WIN  = 4,
    WAF_GROUP_RATE_BASED   = 5,
    WAF_GROUP_CUSTOM       = 6,
    WAF_GROUP_IP_REP       = 7,
    WAF_GROUP_GEO          = 8,
    WAF_GROUP_BOT_CONTROL  = 9
} waf_rule_group_type_t;

typedef struct {
    waf_condition_type_t type;
    waf_match_mode_t     match_mode;
    char                 target_field[WAF_HEADER_MAX_LEN];
    char                 match_value[WAF_URI_MAX_LEN];
    char                 regex_pattern[WAF_URI_MAX_LEN];
    char                 geo_country[8];
    char                 ip_cidr[WAF_IP_MAX_LEN];
    int                  size_limit;
    int                  rate_threshold;
    int                  rate_window_sec;
} waf_condition_t;

typedef struct {
    int             id;
    char            name[WAF_HEADER_MAX_LEN];
    int             priority;
    waf_action_t    action;
    waf_condition_t conditions[WAF_MAX_CONDITIONS];
    int             condition_count;
    int             enabled;
    int             metric_counter;
    float           oversize_handling; 
} waf_rule_t;

typedef struct {
    int             id;
    char            name[WAF_HEADER_MAX_LEN];
    waf_rule_group_type_t type;
    waf_rule_t      rules[WAF_MAX_RULES];
    int             rule_count;
    waf_action_t    default_action;
    int             enabled;
} waf_rule_group_t;

typedef struct {
    char        method[16];
    char        uri[WAF_URI_MAX_LEN];
    char        headers[32][2][WAF_HEADER_MAX_LEN];
    int         header_count;
    char        body[WAF_BODY_MAX_LEN];
    int         body_len;
    char        client_ip[WAF_IP_MAX_LEN];
    char        client_country[8];
    int         content_length;
    const char *query_string;
} waf_request_t;

typedef struct {
    char    ip[WAF_IP_MAX_LEN];
    time_t  first_request;
    int     request_count;
    int     blocked;
} waf_rate_entry_t;

typedef struct {
    waf_rule_group_t groups[WAF_MAX_RULE_GROUPS];
    int              group_count;
    waf_rate_entry_t rate_entries[WAF_RATE_MAX_TRACKED];
    int              rate_entry_count;
    int              total_requests;
    int              total_blocked;
    int              total_allowed;
    int              sql_injection_detected;
    int              xss_detected;
    time_t           start_time;
} waf_state_t;

waf_rule_group_t* waf_create_rule_group(const char *name,
                                         waf_rule_group_type_t type,
                                         waf_action_t default_action);
waf_rule_t*       waf_add_rule(waf_rule_group_t *group, const char *name,
                                int priority, waf_action_t action);
void              waf_rule_add_condition(waf_rule_t *rule,
                                          waf_condition_type_t type,
                                          const char *target, const char *value);
void              waf_rule_add_ip_condition(waf_rule_t *rule,
                                             const char *cidr);
void              waf_rule_add_regex_condition(waf_rule_t *rule,
                                                const char *field,
                                                const char *pattern);
void              waf_rule_add_geo_condition(waf_rule_t *rule,
                                              const char *country_code);
void              waf_rule_set_rate_limit(waf_rule_t *rule,
                                           int threshold, int window_sec);

int               waf_check_sql_injection(const char *input);
int               waf_check_xss(const char *input);
int               waf_check_path_traversal(const char *input);
int               waf_check_command_injection(const char *input);

waf_action_t      waf_evaluate_rule(waf_rule_t *rule,
                                     const waf_request_t *req,
                                     waf_state_t *state);
waf_action_t      waf_evaluate_group(waf_rule_group_t *group,
                                      const waf_request_t *req,
                                      waf_state_t *state);
waf_action_t      waf_evaluate_all(waf_state_t *state,
                                    const waf_request_t *req);

int               waf_ip_in_cidr(const char *ip, const char *cidr);
void              waf_rate_reset(waf_state_t *state);
int               waf_rate_check(waf_state_t *state, const char *ip);
int               waf_managed_rule_sqli(const waf_request_t *req);
int               waf_managed_rule_xss(const waf_request_t *req);

void              waf_init_state(waf_state_t *state);
void              waf_add_managed_groups(waf_state_t *state);
const char*       waf_action_name(waf_action_t a);
void              waf_print_stats(const waf_state_t *state);

#endif
