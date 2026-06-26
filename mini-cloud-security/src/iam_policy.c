#include "iam_policy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int g_next_policy_id = 1;

iam_policy_t* iam_policy_create(const char *name, iam_policy_type_t type) {
    iam_policy_t *p = calloc(1, sizeof(iam_policy_t));
    if (!p) return NULL;
    p->id = g_next_policy_id++;
    if (name) { strncpy(p->name, name, IAM_NAME_LEN - 1); }
    p->type = type;
    p->statement_count = 0;
    snprintf(p->raw_json, IAM_POLICY_JSON_MAX, "{ \"Version\":\"2012-10-17\", \"Id\":\"%s\" }", name ? name : "default");
    return p;
}

void iam_policy_add_statement(iam_policy_t *p, iam_effect_t effect,
                               const char *action, const char *resource) {
    if (!p || p->statement_count >= IAM_MAX_STATEMENTS) return;
    iam_statement_t *s = &p->statements[p->statement_count++];
    memset(s, 0, sizeof(iam_statement_t));
    s->effect = effect;
    if (action) { strncpy(s->action, action, IAM_ACTION_LEN - 1); }
    if (resource) { strncpy(s->resource, resource, IAM_RESOURCE_LEN - 1); }
}

void iam_policy_add_condition(iam_policy_t *p, int stmt_idx,
                               const char *key, const char *value,
                               iam_condition_op_t op) {
    if (!p || stmt_idx < 0 || stmt_idx >= p->statement_count) return;
    iam_statement_t *s = &p->statements[stmt_idx];
    if (s->condition_count >= IAM_MAX_CONDITIONS) return;
    iam_condition_t *c = &s->conditions[s->condition_count++];
    if (key) { strncpy(c->key, key, IAM_COND_KEY_LEN - 1); }
    if (value) { strncpy(c->value, value, IAM_COND_VAL_LEN - 1); }
    c->op = op;
}

void iam_policy_free(iam_policy_t *p) {
    free(p);
}

int iam_condition_match(const iam_condition_t *cond, const char *ctx_value) {
    if (!cond || !ctx_value) return 0;
    switch (cond->op) {
        case IAM_COND_STRING_EQUALS:
            return strcmp(cond->value, ctx_value) == 0;
        case IAM_COND_STRING_NOT_EQUALS:
            return strcmp(cond->value, ctx_value) != 0;
        case IAM_COND_STRING_EQUALS_IGNORE:
            return strcasecmp(cond->value, ctx_value) == 0;
        case IAM_COND_STRING_LIKE:
            return strstr(ctx_value, cond->value) != NULL;
        case IAM_COND_ARN_EQUALS:
            return strstr(ctx_value, cond->value) != NULL;
        case IAM_COND_BOOL:
            return (strcmp(cond->value, "true") == 0) ==
                   (strcmp(ctx_value, "true") == 0);
        case IAM_COND_NUMERIC_EQUALS:
            return atoi(cond->value) == atoi(ctx_value);
        case IAM_COND_NUMERIC_LESS_THAN:
            return atoi(ctx_value) < atoi(cond->value);
        case IAM_COND_NUMERIC_GREATER_THAN:
            return atoi(ctx_value) > atoi(cond->value);
        default:
            return strcmp(cond->value, ctx_value) == 0;
    }
}

static int iam_resource_match(const char *rule, const char *resource) {
    if (!rule || !resource) return 0;
    if (strcmp(rule, "*") == 0) return 1;
    if (strcmp(rule, resource) == 0) return 1;
    const char *star = strchr(rule, '*');
    if (star) {
        size_t prefix_len = star - rule;
        return strncmp(rule, resource, prefix_len) == 0;
    }
    return 0;
}

static int iam_action_match(const char *rule, const char *action) {
    if (!rule || !action) return 0;
    if (strcmp(rule, "*") == 0) return 1;
    if (strcmp(rule, action) == 0) return 1;
    const char *star = strchr(rule, '*');
    if (star) {
        size_t prefix_len = star - rule;
        return strncmp(rule, action, prefix_len) == 0;
    }
    return 0;
}

static int iam_check_conditions(const iam_statement_t *s,
                                  const char *context_json) {
    if (s->condition_count == 0) return 1;
    for (int i = 0; i < s->condition_count; i++) {
        if (!iam_condition_match(&s->conditions[i], context_json)) {
            return 0;
        }
    }
    return 1;
}

iam_result_t iam_evaluate_policy(const iam_policy_t *p, const char *action,
                                  const char *resource, const char *context) {
    if (!p || !action || !resource) return IAM_RESULT_ERROR;
    int explicit_allow = 0;
    int explicit_deny  = 0;

    for (int i = 0; i < p->statement_count; i++) {
        const iam_statement_t *s = &p->statements[i];
        if (!iam_action_match(s->action, action)) continue;
        if (!iam_resource_match(s->resource, resource)) continue;
        if (!iam_check_conditions(s, context)) continue;

        if (s->effect == IAM_EFFECT_DENY) {
            explicit_deny = 1;
        } else {
            explicit_allow = 1;
        }
    }

    if (explicit_deny) return IAM_RESULT_DENY;
    if (explicit_allow) return IAM_RESULT_ALLOW;
    return IAM_RESULT_DENY; 
}

iam_result_t iam_evaluate_all(const iam_policy_t **policies, int count,
                               const char *action, const char *resource,
                               const char *context) {
    int allow = 0;
    for (int i = 0; i < count; i++) {
        iam_result_t r = iam_evaluate_policy(policies[i], action, resource, context);
        if (r == IAM_RESULT_DENY) return IAM_RESULT_DENY;
        if (r == IAM_RESULT_ALLOW) allow = 1;
    }
    return allow ? IAM_RESULT_ALLOW : IAM_RESULT_DENY;
}

iam_result_t iam_check_permission_boundary(iam_result_t base,
                                            const iam_policy_t *boundary,
                                            const char *action,
                                            const char *resource,
                                            const char *context) {
    if (!boundary) return base;
    if (base == IAM_RESULT_DENY) return IAM_RESULT_DENY;
    return iam_evaluate_policy(boundary, action, resource, context);
}

iam_result_t iam_evaluate_scp(const iam_policy_t *scp, const char *action,
                               const char *resource, const char *context) {
    if (!scp) return IAM_RESULT_ALLOW; 
    return iam_evaluate_policy(scp, action, resource, context);
}

const char* iam_result_to_string(iam_result_t r) {
    switch (r) {
        case IAM_RESULT_ALLOW: return "ALLOW";
        case IAM_RESULT_DENY:  return "DENY";
        case IAM_RESULT_ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

const char* iam_effect_to_string(iam_effect_t e) {
    return e == IAM_EFFECT_ALLOW ? "Allow" : "Deny";
}

iam_user_t* iam_user_create(const char *name) {
    iam_user_t *u = calloc(1, sizeof(iam_user_t));
    if (!u) return NULL;
    if (name) { strncpy(u->name, name, IAM_NAME_LEN - 1); }
    snprintf(u->arn, IAM_ARN_LEN, "arn:aws:iam::123456789012:user/%s", name ? name : "unknown");
    return u;
}

void iam_user_attach_policy(iam_user_t *u, int policy_id) {
    if (!u || u->attached_count >= IAM_MAX_POLICIES) return;
    u->attached_policy_ids[u->attached_count++] = policy_id;
}

void iam_user_set_boundary(iam_user_t *u, void *boundary) {
    if (u) u->boundary = boundary;
}

void iam_user_free(iam_user_t *u) {
    free(u);
}

iam_role_t* iam_role_create(const char *name, const char *trust_policy_json,
                             int max_session_seconds) {
    iam_role_t *r = calloc(1, sizeof(iam_role_t));
    if (!r) return NULL;
    if (name) { strncpy(r->name, name, IAM_NAME_LEN - 1); }
    if (trust_policy_json) {
        strncpy(r->trust_policy, trust_policy_json, IAM_POLICY_JSON_MAX - 1);
    }
    snprintf(r->arn, IAM_ARN_LEN, "arn:aws:iam::123456789012:role/%s", name ? name : "unknown");
    r->max_session_seconds = max_session_seconds > 0 ? max_session_seconds : 3600;
    return r;
}

void iam_role_attach_policy(iam_role_t *r, int policy_id) {
    if (!r || r->attached_count >= IAM_MAX_POLICIES) return;
    r->attached_policy_ids[r->attached_count++] = policy_id;
}

void iam_role_free(iam_role_t *r) {
    free(r);
}

iam_session_t* iam_assume_role(const iam_role_t *role,
                                const char *principal_arn,
                                int duration_seconds) {
    if (!role || !principal_arn) return NULL;
    iam_session_t *s = calloc(1, sizeof(iam_session_t));
    if (!s) return NULL;
    strncpy(s->assumed_role_arn, role->arn, IAM_ARN_LEN - 1);
    strncpy(s->principal_arn, principal_arn, IAM_ARN_LEN - 1);
    if (duration_seconds <= 0) duration_seconds = 3600;
    if (duration_seconds > role->max_session_seconds)
        duration_seconds = role->max_session_seconds;
    s->expiration = (int64_t)time(NULL) + duration_seconds;
    s->permissions_boundary = role->permissions_boundary;
    return s;
}

void iam_session_free(iam_session_t *s) {
    free(s);
}

int iam_policy_parse_json(iam_policy_t *p, const char *json) {
    if (!p || !json) return -1;
    strncpy(p->raw_json, json, IAM_POLICY_JSON_MAX - 1);
    const char *eff = strstr(json, "\"Effect\"");
    if (eff) {
        if (strstr(eff, "Allow")) {
            iam_policy_add_statement(p, IAM_EFFECT_ALLOW, "*", "*");
        } else if (strstr(eff, "Deny")) {
            iam_policy_add_statement(p, IAM_EFFECT_DENY, "*", "*");
        }
    }
    return 0;
}
