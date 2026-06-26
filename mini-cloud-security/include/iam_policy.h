#ifndef IAM_POLICY_H
#define IAM_POLICY_H

#include <stddef.h>
#include <stdint.h>

#define IAM_MAX_USERS      256
#define IAM_MAX_GROUPS     128
#define IAM_MAX_ROLES      64
#define IAM_MAX_POLICIES   512
#define IAM_MAX_CONDITIONS 32
#define IAM_MAX_STATEMENTS 64
#define IAM_NAME_LEN       128
#define IAM_ARN_LEN        256
#define IAM_ACTION_LEN     256
#define IAM_RESOURCE_LEN   512
#define IAM_COND_KEY_LEN   128
#define IAM_COND_VAL_LEN   256
#define IAM_POLICY_JSON_MAX 8192

typedef enum {
    IAM_EFFECT_ALLOW = 0,
    IAM_EFFECT_DENY  = 1
} iam_effect_t;

typedef enum {
    IAM_RESULT_ALLOW = 0,
    IAM_RESULT_DENY  = 1,
    IAM_RESULT_ERROR = 2
} iam_result_t;

typedef enum {
    IAM_COND_STRING_EQUALS           = 0,
    IAM_COND_STRING_NOT_EQUALS       = 1,
    IAM_COND_STRING_EQUALS_IGNORE    = 2,
    IAM_COND_STRING_LIKE             = 3,
    IAM_COND_NUMERIC_EQUALS          = 4,
    IAM_COND_NUMERIC_LESS_THAN       = 5,
    IAM_COND_NUMERIC_GREATER_THAN    = 6,
    IAM_COND_IP_ADDRESS              = 7,
    IAM_COND_NOT_IP_ADDRESS          = 8,
    IAM_COND_ARN_EQUALS              = 9,
    IAM_COND_BOOL                    = 10,
    IAM_COND_DATE_LESS_THAN          = 11,
    IAM_COND_DATE_GREATER_THAN       = 12
} iam_condition_op_t;

typedef enum {
    IAM_POLICY_IDENTITY = 0,
    IAM_POLICY_RESOURCE = 1,
    IAM_POLICY_PERMISSION_BOUNDARY = 2,
    IAM_POLICY_SCP       = 3,
    IAM_POLICY_SESSION   = 4
} iam_policy_type_t;

typedef struct {
    char key[IAM_COND_KEY_LEN];
    char value[IAM_COND_VAL_LEN];
    iam_condition_op_t op;
} iam_condition_t;

typedef struct {
    iam_effect_t effect;
    char action[IAM_ACTION_LEN];
    char resource[IAM_RESOURCE_LEN];
    iam_condition_t conditions[IAM_MAX_CONDITIONS];
    int condition_count;
} iam_statement_t;

typedef struct {
    char    name[IAM_NAME_LEN];
    char    arn[IAM_ARN_LEN];
    int     attached_policy_ids[IAM_MAX_POLICIES];
    int     attached_count;
    void   *boundary; 
} iam_user_t;

typedef struct {
    char    name[IAM_NAME_LEN];
    char    arn[IAM_ARN_LEN];
    int     member_user_ids[IAM_MAX_USERS];
    int     member_count;
    int     attached_policy_ids[IAM_MAX_POLICIES];
    int     attached_count;
} iam_group_t;

typedef struct {
    char          name[IAM_NAME_LEN];
    char          arn[IAM_ARN_LEN];
    char          trust_policy[IAM_POLICY_JSON_MAX];
    int           attached_policy_ids[IAM_MAX_POLICIES];
    int           attached_count;
    void         *permissions_boundary;
    int           max_session_seconds;
} iam_role_t;

typedef struct {
    int             id;
    char            name[IAM_NAME_LEN];
    iam_policy_type_t type;
    iam_statement_t statements[IAM_MAX_STATEMENTS];
    int             statement_count;
    char            raw_json[IAM_POLICY_JSON_MAX];
} iam_policy_t;

typedef struct {
    char         assumed_role_arn[IAM_ARN_LEN];
    char         principal_arn[IAM_ARN_LEN];
    int64_t      expiration;
    iam_policy_t *session_policies;
    int          session_policy_count;
    void        *permissions_boundary;
} iam_session_t;

iam_policy_t* iam_policy_create(const char *name, iam_policy_type_t type);
void          iam_policy_add_statement(iam_policy_t *p, iam_effect_t effect,
                                       const char *action, const char *resource);
void          iam_policy_add_condition(iam_policy_t *p, int stmt_idx,
                                       const char *key, const char *value,
                                       iam_condition_op_t op);
int           iam_policy_parse_json(iam_policy_t *p, const char *json);
void          iam_policy_free(iam_policy_t *p);

iam_result_t  iam_evaluate_policy(const iam_policy_t *p, const char *action,
                                   const char *resource, const char *context_json);
iam_result_t  iam_evaluate_all(const iam_policy_t **policies, int count,
                                const char *action, const char *resource,
                                const char *context_json);

int           iam_condition_match(const iam_condition_t *cond,
                                   const char *context_value);
const char*   iam_result_to_string(iam_result_t r);
const char*   iam_effect_to_string(iam_effect_t e);

iam_user_t*   iam_user_create(const char *name);
void          iam_user_attach_policy(iam_user_t *u, int policy_id);
void          iam_user_set_boundary(iam_user_t *u, void *boundary);
void          iam_user_free(iam_user_t *u);

iam_role_t*   iam_role_create(const char *name, const char *trust_policy_json,
                               int max_session_seconds);
void          iam_role_attach_policy(iam_role_t *r, int policy_id);
void          iam_role_free(iam_role_t *r);

iam_session_t* iam_assume_role(const iam_role_t *role,
                                const char *principal_arn,
                                int duration_seconds);
void           iam_session_free(iam_session_t *s);

iam_result_t  iam_check_permission_boundary(iam_result_t base_result,
                                             const iam_policy_t *boundary,
                                             const char *action,
                                             const char *resource,
                                             const char *context);
iam_result_t  iam_evaluate_scp(const iam_policy_t *scp, const char *action,
                                const char *resource, const char *context);

#endif
