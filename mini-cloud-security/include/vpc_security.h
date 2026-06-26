#ifndef VPC_SECURITY_H
#define VPC_SECURITY_H

#include <stddef.h>
#include <stdint.h>

#define VPC_MAX_SG_RULES       256
#define VPC_MAX_NACL_RULES     256
#define VPC_MAX_SECURITY_GROUPS 64
#define VPC_MAX_NACLS           32
#define VPC_MAX_CIDRS          128
#define VPC_IP_LEN              45
#define VPC_PROTO_LEN            8
#define VPC_CIDR_LEN            45
#define VPC_NAME_LEN           256
#define VPC_DESC_LEN           512

typedef enum {
    VPC_TCP  = 0,
    VPC_UDP  = 1,
    VPC_ICMP = 2,
    VPC_ALL  = 99
} vpc_protocol_t;

typedef enum {
    VPC_INBOUND  = 0,
    VPC_OUTBOUND = 1
} vpc_direction_t;

typedef enum {
    VPC_RULE_ALLOW = 0,
    VPC_RULE_DENY  = 1
} vpc_rule_action_t;

typedef enum {
    VPC_CIDR_IPV4 = 0,
    VPC_CIDR_IPV6 = 1
} vpc_cidr_family_t;

typedef struct {
    int             id;
    vpc_direction_t direction;
    vpc_protocol_t  protocol;
    int             from_port;
    int             to_port;
    char            cidr[VPC_CIDR_LEN];
    char            group_id[VPC_NAME_LEN];
    char            description[VPC_DESC_LEN];
    int             priority;
    int             enabled;
} vpc_sg_rule_t;

typedef struct {
    int             id;
    vpc_direction_t direction;
    vpc_protocol_t  protocol;
    int             from_port;
    int             to_port;
    char            cidr[VPC_CIDR_LEN];
    char            description[VPC_DESC_LEN];
    vpc_rule_action_t action;
    int             rule_number;
    int             enabled;
} vpc_nacl_rule_t;

typedef struct {
    char         group_id[VPC_NAME_LEN];
    char         group_name[VPC_NAME_LEN];
    char         vpc_id[VPC_NAME_LEN];
    char         description[VPC_DESC_LEN];
    vpc_sg_rule_t inbound_rules[VPC_MAX_SG_RULES];
    int          inbound_count;
    vpc_sg_rule_t outbound_rules[VPC_MAX_SG_RULES];
    int          outbound_count;
    int          attached_enis;
    time_t       created_at;
} vpc_security_group_t;

typedef struct {
    char          nacl_id[VPC_NAME_LEN];
    char          vpc_id[VPC_NAME_LEN];
    vpc_nacl_rule_t inbound_rules[VPC_MAX_NACL_RULES];
    int           inbound_count;
    vpc_nacl_rule_t outbound_rules[VPC_MAX_NACL_RULES];
    int           outbound_count;
    int           associated_subnets;
    int           is_default;
} vpc_network_acl_t;

typedef struct {
    char                address[VPC_CIDR_LEN];
    vpc_cidr_family_t   family;
    int                 prefix_length;
    uint32_t            ip_int;
    uint64_t            ip_int6[2];
} vpc_cidr_t;

typedef struct {
    vpc_security_group_t groups[VPC_MAX_SECURITY_GROUPS];
    int                  group_count;
    vpc_network_acl_t    nacls[VPC_MAX_NACLS];
    int                  nacl_count;
    vpc_cidr_t           known_cidrs[VPC_MAX_CIDRS];
    int                  cidr_count;
    int                  sg_rule_evaluations;
    int                  nacl_rule_evaluations;
    int                  blocked_connections;
    int                  allowed_connections;
} vpc_state_t;

vpc_security_group_t* vpc_sg_create(const char *group_id, const char *name,
                                      const char *vpc_id, const char *description);
vpc_sg_rule_t*        vpc_sg_add_rule(vpc_security_group_t *sg,
                                       vpc_direction_t dir, vpc_protocol_t proto,
                                       int from_port, int to_port,
                                       const char *cidr);
vpc_sg_rule_t*        vpc_sg_add_rule_by_group(vpc_security_group_t *sg,
                                                 vpc_direction_t dir,
                                                 vpc_protocol_t proto,
                                                 int from_port, int to_port,
                                                 const char *source_group_id);
int                   vpc_sg_evaluate(const vpc_security_group_t *sg,
                                       vpc_direction_t dir,
                                       vpc_protocol_t proto, int port,
                                       const char *source_ip);
int                   vpc_sg_evaluate_all(vpc_state_t *state,
                                           const char *target_group_id,
                                           vpc_direction_t dir,
                                           vpc_protocol_t proto, int port,
                                           const char *source_ip);

vpc_network_acl_t*    vpc_nacl_create(const char *nacl_id, const char *vpc_id,
                                        int is_default);
vpc_nacl_rule_t*      vpc_nacl_add_rule(vpc_network_acl_t *nacl,
                                          vpc_direction_t dir, int rule_number,
                                          vpc_rule_action_t action,
                                          vpc_protocol_t proto,
                                          int from_port, int to_port,
                                          const char *cidr);
int                   vpc_nacl_evaluate(const vpc_network_acl_t *nacl,
                                         vpc_direction_t dir,
                                         vpc_protocol_t proto, int port,
                                         const char *source_ip, int *matched_rule);

vpc_cidr_t*           vpc_cidr_parse(const char *cidr_str);
int                   vpc_cidr_contains(const vpc_cidr_t *cidr, const char *ip);
int                   vpc_cidr_overlap(const vpc_cidr_t *a, const vpc_cidr_t *b);
int                   vpc_cidr_subset(const vpc_cidr_t *inner, const vpc_cidr_t *outer);
int                   vpc_cidr_adjacent(const vpc_cidr_t *a, const vpc_cidr_t *b);
vpc_cidr_t*           vpc_cidr_merge(const vpc_cidr_t *a, const vpc_cidr_t *b);
int                   vpc_cidr_split(const vpc_cidr_t *cidr,
                                      vpc_cidr_t *a, vpc_cidr_t *b);
int                   vpc_ip_in_cidr(const char *ip, const char *cidr);
int                   vpc_find_cidr_conflicts(vpc_cidr_t *cidrs, int count,
                                               int conflicts[][2]);

void                  vpc_state_init(vpc_state_t *state);
void                  vpc_state_print_summary(const vpc_state_t *state);

const char*           vpc_protocol_name(vpc_protocol_t p);
const char*           vpc_rule_action_name(vpc_rule_action_t a);
void                  vpc_sg_print(const vpc_security_group_t *sg);
void                  vpc_nacl_print(const vpc_network_acl_t *nacl);

#endif
