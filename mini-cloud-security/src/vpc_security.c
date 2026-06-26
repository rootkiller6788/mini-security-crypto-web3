#include "vpc_security.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int g_next_sg_id = 1;
static int g_next_nacl_id = 1;
static int g_next_rule_id = 1;

/* ?? L2: Security Group (stateful firewall) ??
 * AWS Security Groups are stateful: if inbound traffic is allowed,
 * the response is automatically allowed regardless of outbound rules.
 * Ref: AWS VPC User Guide ?SecurityGroups
 */
vpc_security_group_t* vpc_sg_create(const char *group_id, const char *name,
                                      const char *vpc_id, const char *description) {
    vpc_security_group_t *sg = calloc(1, sizeof(vpc_security_group_t));
    if (!sg) return NULL;
    if (group_id) strncpy(sg->group_id, group_id, VPC_NAME_LEN - 1);
    else snprintf(sg->group_id, VPC_NAME_LEN, "sg-%08x", g_next_sg_id);
    if (name) strncpy(sg->group_name, name, VPC_NAME_LEN - 1);
    if (vpc_id) strncpy(sg->vpc_id, vpc_id, VPC_NAME_LEN - 1);
    if (description) strncpy(sg->description, description, VPC_DESC_LEN - 1);
    sg->created_at = time(NULL);
    g_next_sg_id++;
    return sg;
}

vpc_sg_rule_t* vpc_sg_add_rule(vpc_security_group_t *sg,
                                vpc_direction_t dir, vpc_protocol_t proto,
                                int from_port, int to_port,
                                const char *cidr) {
    if (!sg || !cidr) return NULL;
    vpc_sg_rule_t *rules = (dir == VPC_INBOUND) ? sg->inbound_rules : sg->outbound_rules;
    int *count = (dir == VPC_INBOUND) ? &sg->inbound_count : &sg->outbound_count;
    if (*count >= VPC_MAX_SG_RULES) return NULL;

    vpc_sg_rule_t *r = &rules[*count];
    memset(r, 0, sizeof(vpc_sg_rule_t));
    r->id = g_next_rule_id++;
    r->direction = dir;
    r->protocol = proto;
    r->from_port = from_port;
    r->to_port = to_port;
    strncpy(r->cidr, cidr, VPC_CIDR_LEN - 1);
    r->enabled = 1;
    r->priority = *count;
    (*count)++;
    return r;
}

vpc_sg_rule_t* vpc_sg_add_rule_by_group(vpc_security_group_t *sg,
                                          vpc_direction_t dir,
                                          vpc_protocol_t proto,
                                          int from_port, int to_port,
                                          const char *source_group_id) {
    if (!sg || !source_group_id) return NULL;
    vpc_sg_rule_t *rules = (dir == VPC_INBOUND) ? sg->inbound_rules : sg->outbound_rules;
    int *count = (dir == VPC_INBOUND) ? &sg->inbound_count : &sg->outbound_count;
    if (*count >= VPC_MAX_SG_RULES) return NULL;

    vpc_sg_rule_t *r = &rules[*count];
    memset(r, 0, sizeof(vpc_sg_rule_t));
    r->id = g_next_rule_id++;
    r->direction = dir;
    r->protocol = proto;
    r->from_port = from_port;
    r->to_port = to_port;
    strncpy(r->group_id, source_group_id, VPC_NAME_LEN - 1);
    r->enabled = 1;
    r->priority = *count;
    (*count)++;
    return r;
}

/* ?? L5: CIDR matching (IPv4 prefix-based) ??
 * Converts dotted-quad and CIDR prefix to bitwise mask matching.
 * Complexity: O(1) per evaluation, O(1) memory.
 */
static unsigned int ipv4_to_int(const char *ip) {
    unsigned int a = 0, b = 0, c = 0, d = 0;
    if (sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 0;
    return (a << 24) | (b << 16) | (c << 8) | d;
}

static unsigned int cidr_mask(int prefix) {
    if (prefix <= 0) return 0;
    if (prefix >= 32) return 0xFFFFFFFF;
    return 0xFFFFFFFF << (32 - prefix);
}

vpc_cidr_t* vpc_cidr_parse(const char *cidr_str) {
    if (!cidr_str) return NULL;
    static vpc_cidr_t parsed;
    memset(&parsed, 0, sizeof(parsed));
    strncpy(parsed.address, cidr_str, VPC_CIDR_LEN - 1);
    parsed.family = VPC_CIDR_IPV4;

    char ip_part[VPC_IP_LEN];
    strncpy(ip_part, cidr_str, VPC_IP_LEN - 1);
    ip_part[VPC_IP_LEN - 1] = '\0';
    char *slash = strchr(ip_part, '/');
    if (slash) {
        *slash = '\0';
        parsed.prefix_length = atoi(slash + 1);
    } else {
        parsed.prefix_length = 32;
    }
    parsed.ip_int = ipv4_to_int(ip_part);
    return &parsed;
}

int vpc_cidr_contains(const vpc_cidr_t *cidr, const char *ip) {
    if (!cidr || !ip) return 0;
    if (cidr->family != VPC_CIDR_IPV4) return 0;
    unsigned int ip_int = ipv4_to_int(ip);
    unsigned int mask = cidr_mask(cidr->prefix_length);
    return (ip_int & mask) == (cidr->ip_int & mask);
}

/* ?? L5: CIDR overlap detection ??
 * Two CIDRs overlap if the range [base, base+size) of one intersects the other.
 * Lemma: CIDR A and B overlap iff (A.lo <= B.hi) and (B.lo <= A.hi).
 */
int vpc_cidr_overlap(const vpc_cidr_t *a, const vpc_cidr_t *b) {
    if (!a || !b) return 0;
    if (a->family != b->family) return 0;
    unsigned int a_lo = a->ip_int & cidr_mask(a->prefix_length);
    unsigned int a_hi = a_lo | ~cidr_mask(a->prefix_length);
    unsigned int b_lo = b->ip_int & cidr_mask(b->prefix_length);
    unsigned int b_hi = b_lo | ~cidr_mask(b->prefix_length);
    return (a_lo <= b_hi) && (b_lo <= a_hi);
}

int vpc_cidr_subset(const vpc_cidr_t *inner, const vpc_cidr_t *outer) {
    if (!inner || !outer) return 0;
    unsigned int in_lo = inner->ip_int & cidr_mask(inner->prefix_length);
    unsigned int in_hi = in_lo | ~cidr_mask(inner->prefix_length);
    unsigned int out_lo = outer->ip_int & cidr_mask(outer->prefix_length);
    unsigned int out_hi = out_lo | ~cidr_mask(outer->prefix_length);
    return (in_lo >= out_lo) && (in_hi <= out_hi);
}

int vpc_cidr_adjacent(const vpc_cidr_t *a, const vpc_cidr_t *b) {
    if (!a || !b || a->prefix_length != b->prefix_length) return 0;
    unsigned int a_lo = a->ip_int & cidr_mask(a->prefix_length);
    unsigned int a_hi = a_lo | ~cidr_mask(a->prefix_length);
    unsigned int b_lo = b->ip_int & cidr_mask(b->prefix_length);
    unsigned int b_hi = b_lo | ~cidr_mask(b->prefix_length);
    return (a_hi + 1 == b_lo) || (b_hi + 1 == a_lo);
}

vpc_cidr_t* vpc_cidr_merge(const vpc_cidr_t *a, const vpc_cidr_t *b) {
    if (!a || !b || a->prefix_length != b->prefix_length) return NULL;
    if (!vpc_cidr_adjacent(a, b)) return NULL;
    static vpc_cidr_t merged;
    merged.family = a->family;
    merged.prefix_length = a->prefix_length - 1;
    unsigned int a_lo = a->ip_int & cidr_mask(a->prefix_length);
    unsigned int b_lo = b->ip_int & cidr_mask(b->prefix_length);
    merged.ip_int = (a_lo < b_lo) ? a_lo : b_lo;
    snprintf(merged.address, VPC_CIDR_LEN, "%u.%u.%u.%u/%d",
             (merged.ip_int >> 24) & 0xFF, (merged.ip_int >> 16) & 0xFF,
             (merged.ip_int >> 8) & 0xFF, merged.ip_int & 0xFF,
             merged.prefix_length);
    return &merged;
}

int vpc_cidr_split(const vpc_cidr_t *cidr, vpc_cidr_t *a, vpc_cidr_t *b) {
    if (!cidr || !a || !b || cidr->prefix_length >= 32) return -1;
    int new_prefix = cidr->prefix_length + 1;
    a->family = cidr->family;
    a->prefix_length = new_prefix;
    a->ip_int = cidr->ip_int;
    snprintf(a->address, VPC_CIDR_LEN, "%u.%u.%u.%u/%d",
             (a->ip_int >> 24) & 0xFF, (a->ip_int >> 16) & 0xFF,
             (a->ip_int >> 8) & 0xFF, a->ip_int & 0xFF, new_prefix);

    b->family = cidr->family;
    b->prefix_length = new_prefix;
    b->ip_int = cidr->ip_int | (1u << (32 - new_prefix));
    snprintf(b->address, VPC_CIDR_LEN, "%u.%u.%u.%u/%d",
             (b->ip_int >> 24) & 0xFF, (b->ip_int >> 16) & 0xFF,
             (b->ip_int >> 8) & 0xFF, b->ip_int & 0xFF, new_prefix);
    return 0;
}

int vpc_ip_in_cidr(const char *ip, const char *cidr) {
    if (!ip || !cidr) return 0;
    char tmp[VPC_CIDR_LEN];
    strncpy(tmp, cidr, VPC_CIDR_LEN - 1);
    tmp[VPC_CIDR_LEN - 1] = '\0';
    char *slash = strchr(tmp, '/');
    int prefix = 32;
    if (slash) {
        *slash = '\0';
        prefix = atoi(slash + 1);
    }
    unsigned int ip_int = ipv4_to_int(ip);
    unsigned int cidr_int = ipv4_to_int(tmp);
    unsigned int mask = cidr_mask(prefix);
    return (ip_int & mask) == (cidr_int & mask);
}

/* ?? L5: Conflict detection in CIDR sets ??
 * Finds all pairs of overlapping CIDR blocks in a set.
 * Complexity: O(n^2) pairwise comparison. For production, use interval trees.
 */
int vpc_find_cidr_conflicts(vpc_cidr_t *cidrs, int count, int conflicts[][2]) {
    if (!cidrs || count < 2 || !conflicts) return 0;
    int conflict_count = 0;
    for (int i = 0; i < count; i++) {
        for (int j = i + 1; j < count; j++) {
            if (vpc_cidr_overlap(&cidrs[i], &cidrs[j])) {
                if (conflicts && conflict_count < VPC_MAX_CIDRS) {
                    conflicts[conflict_count][0] = i;
                    conflicts[conflict_count][1] = j;
                }
                conflict_count++;
            }
        }
    }
    return conflict_count;
}

/* ?? L3: Security Group rule evaluation (stateful) ??
 * SG evaluation follows "default deny, explicit allow" model.
 * All rules are evaluated; if any rule matches with ALLOW, traffic is permitted.
 * No explicit DENY rules in SG (unlike NACL).
 * Stateful property: response traffic is always allowed.
 */
int vpc_sg_evaluate(const vpc_security_group_t *sg,
                     vpc_direction_t dir,
                     vpc_protocol_t proto, int port,
                     const char *source_ip) {
    if (!sg || !source_ip) return 0;
    const vpc_sg_rule_t *rules = (dir == VPC_INBOUND) ? sg->inbound_rules : sg->outbound_rules;
    int count = (dir == VPC_INBOUND) ? sg->inbound_count : sg->outbound_count;

    for (int i = 0; i < count; i++) {
        const vpc_sg_rule_t *r = &rules[i];
        if (!r->enabled) continue;
        if (r->protocol != VPC_ALL && r->protocol != proto) continue;
        if (r->from_port > 0 && (port < r->from_port || port > r->to_port)) continue;
        if (r->cidr[0] != '\0' && !vpc_ip_in_cidr(source_ip, r->cidr)) continue;
        return 1;
    }
    return 0;
}

int vpc_sg_evaluate_all(vpc_state_t *state,
                         const char *target_group_id,
                         vpc_direction_t dir,
                         vpc_protocol_t proto, int port,
                         const char *source_ip) {
    if (!state || !target_group_id || !source_ip) return 0;
    state->sg_rule_evaluations++;
    for (int i = 0; i < state->group_count; i++) {
        if (strcmp(state->groups[i].group_id, target_group_id) == 0) {
            int result = vpc_sg_evaluate(&state->groups[i], dir, proto, port, source_ip);
            if (result) state->allowed_connections++;
            else state->blocked_connections++;
            return result;
        }
    }
    state->blocked_connections++;
    return 0;
}

/* ?? L2: Network ACL (stateless firewall) ??
 * NACLs are stateless: both inbound and outbound traffic must be
 * explicitly allowed. Rules are evaluated in ascending rule_number order.
 * The first matching rule determines the action (ALLOW or DENY).
 * The catch-all rule (*, DENY) at rule_number 32767 is implicit.
 * Ref: AWS VPC User Guide ?NetworkACLs
 */
vpc_network_acl_t* vpc_nacl_create(const char *nacl_id, const char *vpc_id,
                                     int is_default) {
    vpc_network_acl_t *nacl = calloc(1, sizeof(vpc_network_acl_t));
    if (!nacl) return NULL;
    if (nacl_id) strncpy(nacl->nacl_id, nacl_id, VPC_NAME_LEN - 1);
    else snprintf(nacl->nacl_id, VPC_NAME_LEN, "acl-%08x", g_next_nacl_id);
    if (vpc_id) strncpy(nacl->vpc_id, vpc_id, VPC_NAME_LEN - 1);
    nacl->is_default = is_default;
    g_next_nacl_id++;

    if (is_default) {
        vpc_nacl_add_rule(nacl, VPC_INBOUND, 100, VPC_RULE_ALLOW,
                          VPC_ALL, 0, 65535, "0.0.0.0/0");
        vpc_nacl_add_rule(nacl, VPC_OUTBOUND, 100, VPC_RULE_ALLOW,
                          VPC_ALL, 0, 65535, "0.0.0.0/0");
    }
    return nacl;
}

vpc_nacl_rule_t* vpc_nacl_add_rule(vpc_network_acl_t *nacl,
                                     vpc_direction_t dir, int rule_number,
                                     vpc_rule_action_t action,
                                     vpc_protocol_t proto,
                                     int from_port, int to_port,
                                     const char *cidr) {
    if (!nacl || !cidr) return NULL;
    vpc_nacl_rule_t *rules = (dir == VPC_INBOUND) ? nacl->inbound_rules : nacl->outbound_rules;
    int *count = (dir == VPC_INBOUND) ? &nacl->inbound_count : &nacl->outbound_count;
    if (*count >= VPC_MAX_NACL_RULES) return NULL;

    vpc_nacl_rule_t *r = &rules[*count];
    memset(r, 0, sizeof(vpc_nacl_rule_t));
    r->id = g_next_rule_id++;
    r->direction = dir;
    r->rule_number = rule_number;
    r->action = action;
    r->protocol = proto;
    r->from_port = from_port;
    r->to_port = to_port;
    strncpy(r->cidr, cidr, VPC_CIDR_LEN - 1);
    r->enabled = 1;
    (*count)++;
    return r;
}

int vpc_nacl_evaluate(const vpc_network_acl_t *nacl,
                       vpc_direction_t dir,
                       vpc_protocol_t proto, int port,
                       const char *source_ip, int *matched_rule) {
    if (!nacl || !source_ip) return 0;
    const vpc_nacl_rule_t *rules = (dir == VPC_INBOUND) ? nacl->inbound_rules : nacl->outbound_rules;
    int count = (dir == VPC_INBOUND) ? nacl->inbound_count : nacl->outbound_count;

    int best_match_num = 999999;
    vpc_rule_action_t best_action = VPC_RULE_DENY;

    for (int i = 0; i < count; i++) {
        const vpc_nacl_rule_t *r = &rules[i];
        if (!r->enabled) continue;
        if (r->rule_number >= best_match_num) continue;
        if (r->protocol != VPC_ALL && r->protocol != proto) continue;
        if (r->from_port > 0 && (port < r->from_port || port > r->to_port)) continue;
        if (!vpc_ip_in_cidr(source_ip, r->cidr)) continue;

        best_match_num = r->rule_number;
        best_action = r->action;
    }

    if (matched_rule) *matched_rule = (best_match_num < 999999) ? best_match_num : 0;
    return (best_action == VPC_RULE_ALLOW) ? 1 : 0;
}

/* ?? Utility Functions ?? */
void vpc_state_init(vpc_state_t *state) {
    if (!state) return;
    memset(state, 0, sizeof(vpc_state_t));
}

void vpc_state_print_summary(const vpc_state_t *state) {
    if (!state) return;
    printf("VPC Security State:\n");
    printf("  Security Groups:     %d\n", state->group_count);
    printf("  Network ACLs:        %d\n", state->nacl_count);
    printf("  Known CIDRs:         %d\n", state->cidr_count);
    printf("  SG Evaluations:      %d\n", state->sg_rule_evaluations);
    printf("  NACL Evaluations:    %d\n", state->nacl_rule_evaluations);
    printf("  Allowed Connections: %d\n", state->allowed_connections);
    printf("  Blocked Connections: %d\n", state->blocked_connections);
}

const char* vpc_protocol_name(vpc_protocol_t p) {
    switch (p) {
        case VPC_TCP:  return "TCP";
        case VPC_UDP:  return "UDP";
        case VPC_ICMP: return "ICMP";
        case VPC_ALL:  return "ALL";
        default: return "UNKNOWN";
    }
}

const char* vpc_rule_action_name(vpc_rule_action_t a) {
    return a == VPC_RULE_ALLOW ? "ALLOW" : "DENY";
}

void vpc_sg_print(const vpc_security_group_t *sg) {
    if (!sg) return;
    printf("Security Group: %s (%s)\n", sg->group_name, sg->group_id);
    printf("  VPC: %s\n", sg->vpc_id);
    printf("  Description: %s\n", sg->description);
    printf("  Inbound Rules: %d\n", sg->inbound_count);
    for (int i = 0; i < sg->inbound_count; i++) {
        const vpc_sg_rule_t *r = &sg->inbound_rules[i];
        printf("    %s %d-%d from %s\n",
               vpc_protocol_name(r->protocol), r->from_port, r->to_port,
               r->cidr[0] ? r->cidr : r->group_id);
    }
    printf("  Outbound Rules: %d\n", sg->outbound_count);
    for (int i = 0; i < sg->outbound_count; i++) {
        const vpc_sg_rule_t *r = &sg->outbound_rules[i];
        printf("    %s %d-%d to %s\n",
               vpc_protocol_name(r->protocol), r->from_port, r->to_port,
               r->cidr[0] ? r->cidr : r->group_id);
    }
}

void vpc_nacl_print(const vpc_network_acl_t *nacl) {
    if (!nacl) return;
    printf("Network ACL: %s (VPC: %s, default=%d)\n",
           nacl->nacl_id, nacl->vpc_id, nacl->is_default);
    printf("  Inbound Rules: %d\n", nacl->inbound_count);
    for (int i = 0; i < nacl->inbound_count; i++) {
        const vpc_nacl_rule_t *r = &nacl->inbound_rules[i];
        printf("    #%d %s %s %d-%d %s\n",
               r->rule_number, vpc_rule_action_name(r->action),
               vpc_protocol_name(r->protocol), r->from_port, r->to_port, r->cidr);
    }
    printf("  Outbound Rules: %d\n", nacl->outbound_count);
    for (int i = 0; i < nacl->outbound_count; i++) {
        const vpc_nacl_rule_t *r = &nacl->outbound_rules[i];
        printf("    #%d %s %s %d-%d %s\n",
               r->rule_number, vpc_rule_action_name(r->action),
               vpc_protocol_name(r->protocol), r->from_port, r->to_port, r->cidr);
    }
}
