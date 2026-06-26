#ifndef DDOS_PROTECT_H
#define DDOS_PROTECT_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define DDOS_MAX_CLIENTS      65536
#define DDOS_MAX_SOURCES        512
#define DDOS_MAX_RULES          128
#define DDOS_IP_LEN              45
#define DDOS_RATE_WINDOW          5
#define DDOS_RATE_BASELINE       10
#define DDOS_SYN_THRESHOLD      200
#define DDOS_UDP_THRESHOLD      500
#define DDOS_DNS_THRESHOLD      100
#define DDOS_SCRUB_WINDOW_SEC    60
#define DDOS_BLACKHOLE_TIMEOUT  300

typedef enum {
    DDOS_SYN_FLOOD    = 0,
    DDOS_UDP_FLOOD    = 1,
    DDOS_ACK_FLOOD    = 2,
    DDOS_HTTP_FLOOD   = 3,
    DDOS_DNS_AMPLIFY  = 4,
    DDOS_NTP_AMPLIFY  = 5,
    DDOS_SLOWLORIS    = 6,
    DDOS_ICMP_FLOOD   = 7,
    DDOS_REF_SYN      = 8,
    DDOS_MEMCACHED    = 9,
    DDOS_CLDAP_AMPLIFY = 10,
    DDOS_UNKNOWN      = 99
} ddos_attack_type_t;

typedef enum {
    DDOS_ACTION_NONE         = 0,
    DDOS_ACTION_RATE_LIMIT   = 1,
    DDOS_ACTION_CHALLENGE    = 2,
    DDOS_ACTION_CAPTCHA      = 3,
    DDOS_ACTION_SCRUB        = 4,
    DDOS_ACTION_BLACKHOLE    = 5,
    DDOS_ACTION_BLOCK        = 6,
    DDOS_ACTION_TARPIT       = 7,
    DDOS_ACTION_TRANSFER     = 8 
} ddos_action_t;

typedef enum {
    DDOS_SHIELD_STANDARD  = 0,
    DDOS_SHIELD_ADVANCED  = 1
} ddos_shield_tier_t;

typedef struct {
    char             source_ip[DDOS_IP_LEN];
    uint16_t         source_port;
    int              syn_count;
    int              udp_count;
    int              dns_query_count;
    int              http_request_count;
    int              total_packets;
    int              total_bytes;
    time_t           first_seen;
    time_t           last_seen;
    ddos_attack_type_t detected_type;
    int              confidence;
    int              blocked;
    time_t           blocked_until;
} ddos_source_t;

typedef struct {
    uint64_t packets_in;
    uint64_t packets_out;
    uint64_t bytes_in;
    uint64_t bytes_out;
    int      syn_per_sec;
    int      udp_per_sec;
    int      dns_per_sec;
    int      http_per_sec;
    int      active_connections;
    int      blocked_connections;
    int      scrubbed_packets;
    int      challenged_clients;
    time_t   sample_time;
} ddos_traffic_stats_t;

typedef struct {
    ddos_attack_type_t type;
    int    packet_threshold;
    int    byte_threshold;
    int    window_seconds;
    float  amplification_ratio;
    int    enabled;
} ddos_detection_rule_t;

typedef struct {
    ddos_action_t action;
    int           burst_limit;
    int           sustained_limit;
    int           window_seconds;
    int           challenge_difficulty;
    int           enabled;
} ddos_mitigation_rule_t;

typedef struct {
    char     destination_ip[DDOS_IP_LEN];
    int      packet_rate_per_sec;
    int      byte_rate_per_sec;
    int      active_flows;
    float    entropy_score;
    int      is_under_attack;
    ddos_attack_type_t active_attack_type;
    time_t   mitigation_start;
    time_t   last_traffic_sample;
} ddos_target_t;

typedef struct {
    ddos_source_t          sources[DDOS_MAX_SOURCES];
    int                    source_count;
    ddos_detection_rule_t  detection_rules[DDOS_MAX_RULES];
    int                    detection_rule_count;
    ddos_mitigation_rule_t mitigation_rules[DDOS_MAX_RULES];
    int                    mitigation_rule_count;
    ddos_traffic_stats_t   traffic;
    ddos_target_t          target;
    ddos_shield_tier_t     shield_tier;
    int                    total_blocked;
    int                    total_scrubbed;
    int                    total_challenged;
    int                    under_attack;
    time_t                 attack_start;
    time_t                 attack_end;
    time_t                 start_time;
    int                    blackhole_active;
    time_t                 blackhole_start;
} ddos_protection_t;

void              ddos_init(ddos_protection_t *dp);
void              ddos_set_shield_tier(ddos_protection_t *dp,
                                        ddos_shield_tier_t tier);

void              ddos_add_detection_rule(ddos_protection_t *dp,
                                           ddos_attack_type_t type,
                                           int pkt_threshold, int byte_threshold,
                                           int window_sec);
void              ddos_add_mitigation_rule(ddos_protection_t *dp,
                                            ddos_action_t action,
                                            int burst_limit, int sustained_limit,
                                            int window_sec);

int               ddos_record_traffic(ddos_protection_t *dp,
                                       const char *source_ip, uint16_t source_port,
                                       int packet_size, int protocol);

ddos_attack_type_t ddos_detect_anomaly(ddos_protection_t *dp);
ddos_action_t     ddos_decide_action(ddos_protection_t *dp,
                                       const char *source_ip);
int               ddos_apply_action(ddos_protection_t *dp,
                                       const char *source_ip,
                                       ddos_action_t action);

void              ddos_sample_traffic(ddos_protection_t *dp);
void              ddos_update_mitigation(ddos_protection_t *dp);

int               ddos_activate_blackhole(ddos_protection_t *dp);
int               ddos_deactivate_blackhole(ddos_protection_t *dp);
int               ddos_scrub_traffic(ddos_protection_t *dp,
                                       const char *source_ip);

float             ddos_calculate_entropy(const ddos_protection_t *dp);
int               ddos_is_amplification_attack(ddos_protection_t *dp,
                                                const char *source_ip);
const char*       ddos_attack_type_name(ddos_attack_type_t t);
const char*       ddos_action_name(ddos_action_t a);
void              ddos_print_status(const ddos_protection_t *dp);

int               ddos_challenge_client(ddos_protection_t *dp,
                                         const char *source_ip);
int               ddos_verify_challenge(const char *source_ip,
                                         const char *solution);

#endif
