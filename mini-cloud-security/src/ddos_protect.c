#include "ddos_protect.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#define UNUSED(x) ((void)(x))

void ddos_init(ddos_protection_t *dp) {
    if (!dp) return;
    memset(dp, 0, sizeof(ddos_protection_t));
    dp->shield_tier = DDOS_SHIELD_STANDARD;
    dp->start_time = time(NULL);
    strncpy(dp->target.destination_ip, "0.0.0.0", DDOS_IP_LEN - 1);

    ddos_add_detection_rule(dp, DDOS_SYN_FLOOD, 200, 0, 5);
    ddos_add_detection_rule(dp, DDOS_UDP_FLOOD, 500, 0, 5);
    ddos_add_detection_rule(dp, DDOS_DNS_AMPLIFY, 100, 0, 10);
    ddos_add_detection_rule(dp, DDOS_HTTP_FLOOD, 300, 0, 5);
    ddos_add_detection_rule(dp, DDOS_NTP_AMPLIFY, 50, 0, 10);
    ddos_add_detection_rule(dp, DDOS_SLOWLORIS, 10, 0, 60);

    ddos_add_mitigation_rule(dp, DDOS_ACTION_RATE_LIMIT, 100, 50, 5);
    ddos_add_mitigation_rule(dp, DDOS_ACTION_CHALLENGE, 200, 100, 5);
    ddos_add_mitigation_rule(dp, DDOS_ACTION_SCRUB, 500, 200, 5);
    ddos_add_mitigation_rule(dp, DDOS_ACTION_BLACKHOLE, 1000, 500, 5);
}

void ddos_set_shield_tier(ddos_protection_t *dp, ddos_shield_tier_t tier) {
    if (dp) dp->shield_tier = tier;
}

void ddos_add_detection_rule(ddos_protection_t *dp, ddos_attack_type_t type,
                              int pkt_threshold, int byte_threshold,
                              int window_sec) {
    if (!dp || dp->detection_rule_count >= DDOS_MAX_RULES) return;
    ddos_detection_rule_t *r = &dp->detection_rules[dp->detection_rule_count++];
    r->type = type;
    r->packet_threshold = pkt_threshold;
    r->byte_threshold = byte_threshold;
    r->window_seconds = window_sec;
    r->amplification_ratio = 1.0f;
    r->enabled = 1;
}

void ddos_add_mitigation_rule(ddos_protection_t *dp, ddos_action_t action,
                               int burst_limit, int sustained_limit,
                               int window_sec) {
    if (!dp || dp->mitigation_rule_count >= DDOS_MAX_RULES) return;
    ddos_mitigation_rule_t *r = &dp->mitigation_rules[dp->mitigation_rule_count++];
    r->action = action;
    r->burst_limit = burst_limit;
    r->sustained_limit = sustained_limit;
    r->window_seconds = window_sec;
    r->challenge_difficulty = 1;
    r->enabled = 1;
}

static ddos_source_t* find_source(ddos_protection_t *dp, const char *ip) {
    for (int i = 0; i < dp->source_count; i++) {
        if (strcmp(dp->sources[i].source_ip, ip) == 0)
            return &dp->sources[i];
    }
    return NULL;
}

static ddos_source_t* find_or_add_source(ddos_protection_t *dp, const char *ip,
                                          uint16_t port) {
    ddos_source_t *src = find_source(dp, ip);
    if (src) {
        src->source_port = port;
        return src;
    }
    if (dp->source_count >= DDOS_MAX_SOURCES) {
        int oldest = 0;
        for (int i = 1; i < DDOS_MAX_SOURCES; i++) {
            if (dp->sources[i].last_seen < dp->sources[oldest].last_seen)
                oldest = i;
        }
        src = &dp->sources[oldest];
    } else {
        src = &dp->sources[dp->source_count++];
    }
    memset(src, 0, sizeof(ddos_source_t));
    strncpy(src->source_ip, ip, DDOS_IP_LEN - 1);
    src->source_port = port;
    src->first_seen = time(NULL);
    return src;
}

int ddos_record_traffic(ddos_protection_t *dp, const char *source_ip,
                         uint16_t source_port, int packet_size, int protocol) {
    if (!dp || !source_ip) return -1;
    time_t now = time(NULL);
    ddos_source_t *src = find_or_add_source(dp, source_ip, source_port);

    src->total_packets++;
    src->total_bytes += packet_size;
    src->last_seen = now;

    switch (protocol) {
        case 6:  src->syn_count++; break;
        case 17: src->udp_count++; break;
        default: break;
    }

    dp->traffic.packets_in++;
    dp->traffic.bytes_in += packet_size;
    dp->traffic.active_connections++;

    return 0;
}

void ddos_sample_traffic(ddos_protection_t *dp) {
    if (!dp) return;
    time_t now = time(NULL);
    if (now - dp->traffic.sample_time < 5) return;
    dp->traffic.sample_time = now;
    int clean_syn = 0, clean_udp = 0;
    for (int i = 0; i < dp->source_count; i++) {
        if (now - dp->sources[i].last_seen > 300) {
            clean_syn += dp->sources[i].syn_count;
            clean_udp += dp->sources[i].udp_count;
            memset(&dp->sources[i], 0, sizeof(ddos_source_t));
        }
    }
    dp->traffic.syn_per_sec -= clean_syn / 5;
    dp->traffic.udp_per_sec -= clean_udp / 5;
    if (dp->traffic.syn_per_sec < 0) dp->traffic.syn_per_sec = 0;
    if (dp->traffic.udp_per_sec < 0) dp->traffic.udp_per_sec = 0;
    dp->target.packet_rate_per_sec = (int)(dp->traffic.packets_in % 10000);
    dp->target.byte_rate_per_sec = (int)(dp->traffic.bytes_in % 100000);
    dp->target.last_traffic_sample = now;
}

static int detect_amplification(ddos_protection_t *dp, const char *ip) {
    if (!dp || !ip) return 0;
    ddos_source_t *src = find_source(dp, ip);
    if (!src || src->total_packets < 10) return 0;
    float avg_size = (float)src->total_bytes / (float)src->total_packets;
    return (avg_size > 500.0f);
}

ddos_attack_type_t ddos_detect_anomaly(ddos_protection_t *dp) {
    if (!dp) return DDOS_UNKNOWN;
    ddos_sample_traffic(dp);

    int syn_total = 0, udp_total = 0, dns_total = 0, http_total = 0;
    for (int i = 0; i < dp->source_count; i++) {
        syn_total += dp->sources[i].syn_count;
        udp_total += dp->sources[i].udp_count;
        dns_total += dp->sources[i].dns_query_count;
        http_total += dp->sources[i].http_request_count;
    }

    for (int i = 0; i < dp->detection_rule_count; i++) {
        ddos_detection_rule_t *r = &dp->detection_rules[i];
        if (!r->enabled) continue;
        switch (r->type) {
            case DDOS_SYN_FLOOD:
                if (syn_total > r->packet_threshold) {
                    dp->target.active_attack_type = DDOS_SYN_FLOOD;
                    dp->under_attack = 1;
                    dp->target.is_under_attack = 1;
                    return DDOS_SYN_FLOOD;
                }
                break;
            case DDOS_UDP_FLOOD:
                if (udp_total > r->packet_threshold) {
                    dp->target.active_attack_type = DDOS_UDP_FLOOD;
                    dp->under_attack = 1;
                    dp->target.is_under_attack = 1;
                    return DDOS_UDP_FLOOD;
                }
                break;
            case DDOS_DNS_AMPLIFY:
                if (dns_total > r->packet_threshold) {
                    for (int j = 0; j < dp->source_count; j++) {
                        if (ddos_is_amplification_attack(dp, dp->sources[j].source_ip)) {
                            dp->target.active_attack_type = DDOS_DNS_AMPLIFY;
                            dp->under_attack = 1;
                            dp->target.is_under_attack = 1;
                            return DDOS_DNS_AMPLIFY;
                        }
                    }
                }
                break;
            case DDOS_HTTP_FLOOD:
                if (http_total > r->packet_threshold) {
                    dp->target.active_attack_type = DDOS_HTTP_FLOOD;
                    dp->under_attack = 1;
                    dp->target.is_under_attack = 1;
                    return DDOS_HTTP_FLOOD;
                }
                break;
            default:
                break;
        }
    }
    dp->under_attack = 0;
    dp->target.is_under_attack = 0;
    return DDOS_UNKNOWN;
}

ddos_action_t ddos_decide_action(ddos_protection_t *dp, const char *source_ip) {
    if (!dp || !source_ip) return DDOS_ACTION_NONE;
    ddos_source_t *src = find_source(dp, source_ip);
    if (!src) return DDOS_ACTION_NONE;

    time_t now = time(NULL);
    if (src->blocked && now < src->blocked_until) return DDOS_ACTION_BLOCK;

    int pkt_rate = src->total_packets;

    for (int i = 0; i < dp->mitigation_rule_count; i++) {
        ddos_mitigation_rule_t *r = &dp->mitigation_rules[i];
        if (!r->enabled) continue;
        if (pkt_rate > r->burst_limit) {
            if (r->action == DDOS_ACTION_BLACKHOLE && !dp->blackhole_active) {
                ddos_activate_blackhole(dp);
            }
            return r->action;
        }
    }

    if (ddos_is_amplification_attack(dp, source_ip)) {
        return DDOS_ACTION_SCRUB;
    }

    return DDOS_ACTION_NONE;
}

int ddos_apply_action(ddos_protection_t *dp, const char *source_ip,
                       ddos_action_t action) {
    if (!dp || !source_ip) return -1;
    ddos_source_t *src = find_source(dp, source_ip);
    if (!src) return -2;

    switch (action) {
        case DDOS_ACTION_RATE_LIMIT:
            src->confidence += 10;
            break;
        case DDOS_ACTION_CHALLENGE:
            dp->total_challenged++;
            src->confidence += 20;
            ddos_challenge_client(dp, source_ip);
            break;
        case DDOS_ACTION_SCRUB:
            dp->total_scrubbed++;
            ddos_scrub_traffic(dp, source_ip);
            break;
        case DDOS_ACTION_BLACKHOLE:
            ddos_activate_blackhole(dp);
            break;
        case DDOS_ACTION_BLOCK:
            dp->total_blocked++;
            src->blocked = 1;
            src->blocked_until = time(NULL) + DDOS_BLACKHOLE_TIMEOUT;
            break;
        default:
            break;
    }
    return 0;
}

void ddos_update_mitigation(ddos_protection_t *dp) {
    if (!dp) return;
    time_t now = time(NULL);
    ddos_attack_type_t detected = ddos_detect_anomaly(dp);
    if (detected != DDOS_UNKNOWN && !dp->attack_start) {
        dp->attack_start = now;
        dp->mitigation_start = now;
        printf("[DDoS ALERT] %s attack detected! Activating countermeasures.\n",
               ddos_attack_type_name(detected));
    } else if (detected == DDOS_UNKNOWN && dp->attack_start) {
        dp->attack_end = now;
        printf("[DDoS] Attack subsided after %ld seconds.\n", (long)(now - dp->attack_start));
        dp->attack_start = 0;
        ddos_deactivate_blackhole(dp);
    }

    if (dp->blackhole_active && now - dp->blackhole_start > DDOS_BLACKHOLE_TIMEOUT) {
        ddos_deactivate_blackhole(dp);
    }
}

int ddos_activate_blackhole(ddos_protection_t *dp) {
    if (!dp || dp->blackhole_active) return -1;
    dp->blackhole_active = 1;
    dp->blackhole_start = time(NULL);
    dp->total_blocked += dp->traffic.active_connections;
    printf("[DDoS BLACKHOLE] Routing all traffic for %s to null.\n",
           dp->target.destination_ip);
    return 0;
}

int ddos_deactivate_blackhole(ddos_protection_t *dp) {
    if (!dp) return -1;
    dp->blackhole_active = 0;
    printf("[DDoS] Blackhole routing deactivated.\n");
    return 0;
}

int ddos_scrub_traffic(ddos_protection_t *dp, const char *source_ip) {
    if (!dp || !source_ip) return -1;
    UNUSED(source_ip);
    dp->traffic.scrubbed_packets++;
    dp->traffic.blocked_connections++;
    return 0;
}

float ddos_calculate_entropy(ddos_protection_t *dp) {
    if (!dp || dp->source_count == 0) return 0.0f;
    float entropy = 0.0f;
    for (int i = 0; i < dp->source_count; i++) {
        float prob = (float)dp->sources[i].total_packets /
                     (float)(dp->traffic.packets_in + 1);
        if (prob > 0.0f) entropy -= prob * logf(prob + 1e-10f);
    }
    return entropy;
}

int ddos_is_amplification_attack(ddos_protection_t *dp, const char *ip) {
    return detect_amplification(dp, ip);
}

int ddos_challenge_client(ddos_protection_t *dp, const char *source_ip) {
    if (!dp || !source_ip) return -1;
    UNUSED(dp); UNUSED(source_ip);
    return 0;
}

int ddos_verify_challenge(const char *source_ip, const char *solution) {
    if (!source_ip || !solution) return -1;
    if (strlen(solution) > 0) return 0;
    return -1;
}

const char* ddos_attack_type_name(ddos_attack_type_t t) {
    switch (t) {
        case DDOS_SYN_FLOOD:     return "SYN Flood";
        case DDOS_UDP_FLOOD:     return "UDP Flood/Reflection";
        case DDOS_ACK_FLOOD:     return "ACK Flood";
        case DDOS_HTTP_FLOOD:    return "HTTP Flood (L7)";
        case DDOS_DNS_AMPLIFY:   return "DNS Amplification";
        case DDOS_NTP_AMPLIFY:   return "NTP Amplification";
        case DDOS_SLOWLORIS:     return "Slowloris (Slow HTTP)";
        case DDOS_ICMP_FLOOD:    return "ICMP Flood";
        case DDOS_REF_SYN:       return "Reflected SYN";
        case DDOS_MEMCACHED:     return "Memcached Amplification";
        case DDOS_CLDAP_AMPLIFY:  return "CLDAP Amplification";
        case DDOS_UNKNOWN:       return "Unknown";
        default: return "Unknown";
    }
}

const char* ddos_action_name(ddos_action_t a) {
    switch (a) {
        case DDOS_ACTION_NONE:       return "NONE";
        case DDOS_ACTION_RATE_LIMIT: return "RATE_LIMIT";
        case DDOS_ACTION_CHALLENGE:  return "CHALLENGE";
        case DDOS_ACTION_CAPTCHA:    return "CAPTCHA";
        case DDOS_ACTION_SCRUB:      return "SCRUB";
        case DDOS_ACTION_BLACKHOLE:  return "BLACKHOLE";
        case DDOS_ACTION_BLOCK:      return "BLOCK";
        case DDOS_ACTION_TARPIT:     return "TARPIT";
        case DDOS_ACTION_TRANSFER:   return "TRANSFER";
        default: return "UNKNOWN";
    }
}

void ddos_print_status(const ddos_protection_t *dp) {
    if (!dp) return;
    printf("DDoS Protection Status:\n");
    printf("  Shield Tier:      %s\n",
           dp->shield_tier == DDOS_SHIELD_STANDARD ? "Standard" : "Advanced");
    printf("  Under Attack:     %s\n", dp->under_attack ? "YES" : "no");
    if (dp->under_attack) {
        printf("  Attack Type:      %s\n", ddos_attack_type_name(dp->target.active_attack_type));
        printf("  Attack Started:   %ld seconds ago\n", (long)(time(NULL) - dp->attack_start));
    }
    printf("  Blackhole Active: %s\n", dp->blackhole_active ? "YES" : "no");
    printf("  Packets In:       %llu\n", (unsigned long long)dp->traffic.packets_in);
    printf("  Total Blocked:    %d\n", dp->total_blocked);
    printf("  Total Scrubbed:   %d\n", dp->total_scrubbed);
    printf("  Total Challenged: %d\n", dp->total_challenged);
    printf("  Sources Tracked:  %d\n", dp->source_count);
    printf("  Detection Rules:  %d\n", dp->detection_rule_count);
    printf("  Mitigation Rules: %d\n", dp->mitigation_rule_count);
    printf("  Entropy Score:    %.3f\n", ddos_calculate_entropy(dp));
}
