#ifndef RATE_LIMITER_H
#define RATE_LIMITER_H
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

/* L5: Rate Limiting Algorithms for Web Security
 *
 * Three fundamental algorithms:
 * 1. Token Bucket: refills at constant rate, bursts up to capacity
 * 2. Leaky Bucket: constant outflow rate, excess discarded
 * 3. Sliding Window Log: precise but memory-intensive
 *
 * L4: Little's Law applied to rate limiting:
 * L = lambda * W  (average items in system = arrival_rate * wait_time)
 * For a rate limiter with capacity C and refill rate r:
 *   max_throughput = r, burst_size = C
 *
 * Reference: MIT 6.033, Stanford CS 144
 */

typedef struct {
    double   capacity;      /* max tokens (burst size) */
    double   tokens;        /* current tokens */
    double   refill_rate;   /* tokens per second */
    uint64_t last_refill;   /* timestamp of last refill (seconds) */
    uint64_t total_allowed;
    uint64_t total_denied;
} TokenBucket;

void tb_init(TokenBucket *tb, double capacity, double refill_rate);
bool tb_consume(TokenBucket *tb, double tokens);
double tb_current_tokens(TokenBucket *tb);
void tb_reset(TokenBucket *tb);

/* L7: Per-IP rate limiter for DDoS mitigation */
#define RL_MAX_CLIENTS 1024
typedef struct {
    TokenBucket buckets[RL_MAX_CLIENTS];
    uint32_t    client_ips[RL_MAX_CLIENTS]; /* hash of IP */
    int         count;
    double      default_capacity;
    double      default_rate;
} IPRateLimiter;

void ipl_init(IPRateLimiter *rl, double capacity, double rate);
bool ipl_allow(IPRateLimiter *rl, uint32_t ip_hash);
int  ipl_blocked_count(const IPRateLimiter *rl);

/* L4: Rate-Delay Theorem (Kleinrock, 1975)
 * For a token bucket (r, b), the maximum delay for a packet
 * of size L at a link of rate R is: D_max = b/R + L/R
 * and the maximum burst size that can be sent at line rate is b. */
double tb_max_delay(double burst_size, double link_rate, double packet_size);

#endif
