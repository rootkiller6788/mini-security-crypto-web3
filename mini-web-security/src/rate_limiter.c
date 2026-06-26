#include "rate_limiter.h"
#include <stdlib.h>
#include <string.h>

/*
 * L5: Token Bucket Rate Limiter Implementation
 *
 * Token bucket is the most widely used rate limiting algorithm:
 * - Tokens are added at a constant refill rate (r tokens/sec)
 * - Bucket has maximum capacity C (allows bursts)
 * - Each request consumes 1 or more tokens
 * - If insufficient tokens, request is denied
 *
 * L4: Burstiness Theorem
 * A token bucket (r, C) is equivalent to a leaky bucket with parameters
 * (r, C/r). The maximum burst duration is C/r seconds at rate C/(C/r).
 *
 * Theorem: Token bucket shaping guarantees that over any interval t,
 * the number of admitted packets <= r*t + C.
 *
 * Reference:
 * - Turner (1986) "New Directions in Communications"
 * - Parekh & Gallager (1993) "A Generalized Processor Sharing Approach"
 * - Stanford CS 244: Advanced Topics in Networking
 * - MIT 6.829: Computer Networks
 */

static uint64_t now_seconds(void) {
    return (uint64_t)time(NULL);
}

void tb_init(TokenBucket *tb, double capacity, double refill_rate)
{
    if (!tb) return;
    memset(tb, 0, sizeof(*tb));
    tb->capacity = capacity;
    tb->tokens = capacity; /* start full */
    tb->refill_rate = refill_rate;
    tb->last_refill = now_seconds();
}

static void tb_refill(TokenBucket *tb)
{
    uint64_t now = now_seconds();
    if (now <= tb->last_refill) return;
    double elapsed = (double)(now - tb->last_refill);
    tb->tokens += elapsed * tb->refill_rate;
    if (tb->tokens > tb->capacity) tb->tokens = tb->capacity;
    tb->last_refill = now;
}

bool tb_consume(TokenBucket *tb, double tokens)
{
    if (!tb || tokens < 0.0) return false;
    tb_refill(tb);
    if (tb->tokens >= tokens) {
        tb->tokens -= tokens;
        tb->total_allowed++;
        return true;
    }
    tb->total_denied++;
    return false;
}

double tb_current_tokens(TokenBucket *tb)
{
    if (!tb) return 0.0;
    tb_refill(tb);
    return tb->tokens;
}

void tb_reset(TokenBucket *tb)
{
    if (!tb) return;
    tb->tokens = tb->capacity;
    tb->last_refill = now_seconds();
    tb->total_allowed = 0;
    tb->total_denied = 0;
}

/* ── Per-IP Rate Limiter (L7: DDoS mitigation) ──────────────────── */

void ipl_init(IPRateLimiter *rl, double capacity, double rate)
{
    if (!rl) return;
    memset(rl, 0, sizeof(*rl));
    rl->default_capacity = capacity;
    rl->default_rate = rate;
}

static int ipl_find(IPRateLimiter *rl, uint32_t ip_hash)
{
    for (int i = 0; i < rl->count; i++)
        if (rl->client_ips[i] == ip_hash) return i;
    return -1;
}

bool ipl_allow(IPRateLimiter *rl, uint32_t ip_hash)
{
    if (!rl) return false;
    int idx = ipl_find(rl, ip_hash);
    if (idx < 0) {
        if (rl->count >= RL_MAX_CLIENTS) return false; /* too many clients */
        idx = rl->count++;
        rl->client_ips[idx] = ip_hash;
        tb_init(&rl->buckets[idx], rl->default_capacity, rl->default_rate);
    }
    return tb_consume(&rl->buckets[idx], 1.0);
}

int ipl_blocked_count(const IPRateLimiter *rl)
{
    if (!rl) return 0;
    int blocked = 0;
    for (int i = 0; i < rl->count; i++)
        blocked += (int)rl->buckets[i].total_denied;
    return blocked;
}

/* L4: Rate-Delay Theorem */
double tb_max_delay(double burst_size, double link_rate, double packet_size)
{
    if (link_rate <= 0.0) return 0.0;
    return burst_size / link_rate + packet_size / link_rate;
}
