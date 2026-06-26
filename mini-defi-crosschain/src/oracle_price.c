#include "oracle_price.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t oracle_rand_seed = 0x0AC1E001;

static uint32_t oracle_rand(void) {
    oracle_rand_seed = oracle_rand_seed * 1103515245 + 12345;
    return oracle_rand_seed;
}

static int oracle_compare_u64(const void *a, const void *b) {
    uint64_t va = *(const uint64_t *)a;
    uint64_t vb = *(const uint64_t *)b;
    if (va < vb) return -1;
    if (va > vb) return 1;
    return 0;
}

void oracle_feed_init(OraclePriceFeed *feed, OracleType type,
                      uint64_t heartbeat) {
    memset(feed, 0, sizeof(OraclePriceFeed));
    feed->type = type;
    feed->round_id = 1;
    feed->deviation_threshold_bps = ORACLE_DEVIATION_BPS;
    feed->heartbeat = heartbeat > 0 ? heartbeat : ORACLE_STALE_THRESHOLD;
    feed->oracle_count = 0;
    feed->stale = false;
}

void oracle_add_node(OraclePriceFeed *feed, const uint8_t addr[20],
                     uint64_t stake) {
    if (feed->oracle_count >= ORACLE_MAX_ORACLES) return;
    OracleNode *n = &feed->oracles[feed->oracle_count];
    memcpy(n->oracle_addr, addr, 20);
    n->stake = stake;
    n->reputation = stake;
    n->active = true;
    memset(&n->latest_submission, 0, sizeof(OracleSubmission));
    feed->oracle_count++;
}

bool oracle_remove_node(OraclePriceFeed *feed, const uint8_t addr[20]) {
    for (int i = 0; i < feed->oracle_count; i++) {
        if (memcmp(feed->oracles[i].oracle_addr, addr, 20) == 0) {
            feed->oracles[i].active = false;
            return true;
        }
    }
    return false;
}

bool oracle_submit_price(OraclePriceFeed *feed, const uint8_t oracle_addr[20],
                          uint64_t price, uint64_t timestamp) {
    for (int i = 0; i < feed->oracle_count; i++) {
        OracleNode *n = &feed->oracles[i];
        if (n->active && memcmp(n->oracle_addr, oracle_addr, 20) == 0) {
            if (feed->latest_price > 0 && !oracle_check_deviation(feed, price)) {
                return false;
            }
            n->latest_submission.price = price;
            n->latest_submission.timestamp = timestamp;
            if (timestamp > feed->latest_timestamp) {
                feed->latest_timestamp = timestamp;
            }
            oracle_update_aggregate(feed);
            feed->round_id++;
            feed->stale = false;
            return true;
        }
    }
    return false;
}

void oracle_update_aggregate(OraclePriceFeed *feed) {
    uint64_t prices[ORACLE_MAX_ORACLES];
    int count = 0;

    for (int i = 0; i < feed->oracle_count; i++) {
        if (feed->oracles[i].active &&
            feed->oracles[i].latest_submission.price > 0) {
            prices[count++] = feed->oracles[i].latest_submission.price;
        }
    }

    if (count == 0) {
        feed->stale = true;
        return;
    }

    feed->median_price = oracle_get_median(prices, count);
    feed->latest_price = feed->median_price;

    uint64_t total_weighted = 0;
    uint64_t total_stake = 0;
    for (int i = 0; i < feed->oracle_count; i++) {
        if (feed->oracles[i].active &&
            feed->oracles[i].latest_submission.price > 0) {
            total_weighted += feed->oracles[i].latest_submission.price
                              * feed->oracles[i].stake;
            total_stake += feed->oracles[i].stake;
        }
    }
    if (total_stake > 0) {
        feed->twap_price = total_weighted / total_stake;
    }
}

uint64_t oracle_get_median(const uint64_t *prices, int count) {
    if (count == 0) return 0;
    if (count == 1) return prices[0];

    uint64_t sorted[ORACLE_MAX_ORACLES];
    memcpy(sorted, prices, count * sizeof(uint64_t));
    qsort(sorted, count, sizeof(uint64_t), oracle_compare_u64);

    if (count % 2 == 1) {
        return sorted[count / 2];
    } else {
        return (sorted[count / 2 - 1] + sorted[count / 2]) / 2;
    }
}

bool oracle_is_stale(const OraclePriceFeed *feed, uint64_t current_time) {
    if (feed->latest_timestamp == 0) return true;
    return (current_time - feed->latest_timestamp) > feed->heartbeat;
}

uint64_t oracle_get_price(const OraclePriceFeed *feed) {
    if (feed->stale) return 0;
    return feed->latest_price;
}

uint64_t oracle_get_twap(const OraclePriceFeed *feed, uint64_t window) {
    if (feed->oracle_count == 0 || window == 0) return feed->latest_price;
    return feed->twap_price > 0 ? feed->twap_price : feed->latest_price;
}

void twap_tracker_init(TWAPTracker *tracker) {
    memset(tracker, 0, sizeof(TWAPTracker));
}

void twap_tracker_update(TWAPTracker *tracker, uint64_t price,
                          uint64_t timestamp) {
    if (tracker->count > 0) {
        int last_idx = (tracker->index - 1 + ORACLE_TWAP_PERIODS)
                       % ORACLE_TWAP_PERIODS;
        uint64_t elapsed = timestamp - tracker->timestamps[last_idx];
        if (elapsed > 0) {
            tracker->accum_price += tracker->prices[last_idx] * elapsed;
        }
    }

    tracker->prices[tracker->index] = price;
    tracker->timestamps[tracker->index] = timestamp;
    tracker->index = (tracker->index + 1) % ORACLE_TWAP_PERIODS;
    if (tracker->count < ORACLE_TWAP_PERIODS) tracker->count++;
}

uint64_t twap_tracker_compute(const TWAPTracker *tracker, uint64_t window) {
    if (tracker->count < 2 || window == 0) return tracker->prices[0] > 0 ? tracker->prices[0] : 0;
    return tracker->accum_price / window;
}

bool oracle_check_deviation(const OraclePriceFeed *feed, uint64_t price) {
    if (feed->latest_price == 0) return true;
    uint64_t diff = price > feed->latest_price
        ? price - feed->latest_price
        : feed->latest_price - price;
    uint64_t max_diff = feed->latest_price * feed->deviation_threshold_bps
                        / LENDING_BPS_DENOM;
    return diff <= max_diff;
}

uint64_t oracle_time_weighted_price(const uint64_t *prices,
                                     const uint64_t *durations, int count) {
    if (count == 0) return 0;

    uint64_t total_weighted = 0;
    uint64_t total_duration = 0;

    for (int i = 0; i < count; i++) {
        total_weighted += prices[i] * durations[i];
        total_duration += durations[i];
    }

    if (total_duration == 0) return prices[0];
    return total_weighted / total_duration;
}

void oracle_simulate_data_feeds(OraclePriceFeed *feeds, int num_feeds) {
    const char *symbols[] = {"ETH/USD", "BTC/USD", "DAI/USD", "LINK/USD"};
    uint64_t base_prices[] = {200000000000, 3500000000000, 100000000, 15000000000};

    int max_symbols = 4;
    for (int i = 0; i < num_feeds && i < max_symbols; i++) {
        oracle_feed_init(&feeds[i], ORACLE_CHAINLINK, 3600);
        memcpy(feeds[i].feed_id, symbols[i], strlen(symbols[i]) + 1);

        uint64_t noise = (oracle_rand() % 10000000) - 5000000;
        feeds[i].latest_price = base_prices[i] + (int64_t)noise;
        feeds[i].latest_timestamp = oracle_rand() + 1000000;
        feeds[i].median_price = feeds[i].latest_price;
    }
}

bool oracle_verify_round(const OracleRound *round, uint64_t min_answers,
                          uint64_t max_deviation) {
    if (!round || !round->valid) return false;
    if (round->observations_count < (int)min_answers) return false;
    if (round->price == 0) return false;

    (void)max_deviation;
    return true;
}

uint64_t oracle_convert_price(uint64_t price_a, uint64_t price_b,
                               uint64_t amount) {
    if (price_b == 0) return 0;
    return (amount * price_a) / price_b;
}
