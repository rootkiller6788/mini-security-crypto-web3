#ifndef ORACLE_PRICE_H
#define ORACLE_PRICE_H

#include <stdbool.h>
#include <stdint.h>

#define ORACLE_MAX_ORACLES      31
#define ORACLE_MAX_FEEDS        64
#define ORACLE_STALE_THRESHOLD  86400
#define ORACLE_PRECISION        100000000
#define ORACLE_DEVIATION_BPS    500
#define ORACLE_TWAP_PERIODS     16

typedef enum {
    ORACLE_CHAINLINK,
    ORACLE_TWAP,
    ORACLE_MEDIAN
} OracleType;

typedef struct {
    uint64_t price;
    uint64_t timestamp;
} OracleSubmission;

typedef struct {
    uint8_t  oracle_addr[20];
    uint64_t stake;
    uint64_t reputation;
    bool     active;
    OracleSubmission latest_submission;
} OracleNode;

typedef struct {
    OracleType type;
    uint8_t  feed_id[32];
    uint64_t round_id;
    uint64_t latest_price;
    uint64_t latest_timestamp;
    uint64_t deviation_threshold_bps;
    uint64_t heartbeat;
    OracleNode oracles[ORACLE_MAX_ORACLES];
    int     oracle_count;
    uint64_t median_price;
    uint64_t twap_price;
    bool    stale;
} OraclePriceFeed;

typedef struct {
    uint64_t price;
    uint64_t timestamp;
    uint64_t round_id;
    uint64_t twap_accumulator;
    int     observations_count;
    bool    valid;
} OracleRound;

typedef struct {
    uint64_t prices[ORACLE_TWAP_PERIODS];
    uint64_t timestamps[ORACLE_TWAP_PERIODS];
    int     index;
    int     count;
    uint64_t accum_price;
} TWAPTracker;

void     oracle_feed_init(OraclePriceFeed *feed, OracleType type, uint64_t heartbeat);
void     oracle_add_node(OraclePriceFeed *feed, const uint8_t addr[20], uint64_t stake);
bool     oracle_remove_node(OraclePriceFeed *feed, const uint8_t addr[20]);
bool     oracle_submit_price(OraclePriceFeed *feed, const uint8_t oracle_addr[20], uint64_t price, uint64_t timestamp);
void     oracle_update_aggregate(OraclePriceFeed *feed);
uint64_t oracle_get_median(const uint64_t *prices, int count);
bool     oracle_is_stale(const OraclePriceFeed *feed, uint64_t current_time);
uint64_t oracle_get_price(const OraclePriceFeed *feed);
uint64_t oracle_get_twap(const OraclePriceFeed *feed, uint64_t window);
void     twap_tracker_init(TWAPTracker *tracker);
void     twap_tracker_update(TWAPTracker *tracker, uint64_t price, uint64_t timestamp);
uint64_t twap_tracker_compute(const TWAPTracker *tracker, uint64_t window);
bool     oracle_check_deviation(const OraclePriceFeed *feed, uint64_t price);
uint64_t oracle_time_weighted_price(const uint64_t *prices, const uint64_t *durations, int count);
void     oracle_simulate_data_feeds(OraclePriceFeed *feeds, int num_feeds);
bool     oracle_verify_round(const OracleRound *round, uint64_t min_answers, uint64_t max_deviation);
uint64_t oracle_convert_price(uint64_t price_a, uint64_t price_b, uint64_t amount);

#endif
