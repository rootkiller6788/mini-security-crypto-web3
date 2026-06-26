#ifndef DATA_POISON_H
#define DATA_POISON_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DP_MAX_DIMS      1024
#define DP_MAX_CLASSES   256
#define DP_TRIGGER_SIZE  32
#define DP_MAX_CLIENTS   1024

typedef enum {
    DP_BACKDOOR = 0,
    DP_CLEAN_LABEL = 1,
    DP_AVAILABILITY = 2,
    DP_TARGETED_MISCLASSIFY = 3,
    DP_LABEL_FLIPPING = 4,
    DP_FEATURE_COLLISION = 5
} dp_poison_type_t;

typedef enum {
    DP_DEFENSE_SANITIZATION = 0,
    DP_DEFENSE_ROBUST_TRAIN = 1,
    DP_DEFENSE_ANOMALY_DETECT = 2,
    DP_DEFENSE_DIFF_PRIVACY = 3,
    DP_DEFENSE_SPECTRAL_SIGNATURE = 4,
    DP_DEFENSE_TRIM = 5,
    DP_DEFENSE_KNN_FILTER = 6,
    DP_DEFENSE_CERTIFIED_ROBUST = 7
} dp_defense_type_t;

typedef enum {
    DP_TRIGGER_PIXEL = 0,
    DP_TRIGGER_PATTERN = 1,
    DP_TRIGGER_WATERMARK = 2,
    DP_TRIGGER_SEMANTIC = 3,
    DP_TRIGGER_FREQUENCY = 4
} dp_trigger_type_t;

typedef struct {
    double *features;
    size_t  dims;
    int     label;
    int     is_poisoned;
    double  anomaly_score;
} dp_sample_t;

typedef struct {
    double *data;
    size_t  rows;
    size_t  cols;
} dp_trigger_t;

typedef struct {
    dp_poison_type_t  type;
    dp_trigger_type_t trigger_type;
    size_t            poison_ratio;
    int               target_label;
    int               source_label;
    double            poison_strength;
    size_t            trigger_size_rows;
    size_t            trigger_size_cols;
    int               clean_label_attack;
    size_t            num_poison_samples;
    int               adaptive;
} dp_poison_config_t;

typedef struct {
    dp_defense_type_t type;
    double            anomaly_threshold;
    double            clip_norm;
    double            epsilon;
    double            delta;
    size_t            num_neighbors;
    int               certified;
    double            certified_radius;
    int               use_trim;
    double            trim_ratio;
} dp_defense_config_t;

typedef struct {
    double poison_success_rate;
    double clean_accuracy;
    double backdoor_accuracy;
    double defense_detection_rate;
    double false_positive_rate;
    double anomaly_scores_mean;
    double anomaly_scores_std;
    int    samples_detected;
    int    samples_total;
} dp_poison_result_t;

typedef struct {
    double *gradients;
    size_t  num_params;
    double  original_norm;
    double  clipped_norm;
    int     was_clipped;
} dp_client_update_t;

typedef struct {
    double *updates;
    size_t  num_clients;
    size_t  params_per_client;
    double *anomaly_scores;
    size_t *malicious_clients;
    size_t  num_malicious;
} dp_fl_aggregate_t;

dp_sample_t  dp_sample_create(size_t dims);
void         dp_sample_free(dp_sample_t *s);
dp_sample_t  dp_sample_clone(const dp_sample_t *src);

dp_poison_config_t  dp_poison_config_default(dp_poison_type_t type);
dp_defense_config_t dp_defense_config_default(dp_defense_type_t type);

void dp_backdoor_inject(dp_sample_t *samples,
                        size_t num_samples,
                        const dp_trigger_t *trigger,
                        const dp_poison_config_t *config);

void dp_trigger_generate(dp_trigger_t *trigger,
                         dp_trigger_type_t type,
                         size_t rows,
                         size_t cols);

void dp_trigger_random(dp_trigger_t *trigger);
void dp_trigger_checkerboard(dp_trigger_t *trigger);
void dp_trigger_watermark(dp_trigger_t *trigger, const char *text);
void dp_trigger_frequency_domain(dp_trigger_t *trigger, double freq);

double dp_trigger_apply(dp_sample_t *sample,
                        const dp_trigger_t *trigger,
                        size_t start_row,
                        size_t start_col);

void dp_clean_label_poison(dp_sample_t *samples,
                           size_t num_samples,
                           const dp_poison_config_t *config);

void dp_availability_attack(dp_sample_t *samples,
                            size_t num_samples,
                            const dp_poison_config_t *config);

void dp_label_flipping(dp_sample_t *samples,
                       size_t num_samples,
                       int target_label,
                       double flip_ratio);

void dp_data_sanitization(dp_sample_t *samples,
                          size_t num_samples,
                          const dp_defense_config_t *config);

int  dp_detect_poison(const dp_sample_t *sample,
                      const dp_defense_config_t *config,
                      double *anomaly_score);

void dp_anomaly_detection(dp_poison_result_t *result,
                          const dp_sample_t *samples,
                          size_t num_samples,
                          const dp_defense_config_t *config);

double dp_outlier_score(const dp_sample_t *sample,
                        const dp_sample_t *dataset,
                        size_t dataset_size);

void dp_robust_training(double *weights,
                        size_t num_weights,
                        const dp_sample_t *samples,
                        size_t num_samples,
                        const dp_defense_config_t *config);

void dp_trimmed_loss(double *gradients,
                     size_t num_gradients,
                     double trim_ratio);

void dp_spectral_signature_defense(dp_poison_result_t *result,
                                   const dp_sample_t *samples,
                                   size_t num_samples,
                                   const dp_defense_config_t *config);

void dp_knn_filter(dp_sample_t *samples,
                   size_t num_samples,
                   const dp_defense_config_t *config);

void dp_certified_robustness(double *radius,
                             const dp_sample_t *sample,
                             const dp_defense_config_t *config);

void dp_fl_malicious_detection(dp_fl_aggregate_t *aggregate,
                               const dp_client_update_t *client_updates,
                               size_t num_clients,
                               const dp_defense_config_t *config);

void dp_fl_secure_aggregate(double *global_model,
                            size_t num_params,
                            const dp_client_update_t *updates,
                            size_t num_clients,
                            const dp_defense_config_t *config);

void dp_fl_byzantine_resilient_agg(double *global_model,
                                   size_t num_params,
                                   const dp_client_update_t *updates,
                                   size_t num_clients,
                                   size_t num_byzantine);

void dp_poison_evaluate(dp_poison_result_t *result,
                        const dp_sample_t *samples,
                        size_t num_samples,
                        const dp_poison_config_t *config,
                        const dp_defense_config_t *defense);

double dp_poison_effectiveness(const dp_poison_result_t *result);

int  dp_trigger_detected(const dp_sample_t *sample,
                         const dp_trigger_t *known_triggers,
                         size_t num_triggers,
                         double threshold);

const char *dp_poison_type_name(dp_poison_type_t type);
const char *dp_defense_type_name(dp_defense_type_t type);
const char *dp_trigger_type_name(dp_trigger_type_t type);

#ifdef __cplusplus
}
#endif

#endif
