#include "data_poison.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>

dp_sample_t dp_sample_create(size_t dims)
{
    dp_sample_t s;
    memset(&s, 0, sizeof(s));
    s.dims     = dims;
    s.features = (double *)calloc(dims, sizeof(double));
    s.label    = -1;
    s.is_poisoned = 0;
    s.anomaly_score = 0.0;
    return s;
}

void dp_sample_free(dp_sample_t *s)
{
    if (s && s->features) { free(s->features); s->features = NULL; s->dims = 0; }
}

dp_sample_t dp_sample_clone(const dp_sample_t *src)
{
    dp_sample_t dst = dp_sample_create(src->dims);
    dst.label        = src->label;
    dst.is_poisoned  = src->is_poisoned;
    dst.anomaly_score = src->anomaly_score;
    if (dst.features && src->features)
        memcpy(dst.features, src->features, src->dims * sizeof(double));
    return dst;
}

dp_poison_config_t dp_poison_config_default(dp_poison_type_t type)
{
    dp_poison_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.type               = type;
    cfg.trigger_type       = DP_TRIGGER_PATTERN;
    cfg.poison_ratio       = 0.1;
    cfg.target_label       = 0;
    cfg.source_label       = -1;
    cfg.poison_strength    = 1.0;
    cfg.trigger_size_rows  = 4;
    cfg.trigger_size_cols  = 4;
    cfg.clean_label_attack = (type == DP_CLEAN_LABEL) ? 1 : 0;
    cfg.num_poison_samples = 100;
    cfg.adaptive           = 0;
    return cfg;
}

dp_defense_config_t dp_defense_config_default(dp_defense_type_t type)
{
    dp_defense_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.type              = type;
    cfg.anomaly_threshold = 2.0;
    cfg.clip_norm         = 1.0;
    cfg.epsilon           = 1.0;
    cfg.delta             = 1e-5;
    cfg.num_neighbors     = 5;
    cfg.certified         = 0;
    cfg.certified_radius  = 0.1;
    cfg.use_trim          = 1;
    cfg.trim_ratio        = 0.1;
    return cfg;
}

void dp_backdoor_inject(dp_sample_t *samples,
                        size_t num_samples,
                        const dp_trigger_t *trigger,
                        const dp_poison_config_t *config)
{
    size_t i;
    size_t poison_count = (size_t)(num_samples * config->poison_ratio);

    for (i = 0; i < num_samples; i++) {
        if (i < poison_count) {
            dp_trigger_apply(&samples[i], trigger, 0, 0);
            samples[i].label       = config->target_label;
            samples[i].is_poisoned = 1;
        }
    }
}

void dp_trigger_generate(dp_trigger_t *trigger,
                         dp_trigger_type_t type,
                         size_t rows,
                         size_t cols)
{
    trigger->rows = rows;
    trigger->cols = cols;
    trigger->data = (double *)calloc(rows * cols, sizeof(double));

    switch (type) {
        case DP_TRIGGER_PIXEL:
            dp_trigger_random(trigger);
            break;
        case DP_TRIGGER_PATTERN:
            dp_trigger_checkerboard(trigger);
            break;
        case DP_TRIGGER_WATERMARK:
            dp_trigger_watermark(trigger, "P");
            break;
        case DP_TRIGGER_SEMANTIC:
            dp_trigger_random(trigger);
            break;
        case DP_TRIGGER_FREQUENCY:
            dp_trigger_frequency_domain(trigger, 0.5);
            break;
        default:
            dp_trigger_random(trigger);
            break;
    }
}

void dp_trigger_random(dp_trigger_t *trigger)
{
    size_t i, total = trigger->rows * trigger->cols;
    for (i = 0; i < total; i++)
        trigger->data[i] = (double)rand() / RAND_MAX;
}

void dp_trigger_checkerboard(dp_trigger_t *trigger)
{
    size_t r, c;
    for (r = 0; r < trigger->rows; r++) {
        for (c = 0; c < trigger->cols; c++) {
            trigger->data[r * trigger->cols + c] =
                ((r + c) % 2 == 0) ? 1.0 : 0.0;
        }
    }
}

void dp_trigger_watermark(dp_trigger_t *trigger, const char *text)
{
    size_t i, total = trigger->rows * trigger->cols;
    double val = (text && text[0]) ? (double)text[0] / 256.0 : 0.5;
    for (i = 0; i < total; i++)
        trigger->data[i] = val;
}

void dp_trigger_frequency_domain(dp_trigger_t *trigger, double freq)
{
    size_t i, total = trigger->rows * trigger->cols;
    for (i = 0; i < total; i++)
        trigger->data[i] = sin(2.0 * 3.141592653589793 * freq * (double)i);
}

double dp_trigger_apply(dp_sample_t *sample,
                        const dp_trigger_t *trigger,
                        size_t start_row,
                        size_t start_col)
{
    size_t r, c;
    double *feat = sample->features ? sample->features : NULL;
    (void)start_row; (void)start_col;

    if (!feat || !trigger->data) return 0.0;

    for (r = 0; r < trigger->rows && r < sample->dims; r++) {
        for (c = 0; c < trigger->cols; c++) {
            size_t idx = r * trigger->cols + c;
            if (idx < sample->dims)
                feat[idx] = trigger->data[idx];
        }
    }
    return 1.0;
}

void dp_clean_label_poison(dp_sample_t *samples,
                           size_t num_samples,
                           const dp_poison_config_t *config)
{
    size_t i, j;
    size_t poison_count = (size_t)(num_samples * config->poison_ratio);
    double base_val = (double)config->target_label / 10.0;

    for (i = 0; i < num_samples; i++) {
        if (i < poison_count) {
            for (j = 0; j < samples[i].dims; j++)
                samples[i].features[j] += base_val * config->poison_strength;
            samples[i].is_poisoned = 1;
        }
    }
}

void dp_availability_attack(dp_sample_t *samples,
                            size_t num_samples,
                            const dp_poison_config_t *config)
{
    size_t i, j;
    size_t poison_count = (size_t)(num_samples * config->poison_ratio);

    for (i = 0; i < num_samples; i++) {
        if (i < poison_count) {
            for (j = 0; j < samples[i].dims; j++)
                samples[i].features[j] = ((double)rand() / RAND_MAX) * 2.0 - 1.0;
            samples[i].label = rand() % 10;
            samples[i].is_poisoned = 1;
        }
    }
}

void dp_label_flipping(dp_sample_t *samples,
                       size_t num_samples,
                       int target_label,
                       double flip_ratio)
{
    size_t i;
    for (i = 0; i < num_samples; i++) {
        if ((double)rand() / RAND_MAX < flip_ratio)
            samples[i].label = target_label;
    }
}

void dp_data_sanitization(dp_sample_t *samples,
                          size_t num_samples,
                          const dp_defense_config_t *config)
{
    size_t i, j;
    double threshold = config->anomaly_threshold;

    for (i = 0; i < num_samples; i++) {
        double score = dp_outlier_score(&samples[i], samples, num_samples);
        if (score > threshold) {
            for (j = 0; j < samples[i].dims; j++)
                samples[i].features[j] = 0.0;
            samples[i].is_poisoned = 0;
        }
    }
}

int dp_detect_poison(const dp_sample_t *sample,
                     const dp_defense_config_t *config,
                     double *anomaly_score)
{
    double score = 0.0;
    size_t i;
    for (i = 0; i < sample->dims; i++)
        score += fabs(sample->features[i]);
    score /= (double)sample->dims;

    if (anomaly_score) *anomaly_score = score;
    return (score > config->anomaly_threshold) ? 1 : 0;
}

void dp_anomaly_detection(dp_poison_result_t *result,
                          const dp_sample_t *samples,
                          size_t num_samples,
                          const dp_defense_config_t *config)
{
    size_t i;
    double sum = 0.0, sum_sq = 0.0;
    memset(result, 0, sizeof(*result));

    for (i = 0; i < num_samples; i++) {
        samples[i].anomaly_score = dp_outlier_score(&samples[i], samples, num_samples);
        sum    += samples[i].anomaly_score;
        sum_sq += samples[i].anomaly_score * samples[i].anomaly_score;
    }

    result->anomaly_scores_mean = sum / (double)num_samples;
    result->anomaly_scores_std  = sqrt(sum_sq / (double)num_samples -
                                       result->anomaly_scores_mean * result->anomaly_scores_mean);

    for (i = 0; i < num_samples; i++) {
        if (samples[i].anomaly_score > config->anomaly_threshold * result->anomaly_scores_std +
            result->anomaly_scores_mean) {
            result->samples_detected++;
        }
    }
    result->samples_total = (int)num_samples;
}

double dp_outlier_score(const dp_sample_t *sample,
                        const dp_sample_t *dataset,
                        size_t dataset_size)
{
    double min_dist = 1e100;
    size_t i, j;

    for (i = 0; i < dataset_size; i++) {
        if (sample == &dataset[i]) continue;
        double dist = 0.0;
        for (j = 0; j < sample->dims && j < dataset[i].dims; j++) {
            double diff = sample->features[j] - dataset[i].features[j];
            dist += diff * diff;
        }
        if (dist < min_dist) min_dist = dist;
    }
    return (min_dist < 1e99) ? sqrt(min_dist) : 0.0;
}

void dp_robust_training(double *weights,
                        size_t num_weights,
                        const dp_sample_t *samples,
                        size_t num_samples,
                        const dp_defense_config_t *config)
{
    size_t i, s;
    double clip_norm = config->clip_norm;
    double *grad = (double *)calloc(num_weights, sizeof(double));

    for (s = 0; s < num_samples; s++) {
        for (i = 0; i < num_weights && i < samples[s].dims; i++) {
            double g = (samples[s].features[i] - weights[i]) * 0.01;
            grad[i] += g;
        }
    }

    for (i = 0; i < num_weights; i++) grad[i] /= (double)num_samples;

    if (config->use_trim)
        dp_trimmed_loss(grad, num_weights, config->trim_ratio);

    double norm_sq = 0.0;
    for (i = 0; i < num_weights; i++) norm_sq += grad[i] * grad[i];
    double norm = sqrt(norm_sq);
    if (norm > clip_norm && norm > 1e-12)
        for (i = 0; i < num_weights; i++) grad[i] *= clip_norm / norm;

    for (i = 0; i < num_weights; i++)
        weights[i] -= 0.01 * grad[i];

    free(grad);
}

void dp_trimmed_loss(double *gradients,
                     size_t num_gradients,
                     double trim_ratio)
{
    size_t i;
    double threshold, *sorted;
    sorted = (double *)malloc(num_gradients * sizeof(double));
    if (!sorted) return;

    memcpy(sorted, gradients, num_gradients * sizeof(double));

    for (i = 0; i < num_gradients - 1; i++) {
        size_t j;
        for (j = i + 1; j < num_gradients; j++) {
            if (fabs(sorted[j]) < fabs(sorted[i])) {
                double tmp = sorted[i];
                sorted[i]  = sorted[j];
                sorted[j]  = tmp;
            }
        }
    }

    threshold = fabs(sorted[(size_t)(num_gradients * (1.0 - trim_ratio))]);

    for (i = 0; i < num_gradients; i++) {
        if (fabs(gradients[i]) > threshold)
            gradients[i] = (gradients[i] > 0 ? threshold : -threshold);
    }

    free(sorted);
}

void dp_spectral_signature_defense(dp_poison_result_t *result,
                                   const dp_sample_t *samples,
                                   size_t num_samples,
                                   const dp_defense_config_t *config)
{
    (void)config;
    dp_anomaly_detection(result, samples, num_samples, config);
}

void dp_knn_filter(dp_sample_t *samples,
                   size_t num_samples,
                   const dp_defense_config_t *config)
{
    dp_data_sanitization(samples, num_samples, config);
}

void dp_certified_robustness(double *radius,
                             const dp_sample_t *sample,
                             const dp_defense_config_t *config)
{
    size_t i;
    double sum = 0.0;
    for (i = 0; i < sample->dims; i++)
        sum += fabs(sample->features[i]);
    *radius = config->certified_radius * sum;
}

void dp_fl_malicious_detection(dp_fl_aggregate_t *aggregate,
                               const dp_client_update_t *client_updates,
                               size_t num_clients,
                               const dp_defense_config_t *config)
{
    size_t i;
    aggregate->num_clients     = num_clients;
    aggregate->params_per_client = client_updates ? client_updates[0].num_params : 0;
    aggregate->anomaly_scores  = (double *)calloc(num_clients, sizeof(double));
    aggregate->malicious_clients = (size_t *)calloc(num_clients, sizeof(size_t));
    aggregate->num_malicious   = 0;

    for (i = 0; i < num_clients; i++) {
        aggregate->anomaly_scores[i] = client_updates[i].original_norm;
        if (aggregate->anomaly_scores[i] > config->anomaly_threshold) {
            aggregate->malicious_clients[aggregate->num_malicious++] = i;
        }
    }
}

void dp_fl_secure_aggregate(double *global_model,
                            size_t num_params,
                            const dp_client_update_t *updates,
                            size_t num_clients,
                            const dp_defense_config_t *config)
{
    size_t c, p;
    dp_fl_byzantine_resilient_agg(global_model, num_params, updates,
                                  num_clients, (size_t)(num_clients * 0.2));
    for (p = 0; p < num_params; p++) {
        for (c = 0; c < num_clients; c++) {
            if (updates[c].gradients && p < updates[c].num_params)
                global_model[p] += 0.05 * updates[c].gradients[p];
        }
        global_model[p] /= (double)num_clients;
    }
    (void)config;
}

void dp_fl_byzantine_resilient_agg(double *global_model,
                                   size_t num_params,
                                   const dp_client_update_t *updates,
                                   size_t num_clients,
                                   size_t num_byzantine)
{
    size_t p, c;
    size_t honest = num_clients - num_byzantine;
    if (honest < 1) honest = 1;

    for (p = 0; p < num_params; p++) {
        double *vals = (double *)malloc(num_clients * sizeof(double));
        size_t v;
        for (c = 0; c < num_clients; c++)
            vals[c] = (c < updates[c].num_params) ? updates[c].gradients[p] : 0.0;

        for (c = 0; c < num_clients - 1; c++)
            for (v = c + 1; v < num_clients; v++)
                if (vals[v] < vals[c]) { double t = vals[c]; vals[c] = vals[v]; vals[v] = t; }

        double sum = 0.0;
        for (c = num_byzantine; c < num_clients; c++)
            sum += vals[c];
        global_model[p] = sum / (double)honest;
        free(vals);
    }
}

void dp_poison_evaluate(dp_poison_result_t *result,
                        const dp_sample_t *samples,
                        size_t num_samples,
                        const dp_poison_config_t *config,
                        const dp_defense_config_t *defense)
{
    size_t i;
    size_t poisoned = 0, detected = 0;
    memset(result, 0, sizeof(*result));

    for (i = 0; i < num_samples; i++) {
        if (samples[i].is_poisoned) poisoned++;
        if (dp_detect_poison(&samples[i], defense, NULL))
            detected++;
    }

    result->samples_total   = (int)num_samples;
    result->samples_detected = (int)detected;
    result->defense_detection_rate = (poisoned > 0) ?
        (double)detected / (double)poisoned : 0.0;
    result->poison_success_rate = (double)poisoned / (double)num_samples;
    (void)config;
}

double dp_poison_effectiveness(const dp_poison_result_t *result)
{
    return result->poison_success_rate;
}

int dp_trigger_detected(const dp_sample_t *sample,
                        const dp_trigger_t *known_triggers,
                        size_t num_triggers,
                        double threshold)
{
    size_t i;
    (void)threshold;
    for (i = 0; i < num_triggers; i++) {
        size_t j;
        double sim = 0.0;
        for (j = 0; j < sample->dims && j < known_triggers[i].rows * known_triggers[i].cols; j++)
            sim += fabs(sample->features[j] - known_triggers[i].data[j]);
        if (sim < 0.01) return 1;
    }
    return 0;
}

const char *dp_poison_type_name(dp_poison_type_t type)
{
    switch (type) {
        case DP_BACKDOOR:             return "Backdoor Injection";
        case DP_CLEAN_LABEL:          return "Clean-Label Poisoning";
        case DP_AVAILABILITY:         return "Availability Attack";
        case DP_TARGETED_MISCLASSIFY: return "Targeted Misclassification";
        case DP_LABEL_FLIPPING:       return "Label Flipping";
        case DP_FEATURE_COLLISION:    return "Feature Collision";
        default:                      return "Unknown";
    }
}

const char *dp_defense_type_name(dp_defense_type_t type)
{
    switch (type) {
        case DP_DEFENSE_SANITIZATION:       return "Data Sanitization";
        case DP_DEFENSE_ROBUST_TRAIN:       return "Robust Training";
        case DP_DEFENSE_ANOMALY_DETECT:     return "Anomaly Detection";
        case DP_DEFENSE_DIFF_PRIVACY:       return "Differential Privacy";
        case DP_DEFENSE_SPECTRAL_SIGNATURE: return "Spectral Signature";
        case DP_DEFENSE_TRIM:               return "Trimmed Loss";
        case DP_DEFENSE_KNN_FILTER:         return "KNN Filter";
        case DP_DEFENSE_CERTIFIED_ROBUST:   return "Certified Robustness";
        default:                            return "Unknown";
    }
}

const char *dp_trigger_type_name(dp_trigger_type_t type)
{
    switch (type) {
        case DP_TRIGGER_PIXEL:     return "Pixel";
        case DP_TRIGGER_PATTERN:   return "Pattern";
        case DP_TRIGGER_WATERMARK: return "Watermark";
        case DP_TRIGGER_SEMANTIC:  return "Semantic";
        case DP_TRIGGER_FREQUENCY: return "Frequency Domain";
        default:                   return "Unknown";
    }
}
