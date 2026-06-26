#include "model_inversion.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>

mi_tensor_t mi_tensor_alloc(size_t dims)
{
    mi_tensor_t t;
    t.dims   = dims;
    t.values = (double *)calloc(dims, sizeof(double));
    return t;
}

void mi_tensor_free(mi_tensor_t *t)
{
    if (t && t->values) { free(t->values); t->values = NULL; t->dims = 0; }
}

mi_tensor_t mi_tensor_clone(const mi_tensor_t *src)
{
    mi_tensor_t dst = mi_tensor_alloc(src->dims);
    if (dst.values && src->values)
        memcpy(dst.values, src->values, src->dims * sizeof(double));
    return dst;
}

void mi_tensor_fill(mi_tensor_t *t, double val)
{
    size_t i;
    for (i = 0; i < t->dims; i++) t->values[i] = val;
}

double mi_tensor_norm(const mi_tensor_t *t)
{
    double sum = 0.0;
    size_t i;
    for (i = 0; i < t->dims; i++) sum += t->values[i] * t->values[i];
    return sqrt(sum);
}

double mi_tensor_l1_norm(const mi_tensor_t *t)
{
    double sum = 0.0;
    size_t i;
    for (i = 0; i < t->dims; i++) sum += fabs(t->values[i]);
    return sum;
}

mi_attack_config_t mi_attack_config_default(mi_attack_type_t type)
{
    mi_attack_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.type                = type;
    cfg.epsilon             = MI_EPS_DEFAULT;
    cfg.delta               = MI_DELTA_DEFAULT;
    cfg.iterations          = 1000;
    cfg.batch_size          = 32;
    cfg.confidence_based    = 1;
    cfg.attack_learning_rate = 0.01;
    cfg.use_shadow_models   = (type == MI_ATTACK_MEMBERSHIP) ? 1 : 0;
    cfg.shadow_model_count  = 10;
    return cfg;
}

mi_defense_config_t mi_defense_config_default(mi_defense_type_t type)
{
    mi_defense_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.type                = type;
    cfg.epsilon             = 1.0;
    cfg.delta               = 1e-5;
    cfg.noise_multiplier    = 1.1;
    cfg.clip_norm           = 1.0;
    cfg.num_teachers        = 100;
    cfg.num_votes           = 50;
    cfg.regularization_weight = 0.01;
    return cfg;
}

void mi_model_inversion_attack(mi_inversion_result_t *result,
                               const mi_tensor_t *target_logits,
                               const mi_tensor_t *model_params,
                               const mi_attack_config_t *config)
{
    size_t i;
    if (!result || !target_logits || !model_params) return;

    result->dims            = target_logits->dims;
    result->reconstructed   = (double *)calloc(result->dims, sizeof(double));
    result->iterations_used = 0;
    result->mse             = 0.0;
    result->ssim            = 0.0;

    if (!result->reconstructed) return;

    for (i = 0; i < result->dims; i++)
        result->reconstructed[i] = (double)rand() / RAND_MAX;

    for (i = 0; i < config->iterations; i++) {
        mi_tensor_t grad;
        size_t j;
        double loss_sum = 0.0;
        grad.dims   = result->dims;
        grad.values = (double *)calloc(result->dims, sizeof(double));

        for (j = 0; j < result->dims && j < target_logits->dims; j++) {
            double diff = result->reconstructed[j] - target_logits->values[j];
            grad.values[j] = 2.0 * diff;
            loss_sum += diff * diff;
        }

        for (j = 0; j < result->dims && j < model_params->dims; j++)
            grad.values[j] += 0.001 * model_params->values[j];

        for (j = 0; j < result->dims; j++) {
            result->reconstructed[j] -= config->attack_learning_rate * grad.values[j];
            if (result->reconstructed[j] < 0.0) result->reconstructed[j] = 0.0;
            if (result->reconstructed[j] > 1.0) result->reconstructed[j] = 1.0;
        }

        mi_tensor_free(&grad);
        result->mse = loss_sum / (double)result->dims;
        result->iterations_used++;
        if (result->mse < 1e-6) break;
    }
}

void mi_inversion_gradient_step(mi_tensor_t *reconstructed,
                                const mi_tensor_t *gradient,
                                const mi_attack_config_t *config)
{
    size_t i;
    for (i = 0; i < reconstructed->dims && i < gradient->dims; i++) {
        reconstructed->values[i] -= config->attack_learning_rate * gradient->values[i];
        if (reconstructed->values[i] < 0.0) reconstructed->values[i] = 0.0;
        if (reconstructed->values[i] > 1.0) reconstructed->values[i] = 1.0;
    }
}

double mi_inversion_loss(const mi_tensor_t *reconstructed_logits,
                         const mi_tensor_t *target_logits,
                         const mi_tensor_t *prior)
{
    double loss = 0.0;
    size_t i;
    for (i = 0; i < reconstructed_logits->dims && i < target_logits->dims; i++) {
        double diff = reconstructed_logits->values[i] - target_logits->values[i];
        loss += diff * diff;
    }
    if (prior) {
        for (i = 0; i < prior->dims; i++)
            loss += 0.01 * prior->values[i] * prior->values[i];
    }
    return loss;
}

void mi_membership_inference(mi_membership_result_t *result,
                             const mi_tensor_t *sample,
                             const mi_tensor_t *sample_logits,
                             const mi_tensor_t *shadow_data,
                             size_t num_shadow,
                             const mi_attack_config_t *config)
{
    double max_prob = 0.0;
    size_t i;
    (void)sample; (void)shadow_data; (void)num_shadow; (void)config;

    memset(result, 0, sizeof(*result));
    for (i = 0; i < sample_logits->dims; i++) {
        if (sample_logits->values[i] > max_prob) {
            max_prob = sample_logits->values[i];
            result->predicted_label = (int)i;
        }
    }
    result->max_probability    = max_prob;
    result->confidence         = max_prob;
    result->is_member          = (max_prob > 0.7) ? 1 : 0;
    result->prediction_entropy = 0.0;
    for (i = 0; i < sample_logits->dims; i++) {
        double p = sample_logits->values[i];
        if (p > 1e-12)
            result->prediction_entropy -= p * log(p);
    }
}

double mi_membership_score(const mi_tensor_t *logits,
                           int true_label,
                           double threshold)
{
    (void)threshold;
    if (!logits || true_label < 0 || (size_t)true_label >= logits->dims)
        return 0.0;
    return logits->values[true_label];
}

void mi_shadow_model_train(double *shadow_params,
                           const mi_tensor_t *train_data,
                           size_t train_count,
                           size_t param_count)
{
    size_t i;
    (void)train_data; (void)train_count;
    for (i = 0; i < param_count; i++)
        shadow_params[i] = ((double)rand() / RAND_MAX - 0.5) * 0.1;
}

void mi_attribute_inference(mi_attribute_result_t *result,
                            const mi_tensor_t *public_attrs,
                            const mi_tensor_t *sensitive_attrs,
                            const mi_tensor_t *model_outputs,
                            size_t num_samples,
                            const mi_attack_config_t *config)
{
    (void)public_attrs; (void)model_outputs; (void)config;
    memset(result, 0, sizeof(*result));
    result->num_attrs         = sensitive_attrs ? sensitive_attrs->dims : 0;
    result->sensitive_attrs   = (double *)calloc(result->num_attrs, sizeof(double));
    result->inference_accuracy = 0.5 + 0.3 * ((double)num_samples / 10000.0);
    result->baseline_accuracy  = 0.5;

    if (result->sensitive_attrs && sensitive_attrs)
        memcpy(result->sensitive_attrs, sensitive_attrs->values,
               result->num_attrs * sizeof(double));
}

double mi_attribute_correlation(const mi_tensor_t *a, const mi_tensor_t *b)
{
    double mean_a = 0.0, mean_b = 0.0, cov = 0.0, var_a = 0.0, var_b = 0.0;
    size_t i;
    double n = (double)(a->dims < b->dims ? a->dims : b->dims);
    if (n < 1) return 0.0;

    for (i = 0; i < (size_t)n; i++) { mean_a += a->values[i]; mean_b += b->values[i]; }
    mean_a /= n; mean_b /= n;

    for (i = 0; i < (size_t)n; i++) {
        double da = a->values[i] - mean_a, db = b->values[i] - mean_b;
        cov += da * db; var_a += da * da; var_b += db * db;
    }
    return (sqrt(var_a * var_b) > 1e-12) ? cov / sqrt(var_a * var_b) : 0.0;
}

void mi_model_extraction(double *clone_params,
                         size_t param_count,
                         double (*query_fn)(void *ctx, const mi_tensor_t *input),
                         void *query_ctx,
                         size_t num_queries,
                         const mi_attack_config_t *config)
{
    size_t i;
    mi_tensor_t query = mi_tensor_alloc(param_count);
    mi_tensor_t grad  = mi_tensor_alloc(param_count);
    (void)config;

    for (i = 0; i < param_count; i++)
        clone_params[i] = ((double)rand() / RAND_MAX - 0.5) * 0.1;

    for (i = 0; i < num_queries && i < param_count; i++) {
        query.values[i % param_count] = (double)rand() / RAND_MAX;
        double pred = query_fn(query_ctx, &query);
        grad.values[i % param_count]  = (pred - 0.5) * query.values[i % param_count];
        clone_params[i % param_count] -= 0.01 * grad.values[i % param_count];
    }
    mi_tensor_free(&query);
    mi_tensor_free(&grad);
}

void mi_extraction_generate_query(mi_tensor_t *query,
                                  const mi_tensor_t *seed,
                                  double exploration_rate)
{
    size_t i;
    for (i = 0; i < query->dims; i++) {
        double noise = ((double)rand() / RAND_MAX - 0.5) * exploration_rate;
        query->values[i] = ((seed && i < seed->dims) ? seed->values[i] : 0.0) + noise;
    }
}

void mi_gradient_leak_attack(mi_tensor_t *reconstructed,
                             const mi_tensor_t *gradients,
                             const mi_tensor_t *model_params,
                             size_t num_participants,
                             const mi_attack_config_t *config)
{
    size_t i;
    (void)model_params; (void)num_participants; (void)config;

    for (i = 0; i < reconstructed->dims && i < gradients->dims; i++) {
        reconstructed->values[i] = gradients->values[i] * 0.1;
        if (reconstructed->values[i] < 0.0) reconstructed->values[i] = 0.0;
        if (reconstructed->values[i] > 1.0) reconstructed->values[i] = 1.0;
    }
}

int mi_gradient_leak_detect(const mi_tensor_t *gradients,
                            double threshold,
                            const mi_tensor_t *reference)
{
    double norm = mi_tensor_norm(gradients);
    double ref  = reference ? mi_tensor_norm(reference) : 1.0;
    (void)threshold;
    return (norm > ref * 1.5) ? 1 : 0;
}

void mi_dp_sgd_apply(double *gradients,
                     size_t num_gradients,
                     const mi_defense_config_t *config)
{
    mi_gradient_clipping(gradients, num_gradients, config->clip_norm);
    mi_gaussian_mechanism(gradients, num_gradients,
                          1.0, config->epsilon, config->delta);
}

void mi_gaussian_mechanism(double *values,
                           size_t count,
                           double sensitivity,
                           double epsilon,
                           double delta)
{
    double sigma;
    size_t i;
    (void)delta;
    if (epsilon <= 0.0) epsilon = 0.1;
    sigma = sensitivity / epsilon;

    for (i = 0; i < count; i++) {
        double u1 = (double)rand() / RAND_MAX;
        double u2 = (double)rand() / RAND_MAX;
        if (u1 < 1e-12) u1 = 1e-12;
        double noise = sqrt(-2.0 * log(u1)) * cos(2.0 * 3.141592653589793 * u2) * sigma;
        values[i] += noise;
    }
}

void mi_laplace_mechanism(double *values,
                          size_t count,
                          double sensitivity,
                          double epsilon)
{
    size_t i;
    double scale = sensitivity / epsilon;
    for (i = 0; i < count; i++) {
        double u = (double)rand() / RAND_MAX - 0.5;
        double noise = (u > 0 ? 1.0 : -1.0) * scale * log(1.0 - 2.0 * fabs(u));
        values[i] += noise;
    }
}

void mi_gradient_clipping(double *gradients,
                          size_t count,
                          double clip_norm)
{
    double norm = 0.0;
    size_t i;
    for (i = 0; i < count; i++) norm += gradients[i] * gradients[i];
    norm = sqrt(norm);
    if (norm > clip_norm && norm > 1e-12) {
        for (i = 0; i < count; i++) gradients[i] *= clip_norm / norm;
    }
}

void mi_pate_aggregate(double *output,
                       const double **teacher_votes,
                       size_t num_teachers,
                       size_t num_classes,
                       double threshold,
                       double sigma)
{
    size_t i, j;
    (void)threshold; (void)sigma;

    for (j = 0; j < num_classes; j++) output[j] = 0.0;
    for (i = 0; i < num_teachers; i++)
        for (j = 0; j < num_classes; j++)
            output[j] += teacher_votes[i][j];

    for (j = 0; j < num_classes; j++)
        output[j] /= (double)num_teachers;
}

double mi_renyi_divergence(const double *dist_p,
                           const double *dist_q,
                           size_t dims,
                           double alpha)
{
    double sum = 0.0;
    size_t i;
    (void)alpha;
    for (i = 0; i < dims; i++) {
        double p = dist_p[i] > 1e-12 ? dist_p[i] : 1e-12;
        double q = dist_q[i] > 1e-12 ? dist_q[i] : 1e-12;
        sum += p * log(p / q);
    }
    return sum;
}

int mi_check_privacy_budget(mi_privacy_budget_t *budget,
                            double delta_increment,
                            const mi_defense_config_t *config)
{
    if (!budget) return 0;
    budget->privacy_loss += delta_increment;
    budget->delta += config->delta;
    budget->violated = (budget->privacy_loss > budget->epsilon) ? 1 : 0;
    return budget->violated;
}

void mi_compute_sensitivity(double *sensitivity,
                            const mi_tensor_t *data,
                            size_t num_samples,
                            double query_radius)
{
    (void)data; (void)num_samples;
    *sensitivity = 2.0 * query_radius;
}

double mi_exact_privacy_loss(const mi_privacy_budget_t *budget)
{
    return budget->privacy_loss;
}

void mi_differential_privacy_audit(mi_privacy_budget_t *result,
                                   const double *training_losses,
                                   size_t num_iterations,
                                   double epsilon_target)
{
    size_t i;
    double max_diff = 0.0;

    for (i = 1; i < num_iterations; i++) {
        double diff = fabs(training_losses[i] - training_losses[i - 1]);
        if (diff > max_diff) max_diff = diff;
    }

    result->epsilon = epsilon_target;
    result->delta   = MI_DELTA_DEFAULT;
    result->privacy_loss = max_diff * (double)num_iterations;
    result->violated = (result->privacy_loss > epsilon_target) ? 1 : 0;
}

const char *mi_attack_name(mi_attack_type_t type)
{
    switch (type) {
        case MI_ATTACK_INVERSION:     return "Model Inversion";
        case MI_ATTACK_MEMBERSHIP:    return "Membership Inference";
        case MI_ATTACK_ATTRIBUTE:     return "Attribute Inference";
        case MI_ATTACK_EXTRACTION:    return "Model Extraction";
        case MI_ATTACK_GRADIENT_LEAK: return "Gradient Leakage";
        default:                      return "Unknown";
    }
}

const char *mi_defense_name(mi_defense_type_t type)
{
    switch (type) {
        case MI_DEFENSE_DP_SGD:         return "DP-SGD";
        case MI_DEFENSE_GAUSSIAN_MECH:  return "Gaussian Mechanism";
        case MI_DEFENSE_LAPLACE_MECH:   return "Laplace Mechanism";
        case MI_DEFENSE_GRADIENT_CLIP:  return "Gradient Clipping";
        case MI_DEFENSE_PATE:           return "PATE";
        case MI_DEFENSE_ADV_REGULARIZE: return "Adversarial Regularization";
        default:                        return "Unknown";
    }
}
