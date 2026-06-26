#include "adversarial_ml.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>

adv_tensor_t adv_tensor_create(size_t dims)
{
    adv_tensor_t t;
    t.dims   = dims;
    t.stride = 1;
    t.data   = (double *)calloc(dims, sizeof(double));
    return t;
}

void adv_tensor_free(adv_tensor_t *t)
{
    if (t && t->data) { free(t->data); t->data = NULL; t->dims = 0; }
}

adv_tensor_t adv_tensor_clone(const adv_tensor_t *src)
{
    adv_tensor_t dst = adv_tensor_create(src->dims);
    dst.stride = src->stride;
    if (src->data && dst.data)
        memcpy(dst.data, src->data, src->dims * sizeof(double));
    return dst;
}

adv_attack_config_t adv_attack_config_default(adv_attack_type_t type)
{
    adv_attack_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.type           = type;
    cfg.norm           = ADV_NORM_LINF;
    cfg.epsilon        = ADV_ML_EPSILON_DEF;
    cfg.alpha          = ADV_ML_ALPHA_DEF;
    cfg.iterations     = (type == ADV_ATTACK_PGD) ? 40 : 1;
    cfg.patch_rows     = 16;
    cfg.patch_cols     = 16;
    cfg.targeted       = 0;
    cfg.target_class   = 0;
    cfg.random_start   = (type == ADV_ATTACK_PGD) ? 1 : 0;
    cfg.confidence     = 0.0;
    cfg.learning_rate  = 0.01;
    cfg.max_iterations = 1000;
    if (type == ADV_ATTACK_CW_L2 || type == ADV_ATTACK_CW_LINF) {
        cfg.confidence     = 0.0;
        cfg.learning_rate  = 0.01;
        cfg.max_iterations = 1000;
        cfg.iterations     = 1000;
    }
    return cfg;
}

adv_defense_config_t adv_defense_config_default(adv_defense_type_t type)
{
    adv_defense_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.type               = type;
    cfg.temperature         = (type == ADV_DEFENSE_DISTILLATION) ? 100.0 : 1.0;
    cfg.epsilon_bound       = 0.3;
    cfg.ensemble_count      = 3;
    cfg.use_gaussian        = (type == ADV_DEFENSE_INPUT_TRANSFORM) ? 1 : 0;
    cfg.use_jpeg_compress   = 0;
    cfg.apply_bit_depth_reduce = 0;
    return cfg;
}

void adv_fgsm_generate(adv_tensor_t *adversarial,
                       const adv_tensor_t *input,
                       const adv_tensor_t *gradient,
                       double epsilon)
{
    size_t i;
    for (i = 0; i < input->dims && i < adversarial->dims; i++) {
        double sign_val = (gradient->data[i] > 0.0) ? 1.0 :
                          (gradient->data[i] < 0.0) ? -1.0 : 0.0;
        adversarial->data[i] = input->data[i] + epsilon * sign_val;
        if (adversarial->data[i] < 0.0) adversarial->data[i] = 0.0;
        if (adversarial->data[i] > 1.0) adversarial->data[i] = 1.0;
    }
}

void adv_fgsm_targeted(adv_tensor_t *adversarial,
                       const adv_tensor_t *input,
                       const adv_tensor_t *gradient,
                       double epsilon)
{
    size_t i;
    for (i = 0; i < input->dims && i < adversarial->dims; i++) {
        double sign_val = (gradient->data[i] > 0.0) ? 1.0 :
                          (gradient->data[i] < 0.0) ? -1.0 : 0.0;
        adversarial->data[i] = input->data[i] - epsilon * sign_val;
        if (adversarial->data[i] < 0.0) adversarial->data[i] = 0.0;
        if (adversarial->data[i] > 1.0) adversarial->data[i] = 1.0;
    }
}

void adv_pgd_iteration(adv_tensor_t *current,
                       const adv_tensor_t *gradient,
                       double alpha,
                       adv_norm_t norm)
{
    size_t i;
    (void)norm;
    for (i = 0; i < current->dims && i < gradient->dims; i++) {
        double sign_val = (gradient->data[i] > 0.0) ? 1.0 :
                          (gradient->data[i] < 0.0) ? -1.0 : 0.0;
        current->data[i] += alpha * sign_val;
    }
}

void adv_pgd_generate(adv_tensor_t *adversarial,
                      const adv_tensor_t *input,
                      const adv_tensor_t *gradients,
                      const adv_attack_config_t *config)
{
    size_t iter, idx;
    (void)gradients;
    for (idx = 0; idx < input->dims && idx < adversarial->dims; idx++)
        adversarial->data[idx] = input->data[idx];

    for (iter = 0; iter < config->iterations; iter++) {
        for (idx = 0; idx < adversarial->dims; idx++) {
            double noise = ((double)rand() / RAND_MAX - 0.5) * 2.0 * config->alpha;
            adversarial->data[idx] += noise;
        }
        adv_clip_perturbation(adversarial, input, config->epsilon, config->norm);
    }
}

void adv_clip_perturbation(adv_tensor_t *adversarial,
                           const adv_tensor_t *original,
                           double epsilon,
                           adv_norm_t norm)
{
    size_t i;
    for (i = 0; i < adversarial->dims && i < original->dims; i++) {
        double diff = adversarial->data[i] - original->data[i];
        if (norm == ADV_NORM_LINF) {
            if (diff >  epsilon) adversarial->data[i] = original->data[i] + epsilon;
            if (diff < -epsilon) adversarial->data[i] = original->data[i] - epsilon;
        } else if (norm == ADV_NORM_L2) {
            double l2 = 0.0;
            size_t j;
            for (j = 0; j < adversarial->dims && j < original->dims; j++) {
                double d = adversarial->data[j] - original->data[j];
                l2 += d * d;
            }
            l2 = sqrt(l2);
            if (l2 > epsilon && l2 > 1e-12) {
                for (j = 0; j < adversarial->dims; j++)
                    adversarial->data[j] = original->data[j] +
                        (adversarial->data[j] - original->data[j]) * epsilon / l2;
            }
            break;
        }
        if (adversarial->data[i] < 0.0) adversarial->data[i] = 0.0;
        if (adversarial->data[i] > 1.0) adversarial->data[i] = 1.0;
    }
}

int adv_cw_loss(const adv_tensor_t *logits,
                int target_class,
                int true_class,
                adv_norm_t norm,
                double confidence,
                double *loss_out)
{
    size_t i;
    double target_logit, max_other;
    (void)norm;
    if (!logits || !loss_out) return -1;

    target_logit = (target_class >= 0 && (size_t)target_class < logits->dims)
                   ? logits->data[target_class] : 0.0;

    max_other = -1e100;
    for (i = 0; i < logits->dims; i++) {
        if ((int)i == target_class) continue;
        if ((int)i == true_class && target_class != true_class) continue;
        if (logits->data[i] > max_other) max_other = logits->data[i];
    }
    *loss_out = (max_other - target_logit + confidence) > 0.0 ?
                (max_other - target_logit + confidence) : 0.0;
    return 0;
}

void adv_patch_apply(adv_tensor_t *image,
                     const adv_tensor_t *patch,
                     size_t row_start,
                     size_t col_start)
{
    (void)image; (void)patch; (void)row_start; (void)col_start;
}

void adv_patch_generate(adv_tensor_t *patch,
                        const adv_tensor_t *images,
                        size_t num_images,
                        const adv_attack_config_t *config)
{
    size_t i;
    (void)images; (void)num_images; (void)config;
    for (i = 0; i < patch->dims; i++)
        patch->data[i] = (double)rand() / RAND_MAX;
}

void adv_physical_transform(adv_tensor_t *output,
                            const adv_tensor_t *input,
                            double rotation_deg,
                            double scale_factor,
                            double brightness_delta)
{
    size_t i;
    for (i = 0; i < input->dims && i < output->dims; i++) {
        output->data[i] = input->data[i] * scale_factor + brightness_delta;
        if (output->data[i] < 0.0) output->data[i] = 0.0;
        if (output->data[i] > 1.0) output->data[i] = 1.0;
    }
    (void)rotation_deg;
}

double adv_physical_robustness_score(const adv_tensor_t *original,
                                     const adv_tensor_t *transformed,
                                     adv_norm_t norm)
{
    return adv_perturbation_norm(original, transformed, norm);
}

void adv_input_transform_defense(adv_tensor_t *output,
                                 const adv_tensor_t *input,
                                 const adv_defense_config_t *config)
{
    size_t i;
    for (i = 0; i < input->dims && i < output->dims; i++)
        output->data[i] = input->data[i];

    if (config->use_gaussian)
        adv_gaussian_noise_defense(output, output, 0.05);
    if (config->use_jpeg_compress)
        adv_median_filter(output, output, 3);
    if (config->apply_bit_depth_reduce)
        adv_bit_depth_reduce(output, output, 6);
}

void adv_bit_depth_reduce(adv_tensor_t *output,
                          const adv_tensor_t *input,
                          int bits)
{
    size_t i;
    double levels = (double)((1 << bits) - 1);
    for (i = 0; i < input->dims && i < output->dims; i++)
        output->data[i] = round(input->data[i] * levels) / levels;
}

void adv_median_filter(adv_tensor_t *output,
                       const adv_tensor_t *input,
                       size_t kernel_size)
{
    size_t i;
    (void)kernel_size;
    for (i = 0; i < input->dims && i < output->dims; i++)
        output->data[i] = input->data[i];
}

void adv_gaussian_noise_defense(adv_tensor_t *output,
                                const adv_tensor_t *input,
                                double stddev)
{
    size_t i;
    for (i = 0; i < input->dims && i < output->dims; i++) {
        double u1 = (double)rand() / RAND_MAX;
        double u2 = (double)rand() / RAND_MAX;
        if (u1 < 1e-12) u1 = 1e-12;
        double noise = sqrt(-2.0 * log(u1)) * cos(2.0 * 3.141592653589793 * u2) * stddev;
        output->data[i] = input->data[i] + noise;
        if (output->data[i] < 0.0) output->data[i] = 0.0;
        if (output->data[i] > 1.0) output->data[i] = 1.0;
    }
}

void adv_random_resize_pad(adv_tensor_t *output,
                           const adv_tensor_t *input,
                           size_t min_size,
                           size_t max_size)
{
    size_t i;
    (void)min_size; (void)max_size;
    for (i = 0; i < input->dims && i < output->dims; i++)
        output->data[i] = input->data[i];
}

double adv_perturbation_norm(const adv_tensor_t *original,
                             const adv_tensor_t *adversarial,
                             adv_norm_t norm)
{
    double result = 0.0;
    size_t i;
    if (norm == ADV_NORM_LINF) {
        result = 0.0;
        for (i = 0; i < original->dims && i < adversarial->dims; i++) {
            double diff = fabs(adversarial->data[i] - original->data[i]);
            if (diff > result) result = diff;
        }
    } else if (norm == ADV_NORM_L2) {
        for (i = 0; i < original->dims && i < adversarial->dims; i++) {
            double diff = adversarial->data[i] - original->data[i];
            result += diff * diff;
        }
        result = sqrt(result);
    } else {
        for (i = 0; i < original->dims && i < adversarial->dims; i++)
            result += fabs(adversarial->data[i] - original->data[i]);
    }
    return result;
}

int adv_transferability_test(const adv_tensor_t *sample,
                             const adv_tensor_t *adversarial,
                             double *transfer_score)
{
    if (!sample || !adversarial || !transfer_score) return -1;
    *transfer_score = adv_perturbation_norm(sample, adversarial, ADV_NORM_L2);
    return 0;
}

double adv_distillation_temperature(double logit, double temperature)
{
    return logit / temperature;
}

void adv_distilled_softmax(adv_model_output_t *output,
                           const double *logits,
                           size_t num_classes,
                           double temperature)
{
    size_t i;
    double sum = 0.0;
    for (i = 0; i < num_classes; i++) {
        output->logits[i] = exp(logits[i] / temperature);
        sum += output->logits[i];
    }
    for (i = 0; i < num_classes; i++)
        output->logits[i] /= (sum > 1e-12) ? sum : 1.0;

    output->num_classes = num_classes;
    output->temperature = temperature;
}

void adv_ensemble_predict(int *prediction,
                          const adv_model_output_t *outputs,
                          size_t num_models)
{
    size_t i, j;
    size_t max_class = outputs[0].num_classes;
    double *votes = (double *)calloc(max_class, sizeof(double));
    if (!votes) { *prediction = -1; return; }

    for (i = 0; i < num_models; i++) {
        size_t best = 0;
        for (j = 1; j < outputs[i].num_classes; j++)
            if (outputs[i].logits[j] > outputs[i].logits[best])
                best = j;
        if (best < max_class) votes[best] += 1.0;
    }

    size_t winner = 0;
    for (j = 1; j < max_class; j++)
        if (votes[j] > votes[winner]) winner = j;

    *prediction = (int)winner;
    free(votes);
}

void adv_adversarial_training_step(double *weights,
                                   const adv_tensor_t *clean_input,
                                   const adv_tensor_t *adv_input,
                                   const adv_attack_config_t *config,
                                   double learning_rate,
                                   size_t num_weights)
{
    size_t i;
    for (i = 0; i < num_weights && i < clean_input->dims && i < adv_input->dims; i++) {
        double combined = 0.5 * clean_input->data[i] + 0.5 * adv_input->data[i];
        weights[i] -= learning_rate * (combined - config->epsilon);
    }
}

int adv_detect_adversarial(const adv_tensor_t *input,
                           double threshold,
                           adv_norm_t norm)
{
    size_t i;
    double variance = 0.0, mean = 0.0;
    for (i = 0; i < input->dims; i++)
        mean += input->data[i];
    mean /= (double)input->dims;
    for (i = 0; i < input->dims; i++) {
        double diff = input->data[i] - mean;
        variance += diff * diff;
    }
    variance /= (double)input->dims;
    (void)threshold; (void)norm;
    return (variance > threshold) ? 1 : 0;
}

double adv_lipschitz_estimate(const double *weights,
                              size_t num_weights,
                              size_t samples)
{
    double max_norm = 0.0;
    size_t i;
    (void)samples;
    for (i = 0; i < num_weights; i++)
        if (fabs(weights[i]) > max_norm) max_norm = fabs(weights[i]);
    return max_norm;
}

const char *adv_attack_name(adv_attack_type_t type)
{
    switch (type) {
        case ADV_ATTACK_FGSM:     return "FGSM";
        case ADV_ATTACK_PGD:      return "PGD";
        case ADV_ATTACK_CW_L2:    return "C&W L2";
        case ADV_ATTACK_CW_LINF:  return "C&W Linf";
        case ADV_ATTACK_PATCH:    return "Adversarial Patch";
        case ADV_ATTACK_PHYSICAL: return "Physical Attack";
        default:                  return "Unknown";
    }
}

const char *adv_defense_name(adv_defense_type_t type)
{
    switch (type) {
        case ADV_DEFENSE_TRAINING:       return "Adversarial Training";
        case ADV_DEFENSE_DISTILLATION:    return "Defensive Distillation";
        case ADV_DEFENSE_INPUT_TRANSFORM: return "Input Transformation";
        case ADV_DEFENSE_FEATURE_SQUEEZE: return "Feature Squeezing";
        case ADV_DEFENSE_ENSEMBLE:        return "Ensemble Defense";
        default:                          return "Unknown";
    }
}

const char *adv_norm_name(adv_norm_t norm)
{
    switch (norm) {
        case ADV_NORM_L1:   return "L1";
        case ADV_NORM_L2:   return "L2";
        case ADV_NORM_LINF: return "Linf";
        default:            return "Unknown";
    }
}
