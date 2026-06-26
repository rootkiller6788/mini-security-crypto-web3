#ifndef ADVERSARIAL_ML_H
#define ADVERSARIAL_ML_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ADV_ML_MAX_DIMS    1024
#define ADV_ML_MAX_CLASSES 256
#define ADV_ML_EPSILON_DEF 0.007f
#define ADV_ML_ALPHA_DEF   0.001f

typedef enum {
    ADV_ATTACK_FGSM = 0,
    ADV_ATTACK_PGD  = 1,
    ADV_ATTACK_CW_L2 = 2,
    ADV_ATTACK_CW_LINF = 3,
    ADV_ATTACK_PATCH = 4,
    ADV_ATTACK_PHYSICAL = 5
} adv_attack_type_t;

typedef enum {
    ADV_DEFENSE_TRAINING = 0,
    ADV_DEFENSE_DISTILLATION = 1,
    ADV_DEFENSE_INPUT_TRANSFORM = 2,
    ADV_DEFENSE_FEATURE_SQUEEZE = 3,
    ADV_DEFENSE_ENSEMBLE = 4
} adv_defense_type_t;

typedef enum {
    ADV_NORM_L1 = 0,
    ADV_NORM_L2 = 1,
    ADV_NORM_LINF = 2
} adv_norm_t;

typedef struct {
    double *data;
    size_t  dims;
    size_t  stride;
} adv_tensor_t;

typedef struct {
    adv_attack_type_t type;
    adv_norm_t        norm;
    double            epsilon;
    double            alpha;
    size_t            iterations;
    size_t            patch_rows;
    size_t            patch_cols;
    int               targeted;
    int               target_class;
    int               random_start;
    double            confidence;
    double            learning_rate;
    size_t            max_iterations;
} adv_attack_config_t;

typedef struct {
    adv_defense_type_t type;
    double             temperature;
    double             epsilon_bound;
    size_t             ensemble_count;
    int                use_gaussian;
    int                use_jpeg_compress;
    int                apply_bit_depth_reduce;
} adv_defense_config_t;

typedef struct {
    double *gradients;
    size_t  num_params;
    double  loss;
    int     predicted_class;
    int     true_class;
} adv_gradient_info_t;

typedef struct {
    double *logits;
    size_t  num_classes;
    double  temperature;
} adv_model_output_t;

adv_tensor_t        adv_tensor_create(size_t dims);
void                adv_tensor_free(adv_tensor_t *t);
adv_tensor_t        adv_tensor_clone(const adv_tensor_t *src);

adv_attack_config_t adv_attack_config_default(adv_attack_type_t type);
adv_defense_config_t adv_defense_config_default(adv_defense_type_t type);

void adv_fgsm_generate(adv_tensor_t *adversarial,
                       const adv_tensor_t *input,
                       const adv_tensor_t *gradient,
                       double epsilon);

void adv_fgsm_targeted(adv_tensor_t *adversarial,
                       const adv_tensor_t *input,
                       const adv_tensor_t *gradient,
                       double epsilon);

void adv_pgd_generate(adv_tensor_t *adversarial,
                      const adv_tensor_t *input,
                      const adv_tensor_t *gradients,
                      const adv_attack_config_t *config);

void adv_pgd_iteration(adv_tensor_t *current,
                       const adv_tensor_t *gradient,
                       double alpha,
                       adv_norm_t norm);

void adv_clip_perturbation(adv_tensor_t *adversarial,
                           const adv_tensor_t *original,
                           double epsilon,
                           adv_norm_t norm);

int  adv_cw_loss(const adv_tensor_t *logits,
                 int target_class,
                 int true_class,
                 adv_norm_t norm,
                 double confidence,
                 double *loss_out);

void adv_patch_apply(adv_tensor_t *image,
                     const adv_tensor_t *patch,
                     size_t row_start,
                     size_t col_start);

void adv_patch_generate(adv_tensor_t *patch,
                        const adv_tensor_t *images,
                        size_t num_images,
                        const adv_attack_config_t *config);

void adv_physical_transform(adv_tensor_t *output,
                            const adv_tensor_t *input,
                            double rotation_deg,
                            double scale_factor,
                            double brightness_delta);

double adv_physical_robustness_score(const adv_tensor_t *original,
                                     const adv_tensor_t *transformed,
                                     adv_norm_t norm);

void adv_input_transform_defense(adv_tensor_t *output,
                                 const adv_tensor_t *input,
                                 const adv_defense_config_t *config);

void adv_bit_depth_reduce(adv_tensor_t *output,
                          const adv_tensor_t *input,
                          int bits);

void adv_median_filter(adv_tensor_t *output,
                       const adv_tensor_t *input,
                       size_t kernel_size);

void adv_gaussian_noise_defense(adv_tensor_t *output,
                                const adv_tensor_t *input,
                                double stddev);

void adv_random_resize_pad(adv_tensor_t *output,
                           const adv_tensor_t *input,
                           size_t min_size,
                           size_t max_size);

double adv_perturbation_norm(const adv_tensor_t *original,
                             const adv_tensor_t *adversarial,
                             adv_norm_t norm);

int  adv_transferability_test(const adv_tensor_t *sample,
                              const adv_tensor_t *adversarial,
                              double *transfer_score);

double adv_distillation_temperature(double logit,
                                    double temperature);

void adv_distilled_softmax(adv_model_output_t *output,
                           const double *logits,
                           size_t num_classes,
                           double temperature);

void adv_ensemble_predict(int *prediction,
                          const adv_model_output_t *outputs,
                          size_t num_models);

void adv_adversarial_training_step(double *weights,
                                   const adv_tensor_t *clean_input,
                                   const adv_tensor_t *adv_input,
                                   const adv_attack_config_t *config,
                                   double learning_rate,
                                   size_t num_weights);

int  adv_detect_adversarial(const adv_tensor_t *input,
                            double threshold,
                            adv_norm_t norm);

double adv_lipschitz_estimate(const double *weights,
                              size_t num_weights,
                              size_t samples);

const char *adv_attack_name(adv_attack_type_t type);
const char *adv_defense_name(adv_defense_type_t type);
const char *adv_norm_name(adv_norm_t norm);

#ifdef __cplusplus
}
#endif

#endif
