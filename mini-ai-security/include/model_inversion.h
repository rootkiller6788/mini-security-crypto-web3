#ifndef MODEL_INVERSION_H
#define MODEL_INVERSION_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MI_MAX_DIMS        1024
#define MI_MAX_CLASSES     256
#define MI_EPS_DEFAULT     1.0
#define MI_DELTA_DEFAULT   1e-5

typedef enum {
    MI_ATTACK_INVERSION = 0,
    MI_ATTACK_MEMBERSHIP = 1,
    MI_ATTACK_ATTRIBUTE = 2,
    MI_ATTACK_EXTRACTION = 3,
    MI_ATTACK_GRADIENT_LEAK = 4
} mi_attack_type_t;

typedef enum {
    MI_DEFENSE_DP_SGD = 0,
    MI_DEFENSE_GAUSSIAN_MECH = 1,
    MI_DEFENSE_LAPLACE_MECH = 2,
    MI_DEFENSE_GRADIENT_CLIP = 3,
    MI_DEFENSE_PATE = 4,
    MI_DEFENSE_ADV_REGULARIZE = 5
} mi_defense_type_t;

typedef enum {
    MI_PRIVACY_EPSILON = 0,
    MI_PRIVACY_DELTA = 1,
    MI_PRIVACY_RENYI = 2,
    MI_PRIVACY_ZCDP = 3
} mi_privacy_metric_t;

typedef struct {
    double *values;
    size_t  dims;
} mi_tensor_t;

typedef struct {
    mi_attack_type_t  type;
    double            epsilon;
    double            delta;
    size_t            iterations;
    size_t            batch_size;
    int               confidence_based;
    double            attack_learning_rate;
    int               use_shadow_models;
    size_t            shadow_model_count;
} mi_attack_config_t;

typedef struct {
    mi_defense_type_t  type;
    double             epsilon;
    double             delta;
    double             noise_multiplier;
    double             clip_norm;
    size_t             num_teachers;
    size_t             num_votes;
    double             regularization_weight;
} mi_defense_config_t;

typedef struct {
    double epsilon;
    double delta;
    double privacy_loss;
    double renyi_alpha;
    int    violated;
} mi_privacy_budget_t;

typedef struct {
    double confidence;
    double prediction_entropy;
    double max_probability;
    double gradient_norm;
    int    predicted_label;
    int    is_member;
} mi_membership_result_t;

typedef struct {
    double *sensitive_attrs;
    size_t  num_attrs;
    double  inference_accuracy;
    double  baseline_accuracy;
} mi_attribute_result_t;

typedef struct {
    double *reconstructed;
    size_t  dims;
    double  mse;
    double  ssim;
    size_t  iterations_used;
} mi_inversion_result_t;

mi_tensor_t  mi_tensor_alloc(size_t dims);
void         mi_tensor_free(mi_tensor_t *t);
mi_tensor_t  mi_tensor_clone(const mi_tensor_t *src);
void         mi_tensor_fill(mi_tensor_t *t, double val);
double       mi_tensor_norm(const mi_tensor_t *t);
double       mi_tensor_l1_norm(const mi_tensor_t *t);

mi_attack_config_t  mi_attack_config_default(mi_attack_type_t type);
mi_defense_config_t mi_defense_config_default(mi_defense_type_t type);

void mi_model_inversion_attack(mi_inversion_result_t *result,
                               const mi_tensor_t *target_logits,
                               const mi_tensor_t *model_params,
                               const mi_attack_config_t *config);

void mi_inversion_gradient_step(mi_tensor_t *reconstructed,
                                const mi_tensor_t *gradient,
                                const mi_attack_config_t *config);

double mi_inversion_loss(const mi_tensor_t *reconstructed_logits,
                         const mi_tensor_t *target_logits,
                         const mi_tensor_t *prior);

void mi_membership_inference(mi_membership_result_t *result,
                             const mi_tensor_t *sample,
                             const mi_tensor_t *sample_logits,
                             const mi_tensor_t *shadow_data,
                             size_t num_shadow,
                             const mi_attack_config_t *config);

double mi_membership_score(const mi_tensor_t *logits,
                           int true_label,
                           double threshold);

void mi_shadow_model_train(double *shadow_params,
                           const mi_tensor_t *train_data,
                           size_t train_count,
                           size_t param_count);

void mi_attribute_inference(mi_attribute_result_t *result,
                            const mi_tensor_t *public_attrs,
                            const mi_tensor_t *sensitive_attrs,
                            const mi_tensor_t *model_outputs,
                            size_t num_samples,
                            const mi_attack_config_t *config);

double mi_attribute_correlation(const mi_tensor_t *a,
                                const mi_tensor_t *b);

void mi_model_extraction(double *clone_params,
                         size_t param_count,
                         double (*query_fn)(void *ctx, const mi_tensor_t *input),
                         void *query_ctx,
                         size_t num_queries,
                         const mi_attack_config_t *config);

void mi_extraction_generate_query(mi_tensor_t *query,
                                  const mi_tensor_t *seed,
                                  double exploration_rate);

void mi_gradient_leak_attack(mi_tensor_t *reconstructed,
                             const mi_tensor_t *gradients,
                             const mi_tensor_t *model_params,
                             size_t num_participants,
                             const mi_attack_config_t *config);

int  mi_gradient_leak_detect(const mi_tensor_t *gradients,
                             double threshold,
                             const mi_tensor_t *reference);

void mi_dp_sgd_apply(double *gradients,
                     size_t num_gradients,
                     const mi_defense_config_t *config);

void mi_gaussian_mechanism(double *values,
                           size_t count,
                           double sensitivity,
                           double epsilon,
                           double delta);

void mi_laplace_mechanism(double *values,
                          size_t count,
                          double sensitivity,
                          double epsilon);

void mi_gradient_clipping(double *gradients,
                          size_t count,
                          double clip_norm);

void mi_pate_aggregate(double *output,
                       const double **teacher_votes,
                       size_t num_teachers,
                       size_t num_classes,
                       double threshold,
                       double sigma);

double mi_renyi_divergence(const double *dist_p,
                           const double *dist_q,
                           size_t dims,
                           double alpha);

int  mi_check_privacy_budget(mi_privacy_budget_t *budget,
                             double delta_increment,
                             const mi_defense_config_t *config);

void mi_compute_sensitivity(double *sensitivity,
                            const mi_tensor_t *data,
                            size_t num_samples,
                            double query_radius);

double mi_exact_privacy_loss(const mi_privacy_budget_t *budget);

void mi_differential_privacy_audit(mi_privacy_budget_t *result,
                                   const double *training_losses,
                                   size_t num_iterations,
                                   double epsilon_target);

const char *mi_attack_name(mi_attack_type_t type);
const char *mi_defense_name(mi_defense_type_t type);

#ifdef __cplusplus
}
#endif

#endif
