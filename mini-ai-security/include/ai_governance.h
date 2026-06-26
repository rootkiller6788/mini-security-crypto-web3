#ifndef AI_GOVERNANCE_H
#define AI_GOVERNANCE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AG_MAX_DIMS           1024
#define AG_MAX_FEATURES       256
#define AG_MAX_MODEL_DESC_LEN 4096
#define AG_MAX_SHAP_SAMPLES   2048

typedef enum {
    AG_BIAS_DEMOGRAPHIC_PARITY = 0,
    AG_BIAS_EQUALIZED_ODDS = 1,
    AG_BIAS_EQUAL_OPPORTUNITY = 2,
    AG_BIAS_DISPARATE_IMPACT = 3,
    AG_BIAS_CALIBRATION = 4,
    AG_BIAS_INDIVIDUAL_FAIRNESS = 5,
    AG_BIAS_COUNTERFACTUAL = 6
} ag_bias_metric_t;

typedef enum {
    AG_XAI_SHAP = 0,
    AG_XAI_LIME = 1,
    AG_XAI_INTEGRATED_GRAD = 2,
    AG_XAI_DEEP_LIFT = 3,
    AG_XAI_SALIENCY = 4,
    AG_XAI_PARTIAL_DEP = 5,
    AG_XAI_PERMUTATION = 6
} ag_xai_method_t;

typedef enum {
    AG_AUDIT_RED_TEAM = 0,
    AG_AUDIT_SAFETY_EVAL = 1,
    AG_AUDIT_FAILURE_MODE = 2,
    AG_AUDIT_ROBUSTNESS = 3,
    AG_AUDIT_FAIRNESS = 4,
    AG_AUDIT_TRANSPARENCY = 5,
    AG_AUDIT_ACCOUNTABILITY = 6
} ag_audit_type_t;

typedef enum {
    AG_CONTENT_SAFE = 0,
    AG_CONTENT_HATE = 1,
    AG_CONTENT_VIOLENCE = 2,
    AG_CONTENT_SEXUAL = 3,
    AG_CONTENT_SELF_HARM = 4,
    AG_CONTENT_HARASSMENT = 5,
    AG_CONTENT_MISINFO = 6,
    AG_CONTENT_ILLEGAL = 7
} ag_content_category_t;

typedef struct {
    double *attributes;
    size_t  dims;
    int     label;
    int     group_id;
} ag_fairness_sample_t;

typedef struct {
    double *feature_values;
    double *shap_values;
    double *lime_weights;
    double *integrated_gradients;
    double *saliency_map;
    size_t  num_features;
    double  base_value;
    double  prediction;
} ag_explanation_t;

typedef struct {
    char   *name;
    char   *version;
    char   *intended_use;
    char   *limitations;
    char   *training_data_desc;
    char   *evaluation_data_desc;
    double *metrics;
    size_t num_metrics;
    char   **metric_names;
    char   *ethical_considerations;
    char   *caveats;
    char   *license_info;
    char   *maintainer_contact;
} ag_model_card_t;

typedef struct {
    ag_bias_metric_t metric;
    double           value;
    double           threshold;
    int              is_fair;
    double           group_a_rate;
    double           group_b_rate;
    double           p_value;
} ag_bias_result_t;

typedef struct {
    ag_audit_type_t  type;
    size_t           num_tests;
    size_t           num_passed;
    size_t           num_failed;
    double           critical_failures;
    double           overall_score;
    char             **findings;
    size_t           num_findings;
    char             *report_summary;
} ag_audit_result_t;

typedef struct {
    ag_content_category_t category;
    double                score;
    int                   is_flagged;
    double                threshold;
    char                  *explanation;
} ag_content_safety_t;

typedef struct {
    char   *model_hash;
    char   *training_hash;
    char   *code_hash;
    char   *data_version;
    char   *timestamp;
    int     verified;
} ag_model_provenance_t;

ag_fairness_sample_t ag_fairness_sample_create(size_t dims);
void                 ag_fairness_sample_free(ag_fairness_sample_t *s);

ag_model_card_t ag_model_card_create(void);
void            ag_model_card_free(ag_model_card_t *card);
void            ag_model_card_to_json(const ag_model_card_t *card,
                                     char *buffer, size_t buffer_size);

void ag_compute_demographic_parity(ag_bias_result_t *result,
                                   const ag_fairness_sample_t *samples,
                                   size_t num_samples,
                                   int group_a,
                                   int group_b);

void ag_compute_equalized_odds(ag_bias_result_t *result,
                               const ag_fairness_sample_t *samples,
                               const int *true_labels,
                               const int *predictions,
                               size_t num_samples,
                               int group_a,
                               int group_b);

void ag_compute_equal_opportunity(ag_bias_result_t *result,
                                  const ag_fairness_sample_t *samples,
                                  const int *true_labels,
                                  const int *predictions,
                                  size_t num_samples,
                                  int group_a,
                                  int group_b);

void ag_compute_disparate_impact(ag_bias_result_t *result,
                                 const ag_fairness_sample_t *samples,
                                 const int *predictions,
                                 size_t num_samples,
                                 int group_a,
                                 int group_b,
                                 int favorable_outcome);

void ag_compute_calibration(ag_bias_result_t *result,
                            const ag_fairness_sample_t *samples,
                            const double *confidence_scores,
                            const int *true_labels,
                            size_t num_samples,
                            int group_a,
                            int group_b);

void ag_compute_individual_fairness(ag_bias_result_t *result,
                                    const ag_fairness_sample_t *sample_a,
                                    const ag_fairness_sample_t *sample_b,
                                    double distance_threshold);

ag_explanation_t ag_explanation_create(size_t num_features);
void             ag_explanation_free(ag_explanation_t *exp);

void ag_compute_shap_values(ag_explanation_t *explanation,
                            const ag_fairness_sample_t *sample,
                            size_t num_samples,
                            size_t num_samples_to_explain,
                            const char *method);

void ag_shap_kernel_explainer(ag_explanation_t *explanation,
                              const ag_fairness_sample_t *sample,
                              const ag_fairness_sample_t *background,
                              size_t background_size,
                              size_t num_samples);

void ag_shap_tree_explainer(ag_explanation_t *explanation,
                            const ag_fairness_sample_t *sample,
                            const double *tree_structure,
                            size_t num_trees);

void ag_compute_lime(ag_explanation_t *explanation,
                     const ag_fairness_sample_t *sample,
                     size_t num_perturbations,
                     double kernel_width);

void ag_lime_perturb_sample(ag_fairness_sample_t *perturbed,
                            const ag_fairness_sample_t *original,
                            size_t num_active_features);

double ag_lime_exponential_kernel(double distance, double kernel_width);

void ag_compute_integrated_gradients(ag_explanation_t *explanation,
                                     const ag_fairness_sample_t *sample,
                                     const ag_fairness_sample_t *baseline,
                                     size_t num_steps);

void ag_compute_saliency_map(ag_explanation_t *explanation,
                             const ag_fairness_sample_t *sample);

void ag_compute_permutation_importance(double *importance,
                                       size_t num_features,
                                       const ag_fairness_sample_t *samples,
                                       size_t num_samples,
                                       int *labels,
                                       double baseline_score,
                                       size_t num_repeats);

void ag_run_red_team_audit(ag_audit_result_t *result,
                           const char *model_name,
                           const char **test_prompts,
                           size_t num_prompts,
                           const char **expected_behaviors);

void ag_run_safety_evaluation(ag_audit_result_t *result,
                              const char **dangerous_prompts,
                              size_t num_prompts,
                              const char **safe_responses,
                              double threshold);

void ag_run_failure_mode_analysis(ag_audit_result_t *result,
                                  const ag_fairness_sample_t *edge_cases,
                                  size_t num_edge_cases,
                                  const int *predictions,
                                  const int *expected);

void ag_run_robustness_audit(ag_audit_result_t *result,
                             const ag_fairness_sample_t *samples,
                             size_t num_samples,
                             double perturbation_magnitude);

void ag_run_fairness_audit(ag_audit_result_t *result,
                           const ag_fairness_sample_t *samples,
                           const int *predictions,
                           const int *true_labels,
                           const int *group_ids,
                           size_t num_samples);

void ag_check_content_safety(ag_content_safety_t *result,
                             const char *content,
                             double threshold);

ag_content_category_t ag_classify_content(const char *content,
                                          double *confidence);

void ag_content_safety_filter(char *output,
                              const char *input,
                              size_t max_len,
                              const char **blocklist,
                              size_t blocklist_size);

void ag_verify_model_provenance(ag_model_provenance_t *provenance,
                                const char *model_hash,
                                const char *expected_hash);

void ag_compute_model_hash(ag_model_provenance_t *provenance,
                           const double *weights,
                           size_t num_weights,
                           const char *training_data_id);

void ag_generate_model_card(ag_model_card_t *card,
                            const char *name,
                            const char *version,
                            const char *intended_use,
                            const char *limitations,
                            const double *metrics,
                            const char **metric_names,
                            size_t num_metrics);

void ag_responsible_ai_checklist(int *checklist,
                                 size_t num_items,
                                 const ag_model_card_t *card);

double ag_fairness_summary(const ag_bias_result_t *results,
                           size_t num_results);

int  ag_compare_models_fairness(const ag_bias_result_t *model_a,
                                const ag_bias_result_t *model_b,
                                size_t num_metrics);

void ag_bias_mitigation_rewrite(ag_fairness_sample_t *samples,
                                size_t num_samples,
                                const ag_bias_result_t *bias_results,
                                size_t num_biases);

void ag_disaggregated_evaluation(double *results,
                                 const ag_fairness_sample_t *samples,
                                 size_t num_samples,
                                 const int *group_ids,
                                 size_t num_groups);

const char *ag_bias_metric_name(ag_bias_metric_t metric);
const char *ag_xai_method_name(ag_xai_method_t method);
const char *ag_audit_type_name(ag_audit_type_t type);
const char *ag_content_category_name(ag_content_category_t cat);

#ifdef __cplusplus
}
#endif

#endif
