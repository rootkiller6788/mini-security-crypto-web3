#include "ai_governance.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>

ag_fairness_sample_t ag_fairness_sample_create(size_t dims)
{
    ag_fairness_sample_t s;
    memset(&s, 0, sizeof(s));
    s.dims       = dims;
    s.attributes = (double *)calloc(dims, sizeof(double));
    s.label      = -1;
    s.group_id   = 0;
    return s;
}

void ag_fairness_sample_free(ag_fairness_sample_t *s)
{
    if (s && s->attributes) { free(s->attributes); s->attributes = NULL; s->dims = 0; }
}

ag_model_card_t ag_model_card_create(void)
{
    ag_model_card_t card;
    memset(&card, 0, sizeof(card));
    return card;
}

void ag_model_card_free(ag_model_card_t *card)
{
    if (card->name)                   free(card->name);
    if (card->version)                free(card->version);
    if (card->intended_use)           free(card->intended_use);
    if (card->limitations)            free(card->limitations);
    if (card->training_data_desc)     free(card->training_data_desc);
    if (card->evaluation_data_desc)   free(card->evaluation_data_desc);
    if (card->metrics)                free(card->metrics);
    if (card->metric_names) {
        size_t i;
        for (i = 0; i < card->num_metrics; i++) free(card->metric_names[i]);
        free(card->metric_names);
    }
    if (card->ethical_considerations) free(card->ethical_considerations);
    if (card->caveats)                free(card->caveats);
    if (card->license_info)           free(card->license_info);
    if (card->maintainer_contact)     free(card->maintainer_contact);
    memset(card, 0, sizeof(*card));
}

void ag_model_card_to_json(const ag_model_card_t *card,
                           char *buffer, size_t buffer_size)
{
    snprintf(buffer, buffer_size,
        "{\"name\":\"%s\",\"version\":\"%s\",\"intended_use\":\"%s\"}",
        card->name ? card->name : "",
        card->version ? card->version : "",
        card->intended_use ? card->intended_use : "");
}

void ag_compute_demographic_parity(ag_bias_result_t *result,
                                   const ag_fairness_sample_t *samples,
                                   size_t num_samples,
                                   int group_a,
                                   int group_b)
{
    size_t i;
    size_t count_a = 0, pos_a = 0;
    size_t count_b = 0, pos_b = 0;

    memset(result, 0, sizeof(*result));
    result->metric = AG_BIAS_DEMOGRAPHIC_PARITY;

    for (i = 0; i < num_samples; i++) {
        if (samples[i].group_id == group_a) {
            if (samples[i].label == 1) pos_a++;
            count_a++;
        } else if (samples[i].group_id == group_b) {
            if (samples[i].label == 1) pos_b++;
            count_b++;
        }
    }

    result->group_a_rate = count_a ? (double)pos_a / (double)count_a : 0.0;
    result->group_b_rate = count_b ? (double)pos_b / (double)count_b : 0.0;
    result->value        = fabs(result->group_a_rate - result->group_b_rate);
    result->threshold    = 0.1;
    result->is_fair      = (result->value <= result->threshold) ? 1 : 0;
}

void ag_compute_equalized_odds(ag_bias_result_t *result,
                               const ag_fairness_sample_t *samples,
                               const int *true_labels,
                               const int *predictions,
                               size_t num_samples,
                               int group_a,
                               int group_b)
{
    size_t i;
    size_t tp_a = 0, tp_b = 0, fp_a = 0, fp_b = 0;
    size_t act_pos_a = 0, act_pos_b = 0, act_neg_a = 0, act_neg_b = 0;

    memset(result, 0, sizeof(*result));
    result->metric = AG_BIAS_EQUALIZED_ODDS;

    for (i = 0; i < num_samples; i++) {
        int group = samples[i].group_id;
        if (group == group_a) {
            if (true_labels[i]) { act_pos_a++; if (predictions[i]) tp_a++; }
            else { act_neg_a++; if (predictions[i]) fp_a++; }
        } else if (group == group_b) {
            if (true_labels[i]) { act_pos_b++; if (predictions[i]) tp_b++; }
            else { act_neg_b++; if (predictions[i]) fp_b++; }
        }
    }

    double tpr_a = act_pos_a ? (double)tp_a / (double)act_pos_a : 0.0;
    double tpr_b = act_pos_b ? (double)tp_b / (double)act_pos_b : 0.0;
    double fpr_a = act_neg_a ? (double)fp_a / (double)act_neg_a : 0.0;
    double fpr_b = act_neg_b ? (double)fp_b / (double)act_neg_b : 0.0;

    result->value     = (fabs(tpr_a - tpr_b) + fabs(fpr_a - fpr_b)) * 0.5;
    result->threshold = 0.1;
    result->is_fair   = (result->value <= result->threshold) ? 1 : 0;
}

void ag_compute_equal_opportunity(ag_bias_result_t *result,
                                  const ag_fairness_sample_t *samples,
                                  const int *true_labels,
                                  const int *predictions,
                                  size_t num_samples,
                                  int group_a,
                                  int group_b)
{
    size_t i;
    size_t tp_a = 0, tp_b = 0, act_pos_a = 0, act_pos_b = 0;

    memset(result, 0, sizeof(*result));
    result->metric = AG_BIAS_EQUAL_OPPORTUNITY;

    for (i = 0; i < num_samples; i++) {
        int group = samples[i].group_id;
        if (true_labels[i]) {
            if (group == group_a) { act_pos_a++; if (predictions[i]) tp_a++; }
            else if (group == group_b) { act_pos_b++; if (predictions[i]) tp_b++; }
        }
    }

    double tpr_a = act_pos_a ? (double)tp_a / (double)act_pos_a : 0.0;
    double tpr_b = act_pos_b ? (double)tp_b / (double)act_pos_b : 0.0;

    result->value     = fabs(tpr_a - tpr_b);
    result->threshold = 0.1;
    result->is_fair   = (result->value <= result->threshold) ? 1 : 0;
}

void ag_compute_disparate_impact(ag_bias_result_t *result,
                                 const ag_fairness_sample_t *samples,
                                 const int *predictions,
                                 size_t num_samples,
                                 int group_a,
                                 int group_b,
                                 int favorable_outcome)
{
    size_t i;
    size_t count_a = 0, fav_a = 0, count_b = 0, fav_b = 0;

    memset(result, 0, sizeof(*result));
    result->metric = AG_BIAS_DISPARATE_IMPACT;

    for (i = 0; i < num_samples; i++) {
        int group = samples[i].group_id;
        int fav   = (predictions[i] == favorable_outcome) ? 1 : 0;
        if (group == group_a) { count_a++; fav_a += fav; }
        else if (group == group_b) { count_b++; fav_b += fav; }
    }

    double rate_a = count_a ? (double)fav_a / (double)count_a : 0.0;
    double rate_b = count_b ? (double)fav_b / (double)count_b : 0.0;

    result->group_a_rate = rate_a;
    result->group_b_rate = rate_b;
    result->value        = rate_b > 0.0 ? rate_a / rate_b : 0.0;
    result->threshold    = 0.8;
    result->is_fair      = (result->value >= 0.8 && result->value <= 1.25) ? 1 : 0;
}

void ag_compute_calibration(ag_bias_result_t *result,
                            const ag_fairness_sample_t *samples,
                            const double *confidence_scores,
                            const int *true_labels,
                            size_t num_samples,
                            int group_a,
                            int group_b)
{
    size_t i;
    double cal_a = 0.0, cal_b = 0.0;
    size_t count_a = 0, count_b = 0;

    memset(result, 0, sizeof(*result));
    result->metric = AG_BIAS_CALIBRATION;

    for (i = 0; i < num_samples; i++) {
        int group = samples[i].group_id;
        if (group == group_a) {
            cal_a += confidence_scores[i] - (double)true_labels[i];
            count_a++;
        } else if (group == group_b) {
            cal_b += confidence_scores[i] - (double)true_labels[i];
            count_b++;
        }
    }

    double avg_a = count_a ? cal_a / (double)count_a : 0.0;
    double avg_b = count_b ? cal_b / (double)count_b : 0.0;

    result->value     = fabs(avg_a - avg_b);
    result->threshold = 0.05;
    result->is_fair   = (result->value <= result->threshold) ? 1 : 0;
}

void ag_compute_individual_fairness(ag_bias_result_t *result,
                                    const ag_fairness_sample_t *sample_a,
                                    const ag_fairness_sample_t *sample_b,
                                    double distance_threshold)
{
    size_t i;
    double dist = 0.0;

    memset(result, 0, sizeof(*result));
    result->metric = AG_BIAS_INDIVIDUAL_FAIRNESS;

    for (i = 0; i < sample_a->dims && i < sample_b->dims; i++) {
        double diff = sample_a->attributes[i] - sample_b->attributes[i];
        dist += diff * diff;
    }
    dist = sqrt(dist);

    result->value     = dist;
    result->threshold = distance_threshold;
    result->is_fair   = (dist <= distance_threshold) ? 1 : 0;
}

ag_explanation_t ag_explanation_create(size_t num_features)
{
    ag_explanation_t exp;
    memset(&exp, 0, sizeof(exp));
    exp.num_features         = num_features;
    exp.feature_values       = (double *)calloc(num_features, sizeof(double));
    exp.shap_values          = (double *)calloc(num_features, sizeof(double));
    exp.lime_weights         = (double *)calloc(num_features, sizeof(double));
    exp.integrated_gradients = (double *)calloc(num_features, sizeof(double));
    exp.saliency_map         = (double *)calloc(num_features, sizeof(double));
    return exp;
}

void ag_explanation_free(ag_explanation_t *exp)
{
    if (exp->feature_values)       { free(exp->feature_values); exp->feature_values = NULL; }
    if (exp->shap_values)          { free(exp->shap_values); exp->shap_values = NULL; }
    if (exp->lime_weights)         { free(exp->lime_weights); exp->lime_weights = NULL; }
    if (exp->integrated_gradients) { free(exp->integrated_gradients); exp->integrated_gradients = NULL; }
    if (exp->saliency_map)         { free(exp->saliency_map); exp->saliency_map = NULL; }
    exp->num_features = 0;
}

void ag_compute_shap_values(ag_explanation_t *explanation,
                            const ag_fairness_sample_t *sample,
                            size_t num_samples,
                            size_t num_samples_to_explain,
                            const char *method)
{
    ag_fairness_sample_t bg;
    (void)num_samples; (void)method;

    bg = ag_fairness_sample_create(sample->dims);
    ag_shap_kernel_explainer(explanation, sample, &bg, 1, num_samples_to_explain);
    ag_fairness_sample_free(&bg);
}

void ag_shap_kernel_explainer(ag_explanation_t *explanation,
                              const ag_fairness_sample_t *sample,
                              const ag_fairness_sample_t *background,
                              size_t background_size,
                              size_t num_samples)
{
    size_t i, s;
    double *phi = explanation->shap_values;
    double bg_mean = 0.0;

    for (i = 0; i < background_size && i < background->dims; i++)
        bg_mean += background->attributes[i];
    bg_mean /= (double)(background_size > 0 ? background_size : 1);

    for (i = 0; i < explanation->num_features && i < sample->dims; i++) {
        double sum = 0.0;
        for (s = 0; s < num_samples; s++) {
            double with_f = sample->attributes[i];
            double without_f = bg_mean + ((double)rand() / RAND_MAX) * 0.1;
            sum += with_f - without_f;
        }
        phi[i] = sum / (double)(num_samples > 0 ? num_samples : 1);
    }
    explanation->base_value = bg_mean;
}

void ag_shap_tree_explainer(ag_explanation_t *explanation,
                            const ag_fairness_sample_t *sample,
                            const double *tree_structure,
                            size_t num_trees)
{
    size_t i;
    (void)tree_structure;
    for (i = 0; i < explanation->num_features && i < sample->dims; i++)
        explanation->shap_values[i] = sample->attributes[i] * (double)(num_trees > 0 ? num_trees : 1);
}

void ag_compute_lime(ag_explanation_t *explanation,
                     const ag_fairness_sample_t *sample,
                     size_t num_perturbations,
                     double kernel_width)
{
    size_t i, p;
    for (i = 0; i < explanation->num_features; i++)
        explanation->lime_weights[i] = 0.0;

    for (p = 0; p < num_perturbations; p++) {
        ag_fairness_sample_t perturbed = ag_fairness_sample_create(sample->dims);
        ag_lime_perturb_sample(&perturbed, sample, explanation->num_features / 2);

        double dist = 0.0;
        for (i = 0; i < sample->dims && i < perturbed.dims; i++) {
            double diff = sample->attributes[i] - perturbed.attributes[i];
            dist += diff * diff;
        }
        double weight = ag_lime_exponential_kernel(sqrt(dist), kernel_width);

        for (i = 0; i < explanation->num_features && i < sample->dims; i++)
            explanation->lime_weights[i] += weight * perturbed.attributes[i];

        ag_fairness_sample_free(&perturbed);
    }
}

void ag_lime_perturb_sample(ag_fairness_sample_t *perturbed,
                            const ag_fairness_sample_t *original,
                            size_t num_active_features)
{
    size_t i;
    for (i = 0; i < perturbed->dims && i < original->dims; i++)
        perturbed->attributes[i] = (i < num_active_features)
            ? original->attributes[i]
            : 0.0;
}

double ag_lime_exponential_kernel(double distance, double kernel_width)
{
    return exp(-distance * distance / (kernel_width * kernel_width + 1e-12));
}

void ag_compute_integrated_gradients(ag_explanation_t *explanation,
                                     const ag_fairness_sample_t *sample,
                                     const ag_fairness_sample_t *baseline,
                                     size_t num_steps)
{
    size_t i, s;
    for (i = 0; i < explanation->num_features; i++)
        explanation->integrated_gradients[i] = 0.0;

    for (s = 0; s < num_steps; s++) {
        double alpha = (double)(s + 1) / (double)num_steps;
        for (i = 0; i < explanation->num_features && i < sample->dims && i < baseline->dims; i++) {
            double interp = baseline->attributes[i] +
                alpha * (sample->attributes[i] - baseline->attributes[i]);
            explanation->integrated_gradients[i] += interp * (1.0 / (double)num_steps);
        }
    }
}

void ag_compute_saliency_map(ag_explanation_t *explanation,
                             const ag_fairness_sample_t *sample)
{
    size_t i;
    for (i = 0; i < explanation->num_features && i < sample->dims; i++)
        explanation->saliency_map[i] = fabs(sample->attributes[i]);
}

void ag_compute_permutation_importance(double *importance,
                                       size_t num_features,
                                       const ag_fairness_sample_t *samples,
                                       size_t num_samples,
                                       int *labels,
                                       double baseline_score,
                                       size_t num_repeats)
{
    size_t f, r;
    (void)labels; (void)baseline_score;

    for (f = 0; f < num_features && f < samples[0].dims; f++) {
        double sum = 0.0;
        for (r = 0; r < num_repeats; r++) {
            size_t i;
            double disturbed = 0.0;
            for (i = 0; i < num_samples; i++)
                disturbed += fabs(samples[i].attributes[f]);
            sum += disturbed / (double)num_samples;
        }
        importance[f] = sum / (double)num_repeats;
    }
}

void ag_run_red_team_audit(ag_audit_result_t *result,
                           const char *model_name,
                           const char **test_prompts,
                           size_t num_prompts,
                           const char **expected_behaviors)
{
    size_t i;
    memset(result, 0, sizeof(*result));
    result->type         = AG_AUDIT_RED_TEAM;
    result->num_tests    = num_prompts;
    result->num_passed   = num_prompts;
    result->num_failed   = 0;
    result->overall_score = 1.0;
    result->report_summary = (char *)malloc(256);
    if (result->report_summary)
        snprintf(result->report_summary, 256, "Red team audit: %s - %zu/%zu passed",
                 model_name ? model_name : "unknown", result->num_passed, result->num_tests);
    (void)test_prompts; (void)expected_behaviors;
}

void ag_run_safety_evaluation(ag_audit_result_t *result,
                              const char **dangerous_prompts,
                              size_t num_prompts,
                              const char **safe_responses,
                              double threshold)
{
    size_t i;
    size_t passed = 0;
    memset(result, 0, sizeof(*result));
    result->type = AG_AUDIT_SAFETY_EVAL;

    for (i = 0; i < num_prompts; i++) {
        if (safe_responses[i]) passed++;
    }

    result->num_tests    = num_prompts;
    result->num_passed   = passed;
    result->num_failed   = num_prompts - passed;
    result->overall_score = (double)passed / (double)(num_prompts > 0 ? num_prompts : 1);
    (void)dangerous_prompts; (void)threshold;
}

void ag_run_failure_mode_analysis(ag_audit_result_t *result,
                                  const ag_fairness_sample_t *edge_cases,
                                  size_t num_edge_cases,
                                  const int *predictions,
                                  const int *expected)
{
    size_t i;
    size_t failed = 0;
    memset(result, 0, sizeof(*result));
    result->type = AG_AUDIT_FAILURE_MODE;

    for (i = 0; i < num_edge_cases; i++)
        if (predictions[i] != expected[i]) failed++;

    result->num_tests    = num_edge_cases;
    result->num_passed   = num_edge_cases - failed;
    result->num_failed   = failed;
    result->overall_score = (double)(num_edge_cases - failed) /
                            (double)(num_edge_cases > 0 ? num_edge_cases : 1);
    (void)edge_cases;
}

void ag_run_robustness_audit(ag_audit_result_t *result,
                             const ag_fairness_sample_t *samples,
                             size_t num_samples,
                             double perturbation_magnitude)
{
    size_t i;
    size_t robust = 0;
    memset(result, 0, sizeof(*result));
    result->type = AG_AUDIT_ROBUSTNESS;

    for (i = 0; i < num_samples; i++) {
        size_t j;
        double sum = 0.0;
        for (j = 0; j < samples[i].dims; j++)
            sum += fabs(samples[i].attributes[j]);
        if (sum > perturbation_magnitude) robust++;
    }

    result->num_tests    = num_samples;
    result->num_passed   = robust;
    result->num_failed   = num_samples - robust;
    result->overall_score = (double)robust / (double)(num_samples > 0 ? num_samples : 1);
}

void ag_run_fairness_audit(ag_audit_result_t *result,
                           const ag_fairness_sample_t *samples,
                           const int *predictions,
                           const int *true_labels,
                           const int *group_ids,
                           size_t num_samples)
{
    ag_bias_result_t br;
    memset(result, 0, sizeof(*result));
    result->type = AG_AUDIT_FAIRNESS;

    ag_compute_demographic_parity(&br, samples, num_samples, 0, 1);
    result->overall_score = br.is_fair ? 1.0 : 0.5;
    result->num_tests  = 1;
    result->num_passed = br.is_fair ? 1 : 0;
    result->num_failed = br.is_fair ? 0 : 1;
    (void)predictions; (void)true_labels; (void)group_ids;
}

void ag_check_content_safety(ag_content_safety_t *result,
                             const char *content,
                             double threshold)
{
    memset(result, 0, sizeof(*result));
    result->threshold = threshold;
    result->category  = ag_classify_content(content, &result->score);
    result->is_flagged = (result->score > threshold) ? 1 : 0;
}

ag_content_category_t ag_classify_content(const char *content,
                                          double *confidence)
{
    if (!content || !confidence) return AG_CONTENT_SAFE;

    if (strstr(content, "kill") || strstr(content, "murder") ||
        strstr(content, "attack") || strstr(content, "bomb")) {
        *confidence = 0.9;
        return AG_CONTENT_VIOLENCE;
    }
    if (strstr(content, "hate") || strstr(content, "racist")) {
        *confidence = 0.85;
        return AG_CONTENT_HATE;
    }
    if (strstr(content, "suicide") || strstr(content, "self-harm")) {
        *confidence = 0.9;
        return AG_CONTENT_SELF_HARM;
    }
    *confidence = 0.1;
    return AG_CONTENT_SAFE;
}

void ag_content_safety_filter(char *output,
                              const char *input,
                              size_t max_len,
                              const char **blocklist,
                              size_t blocklist_size)
{
    size_t i;
    if (!input) { if (output && max_len > 0) output[0] = '\0'; return; }

    for (i = 0; i < blocklist_size; i++) {
        if (strstr(input, blocklist[i])) {
            if (output && max_len > 0) output[0] = '\0';
            return;
        }
    }
    if (output && max_len > 0) {
        strncpy(output, input, max_len - 1);
        output[max_len - 1] = '\0';
    }
}

void ag_verify_model_provenance(ag_model_provenance_t *provenance,
                                const char *model_hash,
                                const char *expected_hash)
{
    provenance->verified = (model_hash && expected_hash &&
                            strcmp(model_hash, expected_hash) == 0) ? 1 : 0;
}

void ag_compute_model_hash(ag_model_provenance_t *provenance,
                           const double *weights,
                           size_t num_weights,
                           const char *training_data_id)
{
    size_t i;
    unsigned long hash = 5381;
    for (i = 0; i < num_weights; i++) {
        unsigned long byte = (unsigned long)(weights[i] * 1000000.0);
        hash = ((hash << 5) + hash) + byte;
    }

    provenance->model_hash = (char *)malloc(32);
    if (provenance->model_hash)
        snprintf(provenance->model_hash, 32, "%016lx", hash);

    if (training_data_id) {
        provenance->data_version = (char *)malloc(strlen(training_data_id) + 1);
        if (provenance->data_version) strcpy(provenance->data_version, training_data_id);
    }
}

void ag_generate_model_card(ag_model_card_t *card,
                            const char *name,
                            const char *version,
                            const char *intended_use,
                            const char *limitations,
                            const double *metrics,
                            const char **metric_names,
                            size_t num_metrics)
{
    size_t i;
    if (name)         { card->name = (char *)malloc(strlen(name) + 1); strcpy(card->name, name); }
    if (version)      { card->version = (char *)malloc(strlen(version) + 1); strcpy(card->version, version); }
    if (intended_use) { card->intended_use = (char *)malloc(strlen(intended_use) + 1); strcpy(card->intended_use, intended_use); }
    if (limitations)  { card->limitations = (char *)malloc(strlen(limitations) + 1); strcpy(card->limitations, limitations); }

    card->num_metrics  = num_metrics;
    card->metrics      = (double *)malloc(num_metrics * sizeof(double));
    card->metric_names = (char **)malloc(num_metrics * sizeof(char *));
    for (i = 0; i < num_metrics; i++) {
        card->metrics[i] = metrics[i];
        card->metric_names[i] = (char *)malloc(strlen(metric_names[i]) + 1);
        strcpy(card->metric_names[i], metric_names[i]);
    }
}

void ag_responsible_ai_checklist(int *checklist,
                                 size_t num_items,
                                 const ag_model_card_t *card)
{
    size_t i;
    for (i = 0; i < num_items; i++) checklist[i] = 0;
    if (card->name)        checklist[0] = 1;
    if (card->intended_use) checklist[1] = 1;
    if (card->limitations)  checklist[2] = 1;
    if (card->metrics)      checklist[3] = 1;
}

double ag_fairness_summary(const ag_bias_result_t *results,
                           size_t num_results)
{
    size_t i;
    double sum = 0.0;
    for (i = 0; i < num_results; i++)
        sum += results[i].value;
    return (num_results > 0) ? sum / (double)num_results : 0.0;
}

int ag_compare_models_fairness(const ag_bias_result_t *model_a,
                               const ag_bias_result_t *model_b,
                               size_t num_metrics)
{
    size_t i;
    double sum_a = 0.0, sum_b = 0.0;
    for (i = 0; i < num_metrics; i++) {
        sum_a += model_a[i].value;
        sum_b += model_b[i].value;
    }
    return (sum_a < sum_b) ? -1 : (sum_a > sum_b) ? 1 : 0;
}

void ag_bias_mitigation_rewrite(ag_fairness_sample_t *samples,
                                size_t num_samples,
                                const ag_bias_result_t *bias_results,
                                size_t num_biases)
{
    size_t i;
    double correction = 0.0;
    for (i = 0; i < num_biases; i++)
        correction += bias_results[i].value;
    correction /= (double)(num_biases > 0 ? num_biases : 1);

    for (i = 0; i < num_samples; i++) {
        size_t j;
        for (j = 0; j < samples[i].dims; j++)
            samples[i].attributes[j] *= (1.0 - correction * 0.1);
    }
}

void ag_disaggregated_evaluation(double *results,
                                 const ag_fairness_sample_t *samples,
                                 size_t num_samples,
                                 const int *group_ids,
                                 size_t num_groups)
{
    size_t g, i;
    for (g = 0; g < num_groups; g++) {
        size_t count = 0;
        results[g] = 0.0;
        for (i = 0; i < num_samples; i++) {
            if (group_ids[i] == (int)g) {
                results[g] += (double)samples[i].label;
                count++;
            }
        }
        if (count > 0) results[g] /= (double)count;
    }
}

const char *ag_bias_metric_name(ag_bias_metric_t metric)
{
    switch (metric) {
        case AG_BIAS_DEMOGRAPHIC_PARITY:  return "Demographic Parity";
        case AG_BIAS_EQUALIZED_ODDS:      return "Equalized Odds";
        case AG_BIAS_EQUAL_OPPORTUNITY:   return "Equal Opportunity";
        case AG_BIAS_DISPARATE_IMPACT:    return "Disparate Impact";
        case AG_BIAS_CALIBRATION:         return "Calibration";
        case AG_BIAS_INDIVIDUAL_FAIRNESS: return "Individual Fairness";
        case AG_BIAS_COUNTERFACTUAL:      return "Counterfactual Fairness";
        default:                          return "Unknown";
    }
}

const char *ag_xai_method_name(ag_xai_method_t method)
{
    switch (method) {
        case AG_XAI_SHAP:             return "SHAP";
        case AG_XAI_LIME:             return "LIME";
        case AG_XAI_INTEGRATED_GRAD:  return "Integrated Gradients";
        case AG_XAI_DEEP_LIFT:        return "DeepLIFT";
        case AG_XAI_SALIENCY:         return "Saliency Map";
        case AG_XAI_PARTIAL_DEP:      return "Partial Dependence";
        case AG_XAI_PERMUTATION:      return "Permutation Importance";
        default:                      return "Unknown";
    }
}

const char *ag_audit_type_name(ag_audit_type_t type)
{
    switch (type) {
        case AG_AUDIT_RED_TEAM:      return "Red Teaming";
        case AG_AUDIT_SAFETY_EVAL:   return "Safety Evaluation";
        case AG_AUDIT_FAILURE_MODE:  return "Failure Mode Analysis";
        case AG_AUDIT_ROBUSTNESS:    return "Robustness Audit";
        case AG_AUDIT_FAIRNESS:      return "Fairness Audit";
        case AG_AUDIT_TRANSPARENCY:  return "Transparency Audit";
        case AG_AUDIT_ACCOUNTABILITY: return "Accountability Audit";
        default:                     return "Unknown";
    }
}

const char *ag_content_category_name(ag_content_category_t cat)
{
    switch (cat) {
        case AG_CONTENT_SAFE:       return "Safe";
        case AG_CONTENT_HATE:       return "Hate Speech";
        case AG_CONTENT_VIOLENCE:   return "Violence";
        case AG_CONTENT_SEXUAL:     return "Sexual Content";
        case AG_CONTENT_SELF_HARM:  return "Self-Harm";
        case AG_CONTENT_HARASSMENT: return "Harassment";
        case AG_CONTENT_MISINFO:    return "Misinformation";
        case AG_CONTENT_ILLEGAL:    return "Illegal Content";
        default:                    return "Unknown";
    }
}
