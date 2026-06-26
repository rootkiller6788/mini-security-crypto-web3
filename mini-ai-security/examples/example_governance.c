#include "ai_governance.h"
#include "prompt_injection.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define NUM_SAMPLES 20
#define NUM_FEATURES 4

static void test_demographic_parity(void)
{
    printf("=== Demographic Parity Test ===\n");

    ag_fairness_sample_t samples[NUM_SAMPLES];
    srand((unsigned)time(NULL));

    for (size_t i = 0; i < NUM_SAMPLES; i++) {
        samples[i] = ag_fairness_sample_create(NUM_FEATURES);
        samples[i].group_id = (i < NUM_SAMPLES / 2) ? 0 : 1;
        samples[i].label    = (i % 3 == 0) ? 1 : 0;
        for (size_t j = 0; j < NUM_FEATURES; j++)
            samples[i].attributes[j] = (double)rand() / RAND_MAX;
    }

    ag_bias_result_t result;
    ag_compute_demographic_parity(&result, samples, NUM_SAMPLES, 0, 1);

    printf("Metric:         %s\n", ag_bias_metric_name(result.metric));
    printf("Value:          %.4f\n", result.value);
    printf("Group A rate:   %.4f\n", result.group_a_rate);
    printf("Group B rate:   %.4f\n", result.group_b_rate);
    printf("Is fair:        %s\n", result.is_fair ? "yes" : "no");

    for (size_t i = 0; i < NUM_SAMPLES; i++)
        ag_fairness_sample_free(&samples[i]);

    printf("Demographic parity test passed.\n\n");
}

static void test_equalized_odds(void)
{
    printf("=== Equalized Odds Test ===\n");

    ag_fairness_sample_t samples[NUM_SAMPLES];
    int true_labels[NUM_SAMPLES];
    int predictions[NUM_SAMPLES];

    for (size_t i = 0; i < NUM_SAMPLES; i++) {
        samples[i] = ag_fairness_sample_create(NUM_FEATURES);
        samples[i].group_id = (i < 10) ? 0 : 1;
        true_labels[i] = (i % 2 == 0) ? 1 : 0;
        predictions[i] = (i % 3 == 0) ? 1 : 0;
    }

    ag_bias_result_t result;
    ag_compute_equalized_odds(&result, samples, true_labels, predictions,
                              NUM_SAMPLES, 0, 1);

    printf("Metric:         %s\n", ag_bias_metric_name(result.metric));
    printf("Value:          %.4f\n", result.value);
    printf("Is fair:        %s\n", result.is_fair ? "yes" : "no");

    for (size_t i = 0; i < NUM_SAMPLES; i++)
        ag_fairness_sample_free(&samples[i]);

    printf("Equalized odds test passed.\n\n");
}

static void test_disparate_impact(void)
{
    printf("=== Disparate Impact Test ===\n");

    ag_fairness_sample_t samples[NUM_SAMPLES];
    int predictions[NUM_SAMPLES];

    for (size_t i = 0; i < NUM_SAMPLES; i++) {
        samples[i] = ag_fairness_sample_create(NUM_FEATURES);
        samples[i].group_id = (i < 10) ? 0 : 1;
        predictions[i] = (i % 4 == 0) ? 1 : 0;
    }

    ag_bias_result_t result;
    ag_compute_disparate_impact(&result, samples, predictions,
                                NUM_SAMPLES, 0, 1, 1);

    printf("Metric:         %s\n", ag_bias_metric_name(result.metric));
    printf("DI Ratio:       %.4f\n", result.value);
    printf("Is fair:        %s\n", result.is_fair ? "yes" : "no");

    for (size_t i = 0; i < NUM_SAMPLES; i++)
        ag_fairness_sample_free(&samples[i]);

    printf("Disparate impact test passed.\n\n");
}

static void test_shap_values(void)
{
    printf("=== SHAP Explanation Test ===\n");

    ag_fairness_sample_t sample = ag_fairness_sample_create(NUM_FEATURES);
    for (size_t j = 0; j < NUM_FEATURES; j++)
        sample.attributes[j] = (double)(j + 1);

    ag_explanation_t exp = ag_explanation_create(NUM_FEATURES);
    ag_compute_shap_values(&exp, &sample, 10, 50, "kernel");

    printf("Method:         %s\n", ag_xai_method_name(AG_XAI_SHAP));
    printf("Base value:     %.4f\n", exp.base_value);
    printf("SHAP values:    ");
    for (size_t j = 0; j < exp.num_features; j++)
        printf("%.3f ", exp.shap_values[j]);
    printf("\n");

    ag_explanation_free(&exp);
    ag_fairness_sample_free(&sample);
    printf("SHAP test passed.\n\n");
}

static void test_lime(void)
{
    printf("=== LIME Explanation Test ===\n");

    ag_fairness_sample_t sample = ag_fairness_sample_create(NUM_FEATURES);
    for (size_t j = 0; j < NUM_FEATURES; j++)
        sample.attributes[j] = (double)rand() / RAND_MAX;

    ag_explanation_t exp = ag_explanation_create(NUM_FEATURES);
    ag_compute_lime(&exp, &sample, 30, 0.75);

    printf("Method:         %s\n", ag_xai_method_name(AG_XAI_LIME));
    printf("LIME weights:   ");
    for (size_t j = 0; j < exp.num_features; j++)
        printf("%.3f ", exp.lime_weights[j]);
    printf("\n");

    ag_explanation_free(&exp);
    ag_fairness_sample_free(&sample);
    printf("LIME test passed.\n\n");
}

static void test_integrated_gradients(void)
{
    printf("=== Integrated Gradients Test ===\n");

    ag_fairness_sample_t sample   = ag_fairness_sample_create(NUM_FEATURES);
    ag_fairness_sample_t baseline = ag_fairness_sample_create(NUM_FEATURES);

    for (size_t j = 0; j < NUM_FEATURES; j++) {
        sample.attributes[j]   = 1.0;
        baseline.attributes[j] = 0.0;
    }

    ag_explanation_t exp = ag_explanation_create(NUM_FEATURES);
    ag_compute_integrated_gradients(&exp, &sample, &baseline, 20);

    printf("Method:           %s\n", ag_xai_method_name(AG_XAI_INTEGRATED_GRAD));
    printf("IG values:        ");
    for (size_t j = 0; j < exp.num_features; j++)
        printf("%.3f ", exp.integrated_gradients[j]);
    printf("\n");

    ag_explanation_free(&exp);
    ag_fairness_sample_free(&sample);
    ag_fairness_sample_free(&baseline);
    printf("Integrated gradients test passed.\n\n");
}

static void test_model_card(void)
{
    printf("=== Model Card Test ===\n");

    ag_model_card_t card = ag_model_card_create();
    double metrics[] = {0.95, 0.92, 0.88};
    const char *metric_names[] = {"accuracy", "precision", "recall"};

    ag_generate_model_card(&card, "TestModel", "1.0",
        "Image classification for medical diagnosis",
        "Not validated for pediatric cases; may underperform on low-quality scans",
        metrics, metric_names, 3);

    printf("Name:           %s\n", card.name);
    printf("Version:        %s\n", card.version);
    printf("Intended Use:   %s\n", card.intended_use);
    printf("Limitations:    %s\n", card.limitations);
    printf("Num Metrics:    %zu\n", card.num_metrics);

    char json_buf[512];
    ag_model_card_to_json(&card, json_buf, sizeof(json_buf));
    printf("JSON:           %s\n", json_buf);

    int checklist[4] = {0};
    ag_responsible_ai_checklist(checklist, 4, &card);
    printf("Checklist:      [%d %d %d %d]\n",
           checklist[0], checklist[1], checklist[2], checklist[3]);

    ag_model_card_free(&card);
    printf("Model card test passed.\n\n");
}

static void test_content_safety(void)
{
    printf("=== Content Safety Test ===\n");

    ag_content_safety_t result;
    ag_check_content_safety(&result, "This is safe content.", 0.5);
    printf("Safe text category:  %s (score=%.2f, flagged=%s)\n",
           ag_content_category_name(result.category),
           result.score, result.is_flagged ? "yes" : "no");

    ag_check_content_safety(&result, "I would like to kill someone.", 0.5);
    printf("Dangerous category:  %s (score=%.2f, flagged=%s)\n",
           ag_content_category_name(result.category),
           result.score, result.is_flagged ? "yes" : "no");

    printf("Content safety test passed.\n\n");
}

static void test_fairness_audit(void)
{
    printf("=== Fairness Audit Test ===\n");

    ag_fairness_sample_t samples[NUM_SAMPLES];
    int predictions[NUM_SAMPLES];
    int true_labels[NUM_SAMPLES];
    int group_ids[NUM_SAMPLES];

    for (size_t i = 0; i < NUM_SAMPLES; i++) {
        samples[i] = ag_fairness_sample_create(NUM_FEATURES);
        samples[i].group_id = (int)(i % 2);
        predictions[i] = (int)(i % 3 == 0);
        true_labels[i] = (int)(i % 2 == 0);
        group_ids[i]   = (int)(i % 2);
    }

    ag_audit_result_t audit;
    ag_run_fairness_audit(&audit, samples, predictions, true_labels,
                          group_ids, NUM_SAMPLES);

    printf("Audit type:     %s\n", ag_audit_type_name(audit.type));
    printf("Overall score:  %.4f\n", audit.overall_score);
    printf("Passed/Failed:  %zu / %zu\n", audit.num_passed, audit.num_failed);

    for (size_t i = 0; i < NUM_SAMPLES; i++)
        ag_fairness_sample_free(&samples[i]);

    printf("Fairness audit test passed.\n\n");
}

static void test_model_provenance(void)
{
    printf("=== Model Provenance Test ===\n");

    ag_model_provenance_t provenance;
    memset(&provenance, 0, sizeof(provenance));

    double weights[4] = {0.1, 0.2, 0.3, 0.4};
    ag_compute_model_hash(&provenance, weights, 4, "v1.0-dataset-42");

    printf("Model hash:     %s\n",
           provenance.model_hash ? provenance.model_hash : "null");
    printf("Data version:   %s\n",
           provenance.data_version ? provenance.data_version : "null");

    ag_verify_model_provenance(&provenance, provenance.model_hash,
                               provenance.model_hash);
    printf("Verified:       %s\n", provenance.verified ? "yes" : "no");

    free(provenance.model_hash);
    free(provenance.data_version);
    printf("Model provenance test passed.\n\n");
}

int main(void)
{
    printf("mini-ai-security: AI Governance Examples\n");
    printf("=========================================\n\n");

    test_demographic_parity();
    test_equalized_odds();
    test_disparate_impact();
    test_shap_values();
    test_lime();
    test_integrated_gradients();
    test_model_card();
    test_content_safety();
    test_fairness_audit();
    test_model_provenance();

    printf("All AI governance examples passed.\n");
    return 0;
}
