#include "model_inversion.h"
#include "data_poison.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#define TEST_DIMS     64
#define NUM_SAMPLES   20

static void test_model_inversion(void)
{
    printf("=== Model Inversion Attack Test ===\n");

    mi_tensor_t target_logits = mi_tensor_alloc(TEST_DIMS);
    mi_tensor_t model_params  = mi_tensor_alloc(TEST_DIMS);
    mi_inversion_result_t result;
    mi_attack_config_t config;

    srand((unsigned)time(NULL));

    for (size_t i = 0; i < TEST_DIMS; i++) {
        target_logits.values[i] = (double)(i % 10) / 10.0;
        model_params.values[i]  = ((double)rand() / RAND_MAX) * 0.1;
    }

    config = mi_attack_config_default(MI_ATTACK_INVERSION);
    config.iterations          = 100;
    config.attack_learning_rate = 0.05;

    mi_model_inversion_attack(&result, &target_logits, &model_params, &config);

    printf("Inversion iterations: %zu\n", result.iterations_used);
    printf("Inversion MSE:        %.6f\n", result.mse);

    free(result.reconstructed);
    mi_tensor_free(&target_logits);
    mi_tensor_free(&model_params);
    printf("Model inversion test passed.\n\n");
}

static void test_membership_inference(void)
{
    printf("=== Membership Inference Attack Test ===\n");

    mi_tensor_t sample, logits, shadow;
    mi_membership_result_t result;
    mi_attack_config_t config;

    sample = mi_tensor_alloc(TEST_DIMS);
    logits = mi_tensor_alloc(10);
    shadow = mi_tensor_alloc(TEST_DIMS);

    for (size_t i = 0; i < TEST_DIMS; i++)
        sample.values[i] = (double)rand() / RAND_MAX;

    for (size_t i = 0; i < 10; i++)
        logits.values[i] = (i == 3) ? 0.85 : 0.01;

    config = mi_attack_config_default(MI_ATTACK_MEMBERSHIP);
    config.use_shadow_models = 1;
    config.shadow_model_count = 5;

    mi_membership_inference(&result, &sample, &logits, &shadow, 5, &config);

    printf("Is member:              %s\n", result.is_member ? "yes" : "no");
    printf("Max probability:        %.4f\n", result.max_probability);
    printf("Prediction entropy:     %.6f\n", result.prediction_entropy);
    printf("Membership score:       %.4f\n",
           mi_membership_score(&logits, 3, 0.5));

    mi_tensor_free(&sample);
    mi_tensor_free(&logits);
    mi_tensor_free(&shadow);
    printf("Membership inference test passed.\n\n");
}

static void test_dp_sgd(void)
{
    printf("=== Differential Privacy (DP-SGD) Test ===\n");

    double gradients[TEST_DIMS];
    mi_defense_config_t defense;

    for (size_t i = 0; i < TEST_DIMS; i++)
        gradients[i] = ((double)rand() / RAND_MAX - 0.5) * 10.0;

    defense = mi_defense_config_default(MI_DEFENSE_DP_SGD);
    defense.epsilon       = 1.0;
    defense.delta         = 1e-5;
    defense.clip_norm     = 1.0;
    defense.noise_multiplier = 1.1;

    double norm_before = 0.0;
    for (size_t i = 0; i < TEST_DIMS; i++)
        norm_before += gradients[i] * gradients[i];
    norm_before = sqrt(norm_before);

    mi_dp_sgd_apply(gradients, TEST_DIMS, &defense);

    double norm_after = 0.0;
    for (size_t i = 0; i < TEST_DIMS; i++)
        norm_after += gradients[i] * gradients[i];
    norm_after = sqrt(norm_after);

    printf("Gradient norm before DP: %.6f\n", norm_before);
    printf("Gradient norm after DP:  %.6f\n", norm_after);

    mi_privacy_budget_t budget;
    memset(&budget, 0, sizeof(budget));
    budget.epsilon = 8.0;
    budget.delta   = 1e-5;

    int violated = mi_check_privacy_budget(&budget, 0.01, &defense);
    printf("Privacy budget violated: %s\n", violated ? "yes" : "no");

    printf("DP-SGD test passed.\n\n");
}

static void test_gradient_leak(void)
{
    printf("=== Gradient Leakage in FL Test ===\n");

    mi_tensor_t gradients = mi_tensor_alloc(TEST_DIMS);
    mi_tensor_t params    = mi_tensor_alloc(TEST_DIMS);
    mi_tensor_t reconstructed = mi_tensor_alloc(TEST_DIMS);
    mi_attack_config_t config;

    for (size_t i = 0; i < TEST_DIMS; i++) {
        gradients.values[i] = sin((double)i * 0.1) * 0.5;
        params.values[i]    = 0.1;
    }

    config = mi_attack_config_default(MI_ATTACK_GRADIENT_LEAK);
    mi_gradient_leak_attack(&reconstructed, &gradients, &params, 10, &config);

    int leaked = mi_gradient_leak_detect(&gradients, 0.5, NULL);
    printf("Gradient leak detected: %s\n", leaked ? "yes" : "no");

    mi_tensor_free(&gradients);
    mi_tensor_free(&params);
    mi_tensor_free(&reconstructed);
    printf("Gradient leak test passed.\n\n");
}

static void test_pate(void)
{
    printf("=== PATE (Private Aggregation of Teacher Ensembles) Test ===\n");

    double output[5] = {0};
    double *teacher_votes[3];
    double t0[5] = {0.7, 0.1, 0.1, 0.05, 0.05};
    double t1[5] = {0.6, 0.2, 0.1, 0.05, 0.05};
    double t2[5] = {0.75, 0.1, 0.05, 0.05, 0.05};

    teacher_votes[0] = t0;
    teacher_votes[1] = t1;
    teacher_votes[2] = t2;

    mi_defense_config_t defense = mi_defense_config_default(MI_DEFENSE_PATE);
    defense.num_teachers = 3;
    defense.num_votes    = 2;

    mi_pate_aggregate(output,
                      (const double **)teacher_votes,
                      defense.num_teachers,
                      5, 0.5, 1.0);

    printf("PATE aggregated output:\n");
    for (int i = 0; i < 5; i++)
        printf("  Class %d: %.4f\n", i, output[i]);

    printf("PATE test passed.\n\n");
}

static void test_laplace_mechanism(void)
{
    printf("=== Laplace Mechanism Test ===\n");

    double values[TEST_DIMS];
    for (size_t i = 0; i < TEST_DIMS; i++)
        values[i] = (double)i;

    mi_laplace_mechanism(values, TEST_DIMS, 1.0, 0.5);

    double error = 0.0;
    for (size_t i = 0; i < TEST_DIMS; i++)
        error += fabs(values[i] - (double)i);
    error /= (double)TEST_DIMS;
    printf("Mean absolute error after Laplace: %.6f\n", error);

    printf("Laplace mechanism test passed.\n\n");
}

static void test_privacy_audit(void)
{
    printf("=== Differential Privacy Audit Test ===\n");

    double training_losses[50];
    mi_privacy_budget_t budget;
    for (size_t i = 0; i < 50; i++)
        training_losses[i] = 1.0 - (double)i * 0.01 + ((double)rand() / RAND_MAX - 0.5) * 0.01;

    mi_differential_privacy_audit(&budget, training_losses, 50, 4.0);
    printf("Privacy loss:     %.6f\n", budget.privacy_loss);
    printf("Epsilon target:   %.6f\n", budget.epsilon);
    printf("Budget violated:  %s\n", budget.violated ? "yes" : "no");

    printf("Privacy audit test passed.\n\n");
}

int main(void)
{
    printf("mini-ai-security: Model Inversion & Privacy Examples\n");
    printf("=====================================================\n\n");

    test_model_inversion();
    test_membership_inference();
    test_dp_sgd();
    test_gradient_leak();
    test_pate();
    test_laplace_mechanism();
    test_privacy_audit();

    printf("All model inversion / privacy examples passed.\n");
    return 0;
}
