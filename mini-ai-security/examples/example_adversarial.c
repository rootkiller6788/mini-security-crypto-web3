#include "adversarial_ml.h"
#include "model_inversion.h"
#include "prompt_injection.h"
#include "data_poison.h"
#include "ai_governance.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#define TEST_DIMS     100
#define NUM_SAMPLES   10

static void test_fgsm(void)
{
    adv_tensor_t input, grad, adv;
    double eps = 0.007;

    printf("=== FGSM Adversarial Attack Test ===\n");

    input = adv_tensor_create(TEST_DIMS);
    grad  = adv_tensor_create(TEST_DIMS);
    adv   = adv_tensor_create(TEST_DIMS);

    srand((unsigned)time(NULL));
    for (size_t i = 0; i < TEST_DIMS; i++) {
        input.data[i] = (double)rand() / RAND_MAX;
        grad.data[i]  = ((double)rand() / RAND_MAX - 0.5) * 2.0;
    }

    adv_fgsm_generate(&adv, &input, &grad, eps);

    double pert = adv_perturbation_norm(&input, &adv, ADV_NORM_LINF);
    printf("FGSM perturbation (Linf): %.6f\n", pert);

    int is_adv = adv_detect_adversarial(&adv, 0.01, ADV_NORM_L2);
    printf("Adversarial detected: %s\n", is_adv ? "yes" : "no");

    adv_tensor_free(&input);
    adv_tensor_free(&grad);
    adv_tensor_free(&adv);
    printf("FGSM test passed.\n\n");
}

static void test_pgd(void)
{
    adv_tensor_t input, adv;
    adv_tensor_t grad;
    adv_attack_config_t config;

    printf("=== PGD Adversarial Attack Test ===\n");

    input = adv_tensor_create(TEST_DIMS);
    adv   = adv_tensor_create(TEST_DIMS);
    grad  = adv_tensor_create(TEST_DIMS);

    for (size_t i = 0; i < TEST_DIMS; i++) {
        input.data[i] = 0.5;
        grad.data[i]  = (i % 2 == 0) ? 1.0 : -1.0;
    }

    config = adv_attack_config_default(ADV_ATTACK_PGD);
    config.epsilon    = 0.3;
    config.alpha      = 0.01;
    config.iterations = 10;
    config.norm       = ADV_NORM_LINF;

    adv_pgd_generate(&adv, &input, &grad, &config);

    double pert = adv_perturbation_norm(&input, &adv, ADV_NORM_LINF);
    printf("PGD perturbation (Linf): %.6f (epsilon=%.3f)\n", pert, config.epsilon);
    printf("Attack type: %s\n", adv_attack_name(config.type));
    printf("Defense type: %s\n", adv_defense_name(ADV_DEFENSE_TRAINING));

    adv_tensor_free(&input);
    adv_tensor_free(&adv);
    adv_tensor_free(&grad);
    printf("PGD test passed.\n\n");
}

static void test_input_transform_defense(void)
{
    adv_tensor_t input, defended;
    adv_defense_config_t def_config;

    printf("=== Input Transformation Defense Test ===\n");

    input    = adv_tensor_create(TEST_DIMS);
    defended = adv_tensor_create(TEST_DIMS);

    for (size_t i = 0; i < TEST_DIMS; i++)
        input.data[i] = ((double)rand() / RAND_MAX);

    def_config = adv_defense_config_default(ADV_DEFENSE_INPUT_TRANSFORM);
    def_config.use_gaussian = 1;

    adv_input_transform_defense(&defended, &input, &def_config);

    double diff = adv_perturbation_norm(&input, &defended, ADV_NORM_L2);
    printf("Transformation diff (L2): %.6f\n", diff);

    adv_bit_depth_reduce(&defended, &defended, 6);
    printf("Bit-depth reduced to 6 bits\n");

    adv_tensor_free(&input);
    adv_tensor_free(&defended);
    printf("Input transform defense test passed.\n\n");
}

static void test_distillation(void)
{
    printf("=== Defensive Distillation Test ===\n");

    adv_model_output_t output;
    double logits[10];
    output.logits = (double *)malloc(10 * sizeof(double));

    for (int i = 0; i < 10; i++)
        logits[i] = (double)(i * 10);

    adv_distilled_softmax(&output, logits, 10, 100.0);

    double sum = 0.0;
    for (size_t i = 0; i < output.num_classes; i++)
        sum += output.logits[i];
    printf("Softmax sum: %.6f (temperature=%.1f)\n", sum, output.temperature);

    int prediction;
    adv_ensemble_predict(&prediction, &output, 1);
    printf("Predicted class: %d\n", prediction);

    free(output.logits);
    printf("Distillation test passed.\n\n");
}

static void test_ensemble(void)
{
    printf("=== Ensemble Defense Test ===\n");

    adv_model_output_t outputs[3];
    double logits_a[5] = {0.1, 0.7, 0.1, 0.05, 0.05};
    double logits_b[5] = {0.1, 0.6, 0.2, 0.05, 0.05};
    double logits_c[5] = {0.2, 0.5, 0.2, 0.05, 0.05};

    for (int i = 0; i < 3; i++) {
        outputs[i].logits      = (double *)malloc(5 * sizeof(double));
        outputs[i].num_classes = 5;
        outputs[i].temperature = 1.0;
    }
    memcpy(outputs[0].logits, logits_a, 5 * sizeof(double));
    memcpy(outputs[1].logits, logits_b, 5 * sizeof(double));
    memcpy(outputs[2].logits, logits_c, 5 * sizeof(double));

    int pred;
    adv_ensemble_predict(&pred, outputs, 3);
    printf("Ensemble prediction: %d\n", pred);

    for (int i = 0; i < 3; i++) free(outputs[i].logits);
    printf("Ensemble test passed.\n\n");
}

static void test_adversarial_training(void)
{
    printf("=== Adversarial Training Step Test ===\n");

    double weights[TEST_DIMS];
    adv_tensor_t clean, adv;
    adv_attack_config_t config;

    clean = adv_tensor_create(TEST_DIMS);
    adv   = adv_tensor_create(TEST_DIMS);

    for (size_t i = 0; i < TEST_DIMS; i++) {
        weights[i]      = ((double)rand() / RAND_MAX) * 0.1;
        clean.data[i]   = (double)rand() / RAND_MAX;
        adv.data[i]     = clean.data[i] + 0.01 * ((double)rand() / RAND_MAX - 0.5);
    }

    config = adv_attack_config_default(ADV_ATTACK_FGSM);

    adv_adversarial_training_step(weights, &clean, &adv, &config, 0.001, TEST_DIMS);

    double lip = adv_lipschitz_estimate(weights, TEST_DIMS, 10);
    printf("Lipschitz estimate: %.6f\n", lip);

    adv_tensor_free(&clean);
    adv_tensor_free(&adv);
    printf("Adversarial training test passed.\n\n");
}

int main(void)
{
    printf("mini-ai-security: Adversarial ML Examples\n");
    printf("=========================================\n\n");

    test_fgsm();
    test_pgd();
    test_input_transform_defense();
    test_distillation();
    test_ensemble();
    test_adversarial_training();

    printf("All adversarial ML examples passed.\n");
    return 0;
}
