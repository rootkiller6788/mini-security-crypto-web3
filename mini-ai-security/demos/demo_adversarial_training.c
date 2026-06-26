#include "adversarial_ml.h"
#include "model_inversion.h"
#include "prompt_injection.h"
#include "data_poison.h"
#include "ai_governance.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#define IMG_DIMS      256
#define NUM_CLASSES   10
#define BATCH_SIZE    8
#define EPOCHS        3
#define NUM_ATTACKS   4

typedef struct {
    adv_tensor_t image;
    int          label;
} demo_sample_t;

static demo_sample_t *create_dataset(size_t num_samples)
{
    demo_sample_t *data = (demo_sample_t *)malloc(num_samples * sizeof(demo_sample_t));
    srand((unsigned)time(NULL));

    for (size_t i = 0; i < num_samples; i++) {
        data[i].image = adv_tensor_create(IMG_DIMS);
        data[i].label = (int)(i % NUM_CLASSES);
        for (size_t j = 0; j < IMG_DIMS; j++)
            data[i].image.data[j] = (double)rand() / RAND_MAX;
    }
    return data;
}

static void free_dataset(demo_sample_t *data, size_t num_samples)
{
    for (size_t i = 0; i < num_samples; i++)
        adv_tensor_free(&data[i].image);
    free(data);
}

static void generate_gradient(adv_tensor_t *grad,
                              const adv_tensor_t *input,
                              int label)
{
    for (size_t i = 0; i < input->dims && i < grad->dims; i++)
        grad->data[i] = (input->data[i] - 0.5) * (double)(label + 1) * 0.1;
}

static double compute_accuracy(const adv_tensor_t *sample, int label)
{
    double sum = 0.0;
    for (size_t i = 0; i < sample->dims; i++)
        sum += sample->data[i];
    double avg = sum / (double)sample->dims;
    int pred  = (int)(avg * (double)NUM_CLASSES) % NUM_CLASSES;
    return (pred == label) ? 1.0 : 0.0;
}

static void print_attack_comparison(const char *name,
                                     const adv_tensor_t *original,
                                     const adv_tensor_t *adversarial,
                                     int original_acc,
                                     int adv_acc)
{
    double l0 = adv_perturbation_norm(original, adversarial, ADV_NORM_L1);
    double l2 = adv_perturbation_norm(original, adversarial, ADV_NORM_L2);
    double li = adv_perturbation_norm(original, adversarial, ADV_NORM_LINF);

    printf("  %-18s | L1:%.4f L2:%.4f Linf:%.4f | Orig acc:%d Adv acc:%d\n",
           name, l0, l2, li, original_acc, adv_acc);
}

static void demo_fgsm_attack(demo_sample_t *samples, size_t num_samples)
{
    printf("\n--- FGSM Attack Demo ---\n");

    size_t success_count = 0;
    adv_tensor_t adv = adv_tensor_create(IMG_DIMS);
    adv_tensor_t grad = adv_tensor_create(IMG_DIMS);

    for (size_t i = 0; i < num_samples; i++) {
        generate_gradient(&grad, &samples[i].image, samples[i].label);
        adv_fgsm_generate(&adv, &samples[i].image, &grad, 0.03);
        int orig_correct = (compute_accuracy(&samples[i].image, samples[i].label) > 0.5);
        int adv_correct  = (compute_accuracy(&adv, samples[i].label) > 0.5);
        if (orig_correct && !adv_correct) success_count++;
    }

    print_attack_comparison("FGSM", &samples[0].image, &adv,
        (int)compute_accuracy(&samples[0].image, samples[0].label),
        (int)compute_accuracy(&adv, samples[0].label));
    printf("  FGSM attack success rate: %.1f%%\n",
           100.0 * (double)success_count / (double)num_samples);

    adv_tensor_free(&adv);
    adv_tensor_free(&grad);
}

static void demo_pgd_attack(demo_sample_t *samples, size_t num_samples)
{
    printf("\n--- PGD Attack Demo ---\n");

    adv_attack_config_t config = adv_attack_config_default(ADV_ATTACK_PGD);
    config.epsilon    = 0.3;
    config.alpha      = 0.01;
    config.iterations = 20;
    config.random_start = 1;

    adv_tensor_t adv  = adv_tensor_create(IMG_DIMS);
    adv_tensor_t grad = adv_tensor_create(IMG_DIMS);

    generate_gradient(&grad, &samples[0].image, samples[0].label);
    adv_pgd_generate(&adv, &samples[0].image, &grad, &config);

    print_attack_comparison("PGD", &samples[0].image, &adv,
        (int)compute_accuracy(&samples[0].image, samples[0].label),
        (int)compute_accuracy(&adv, samples[0].label));

    double robust_count = 0;
    for (size_t i = 0; i < num_samples; i++) {
        generate_gradient(&grad, &samples[i].image, samples[i].label);
        adv_pgd_generate(&adv, &samples[i].image, &grad, &config);
        if (compute_accuracy(&adv, samples[i].label) > 0.5) robust_count++;
    }
    printf("  PGD robust accuracy: %.1f%%\n",
           100.0 * robust_count / (double)num_samples);

    adv_tensor_free(&adv);
    adv_tensor_free(&grad);
}

static void demo_cw_attack(demo_sample_t *samples, size_t num_samples)
{
    printf("\n--- C&W Attack Overview Demo ---\n");

    adv_attack_config_t config = adv_attack_config_default(ADV_ATTACK_CW_L2);
    config.confidence     = 5.0;
    config.target_class   = 7;
    config.targeted       = 1;
    config.max_iterations = 500;

    adv_tensor_t logits = adv_tensor_create(NUM_CLASSES);
    for (size_t i = 0; i < NUM_CLASSES; i++)
        logits.data[i] = (i == 3) ? 0.9 : 0.01;

    double loss;
    int ret = adv_cw_loss(&logits, config.target_class, 3, ADV_NORM_L2,
                          config.confidence, &loss);
    printf("  C&W Loss: %.6f (target class %d, true class %d, return=%d)\n",
           loss, config.target_class, 3, ret);

    adv_tensor_free(&logits);
    (void)samples; (void)num_samples;
}

static void demo_defense_training(demo_sample_t *samples, size_t num_samples)
{
    printf("\n--- Adversarial Training Defense Demo ---\n");

    double weights[IMG_DIMS];
    adv_tensor_t adv_sample = adv_tensor_create(IMG_DIMS);
    adv_attack_config_t atk_config = adv_attack_config_default(ADV_ATTACK_FGSM);
    adv_defense_config_t def_config = adv_defense_config_default(ADV_DEFENSE_TRAINING);

    double acc_before = 0.0, acc_after = 0.0;

    for (size_t i = 0; i < IMG_DIMS; i++)
        weights[i] = ((double)rand() / RAND_MAX - 0.5) * 0.01;

    for (size_t i = 0; i < num_samples / 2; i++)
        acc_before += compute_accuracy(&samples[i].image, samples[i].label);
    acc_before /= (num_samples > 0 ? (double)(num_samples / 2) : 1.0);

    for (size_t epoch = 0; epoch < EPOCHS; epoch++) {
        for (size_t s = 0; s < num_samples; s++) {
            adv_tensor_t grad = adv_tensor_create(IMG_DIMS);
            generate_gradient(&grad, &samples[s].image, samples[s].label);
            adv_fgsm_generate(&adv_sample, &samples[s].image, &grad, 0.01);
            adv_adversarial_training_step(weights, &samples[s].image,
                                          &adv_sample, &atk_config, 0.001, IMG_DIMS);
            adv_tensor_free(&grad);
        }
    }

    for (size_t i = 0; i < num_samples / 2; i++)
        acc_after += compute_accuracy(&samples[i].image, samples[i].label);
    acc_after /= (num_samples > 0 ? (double)(num_samples / 2) : 1.0);

    printf("  Defense: %s\n", adv_defense_name(def_config.type));
    printf("  Clean accuracy before: %.4f\n", acc_before);
    printf("  Clean accuracy after:  %.4f\n", acc_after);

    double lip = adv_lipschitz_estimate(weights, IMG_DIMS, 100);
    printf("  Lipschitz constant estimate: %.6f\n", lip);

    adv_tensor_free(&adv_sample);
}

static void demo_defensive_distillation(void)
{
    printf("\n--- Defensive Distillation Demo ---\n");

    double logits[NUM_CLASSES] = {0.05, 0.05, 0.05, 0.05, 0.05,
                                   0.05, 0.05, 0.05, 0.55, 0.05};
    adv_model_output_t output;
    output.logits = (double *)malloc(NUM_CLASSES * sizeof(double));

    double temps[] = {1.0, 10.0, 50.0, 100.0};
    for (size_t t = 0; t < 4; t++) {
        adv_distilled_softmax(&output, logits, NUM_CLASSES, temps[t]);
        printf("  Temperature %.1f: max_prob=%.4f entropy=%.4f\n",
               temps[t], output.logits[8],
               -output.logits[8] * log(output.logits[8] + 1e-12));
    }

    free(output.logits);
}

static void demo_input_transform_defenses(demo_sample_t *samples, size_t num_samples)
{
    printf("\n--- Input Transformation Defenses Demo ---\n");

    adv_tensor_t transformed = adv_tensor_create(IMG_DIMS);
    (void)num_samples;

    adv_defense_config_t def = adv_defense_config_default(ADV_DEFENSE_INPUT_TRANSFORM);

    double sum_before = 0.0, sum_after = 0.0;
    for (size_t i = 0; i < IMG_DIMS; i++)
        sum_before += samples[0].image.data[i];

    adv_input_transform_defense(&transformed, &samples[0].image, &def);
    for (size_t i = 0; i < IMG_DIMS; i++)
        sum_after += transformed.data[i];

    printf("  Input mean before:  %.6f\n", sum_before / IMG_DIMS);
    printf("  Input mean after:   %.6f\n", sum_after / IMG_DIMS);

    adv_median_filter(&transformed, &samples[0].image, 3);
    printf("  Median filter (3x3) applied\n");

    adv_bit_depth_reduce(&transformed, &samples[0].image, 4);
    printf("  Bit depth reduced to 4 bits\n");

    int is_adversarial = adv_detect_adversarial(&samples[0].image, 0.1, ADV_NORM_L2);
    printf("  Adversarial detection: %s\n", is_adversarial ? "flagged" : "clean");

    adv_tensor_free(&transformed);
}

static void demo_transferability(demo_sample_t *samples, size_t num_samples)
{
    printf("\n--- Adversarial Transferability Demo ---\n");

    adv_tensor_t adv_a = adv_tensor_create(IMG_DIMS);
    adv_tensor_t adv_b = adv_tensor_create(IMG_DIMS);
    adv_tensor_t grad = adv_tensor_create(IMG_DIMS);

    generate_gradient(&grad, &samples[0].image, samples[0].label);
    adv_fgsm_generate(&adv_a, &samples[0].image, &grad, 0.02);

    generate_gradient(&grad, &samples[1].image, samples[1].label);
    adv_fgsm_generate(&adv_b, &samples[1].image, &grad, 0.02);

    double transfer_score;
    adv_transferability_test(&adv_a, &adv_b, &transfer_score);
    printf("  Transferability score (A->B): %.6f\n", transfer_score);

    (void)num_samples;
    adv_tensor_free(&adv_a);
    adv_tensor_free(&adv_b);
    adv_tensor_free(&grad);
}

static void demo_physical_attacks(void)
{
    printf("\n--- Physical Attack Simulation Demo ---\n");

    adv_tensor_t original  = adv_tensor_create(IMG_DIMS);
    adv_tensor_t transformed = adv_tensor_create(IMG_DIMS);

    for (size_t i = 0; i < IMG_DIMS; i++)
        original.data[i] = (double)(i % 256) / 256.0;

    double rotations[] = {5.0, 10.0, 15.0, 90.0};
    for (size_t r = 0; r < 4; r++) {
        adv_physical_transform(&transformed, &original,
                               rotations[r], 0.95, 0.02);
        double score = adv_physical_robustness_score(&original, &transformed,
                                                     ADV_NORM_L2);
        printf("  Rotation %.0f deg: robustness=%.4f\n",
               rotations[r], score);
    }

    adv_tensor_free(&original);
    adv_tensor_free(&transformed);
}

static void demo_defense_summary(void)
{
    printf("\n--- Defense Strategy Summary ---\n");

    adv_defense_type_t defenses[] = {
        ADV_DEFENSE_TRAINING,
        ADV_DEFENSE_DISTILLATION,
        ADV_DEFENSE_INPUT_TRANSFORM,
        ADV_DEFENSE_FEATURE_SQUEEZE,
        ADV_DEFENSE_ENSEMBLE
    };

    for (size_t i = 0; i < 5; i++) {
        adv_defense_config_t cfg = adv_defense_config_default(defenses[i]);
        printf("  %-25s | temperature=%.0f eps=%.2f ensemble=%zu\n",
               adv_defense_name(defenses[i]),
               cfg.temperature,
               cfg.epsilon_bound,
               cfg.ensemble_count);
    }
}

int main(void)
{
    printf("============================================================\n");
    printf("  mini-ai-security: Adversarial Training & Defense Demo\n");
    printf("============================================================\n");

    size_t num_samples = 50;
    demo_sample_t *dataset = create_dataset(num_samples);

    demo_fgsm_attack(dataset, num_samples);
    demo_pgd_attack(dataset, num_samples);
    demo_cw_attack(dataset, num_samples);
    demo_defense_training(dataset, num_samples);
    demo_defensive_distillation();
    demo_input_transform_defenses(dataset, num_samples);
    demo_transferability(dataset, num_samples);
    demo_physical_attacks();
    demo_defense_summary();

    free_dataset(dataset, num_samples);

    printf("\n============================================================\n");
    printf("  Demo completed successfully.\n");
    printf("============================================================\n");
    return 0;
}
