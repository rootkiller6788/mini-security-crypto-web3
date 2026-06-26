#include "data_poison.h"
#include "model_inversion.h"
#include "adversarial_ml.h"
#include "ai_governance.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#define NUM_SAMPLES      200
#define FEATURE_DIMS     64
#define NUM_CLIENTS      10
#define NUM_ROUNDS       5
#define TRIGGER_ROWS     4
#define TRIGGER_COLS     4

static dp_sample_t *create_clean_dataset(size_t num_samples)
{
    dp_sample_t *data = (dp_sample_t *)malloc(num_samples * sizeof(dp_sample_t));
    srand((unsigned)time(NULL));

    for (size_t i = 0; i < num_samples; i++) {
        data[i] = dp_sample_create(FEATURE_DIMS);
        data[i].label = (int)(i % 10);
        for (size_t j = 0; j < FEATURE_DIMS; j++)
            data[i].features[j] = (double)rand() / RAND_MAX;
    }
    return data;
}

static void free_dataset(dp_sample_t *data, size_t num_samples)
{
    for (size_t i = 0; i < num_samples; i++)
        dp_sample_free(&data[i]);
    free(data);
}

static void demo_backdoor_injection(void)
{
    printf("=== Demo: Backdoor Injection Attack ===\n\n");

    dp_sample_t *data = create_clean_dataset(NUM_SAMPLES);

    dp_trigger_t trigger;
    dp_poison_config_t config = dp_poison_config_default(DP_BACKDOOR);
    config.poison_ratio  = 0.15;
    config.target_label   = 5;
    config.trigger_type   = DP_TRIGGER_PATTERN;
    config.trigger_size_rows = TRIGGER_ROWS;
    config.trigger_size_cols = TRIGGER_COLS;

    dp_trigger_generate(&trigger, config.trigger_type,
                        TRIGGER_ROWS, TRIGGER_COLS);

    printf("Poison config: %s, target=%d, ratio=%.2f\n",
           dp_poison_type_name(config.type),
           config.target_label, config.poison_ratio);
    printf("Trigger type: %s (%zux%zu)\n",
           dp_trigger_type_name(config.trigger_type),
           trigger.rows, trigger.cols);

    dp_backdoor_inject(data, NUM_SAMPLES, &trigger, &config);

    size_t poisoned_count = 0;
    for (size_t i = 0; i < NUM_SAMPLES; i++)
        if (data[i].is_poisoned) poisoned_count++;

    printf("Samples poisoned: %zu / %zu (%.1f%%)\n",
           poisoned_count, NUM_SAMPLES,
           100.0 * (double)poisoned_count / (double)NUM_SAMPLES);

    dp_defense_config_t defense = dp_defense_config_default(DP_DEFENSE_ANOMALY_DETECT);
    defense.anomaly_threshold = 3.0;

    dp_poison_result_t result;
    dp_anomaly_detection(&result, data, NUM_SAMPLES, &defense);
    printf("Anomaly detection: found %d suspicious (mean=%.4f, std=%.4f)\n",
           result.samples_detected,
           result.anomaly_scores_mean, result.anomaly_scores_std);

    free(trigger.data);
    free_dataset(data, NUM_SAMPLES);
    printf("\n--- Backdoor injection demo done ---\n\n");
}

static void demo_clean_label_poisoning(void)
{
    printf("=== Demo: Clean-Label Poisoning ===\n\n");

    dp_sample_t *data = create_clean_dataset(NUM_SAMPLES);

    dp_poison_config_t config = dp_poison_config_default(DP_CLEAN_LABEL);
    config.poison_ratio   = 0.1;
    config.target_label   = 0;
    config.poison_strength = 2.0;

    printf("Attack type: %s\n", dp_poison_type_name(config.type));
    printf("Poison ratio: %.2f, target label: %d\n",
           config.poison_ratio, config.target_label);

    double pre_mean[FEATURE_DIMS];
    size_t i;
    for (i = 0; i < FEATURE_DIMS; i++) pre_mean[i] = 0.0;
    for (size_t s = 0; s < NUM_SAMPLES; s++)
        for (i = 0; i < FEATURE_DIMS; i++)
            pre_mean[i] += data[s].features[i];
    for (i = 0; i < FEATURE_DIMS; i++) pre_mean[i] /= NUM_SAMPLES;

    dp_clean_label_poison(data, NUM_SAMPLES, &config);

    double post_mean[FEATURE_DIMS];
    for (i = 0; i < FEATURE_DIMS; i++) post_mean[i] = 0.0;
    for (size_t s = 0; s < NUM_SAMPLES; s++)
        for (i = 0; i < FEATURE_DIMS; i++)
            post_mean[i] += data[s].features[i];
    for (i = 0; i < FEATURE_DIMS; i++) post_mean[i] /= NUM_SAMPLES;

    double shift = 0.0;
    for (i = 0; i < FEATURE_DIMS; i++)
        shift += fabs(post_mean[i] - pre_mean[i]);
    shift /= FEATURE_DIMS;
    printf("Feature distribution shift: %.6f\n", shift);

    dp_defense_config_t defense = dp_defense_config_default(DP_DEFENSE_SANITIZATION);
    defense.anomaly_threshold = 2.0;

    dp_data_sanitization(data, NUM_SAMPLES, &defense);

    double post_san_mean[FEATURE_DIMS];
    for (i = 0; i < FEATURE_DIMS; i++) post_san_mean[i] = 0.0;
    for (size_t s = 0; s < NUM_SAMPLES; s++)
        for (i = 0; i < FEATURE_DIMS; i++)
            post_san_mean[i] += data[s].features[i];
    for (i = 0; i < FEATURE_DIMS; i++) post_san_mean[i] /= NUM_SAMPLES;

    double recovery = 0.0;
    for (i = 0; i < FEATURE_DIMS; i++)
        recovery += fabs(post_san_mean[i] - pre_mean[i]);
    recovery /= FEATURE_DIMS;
    printf("After sanitization, residual shift: %.6f\n", recovery);

    free_dataset(data, NUM_SAMPLES);
    printf("\n--- Clean-label poisoning demo done ---\n\n");
}

static void demo_availability_attack(void)
{
    printf("=== Demo: Availability Attack ===\n\n");

    dp_sample_t *data = create_clean_dataset(NUM_SAMPLES);

    double clean_accuracy = 0.0;
    for (size_t s = 0; s < NUM_SAMPLES; s++) {
        int pred = (int)(data[s].features[0] * 10.0) % 10;
        if (pred == data[s].label) clean_accuracy += 1.0;
    }
    clean_accuracy /= NUM_SAMPLES;

    dp_poison_config_t config = dp_poison_config_default(DP_AVAILABILITY);
    config.poison_ratio = 0.3;

    dp_availability_attack(data, NUM_SAMPLES, &config);

    double poisoned_accuracy = 0.0;
    for (size_t s = 0; s < NUM_SAMPLES; s++) {
        int pred = (int)(data[s].features[0] * 10.0) % 10;
        if (pred == data[s].label) poisoned_accuracy += 1.0;
    }
    poisoned_accuracy /= NUM_SAMPLES;

    printf("Clean accuracy before attack:    %.4f\n", clean_accuracy);
    printf("Accuracy after availability attack: %.4f\n", poisoned_accuracy);
    printf("Accuracy degradation: %.2f%%\n",
           100.0 * (clean_accuracy - poisoned_accuracy));

    free_dataset(data, NUM_SAMPLES);
    printf("\n--- Availability attack demo done ---\n\n");
}

static void demo_robust_training_defense(void)
{
    printf("=== Demo: Robust Training Defense ===\n\n");

    double weights[FEATURE_DIMS];
    dp_sample_t *data = create_clean_dataset(NUM_SAMPLES);

    for (size_t i = 0; i < FEATURE_DIMS; i++)
        weights[i] = ((double)rand() / RAND_MAX - 0.5) * 0.1;

    dp_defense_config_t defense = dp_defense_config_default(DP_DEFENSE_ROBUST_TRAIN);
    defense.clip_norm = 1.0;
    defense.use_trim  = 1;
    defense.trim_ratio = 0.1;

    printf("Defense: %s (clip=%.2f, trim=%.2f)\n",
           dp_defense_type_name(defense.type),
           defense.clip_norm, defense.trim_ratio);

    double loss_before = 0.0;
    for (size_t s = 0; s < NUM_SAMPLES / 2; s++)
        for (size_t i = 0; i < FEATURE_DIMS; i++)
            loss_before += (data[s].features[i] - weights[i]) *
                           (data[s].features[i] - weights[i]);

    for (size_t round = 0; round < NUM_ROUNDS; round++)
        dp_robust_training(weights, FEATURE_DIMS, data,
                           NUM_SAMPLES, &defense);

    double loss_after = 0.0;
    for (size_t s = 0; s < NUM_SAMPLES / 2; s++)
        for (size_t i = 0; i < FEATURE_DIMS; i++)
            loss_after += (data[s].features[i] - weights[i]) *
                          (data[s].features[i] - weights[i]);

    printf("Loss before training: %.6f\n",
           loss_before / (FEATURE_DIMS * (NUM_SAMPLES / 2)));
    printf("Loss after training:  %.6f\n",
           loss_after / (FEATURE_DIMS * (NUM_SAMPLES / 2)));

    free_dataset(data, NUM_SAMPLES);
    printf("\n--- Robust training demo done ---\n\n");
}

static void demo_federated_learning_security(void)
{
    printf("=== Demo: Federated Learning Security ===\n\n");

    dp_client_update_t updates[NUM_CLIENTS];
    double *global_model = (double *)calloc(FEATURE_DIMS, sizeof(double));

    for (size_t c = 0; c < NUM_CLIENTS; c++) {
        updates[c].gradients  = (double *)malloc(FEATURE_DIMS * sizeof(double));
        updates[c].num_params = FEATURE_DIMS;
        updates[c].was_clipped = 0;

        for (size_t p = 0; p < FEATURE_DIMS; p++) {
            updates[c].gradients[p] = ((double)rand() / RAND_MAX - 0.5) * 0.2;
            if (c == 0) updates[c].gradients[p] *= 100.0;
        }
        updates[c].original_norm = 0.0;
        for (size_t p = 0; p < FEATURE_DIMS; p++)
            updates[c].original_norm += updates[c].gradients[p] *
                                        updates[c].gradients[p];
        updates[c].original_norm = sqrt(updates[c].original_norm);
    }

    printf("Num clients: %zu, params per client: %zu\n",
           NUM_CLIENTS, FEATURE_DIMS);

    dp_defense_config_t defense = dp_defense_config_default(DP_DEFENSE_ANOMALY_DETECT);
    defense.anomaly_threshold = 4.0;

    dp_fl_aggregate_t aggregate;
    memset(&aggregate, 0, sizeof(aggregate));

    dp_fl_malicious_detection(&aggregate, updates, NUM_CLIENTS, &defense);

    printf("Malicious clients detected: %zu\n", aggregate.num_malicious);
    for (size_t m = 0; m < aggregate.num_malicious; m++)
        printf("  Client %zu: anomaly score = %.4f\n",
               aggregate.malicious_clients[m],
               aggregate.anomaly_scores[aggregate.malicious_clients[m]]);

    dp_fl_secure_aggregate(global_model, FEATURE_DIMS, updates,
                           NUM_CLIENTS, &defense);

    double byzantine_agg[FEATURE_DIMS];
    dp_fl_byzantine_resilient_agg(byzantine_agg, FEATURE_DIMS, updates,
                                  NUM_CLIENTS, aggregate.num_malicious);

    printf("Secure aggregation complete\n");

    free(global_model);
    free(aggregate.anomaly_scores);
    free(aggregate.malicious_clients);
    for (size_t c = 0; c < NUM_CLIENTS; c++)
        free(updates[c].gradients);

    printf("\n--- FL security demo done ---\n\n");
}

static void demo_differential_privacy_mitigation(void)
{
    printf("=== Demo: Differential Privacy as Mitigation ===\n\n");

    dp_sample_t *data = create_clean_dataset(NUM_SAMPLES);

    dp_defense_config_t defense = dp_defense_config_default(DP_DEFENSE_DIFF_PRIVACY);
    defense.epsilon = 1.0;
    defense.delta   = 1e-5;

    printf("DP parameters: epsilon=%.2f, delta=%.1e\n",
           defense.epsilon, defense.delta);

    dp_poison_config_t pcfg = dp_poison_config_default(DP_BACKDOOR);
    pcfg.poison_ratio = 0.1;

    dp_poison_result_t result;
    dp_poison_evaluate(&result, data, NUM_SAMPLES, &pcfg, &defense);

    printf("Poison effectiveness: %.4f\n",
           dp_poison_effectiveness(&result));
    printf("Defense detection rate: %.4f\n",
           result.defense_detection_rate);

    free_dataset(data, NUM_SAMPLES);
    printf("\n--- DP mitigation demo done ---\n\n");
}

static void demo_knn_and_spectral_defenses(void)
{
    printf("=== Demo: KNN Filter & Spectral Signature Defense ===\n\n");

    dp_sample_t *data = create_clean_dataset(NUM_SAMPLES);

    dp_defense_config_t defense = dp_defense_config_default(DP_DEFENSE_KNN_FILTER);
    defense.num_neighbors = 5;

    printf("Defense: %s (k=%zu)\n",
           dp_defense_type_name(defense.type), defense.num_neighbors);

    dp_knn_filter(data, NUM_SAMPLES, &defense);
    printf("KNN filter applied\n");

    dp_poison_result_t spect_result;
    dp_defense_config_t spect_def = dp_defense_config_default(DP_DEFENSE_SPECTRAL_SIGNATURE);
    dp_spectral_signature_defense(&spect_result, data, NUM_SAMPLES, &spect_def);

    printf("Spectral signature defense: detected %d / %d\n",
           spect_result.samples_detected, spect_result.samples_total);

    free_dataset(data, NUM_SAMPLES);
    printf("\n--- KNN/Spectral defense demo done ---\n\n");
}

static void demo_trigger_detection(void)
{
    printf("=== Demo: Trigger Pattern Detection ===\n\n");

    dp_trigger_t known_triggers[3];
    dp_trigger_generate(&known_triggers[0], DP_TRIGGER_PATTERN,
                        TRIGGER_ROWS, TRIGGER_COLS);
    dp_trigger_generate(&known_triggers[1], DP_TRIGGER_WATERMARK,
                        TRIGGER_ROWS, TRIGGER_COLS);
    dp_trigger_generate(&known_triggers[2], DP_TRIGGER_PIXEL,
                        TRIGGER_ROWS, TRIGGER_COLS);

    dp_sample_t clean_sample = dp_sample_create(FEATURE_DIMS);
    dp_sample_t triggered_sample = dp_sample_create(FEATURE_DIMS);

    for (size_t i = 0; i < FEATURE_DIMS; i++) {
        clean_sample.features[i] = (double)rand() / RAND_MAX;
        triggered_sample.features[i] = clean_sample.features[i];
    }
    dp_trigger_apply(&triggered_sample, &known_triggers[0], 0, 0);

    int clean_detected = dp_trigger_detected(&clean_sample, known_triggers, 3, 0.5);
    int trig_detected  = dp_trigger_detected(&triggered_sample, known_triggers, 3, 0.5);

    printf("Clean sample trigger detected:    %s\n",
           clean_detected ? "yes" : "no");
    printf("Triggered sample trigger detected: %s\n",
           trig_detected ? "yes" : "no");

    dp_sample_free(&clean_sample);
    dp_sample_free(&triggered_sample);
    free(known_triggers[0].data);
    free(known_triggers[1].data);
    free(known_triggers[2].data);
    printf("\n--- Trigger detection demo done ---\n\n");
}

static void demo_defense_comparison(void)
{
    printf("=== Demo: Defense Strategy Comparison ===\n\n");

    printf("%-28s | %s\n", "Defense", "Key Parameter");
    printf("-------------------------------------------------\n");

    dp_defense_type_t all_defenses[] = {
        DP_DEFENSE_SANITIZATION,
        DP_DEFENSE_ROBUST_TRAIN,
        DP_DEFENSE_ANOMALY_DETECT,
        DP_DEFENSE_DIFF_PRIVACY,
        DP_DEFENSE_SPECTRAL_SIGNATURE,
        DP_DEFENSE_TRIM,
        DP_DEFENSE_KNN_FILTER,
        DP_DEFENSE_CERTIFIED_ROBUST
    };

    for (size_t i = 0; i < 8; i++) {
        dp_defense_config_t cfg = dp_defense_config_default(all_defenses[i]);
        printf("  %-26s | threshold=%.2f clip=%.2f k=%zu ε=%.2f\n",
               dp_defense_type_name(all_defenses[i]),
               cfg.anomaly_threshold,
               cfg.clip_norm,
               cfg.num_neighbors,
               cfg.epsilon);
    }

    printf("\n--- Defense comparison demo done ---\n\n");
}

int main(void)
{
    printf("=========================================================\n");
    printf("  mini-ai-security: Data Poisoning Attack & Defense Demo\n");
    printf("=========================================================\n\n");

    demo_backdoor_injection();
    demo_clean_label_poisoning();
    demo_availability_attack();
    demo_robust_training_defense();
    demo_federated_learning_security();
    demo_differential_privacy_mitigation();
    demo_knn_and_spectral_defenses();
    demo_trigger_detection();
    demo_defense_comparison();

    printf("=========================================================\n");
    printf("  All data poisoning demos completed successfully.\n");
    printf("=========================================================\n");
    return 0;
}
