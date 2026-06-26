#include "differential_privacy.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>

int main(void) {
    uint64_t seed = 12345ULL;
    printf("=== Differential Privacy Example ===\n\n");

    /* 1. Laplace mechanism */
    {
        printf("--- Laplace Mechanism ---\n");
        double true_val = 2500.0;
        double sensitivity = 1.0;
        double epsilon = 0.1;
        for (int i = 0; i < 5; i++) {
            double result = dp_laplace_mechanism(true_val, sensitivity, epsilon, &seed);
            printf("  query %d: true=%.1f  laplace=%.1f  noise=%.1f\n",
                   i, true_val, result, result - true_val);
        }
    }

    /* 2. Gaussian mechanism */
    {
        printf("\n--- Gaussian Mechanism ---\n");
        double true_val = 5000.0;
        double sensitivity_l2 = 5.0;
        double epsilon = 1.0;
        double delta = 1e-5;
        for (int i = 0; i < 5; i++) {
            double result = dp_gaussian_mechanism(true_val, sensitivity_l2,
                                                  epsilon, delta, &seed);
            printf("  query %d: true=%.1f  gaussian=%.1f  noise=%.3f\n",
                   i, true_val, result, result - true_val);
        }
    }

    /* 3. Composition tracking */
    {
        printf("\n--- Composition ---\n");
        DPComposition comp;
        dp_comp_init(&comp);
        printf("  Initial budget: eps=%.3f\n", comp.total_epsilon);
        dp_comp_sequential(&comp, 0.1, 0.0);
        dp_comp_sequential(&comp, 0.05, 0.0);
        printf("  After 2 queries: eps=%.3f\n", comp.total_epsilon);
        int ok = dp_comp_budget_remaining(&comp, 1.0);
        printf("  Budget remaining (<1.0): %s\n", ok ? "YES" : "NO");
    }

    /* 4. Privacy budget */
    {
        printf("\n--- Privacy Budget ---\n");
        DPBudget budget;
        dp_budget_init(&budget, 1.0, 1e-5);
        printf("  Limit: eps=%.2f\n", budget.epsilon_limit);
        int c1 = dp_budget_consume(&budget, 0.3, 0.0);
        int c2 = dp_budget_consume(&budget, 0.5, 0.0);
        int c3 = dp_budget_consume(&budget, 0.4, 0.0);
        printf("  Consume 0.3: %s\n", c1 ? "ok" : "exhausted");
        printf("  Consume 0.5: %s\n", c2 ? "ok" : "exhausted");
        printf("  Consume 0.4: %s\n", c3 ? "ok" : "exhausted");
        printf("  Remaining eps: %.3f\n", dp_budget_remaining_eps(&budget));
    }

    /* 5. Local DP */
    {
        printf("\n--- Local DP ---\n");
        double user_val = 180.0;
        double sensitivity = 10.0;
        double epsilon = 2.0;
        for (int i = 0; i < 5; i++) {
            double perturbed = dp_local_laplace(user_val, sensitivity, epsilon, &seed);
            printf("  user %d: original=%.0f  perturbed=%.1f\n", i, user_val, perturbed);
        }
    }

    /* 6. Global DP aggregation */
    {
        printf("\n--- Global DP Aggregation ---\n");
        double values[] = {175.0, 182.0, 169.0, 190.0, 178.0, 170.0, 185.0, 172.0};
        size_t n = sizeof(values) / sizeof(values[0]);
        double mean, variance;
        dp_global_aggregate(values, n, &mean, &variance);
        printf("  Raw aggregate: mean=%.2f  var=%.2f\n", mean, variance);
        double perturbed[8];
        dp_laplace_vector(values, perturbed, n, 1.0, 0.5, &seed);
        dp_global_aggregate(perturbed, n, &mean, &variance);
        printf("  DP aggregate:  mean=%.2f  var=%.2f\n", mean, variance);
    }

    /* 7. DP-SGD */
    {
        printf("\n--- DP-SGD ---\n");
        double params[4]   = {1.0, -0.5, 0.3, 0.8};
        double gradients[4] = {0.02, -0.01, 0.05, -0.03};
        double clip_norm   = 0.1;
        double noise_scale = 0.01;
        printf("  Before: [%.4f, %.4f, %.4f, %.4f]\n",
               params[0], params[1], params[2], params[3]);
        dp_sgd_step(params, gradients, 4, 0.01, clip_norm, noise_scale, &seed);
        printf("  After:  [%.4f, %.4f, %.4f, %.4f]\n",
               params[0], params[1], params[2], params[3]);
    }

    /* 8. RAPPOR */
    {
        printf("\n--- RAPPOR ---\n");
        RAPPORClient rc;
        rappor_init(&rc, 32, 0.5, 0.75, 0.25, 42ULL);
        const char *samples[] = {"cat", "dog", "cat", "bird", "dog", "cat", "cat"};
        int num_samples = 7;
        uint8_t reports[7][4] = {{0}};
        for (int i = 0; i < num_samples; i++) {
            rappor_encode(&rc, samples[i]);
            rappor_randomize(&rc, reports[i]);
        }
        double freqs[32] = {0};
        rappor_decode((const uint8_t *)reports, num_samples, 32, rc.f, rc.p, rc.q, freqs);
        printf("  Submitted %d reports, decoded bit 0 freq=%.3f\n",
               num_samples, freqs[0]);
        rappor_free(&rc);
    }

    /* 9. Randomized response */
    {
        printf("\n--- Local Randomized Response ---\n");
        int true_bit = 1;
        for (int i = 0; i < 10; i++) {
            int resp = dp_local_randomize(true_bit, 2.0);
            printf("  flip %d: origin=%d response=%d\n", i, true_bit, resp);
        }
    }

    /* 10. Risk analysis */
    {
        printf("\n--- Risk Analysis ---\n");
        DPConfig config;
        config.epsilon = 1.0;
        config.delta = 1e-5;
        config.budget_used = 0.5;
        config.budget_total = 5.0;
        config.mechanism = 0;
        DPRiskAnalysis risk = dp_analyze_risk(&config, 10, 1000);
        printf("  Privacy loss: %.3f  utility: %.3f  satisfied: %s\n",
               risk.privacy_loss, risk.utility_score, risk.satisfied ? "YES" : "NO");
    }

    printf("\n=== DP Example Complete ===\n");
    return 0;
}
