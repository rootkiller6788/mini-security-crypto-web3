#include "differential_privacy.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

#ifndef M_E
#define M_E  2.71828182845904523536
#endif

static double uniform_random(uint64_t *seed) {
    *seed = (*seed * 6364136223846793005ULL + 1442695040888963407ULL);
    return (double)((*seed >> 33)) / (double)(1ULL << 31);
}

static double box_muller(uint64_t *seed, double mu, double sigma) {
    double u1 = uniform_random(seed);
    double u2 = uniform_random(seed);
    if (u1 < 1e-12) u1 = 1e-12;
    double z = sqrt(-2.0 * log(u1)) * cos(2.0 * M_PI * u2);
    return mu + sigma * z;
}

static double laplace_sample(uint64_t *seed, double b) {
    double u = uniform_random(seed) - 0.5;
    return -b * ((u > 0) ? 1.0 : -1.0) * log(1.0 - 2.0 * fabs(u));
}

static double sigmoid_clip(double x, double clip) {
    if (x > clip) return clip;
    if (x < -clip) return -clip;
    return x;
}

/* ---------- Laplace mechanism ---------- */

double dp_laplace_noise(double scale) {
    uint64_t s = (uint64_t)time(NULL);
    return laplace_sample(&s, scale);
}

double dp_laplace_mechanism(double true_value, double sensitivity, double epsilon,
                            uint64_t *seed) {
    if (epsilon <= 0.0) return true_value;
    double scale = sensitivity / epsilon;
    double noise = laplace_sample(seed, scale);
    return true_value + noise;
}

void dp_laplace_vector(const double *input, double *output, size_t n,
                       double sensitivity, double epsilon, uint64_t *seed) {
    double scale = sensitivity / epsilon;
    for (size_t i = 0; i < n; i++) {
        output[i] = input[i] + laplace_sample(seed, scale);
    }
}

/* ---------- Gaussian mechanism ---------- */

double dp_gaussian_noise(double sigma, uint64_t *seed) {
    return box_muller(seed, 0.0, sigma);
}

double dp_gaussian_mechanism(double true_value, double sensitivity_l2,
                             double epsilon, double delta, uint64_t *seed) {
    if (epsilon <= 0.0 || delta <= 0.0) return true_value;
    double c2 = 2.0 * log(1.25 / delta);
    double sigma = sensitivity_l2 * sqrt(c2) / epsilon;
    return true_value + box_muller(seed, 0.0, sigma);
}

void dp_gaussian_vector(const double *input, double *output, size_t n,
                        double sensitivity_l2, double epsilon, double delta,
                        uint64_t *seed) {
    double c2 = 2.0 * log(1.25 / delta);
    double sigma = sensitivity_l2 * sqrt(c2) / epsilon;
    for (size_t i = 0; i < n; i++) {
        output[i] = input[i] + box_muller(seed, 0.0, sigma);
    }
}

/* ---------- composition ---------- */

void dp_comp_init(DPComposition *comp) {
    comp->total_epsilon = 0.0;
    comp->total_delta   = 0.0;
    comp->num_queries   = 0;
}

int dp_comp_sequential(DPComposition *comp, double eps_consumed, double delta_consumed) {
    comp->total_epsilon += eps_consumed;
    comp->total_delta   += delta_consumed;
    comp->num_queries++;
    return 1;
}

void dp_comp_parallel_query(DPComposition *comp, double eps_per_query, int num_queries) {
    double new_eps = eps_per_query * num_queries;
    if (new_eps > comp->total_epsilon) {
        comp->total_epsilon = new_eps;
    }
    comp->num_queries += num_queries;
}

int dp_comp_budget_remaining(const DPComposition *comp, double eps_limit) {
    return comp->total_epsilon < eps_limit ? 1 : 0;
}

/* ---------- privacy budget ---------- */

void dp_budget_init(DPBudget *budget, double eps, double delta) {
    budget->epsilon_limit = eps;
    budget->epsilon_spent = 0.0;
    budget->delta_limit   = delta;
    budget->delta_spent   = 0.0;
    budget->exhausted     = 0;
}

int dp_budget_consume(DPBudget *budget, double eps, double delta) {
    if (budget->exhausted) return 0;
    budget->epsilon_spent += eps;
    budget->delta_spent   += delta;
    if (budget->epsilon_spent >= budget->epsilon_limit ||
        budget->delta_spent >= budget->delta_limit) {
        budget->exhausted = 1;
    }
    return budget->exhausted ? 0 : 1;
}

double dp_budget_remaining_eps(const DPBudget *budget) {
    double remaining = budget->epsilon_limit - budget->epsilon_spent;
    return remaining > 0.0 ? remaining : 0.0;
}

void dp_budget_reset(DPBudget *budget) {
    budget->epsilon_spent = 0.0;
    budget->delta_spent   = 0.0;
    budget->exhausted     = 0;
}

/* ---------- local DP ---------- */

double dp_local_laplace(double user_value, double sensitivity,
                        double epsilon, uint64_t *seed) {
    return dp_laplace_mechanism(user_value, sensitivity, epsilon, seed);
}

int dp_local_randomize(int true_bit, double epsilon) {
    uint64_t seed = (uint64_t)time(NULL) ^ ((uint64_t)&true_bit);
    double p = exp(epsilon) / (1.0 + exp(epsilon));
    double r = uniform_random(&seed);
    if (true_bit) {
        return (r < p) ? 1 : 0;
    } else {
        return (r < (1.0 - p)) ? 0 : 1;
    }
}

/* ---------- global DP ---------- */

void dp_global_aggregate(const double *perturbed_values, size_t n,
                         double *mean, double *variance) {
    double sum = 0.0;
    double sum_sq = 0.0;
    for (size_t i = 0; i < n; i++) {
        sum    += perturbed_values[i];
        sum_sq += perturbed_values[i] * perturbed_values[i];
    }
    *mean     = sum / (double)n;
    *variance = (sum_sq / (double)n) - (*mean * *mean);
}

/* ---------- DP-SGD ---------- */

void dp_sgd_clip_gradients(double *gradients, size_t n, double clip_norm) {
    double norm_sq = 0.0;
    for (size_t i = 0; i < n; i++) {
        norm_sq += gradients[i] * gradients[i];
    }
    double norm = sqrt(norm_sq);
    if (norm > clip_norm) {
        double scale = clip_norm / norm;
        for (size_t i = 0; i < n; i++) {
            gradients[i] *= scale;
        }
    }
}

void dp_sgd_add_noise(double *gradients, size_t n, double noise_scale,
                      uint64_t *seed) {
    for (size_t i = 0; i < n; i++) {
        gradients[i] += box_muller(seed, 0.0, noise_scale);
    }
}

void dp_sgd_step(double *params, const double *gradients, size_t n,
                 double learning_rate, double clip_norm,
                 double noise_scale, uint64_t *seed) {
    double *grad_copy = (double *)malloc(n * sizeof(double));
    if (!grad_copy) return;
    memcpy(grad_copy, gradients, n * sizeof(double));
    dp_sgd_clip_gradients(grad_copy, n, clip_norm);
    dp_sgd_add_noise(grad_copy, n, noise_scale, seed);
    for (size_t i = 0; i < n; i++) {
        params[i] -= learning_rate * grad_copy[i];
    }
    free(grad_copy);
}

/* ---------- RAPPOR ---------- */

void rappor_init(RAPPORClient *rc, int num_bits, double f, double p, double q,
                 uint64_t seed) {
    rc->f        = f;
    rc->p        = p;
    rc->q        = q;
    rc->num_bits = num_bits;
    rc->seed     = seed;
    size_t bytes = (size_t)((num_bits + 7) / 8);
    rc->bloom    = (uint8_t *)calloc(bytes, 1);
}

static uint32_t rappor_hash(const char *s, uint32_t seed) {
    uint32_t h = seed;
    while (*s) {
        h ^= (uint32_t)(unsigned char)(*s++);
        h *= 0x5bd1e995;
        h ^= h >> 15;
    }
    return h;
}

void rappor_encode(RAPPORClient *rc, const char *value) {
    if (!rc->bloom) return;
    size_t bytes = (size_t)((rc->num_bits + 7) / 8);
    memset(rc->bloom, 0, bytes);
    uint32_t h = rappor_hash(value, (uint32_t)(rc->seed & 0xFFFFFFFF));
    double r    = uniform_random(&rc->seed);
    for (int i = 0; i < rc->num_bits; i++) {
        int prob_bit = (r < rc->f) ? 1 : 0;
        if (prob_bit || (h & 1)) {
            int byte_idx = i / 8;
            int bit_idx  = i % 8;
            rc->bloom[byte_idx] |= (uint8_t)(1U << bit_idx);
        }
        h = (h >> 1) ^ ((h & 1) ? 0xEDB88320 : 0);
        r = uniform_random(&rc->seed);
    }
}

void rappor_randomize(RAPPORClient *rc, uint8_t *report) {
    if (!rc->bloom) return;
    size_t bytes = (size_t)((rc->num_bits + 7) / 8);
    for (size_t i = 0; i < bytes; i++) {
        report[i] = 0;
    }
    for (int i = 0; i < rc->num_bits; i++) {
        int byte_idx = i / 8;
        int bit_idx  = i % 8;
        int orig_bit = (rc->bloom[byte_idx] >> bit_idx) & 1;
        double r = uniform_random(&rc->seed);
        int final_bit;
        if (orig_bit) {
            final_bit = (r < rc->p) ? 1 : 0;
        } else {
            final_bit = (r < rc->q) ? 1 : 0;
        }
        report[byte_idx] |= (uint8_t)(final_bit << bit_idx);
    }
}

void rappor_decode(const uint8_t *reports, int num_reports, int num_bits,
                   double f, double p, double q, double *freq_estimates) {
    size_t bytes = (size_t)((num_bits + 7) / 8);
    for (int i = 0; i < num_bits; i++) {
        int sum = 0;
        for (int j = 0; j < num_reports; j++) {
            int byte_idx = i / 8;
            int bit_idx  = i % 8;
            sum += (reports[j * (int)bytes + byte_idx] >> bit_idx) & 1;
        }
        double observed = (double)sum / (double)num_reports;
        double denom    = f * (p - q);
        if (fabs(denom) < 1e-12) {
            freq_estimates[i] = observed;
        } else {
            freq_estimates[i] = (observed - (1.0 - f) * q - f * q) / denom;
            if (freq_estimates[i] < 0.0) freq_estimates[i] = 0.0;
            if (freq_estimates[i] > 1.0) freq_estimates[i] = 1.0;
        }
    }
}

void rappor_free(RAPPORClient *rc) {
    free(rc->bloom);
    rc->bloom = NULL;
}

/* ---------- utility ---------- */

DPRiskAnalysis dp_analyze_risk(const DPConfig *config, int num_queries, int dataset_size) {
    DPRiskAnalysis ra = {0};
    ra.privacy_loss  = config->epsilon * num_queries;
    ra.utility_score = 1.0 / (1.0 + ra.privacy_loss / (double)dataset_size);
    ra.satisfied     = (ra.privacy_loss <= config->budget_total) ? 1 : 0;
    return ra;
}

double dp_advanced_composition(double epsilon, double delta, int k, double delta_prime) {
    double eps_prime = k * epsilon * (exp(epsilon) - 1.0) +
                       epsilon * sqrt(2.0 * (double)k * log(1.0 / delta_prime));
    return eps_prime;
}
