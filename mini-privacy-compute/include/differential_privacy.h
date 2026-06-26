#ifndef DIFFERENTIAL_PRIVACY_H
#define DIFFERENTIAL_PRIVACY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- core types ---------- */

typedef struct {
    double epsilon;
    double delta;
    double budget_used;
    double budget_total;
    int    mechanism;       /* 0=Laplace, 1=Gaussian, 2=RAPPOR */
} DPConfig;

typedef struct {
    double *values;
    size_t  count;
    double  sensitivity_l1;
    double  sensitivity_l2;
    double  epsilon;
    double  clip_norm;
} DPDataset;

typedef struct {
    double *gradients;
    size_t  num_params;
    double  clip_threshold;
    double  noise_scale;
    double  epsilon;
    double  delta;
} DPSGDPConfig;

/* ---------- Laplace mechanism ---------- */

double dp_laplace_noise(      double scale);
double dp_laplace_mechanism(  double true_value, double sensitivity, double epsilon,
                              uint64_t *seed);
void   dp_laplace_vector(     const double *input, double *output, size_t n,
                              double sensitivity, double epsilon, uint64_t *seed);

/* ---------- Gaussian mechanism ---------- */

double dp_gaussian_noise(     double sigma, uint64_t *seed);
double dp_gaussian_mechanism( double true_value, double sensitivity_l2,
                              double epsilon, double delta, uint64_t *seed);
void   dp_gaussian_vector(    const double *input, double *output, size_t n,
                              double sensitivity_l2, double epsilon, double delta,
                              uint64_t *seed);

/* ---------- composition ---------- */

typedef struct {
    double total_epsilon;
    double total_delta;
    int    num_queries;
} DPComposition;

void dp_comp_init(            DPComposition *comp);
int  dp_comp_sequential(      DPComposition *comp, double eps_consumed, double delta_consumed);
void dp_comp_parallel_query(  DPComposition *comp, double eps_per_query, int num_queries);
int  dp_comp_budget_remaining(const DPComposition *comp, double eps_limit);

/* ---------- privacy budget ---------- */

typedef struct {
    double epsilon_limit;
    double epsilon_spent;
    double delta_limit;
    double delta_spent;
    int    exhausted;
} DPBudget;

void    dp_budget_init(        DPBudget *budget, double eps, double delta);
int     dp_budget_consume(     DPBudget *budget, double eps, double delta);
double  dp_budget_remaining_eps(const DPBudget *budget);
void    dp_budget_reset(       DPBudget *budget);

/* ---------- local DP ---------- */

double dp_local_laplace(   double user_value, double sensitivity,
                           double epsilon, uint64_t *seed);
int    dp_local_randomize( int true_bit, double epsilon);

/* ---------- global DP ---------- */

void dp_global_aggregate( const double *perturbed_values, size_t n,
                          double *mean, double *variance);

/* ---------- DP-SGD ---------- */

void dp_sgd_clip_gradients(    double *gradients, size_t n, double clip_norm);
void dp_sgd_add_noise(         double *gradients, size_t n, double noise_scale,
                               uint64_t *seed);
void dp_sgd_step(              double *params, const double *gradients, size_t n,
                               double learning_rate, double clip_norm,
                               double noise_scale, uint64_t *seed);

/* ---------- RAPPOR ---------- */

typedef struct {
    double   f;             /* bloom filter probability */
    double   p;             /* reporting probability */
    double   q;             /* noise probability */
    int      num_bits;
    uint8_t *bloom;
    uint64_t seed;
} RAPPORClient;

void  rappor_init(          RAPPORClient *rc, int num_bits, double f, double p, double q,
                            uint64_t seed);
void  rappor_encode(        RAPPORClient *rc, const char *value);
void  rappor_randomize(     RAPPORClient *rc, uint8_t *report);
void  rappor_decode(        const uint8_t *reports, int num_reports, int num_bits,
                            double f, double p, double q, double *freq_estimates);
void  rappor_free(          RAPPORClient *rc);

/* ---------- utility ---------- */

typedef struct {
    double privacy_loss;
    double utility_score;
    int    satisfied;
} DPRiskAnalysis;

DPRiskAnalysis dp_analyze_risk(const DPConfig *config, int num_queries, int dataset_size);
double         dp_advanced_composition(double epsilon, double delta, int k, double delta_prime);

#ifdef __cplusplus
}
#endif

#endif /* DIFFERENTIAL_PRIVACY_H */
