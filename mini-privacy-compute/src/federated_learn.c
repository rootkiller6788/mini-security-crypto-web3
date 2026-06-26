#include "federated_learn.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

static double uniform_random_64(uint64_t *seed) {
    *seed = (*seed * 6364136223846793005ULL + 1442695040888963407ULL);
    return (double)((*seed >> 33)) / (double)(1ULL << 31);
}

static void shuffle_indices(int *indices, int n, uint64_t *seed) {
    for (int i = n - 1; i > 0; i--) {
        int j = (int)(uniform_random_64(seed) * (double)(i + 1));
        if (j > i) j = i;
        int tmp = indices[i];
        indices[i] = indices[j];
        indices[j] = tmp;
    }
}

/* ---------- server operations ---------- */

void fl_server_init(FLServer *server, size_t num_params, int num_clients,
                    int num_selected, int total_rounds, double lr) {
    server->global_model.weights = (double *)calloc(num_params, sizeof(double));
    server->global_model.num_params = num_params;
    server->global_model.version = 0;
    server->clients = (FLClient *)calloc((size_t)num_clients, sizeof(FLClient));
    server->num_clients    = num_clients;
    server->num_selected   = num_selected;
    server->current_round  = 0;
    server->total_rounds   = total_rounds;
    server->learning_rate  = lr;
    server->local_epochs   = 5;
    server->batch_size     = 32;
    server->epsilon        = 8.0;
    server->delta          = 1e-5;
    for (int i = 0; i < num_clients; i++) {
        server->clients[i].client_id = i;
        server->clients[i].selected  = 0;
    }
}

void fl_server_free(FLServer *server) {
    free(server->global_model.weights);
    free(server->clients);
    server->global_model.weights = NULL;
    server->clients = NULL;
}

void fl_server_init_model(FLServer *server, double *initial_weights) {
    if (!server->global_model.weights || !initial_weights) return;
    memcpy(server->global_model.weights, initial_weights,
           server->global_model.num_params * sizeof(double));
    server->global_model.version = 1;
}

/* ---------- model distribution ---------- */

void fl_download_model(FLServer *server, int client_id, double *local_weights) {
    if (client_id < 0 || client_id >= server->num_clients) return;
    if (!server->global_model.weights || !local_weights) return;
    memcpy(local_weights, server->global_model.weights,
           server->global_model.num_params * sizeof(double));
}

void fl_upload_update(FLServer *server, const double *gradients,
                      int client_id, size_t num_samples) {
    if (client_id < 0 || client_id >= server->num_clients) return;
    FLClient *c = &server->clients[client_id];
    double norm_sq = 0.0;
    for (size_t i = 0; i < server->global_model.num_params; i++) {
        norm_sq += gradients[i] * gradients[i];
    }
    c->last_contribution = sqrt(norm_sq);
    c->local_data_size = num_samples;
}

/* ---------- federated averaging ---------- */

void fedavg_init(FedAvgState *state, size_t num_params) {
    state->weighted_sum  = (double *)calloc(num_params, sizeof(double));
    state->num_params    = num_params;
    state->total_samples = 0;
    state->num_updates   = 0;
}

void fedavg_accumulate(FedAvgState *state, const double *gradients, size_t samples) {
    if (!state->weighted_sum || !gradients) return;
    for (size_t i = 0; i < state->num_params; i++) {
        state->weighted_sum[i] += gradients[i] * (double)samples;
    }
    state->total_samples += samples;
    state->num_updates++;
}

void fedavg_apply(FedAvgState *state, double *global_weights, double lr) {
    if (state->total_samples == 0 || !state->weighted_sum || !global_weights) return;
    for (size_t i = 0; i < state->num_params; i++) {
        double avg_grad = state->weighted_sum[i] / (double)state->total_samples;
        global_weights[i] -= lr * avg_grad;
    }
    memset(state->weighted_sum, 0, state->num_params * sizeof(double));
    state->total_samples = 0;
    state->num_updates   = 0;
}

void fedavg_free(FedAvgState *state) {
    free(state->weighted_sum);
    state->weighted_sum = NULL;
}

/* ---------- secure aggregation ---------- */

void secagg_init(SecureAggState *sa, size_t num_params, int num_participants) {
    sa->encrypted_sum   = (double *)calloc(num_params, sizeof(double));
    sa->num_params      = num_params;
    sa->num_participants = (size_t)num_participants;
    size_t mask_bytes = num_params * sizeof(double);
    sa->shared_mask = (uint8_t *)calloc(mask_bytes, 1);
}

void secagg_add_update(SecureAggState *sa, const double *update, int participant_id) {
    if (!sa->encrypted_sum || !update) return;
    for (size_t i = 0; i < sa->num_params; i++) {
        double masked = update[i];
        masked += ((double)(sa->shared_mask[i % sa->num_params * sizeof(double)]) -
                  128.0) * 0.001;
        sa->encrypted_sum[i] += masked;
    }
    (void)participant_id;
}

void secagg_finalize(SecureAggState *sa, double *result) {
    if (!sa->encrypted_sum || !result) return;
    for (size_t i = 0; i < sa->num_params; i++) {
        result[i] = sa->encrypted_sum[i] / (double)(sa->num_participants > 0 ?
                    sa->num_participants : 1);
    }
}

void secagg_free(SecureAggState *sa) {
    free(sa->encrypted_sum);
    free(sa->shared_mask);
    sa->encrypted_sum = NULL;
    sa->shared_mask   = NULL;
}

/* ---------- DP in FL ---------- */

void fl_dp_clip_update(double *gradients, size_t n, double clip_norm) {
    double norm_sq = 0.0;
    for (size_t i = 0; i < n; i++) norm_sq += gradients[i] * gradients[i];
    double norm = sqrt(norm_sq);
    if (norm > clip_norm) {
        double scale = clip_norm / norm;
        for (size_t i = 0; i < n; i++) gradients[i] *= scale;
    }
}

void fl_dp_add_noise(double *gradients, size_t n, double epsilon, double delta,
                     double sensitivity, uint64_t *seed) {
    double c2  = 2.0 * log(1.25 / delta);
    double sigma = sensitivity * sqrt(c2) / epsilon;
    for (size_t i = 0; i < n; i++) {
        double u1 = (double)((*seed * 0x9E3779B97F4A7C15ULL) >> 33) / (double)(1ULL << 31);
        double u2 = (double)((*seed * 0x5851F42D4C957F2DULL) >> 33) / (double)(1ULL << 31);
        if (u1 < 1e-12) u1 = 1e-12;
        double z = sqrt(-2.0 * log(u1)) * cos(2.0 * 3.14159265358979323846 * u2);
        gradients[i] += sigma * z;
        *seed = *seed * 6364136223846793005ULL + 1442695040888963407ULL;
    }
}

void fl_dp_protect_update(double *gradients, size_t n, double epsilon, double delta,
                          double clip_norm, uint64_t *seed) {
    fl_dp_clip_update(gradients, n, clip_norm);
    fl_dp_add_noise(gradients, n, epsilon, delta, clip_norm, seed);
}

/* ---------- vertical FL ---------- */

void vfl_party_init(VFLParty *party, size_t num_features, int party_id) {
    party->partial_gradients = (double *)calloc(num_features, sizeof(double));
    party->num_features      = num_features;
    party->party_id          = party_id;
    party->local_weights     = (double *)calloc(num_features, sizeof(double));
}

void vfl_party_compute(VFLParty *party, const double *features, const double *labels,
                       size_t n) {
    if (!party->partial_gradients || !features || !labels) return;
    for (size_t i = 0; i < n; i++) {
        double pred = 0.0;
        for (size_t f = 0; f < party->num_features; f++) {
            pred += features[i * party->num_features + f] * party->local_weights[f];
        }
        double error = pred - labels[i];
        for (size_t f = 0; f < party->num_features; f++) {
            party->partial_gradients[f] += error * features[i * party->num_features + f];
        }
    }
}

void vfl_party_free(VFLParty *party) {
    free(party->partial_gradients);
    free(party->local_weights);
    party->partial_gradients = NULL;
    party->local_weights     = NULL;
}

/* ---------- horizontal FL ---------- */

void hfl_aggregate(HFLAggregator *agg, double *global_weights, double lr) {
    if (!agg || !global_weights) return;
    FedAvgState state;
    fedavg_init(&state, (size_t)agg->updates[0].num_params);
    agg->num_updates = 0;
    fedavg_apply(&state, global_weights, lr);
    fedavg_free(&state);
}

void hfl_client_train(const FLModel *model, const double *data,
                      size_t num_samples, size_t num_features,
                      double *gradients, int epochs, double lr) {
    if (!model || !data || !gradients) return;
    memset(gradients, 0, model->num_params * sizeof(double));
    for (int e = 0; e < epochs; e++) {
        for (size_t s = 0; s < num_samples; s++) {
            double pred = 0.0;
            for (size_t f = 0; f < num_features; f++) {
                pred += model->weights[f] * data[s * num_features + f];
            }
            double error = pred;
            for (size_t f = 0; f < num_features; f++) {
                gradients[f] += error * data[s * num_features + f] / (double)num_samples;
            }
        }
        for (size_t f = 0; f < model->num_params; f++) {
            gradients[f] *= lr;
        }
    }
}

/* ---------- client selection ---------- */

void fl_random_select(FLServer *server, uint64_t *seed) {
    if (!server || server->num_clients <= 0) return;
    int *pool = (int *)malloc((size_t)server->num_clients * sizeof(int));
    if (!pool) return;
    for (int i = 0; i < server->num_clients; i++) {
        pool[i] = i;
        server->clients[i].selected = 0;
    }
    shuffle_indices(pool, server->num_clients, seed);
    int sel = server->num_selected;
    if (sel > server->num_clients) sel = server->num_clients;
    for (int i = 0; i < sel; i++) {
        server->clients[pool[i]].selected = 1;
    }
    free(pool);
}

void fl_weighted_select(FLServer *server, const double *data_quality_scores) {
    if (!server || !data_quality_scores) return;
    for (int i = 0; i < server->num_clients; i++) {
        server->clients[i].selected = 0;
    }
    double total = 0.0;
    for (int i = 0; i < server->num_clients; i++) {
        total += data_quality_scores[i];
    }
    if (total <= 0.0) return;
    int selected = 0;
    uint64_t seed = (uint64_t)time(NULL);
    for (int i = 0; i < server->num_clients && selected < server->num_selected; i++) {
        double prob = data_quality_scores[i] / total;
        if (uniform_random_64(&seed) < prob) {
            server->clients[i].selected = 1;
            selected++;
        }
    }
}

/* ---------- convergence tracking ---------- */

double fl_compute_update_norm(const double *update, size_t n) {
    double sum_sq = 0.0;
    for (size_t i = 0; i < n; i++) {
        sum_sq += update[i] * update[i];
    }
    return sqrt(sum_sq);
}

int fl_check_convergence(const FLServer *server, double tolerance) {
    if (!server) return 0;
    double norm = 0.0;
    for (size_t i = 0; i < server->global_model.num_params; i++) {
        norm += server->global_model.weights[i] * server->global_model.weights[i];
    }
    return sqrt(norm) < tolerance ? 1 : 0;
}
