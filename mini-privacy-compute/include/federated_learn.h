#ifndef FEDERATED_LEARN_H
#define FEDERATED_LEARN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- core types ---------- */

typedef struct {
    double *weights;
    size_t  num_params;
    int     version;
} FLModel;

typedef struct {
    double *gradients;
    size_t  num_params;
    int     client_id;
    size_t  local_samples;
} FLUpdate;

typedef struct {
    int    client_id;
    size_t local_data_size;
    int    selected;          /* 1 if selected for current round */
    double last_contribution;
} FLClient;

typedef struct {
    FLModel  global_model;
    FLClient *clients;
    int      num_clients;
    int      num_selected;    /* clients per round */
    int      current_round;
    int      total_rounds;
    double   learning_rate;
    int      local_epochs;
    int      batch_size;
    double   epsilon;         /* DP budget per round */
    double   delta;
} FLServer;

/* ---------- server operations ---------- */

void fl_server_init(         FLServer *server, size_t num_params, int num_clients,
                             int num_selected, int total_rounds, double lr);
void fl_server_free(         FLServer *server);
void fl_server_init_model(   FLServer *server, double *initial_weights);

/* ---------- model distribution ---------- */

void fl_download_model(      FLServer *server, int client_id, double *local_weights);
void fl_upload_update(       FLServer *server, const double *gradients,
                             int client_id, size_t num_samples);

/* ---------- federated averaging (FedAvg) ---------- */

typedef struct {
    double *weighted_sum;
    size_t  total_samples;
    size_t  num_updates;
} FedAvgState;

void fedavg_init(            FedAvgState *state, size_t num_params);
void fedavg_accumulate(      FedAvgState *state, const double *gradients, size_t samples);
void fedavg_apply(           FedAvgState *state, double *global_weights, double lr);
void fedavg_free(            FedAvgState *state);

/* ---------- secure aggregation ---------- */

typedef struct {
    double *encrypted_sum;
    size_t  num_params;
    size_t  num_participants;
    uint8_t *shared_mask;     /* pairwise random mask seed material */
} SecureAggState;

void secagg_init(             SecureAggState *sa, size_t num_params, int num_participants);
void secagg_add_update(       SecureAggState *sa, const double *update, int participant_id);
void secagg_finalize(         SecureAggState *sa, double *result);
void secagg_free(             SecureAggState *sa);

/* ---------- differential privacy in FL ---------- */

void fl_dp_clip_update(       double *gradients, size_t n, double clip_norm);
void fl_dp_add_noise(         double *gradients, size_t n, double epsilon, double delta,
                              double sensitivity, uint64_t *seed);
void fl_dp_protect_update(    double *gradients, size_t n, double epsilon, double delta,
                              double clip_norm, uint64_t *seed);

/* ---------- vertical FL ---------- */

typedef struct {
    double *partial_gradients;
    size_t  num_features;     /* subset of global features */
    int     party_id;
    double *local_weights;
} VFLParty;

void vfl_party_init(         VFLParty *party, size_t num_features, int party_id);
void vfl_party_compute(      VFLParty *party, const double *features, const double *labels,
                             size_t n);
void vfl_party_free(         VFLParty *party);

/* ---------- horizontal FL ---------- */

typedef struct {
    FLUpdate *updates;
    int       num_updates;
    size_t    samples_per_client;
} HFLAggregator;

void hfl_aggregate(          HFLAggregator *agg, double *global_weights, double lr);
void hfl_client_train(       const FLModel *model, const double *data,
                             size_t num_samples, size_t num_features,
                             double *gradients, int epochs, double lr);

/* ---------- client selection ---------- */

void fl_random_select(       FLServer *server, uint64_t *seed);
void fl_weighted_select(     FLServer *server, const double *data_quality_scores);

/* ---------- convergence tracking ---------- */

double fl_compute_update_norm(const double *update, size_t n);
int    fl_check_convergence( const FLServer *server, double tolerance);

#ifdef __cplusplus
}
#endif

#endif /* FEDERATED_LEARN_H */
