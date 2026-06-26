#ifndef ANONYMIZATION_H
#define ANONYMIZATION_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- core types ---------- */

typedef struct {
    char   *quasi_identifiers[16];  /* e.g. age, zip, gender */
    int     num_qi;
    char   *sensitive_attr;        /* e.g. disease */
    char   *values[16];
    int     num_values;
    int     record_id;
} AnonRecord;

typedef struct {
    AnonRecord *records;
    size_t     num_records;
    size_t     num_quasi;
    char       **qi_names;
} AnonDataset;

/* ---------- k-anonymity ---------- */

typedef struct {
    int    *group_ids;
    size_t  num_groups;
    int     k;
    int     satisfied;
} KAnonymityResult;

void kanon_init_dataset(      AnonDataset *ds, size_t num_records, size_t num_qi,
                              char **qi_names);
void kanon_add_record(        AnonDataset *ds, size_t idx, AnonRecord *rec);
int  kanon_check(             const AnonDataset *ds, int k, KAnonymityResult *result);
void kanon_generalize(        AnonDataset *ds, int qi_index, int level);
void kanon_suppress_records(  AnonDataset *ds, double threshold);
int  kanon_equivalence_class( const AnonDataset *ds, int k, int *group_sizes,
                              size_t *num_groups);
void kanon_free_dataset(      AnonDataset *ds);

/* ---------- l-diversity ---------- */

typedef struct {
    int    l;
    int    satisfied;
    int    *distinct_values;    /* count of distinct sensitive values per group */
    size_t num_groups;
} LDiversityResult;

int  ldiversity_check(        const AnonDataset *ds, int l, LDiversityResult *result);
int  ldiversity_entropy_l(    const AnonDataset *ds, double min_entropy,
                              LDiversityResult *result);
int  ldiversity_recursive(    const AnonDataset *ds, double c, LDiversityResult *result);
int  ldiversity_enforce(      AnonDataset *ds, int l);

/* ---------- t-closeness ---------- */

typedef struct {
    double t;
    double overall_dist[32];    /* distribution of sensitive values overall */
    int    num_categories;
    int    satisfied;
    double *emd_distances;      /* Earth Mover's Distance per group */
    size_t num_groups;
} TClosenessResult;

void tclose_compute_overall_dist(const AnonDataset *ds, double *dist, int *num_cat);
int  tclose_check(              const AnonDataset *ds, double t, TClosenessResult *result);
double tclose_emd(              const double *dist_p, const double *dist_q, int n);

/* ---------- pseudonymization ---------- */

typedef struct {
    uint8_t *pseudonym;
    size_t   pseudonym_len;
    uint8_t *token;               /* reversible token */
    uint64_t serial;
} Pseudonym;

void pseud_init(              Pseudonym *p, size_t output_len, uint64_t serial);
void pseud_generate(          Pseudonym *p, const uint8_t *identifier, size_t id_len);
int  pseud_verify(            const Pseudonym *p, const uint8_t *identifier, size_t id_len);
void pseud_serialize(         const Pseudonym *p, uint8_t *buffer, size_t *buf_len);
void pseud_free(              Pseudonym *p);

/* ---------- de-anonymization attack simulation ---------- */

typedef struct {
    double linkage_success_rate;
    double aol_style_risk;        /* search query uniqueness risk */
    double netflix_style_risk;    /* rating pattern uniqueness risk */
    double reidentification_score;
    int    num_vulnerable_records;
} DeAnonRisk;

void deanon_attack_linkage(    const AnonDataset *anonymized, const AnonDataset *auxiliary,
                               DeAnonRisk *risk);
void deanon_attack_netflix(    const AnonDataset *ds, DeAnonRisk *risk);
void deanon_attack_aol(        const AnonDataset *ds, DeAnonRisk *risk);

/* ---------- re-identification risk scoring ---------- */

typedef struct {
    double prosecutor_risk;       /* risk of matching specific target */
    double journalist_risk;       /* risk of finding any match in population */
    double marketer_risk;         /* risk of linking at least one record */
    double uniqueness_score;      /* fraction of unique records */
    double population_estimate;   /* estimated re-identifiable population */
} ReIdRiskScore;

void reid_score_compute(       const AnonDataset *ds, ReIdRiskScore *score);
int  reid_score_assess(        const ReIdRiskScore *score, double threshold);
void reid_score_report(        const ReIdRiskScore *score, char *report, size_t max_len);

/* ---------- utility ---------- */

typedef struct {
    double information_loss;
    double precision_loss;
    int    num_suppressed;
    int    num_generalized;
} AnonUtilityScore;

void anon_measure_utility(    const AnonDataset *original, const AnonDataset *anonymized,
                              AnonUtilityScore *score);
int  anon_validate_invariants(const AnonDataset *ds, const int *required_groups,
                              int num_required);

#ifdef __cplusplus
}
#endif

#endif /* ANONYMIZATION_H */
