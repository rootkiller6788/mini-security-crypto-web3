#include "anonymization.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

/* ---------- k-anonymity ---------- */

void kanon_init_dataset(AnonDataset *ds, size_t num_records, size_t num_qi,
                        char **qi_names) {
    ds->num_records = num_records;
    ds->num_quasi   = num_qi;
    ds->qi_names    = qi_names;
    ds->records     = (AnonRecord *)calloc(num_records, sizeof(AnonRecord));
}

void kanon_add_record(AnonDataset *ds, size_t idx, AnonRecord *rec) {
    if (!ds || !ds->records || idx >= ds->num_records || !rec) return;
    memcpy(&ds->records[idx], rec, sizeof(AnonRecord));
    ds->records[idx].record_id = (int)idx;
}

int kanon_check(const AnonDataset *ds, int k, KAnonymityResult *result) {
    if (!ds || !result) return 0;
    result->k = k;
    result->satisfied = 1;
    size_t max_groups = ds->num_records > 0 ? ds->num_records : 1;
    result->group_ids = (int *)calloc(max_groups, sizeof(int));
    result->num_groups = 0;
    int *eq_classes = (int *)calloc(max_groups, sizeof(int));
    if (!result->group_ids || !eq_classes) {
        free(result->group_ids);
        free(eq_classes);
        return 0;
    }
    for (size_t i = 0; i < ds->num_records; i++) {
        int found = 0;
        for (size_t j = 0; j < i; j++) {
            int matches = 1;
            for (size_t q = 0; q < ds->num_quasi; q++) {
                if (ds->records[i].values[q] && ds->records[j].values[q]) {
                    if (strcmp(ds->records[i].values[q], ds->records[j].values[q]) != 0) {
                        matches = 0;
                        break;
                    }
                }
            }
            if (matches) {
                result->group_ids[i] = result->group_ids[j];
                found = 1;
                break;
            }
        }
        if (!found) {
            result->group_ids[i] = (int)result->num_groups++;
        }
        if ((size_t)result->group_ids[i] < max_groups) {
            eq_classes[result->group_ids[i]]++;
        }
    }
    for (size_t g = 0; g < result->num_groups; g++) {
        if (eq_classes[g] < k) {
            result->satisfied = 0;
            break;
        }
    }
    free(eq_classes);
    return result->satisfied;
}

void kanon_generalize(AnonDataset *ds, int qi_index, int level) {
    if (!ds || qi_index < 0 || (size_t)qi_index >= ds->num_quasi) return;
    for (size_t i = 0; i < ds->num_records; i++) {
        if (!ds->records[i].values[qi_index]) continue;
        size_t len = strlen(ds->records[i].values[qi_index]);
        size_t keep = len > (size_t)level ? len - (size_t)level : 0;
        if (keep < len && keep < sizeof(ds->records[i].values[0])) {
            char *v = ds->records[i].values[qi_index];
            if (keep == 0) {
                strcpy(v, "*");
            } else {
                v[keep] = '\0';
                strcat(v, "*");
            }
        }
    }
}

void kanon_suppress_records(AnonDataset *ds, double threshold) {
    if (!ds) return;
    for (size_t i = 0; i < ds->num_records; i++) {
        double suppression_prob = ((double)rand() / (double)RAND_MAX);
        if (suppression_prob < threshold) {
            for (size_t q = 0; q < ds->num_quasi; q++) {
                free(ds->records[i].values[q]);
                ds->records[i].values[q] = strdup("*");
            }
        }
    }
}

int kanon_equivalence_class(const AnonDataset *ds, int k, int *group_sizes,
                            size_t *num_groups) {
    if (!ds || !group_sizes || !num_groups) return 0;
    KAnonymityResult kr;
    int ret = kanon_check(ds, k, &kr);
    *num_groups = kr.num_groups;
    int *temp = (int *)calloc(kr.num_groups, sizeof(int));
    if (temp) {
        for (size_t i = 0; i < ds->num_records; i++) {
            if ((size_t)kr.group_ids[i] < kr.num_groups) {
                temp[kr.group_ids[i]]++;
            }
        }
        for (size_t g = 0; g < kr.num_groups; g++) {
            group_sizes[g] = temp[g];
        }
        free(temp);
    }
    free(kr.group_ids);
    return ret;
}

void kanon_free_dataset(AnonDataset *ds) {
    if (!ds || !ds->records) return;
    for (size_t i = 0; i < ds->num_records; i++) {
        for (int j = 0; j < ds->records[i].num_qi; j++) {
            free(ds->records[i].values[j]);
        }
        free(ds->records[i].sensitive_attr);
    }
    free(ds->records);
    ds->records = NULL;
}

/* ---------- l-diversity ---------- */

int ldiversity_check(const AnonDataset *ds, int l, LDiversityResult *result) {
    if (!ds || !result) return 0;
    result->l = l;
    result->satisfied = 1;
    int *groups = (int *)calloc(ds->num_records, sizeof(int));
    if (!groups) return 0;
    for (size_t i = 0; i < ds->num_records; i++) {
        int grp = 0;
        for (size_t j = 0; j < i; j++) {
            int eq = 1;
            for (size_t q = 0; q < ds->num_quasi; q++) {
                if (ds->records[i].values[q] && ds->records[j].values[q]) {
                    if (strcmp(ds->records[i].values[q], ds->records[j].values[q]) != 0) {
                        eq = 0; break;
                    }
                }
            }
            if (eq) { grp = groups[j]; break; }
        }
        if (grp == 0 && i > 0) {
            int maxg = 0;
            for (size_t j = 0; j < i; j++) if (groups[j] > maxg) maxg = groups[j];
            grp = maxg + 1;
        }
        if (i == 0) grp = 1;
        groups[i] = grp;
    }
    int max_grp = 0;
    for (size_t i = 0; i < ds->num_records; i++) {
        if (groups[i] > max_grp) max_grp = groups[i];
    }
    result->num_groups = (size_t)max_grp;
    result->distinct_values = (int *)calloc(result->num_groups, sizeof(int));
    for (size_t i = 0; i < ds->num_records; i++) {
        int g_idx = groups[i] - 1;
        if (g_idx >= 0 && (size_t)g_idx < result->num_groups) {
            result->distinct_values[g_idx] = 1;
            for (size_t j = 0; j < i; j++) {
                if (groups[j] - 1 == g_idx) {
                    if (ds->records[i].sensitive_attr && ds->records[j].sensitive_attr &&
                        strcmp(ds->records[i].sensitive_attr, ds->records[j].sensitive_attr) != 0) {
                        result->distinct_values[g_idx]++;
                        break;
                    }
                }
            }
        }
    }
    for (size_t g = 0; g < result->num_groups; g++) {
        if (result->distinct_values[g] < l) {
            result->satisfied = 0;
            break;
        }
    }
    free(groups);
    return result->satisfied;
}

int ldiversity_entropy_l(const AnonDataset *ds, double min_entropy,
                         LDiversityResult *result) {
    if (!ds || !result) return 0;
    result->l = (int)ceil(pow(2.0, min_entropy));
    int base = ldiversity_check(ds, result->l, result);
    if (result->distinct_values) {
        free(result->distinct_values);
        result->distinct_values = NULL;
    }
    return base;
}

int ldiversity_recursive(const AnonDataset *ds, double c, LDiversityResult *result) {
    if (!ds || !result || result->l < 1) return 0;
    result->satisfied = 1;
    for (size_t g = 0; g < result->num_groups; g++) {
        double freq_common = (result->distinct_values && result->num_groups > g) ?
                             1.0 / (double)result->distinct_values[g] : 0.5;
        double rf = freq_common + c * (1.0 - freq_common);
        if (rf > 0.8) result->satisfied = 0;
    }
    return result->satisfied;
}

int ldiversity_enforce(AnonDataset *ds, int l) {
    if (!ds) return 0;
    LDiversityResult res;
    if (!ldiversity_check(ds, l, &res)) {
        for (size_t i = 0; i < ds->num_records && i < 16; i++) {
            if (ds->records[i].num_qi < 16) {
                ds->records[i].values[ds->records[i].num_qi] = strdup("generalized");
                ds->records[i].num_qi++;
            }
        }
    }
    if (res.distinct_values) free(res.distinct_values);
    return 1;
}

/* ---------- t-closeness ---------- */

void tclose_compute_overall_dist(const AnonDataset *ds, double *dist, int *num_cat) {
    if (!ds || !dist || !num_cat) return;
    int cat_count = 0;
    char *seen[32] = {NULL};
    memset(dist, 0, 32 * sizeof(double));
    for (size_t i = 0; i < ds->num_records; i++) {
        if (!ds->records[i].sensitive_attr) continue;
        int found = 0;
        for (int j = 0; j < cat_count; j++) {
            if (seen[j] && strcmp(ds->records[i].sensitive_attr, seen[j]) == 0) {
                dist[j] += 1.0;
                found = 1;
                break;
            }
        }
        if (!found && cat_count < 32) {
            seen[cat_count] = ds->records[i].sensitive_attr;
            dist[cat_count] = 1.0;
            cat_count++;
        }
    }
    double total = (double)ds->num_records;
    for (int i = 0; i < cat_count; i++) dist[i] /= total;
    *num_cat = cat_count;
}

int tclose_check(const AnonDataset *ds, double t, TClosenessResult *result) {
    if (!ds || !result) return 0;
    result->t = t;
    result->satisfied = 1;
    tclose_compute_overall_dist(ds, result->overall_dist, &result->num_categories);
    result->num_groups = 4;
    result->emd_distances = (double *)calloc(result->num_groups, sizeof(double));
    if (!result->emd_distances) return 0;
    for (size_t g = 0; g < result->num_groups; g++) {
        double group_dist[32] = {0};
        int gc = 0;
        for (size_t i = 0; i < ds->num_records; i++) {
            if ((i % result->num_groups) == g && ds->records[i].sensitive_attr) {
                for (int j = 0; j < result->num_categories; j++) {
                    if (strcmp(ds->records[i].sensitive_attr,
                               ds->records[0].sensitive_attr ? ds->records[0].sensitive_attr : "") == 0) {
                        group_dist[j] += 1.0;
                    }
                }
                gc++;
            }
        }
        if (gc > 0) for (int j = 0; j < result->num_categories; j++) group_dist[j] /= (double)gc;
        result->emd_distances[g] = tclose_emd(group_dist, result->overall_dist,
                                              result->num_categories);
        if (result->emd_distances[g] > t) result->satisfied = 0;
    }
    return result->satisfied;
}

double tclose_emd(const double *dist_p, const double *dist_q, int n) {
    double emd = 0.0;
    double cum = 0.0;
    for (int i = 0; i < n; i++) {
        cum += dist_p[i] - dist_q[i];
        emd += fabs(cum);
    }
    return emd;
}

/* ---------- pseudonymization ---------- */

void pseud_init(Pseudonym *p, size_t output_len, uint64_t serial) {
    p->pseudonym_len = output_len;
    p->serial        = serial;
    p->pseudonym     = (uint8_t *)calloc(output_len, 1);
    p->token         = (uint8_t *)calloc(32, 1);
}

void pseud_generate(Pseudonym *p, const uint8_t *identifier, size_t id_len) {
    if (!p || !identifier) return;
    uint32_t hash = 0x811c9dc5;
    uint32_t serial_hash = (uint32_t)(p->serial * 0x5bd1e995);
    for (size_t i = 0; i < id_len; i++) {
        hash ^= (uint32_t)identifier[i];
        hash *= 0x01000193;
    }
    hash ^= serial_hash;
    for (size_t i = 0; i < p->pseudonym_len && i < 32; i++) {
        p->pseudonym[i] = (uint8_t)((hash >> (8 * (i % 4))) & 0xFF);
        hash = hash * 0x5bd1e995 + (uint32_t)i;
    }
    for (int i = 0; i < 4; i++) {
        p->token[i * 8] = (uint8_t)((p->serial >> (i * 8)) & 0xFF);
    }
}

int pseud_verify(const Pseudonym *p, const uint8_t *identifier, size_t id_len) {
    if (!p || !identifier) return 0;
    Pseudonym temp;
    pseud_init(&temp, p->pseudonym_len, p->serial);
    pseud_generate(&temp, identifier, id_len);
    int match = (memcmp(p->pseudonym, temp.pseudonym, p->pseudonym_len) == 0) ? 1 : 0;
    pseud_free(&temp);
    return match;
}

void pseud_serialize(const Pseudonym *p, uint8_t *buffer, size_t *buf_len) {
    if (!p || !buffer || !buf_len) return;
    *buf_len = p->pseudonym_len + 8;
    memcpy(buffer, p->pseudonym, p->pseudonym_len);
    for (int i = 0; i < 8; i++) {
        buffer[p->pseudonym_len + i] = (uint8_t)((p->serial >> (i * 8)) & 0xFF);
    }
}

void pseud_free(Pseudonym *p) {
    free(p->pseudonym);
    free(p->token);
    p->pseudonym = NULL;
    p->token     = NULL;
}

/* ---------- de-anonymization attack simulation ---------- */

void deanon_attack_linkage(const AnonDataset *anonymized, const AnonDataset *auxiliary,
                           DeAnonRisk *risk) {
    if (!anonymized || !auxiliary || !risk) return;
    memset(risk, 0, sizeof(DeAnonRisk));
    size_t matched = 0;
    for (size_t i = 0; i < anonymized->num_records && i < auxiliary->num_records; i++) {
        int qi_match = 0;
        for (size_t q = 0; q < anonymized->num_quasi && q < auxiliary->num_quasi; q++) {
            if (anonymized->records[i].values[q] && auxiliary->records[i].values[q] &&
                strcmp(anonymized->records[i].values[q], auxiliary->records[i].values[q]) == 0) {
                qi_match++;
            }
        }
        if (qi_match > 0 && (size_t)qi_match >= anonymized->num_quasi / 2) matched++;
    }
    risk->linkage_success_rate = anonymized->num_records > 0 ?
                                  (double)matched / (double)anonymized->num_records : 0.0;
    risk->num_vulnerable_records = (int)matched;
}

void deanon_attack_netflix(const AnonDataset *ds, DeAnonRisk *risk) {
    if (!ds || !risk) return;
    risk->netflix_style_risk = ds->num_records > 0 ?
                               1.0 - exp(-(double)ds->num_records / 100.0) : 0.0;
    risk->reidentification_score = risk->netflix_style_risk * 0.7;
}

void deanon_attack_aol(const AnonDataset *ds, DeAnonRisk *risk) {
    if (!ds || !risk) return;
    risk->aol_style_risk = ds->num_records > 0 ?
                           log((double)ds->num_records) / log(1000.0) : 0.0;
    if (risk->aol_style_risk > 1.0) risk->aol_style_risk = 1.0;
    risk->reidentification_score = risk->aol_style_risk * 0.85;
}

/* ---------- re-identification risk scoring ---------- */

void reid_score_compute(const AnonDataset *ds, ReIdRiskScore *score) {
    if (!ds || !score) return;
    memset(score, 0, sizeof(ReIdRiskScore));
    size_t unique_count = 0;
    for (size_t i = 0; i < ds->num_records; i++) {
        int unique = 1;
        for (size_t j = 0; j < ds->num_records; j++) {
            if (i == j) continue;
            int matches = 1;
            for (size_t q = 0; q < ds->num_quasi; q++) {
                if (ds->records[i].values[q] && ds->records[j].values[q]) {
                    if (strcmp(ds->records[i].values[q], ds->records[j].values[q]) != 0) {
                        matches = 0; break;
                    }
                }
            }
            if (matches) { unique = 0; break; }
        }
        if (unique) unique_count++;
    }
    score->uniqueness_score = ds->num_records > 0 ?
                               (double)unique_count / (double)ds->num_records : 0.0;
    score->prosecutor_risk = score->uniqueness_score;
    score->journalist_risk = 1.0 - pow(1.0 - score->uniqueness_score,
                                       (double)ds->num_records);
    score->marketer_risk   = score->uniqueness_score * 0.5;
    score->population_estimate = (double)ds->num_records * score->uniqueness_score * 100.0;
}

int reid_score_assess(const ReIdRiskScore *score, double threshold) {
    if (!score) return 0;
    return (score->prosecutor_risk > threshold) ? 0 : 1;
}

void reid_score_report(const ReIdRiskScore *score, char *report, size_t max_len) {
    if (!score || !report) return;
    snprintf(report, max_len,
             "Re-id Risk: prosecutor=%.4f journalist=%.4f marketer=%.4f unique=%.4f pop=%.0f",
             score->prosecutor_risk, score->journalist_risk, score->marketer_risk,
             score->uniqueness_score, score->population_estimate);
}

/* ---------- utility ---------- */

void anon_measure_utility(const AnonDataset *original, const AnonDataset *anonymized,
                          AnonUtilityScore *score) {
    if (!original || !anonymized || !score) return;
    memset(score, 0, sizeof(AnonUtilityScore));
    for (size_t i = 0; i < anonymized->num_records && i < original->num_records; i++) {
        for (size_t q = 0; q < anonymized->num_quasi && q < original->num_quasi; q++) {
            if (original->records[i].values[q] && anonymized->records[i].values[q]) {
                if (strcmp(original->records[i].values[q],
                           anonymized->records[i].values[q]) != 0) {
                    score->num_generalized++;
                }
            }
        }
    }
    score->information_loss = original->num_records > 0 ?
        (double)score->num_generalized / (double)(original->num_records * original->num_quasi) : 0.0;
}

int anon_validate_invariants(const AnonDataset *ds, const int *required_groups,
                             int num_required) {
    if (!ds || !required_groups) return 0;
    for (int i = 0; i < num_required; i++) {
        if (required_groups[i] < 2) return 0;
    }
    return 1;
}
