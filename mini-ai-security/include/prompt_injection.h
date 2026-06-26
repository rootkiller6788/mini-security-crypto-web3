#ifndef PROMPT_INJECTION_H
#define PROMPT_INJECTION_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PI_MAX_PROMPT_LEN    65536
#define PI_MAX_RESPONSE_LEN  65536
#define PI_MAX_RULES          256
#define PI_MAX_BLOCKLIST      1024

typedef enum {
    PI_DIRECT_INJECTION = 0,
    PI_INDIRECT_INJECTION = 1,
    PI_JAILBREAK = 2,
    PI_PROMPT_LEAKING = 3,
    PI_DATA_EXFILTRATION = 4,
    PI_ROLE_PLAY_BYPASS = 5,
    PI_ENCODING_BYPASS = 6,
    PI_MULTILINGUAL_BYPASS = 7,
    PI_CONTEXT_OVERFLOW = 8,
    PI_CHAINED_ATTACK = 9
} pi_attack_type_t;

typedef enum {
    PI_DEFENSE_INSTRUCTION_HIERARCHY = 0,
    PI_DEFENSE_OUTPUT_FILTER = 1,
    PI_DEFENSE_CONSTRAINT_CHECK = 2,
    PI_DEFENSE_GUARD_MODEL = 3,
    PI_DEFENSE_RLHF_ALIGNMENT = 4,
    PI_DEFENSE_SANDWICH_DEFENSE = 5,
    PI_DEFENSE_INPUT_CANON = 6,
    PI_DEFENSE_PERPLEXITY_CHECK = 7
} pi_defense_type_t;

typedef enum {
    PI_SEVERITY_SAFE = 0,
    PI_SEVERITY_LOW = 1,
    PI_SEVERITY_MEDIUM = 2,
    PI_SEVERITY_HIGH = 3,
    PI_SEVERITY_CRITICAL = 4
} pi_severity_t;

typedef enum {
    PI_ROLE_SYSTEM = 0,
    PI_ROLE_USER = 1,
    PI_ROLE_ASSISTANT = 2,
    PI_ROLE_TOOL = 3,
    PI_ROLE_EXTERNAL = 4
} pi_message_role_t;

typedef struct {
    char   *content;
    size_t  length;
    pi_message_role_t role;
    int     is_trusted_source;
} pi_message_t;

typedef struct {
    pi_attack_type_t type;
    char             *injection_text;
    size_t           injection_len;
    char             *target_instruction;
    int              use_encoding_obfuscation;
    int              chain_count;
    double           perplexity_threshold;
    int              max_retry_attempts;
} pi_attack_config_t;

typedef struct {
    pi_defense_type_t type;
    int    enforce_hierarchy;
    int    filter_harmful;
    int    filter_pii;
    int    check_constraints;
    int    use_guard_model;
    int    rlhf_aligned;
    char   **rule_list;
    size_t rule_count;
    double guard_threshold;
} pi_defense_config_t;

typedef struct {
    pi_severity_t severity;
    double        confidence;
    char          *reason;
    size_t        reason_len;
    int           is_jailbreak;
    int           contains_pii;
    int           data_leak_detected;
    double        guard_score;
} pi_detection_result_t;

typedef struct {
    char   *sanitized_prompt;
    size_t sanitized_len;
    int    was_modified;
    int    modifications_made;
    char   *explanation;
} pi_sanitize_result_t;

typedef struct {
    double alignment_score;
    double harmfulness_score;
    double helpfulness_score;
    double honesty_score;
    double refusal_probability;
    int    should_refuse;
} pi_alignment_eval_t;

pi_message_t  pi_message_create(const char *content, pi_message_role_t role);
void          pi_message_free(pi_message_t *msg);

pi_attack_config_t  pi_attack_config_default(pi_attack_type_t type);
pi_defense_config_t pi_defense_config_default(pi_defense_type_t type);

void pi_detect_injection(pi_detection_result_t *result,
                         const pi_message_t *messages,
                         size_t num_messages,
                         const pi_defense_config_t *config);

int  pi_check_instruction_override(const char *system_prompt,
                                   const pi_message_t *user_message,
                                   const pi_defense_config_t *config);

void pi_sanitize_input(pi_sanitize_result_t *result,
                       const char *prompt,
                       const pi_defense_config_t *config);

int  pi_validate_output(const char *response,
                        const char *prompt,
                        const pi_defense_config_t *config);

void pi_guard_model_evaluate(pi_detection_result_t *result,
                             const char *prompt,
                             const char *response,
                             const pi_defense_config_t *config);

double pi_guard_score(const char *text, const char **dangerous_patterns,
                      size_t num_patterns);

void pi_enforce_instruction_hierarchy(pi_message_t *messages,
                                      size_t num_messages,
                                      const pi_defense_config_t *config);

int  pi_detect_indirect_injection(const pi_message_t *message,
                                  const char *external_data_sources[],
                                  size_t num_sources);

int  pi_detect_jailbreak(const char *prompt,
                         const pi_defense_config_t *config,
                         pi_severity_t *severity);

int  pi_detect_prompt_leaking(const char *response,
                              const char *system_prompt,
                              double *leak_score);

int  pi_detect_data_exfiltration(const char *response,
                                 const char *sensitive_patterns[],
                                 size_t num_patterns,
                                 double *exfil_score);

void pi_apply_rlhf_safety(const char *prompt,
                          char *response,
                          size_t response_capacity,
                          const pi_defense_config_t *config);

void pi_evaluate_alignment(pi_alignment_eval_t *eval,
                           const char *prompt,
                           const char *response);

void pi_constraint_check(const char *prompt,
                         const char *response,
                         const char **constraints,
                         size_t num_constraints,
                         int *violations);

int  pi_perplexity_check(const char *text,
                         double *perplexity,
                         double *burstiness);

void pi_detect_encoding_obfuscation(const char *text,
                                    int *encoding_flags,
                                    int *suspicion_score);

void pi_context_window_protect(pi_message_t *messages,
                               size_t num_messages,
                               size_t max_length,
                               size_t *truncated_to);

int  pi_multi_turn_defense(const pi_message_t *conversation,
                           size_t num_turns,
                           int *cumulative_risk,
                           const pi_defense_config_t *config);

const char *pi_attack_type_name(pi_attack_type_t type);
const char *pi_defense_type_name(pi_defense_type_t type);
const char *pi_severity_name(pi_severity_t severity);

#ifdef __cplusplus
}
#endif

#endif
