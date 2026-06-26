#include "prompt_injection.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

pi_message_t pi_message_create(const char *content, pi_message_role_t role)
{
    pi_message_t msg;
    memset(&msg, 0, sizeof(msg));
    if (content) {
        msg.length  = strlen(content);
        msg.content = (char *)malloc(msg.length + 1);
        if (msg.content) memcpy(msg.content, content, msg.length + 1);
    }
    msg.role              = role;
    msg.is_trusted_source = (role == PI_ROLE_SYSTEM) ? 1 : 0;
    return msg;
}

void pi_message_free(pi_message_t *msg)
{
    if (msg && msg->content) { free(msg->content); msg->content = NULL; msg->length = 0; }
}

pi_attack_config_t pi_attack_config_default(pi_attack_type_t type)
{
    pi_attack_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.type                     = type;
    cfg.injection_text           = NULL;
    cfg.injection_len            = 0;
    cfg.target_instruction       = NULL;
    cfg.use_encoding_obfuscation = 0;
    cfg.chain_count              = 1;
    cfg.perplexity_threshold     = 10.0;
    cfg.max_retry_attempts       = 5;
    return cfg;
}

pi_defense_config_t pi_defense_config_default(pi_defense_type_t type)
{
    pi_defense_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.type                = type;
    cfg.enforce_hierarchy   = 1;
    cfg.filter_harmful      = 1;
    cfg.filter_pii          = 1;
    cfg.check_constraints   = 1;
    cfg.use_guard_model     = (type == PI_DEFENSE_GUARD_MODEL) ? 1 : 0;
    cfg.rlhf_aligned        = (type == PI_DEFENSE_RLHF_ALIGNMENT) ? 1 : 0;
    cfg.rule_list           = NULL;
    cfg.rule_count          = 0;
    cfg.guard_threshold     = 0.7;
    return cfg;
}

static const char *s_dangerous_patterns[] = {
    "ignore previous instructions",
    "pretend you are",
    "you are now",
    "do anything now",
    "DAN mode",
    "jailbreak",
    "system prompt:",
    "override",
    "you must",
    "disregard",
    "new instructions:",
    "forget all previous",
    "roleplay as",
    "act as",
    "from now on"
};

static const size_t s_num_dangerous = sizeof(s_dangerous_patterns) / sizeof(s_dangerous_patterns[0]);

void pi_detect_injection(pi_detection_result_t *result,
                         const pi_message_t *messages,
                         size_t num_messages,
                         const pi_defense_config_t *config)
{
    size_t i, np;
    double max_score = 0.0;
    memset(result, 0, sizeof(*result));

    for (i = 0; i < num_messages; i++) {
        if (messages[i].role == PI_ROLE_USER || messages[i].role == PI_ROLE_EXTERNAL) {
            double score = 0.0;
            for (np = 0; np < s_num_dangerous; np++) {
                const char *pat = s_dangerous_patterns[np];
                if (messages[i].content && strstr(messages[i].content, pat))
                    score += 0.15;
            }
            if (score > max_score) max_score = score;
        }
    }

    result->confidence    = max_score;
    result->is_jailbreak  = (max_score > 0.5) ? 1 : 0;
    result->guard_score   = max_score;

    if (max_score < 0.2)       result->severity = PI_SEVERITY_SAFE;
    else if (max_score < 0.4)  result->severity = PI_SEVERITY_LOW;
    else if (max_score < 0.6)  result->severity = PI_SEVERITY_MEDIUM;
    else if (max_score < 0.8)  result->severity = PI_SEVERITY_HIGH;
    else                       result->severity = PI_SEVERITY_CRITICAL;

    (void)config;
}

int pi_check_instruction_override(const char *system_prompt,
                                  const pi_message_t *user_message,
                                  const pi_defense_config_t *config)
{
    (void)config;
    if (!system_prompt || !user_message || !user_message->content) return 0;

    if (strstr(user_message->content, "ignore") ||
        strstr(user_message->content, "override") ||
        strstr(user_message->content, "system prompt")) {
        return 1;
    }
    return 0;
}

void pi_sanitize_input(pi_sanitize_result_t *result,
                       const char *prompt,
                       const pi_defense_config_t *config)
{
    const char *bad = "ignore previous instructions";
    memset(result, 0, sizeof(*result));

    result->sanitized_len = prompt ? strlen(prompt) : 0;
    result->sanitized     = (char *)malloc(result->sanitized_len + 1);
    if (!result->sanitized) return;

    if (prompt) memcpy(result->sanitized, prompt, result->sanitized_len + 1);

    if (prompt && config && config->check_constraints) {
        if (strstr(prompt, bad)) {
            char *pos = strstr(result->sanitized, bad);
            if (pos) {
                size_t offset = (size_t)(pos - result->sanitized);
                size_t rest = result->sanitized_len - offset - strlen(bad);
                memmove(pos, pos + strlen(bad), rest + 1);
                result->sanitized_len -= strlen(bad);
                result->was_modified   = 1;
                result->modifications_made = 1;
            }
        }
    }
}

int pi_validate_output(const char *response,
                       const char *prompt,
                       const pi_defense_config_t *config)
{
    (void)prompt; (void)config;
    if (!response) return 0;

    if (strstr(response, "system prompt:") ||
        strstr(response, "Here is the system prompt")) {
        return 0;
    }
    return 1;
}

void pi_guard_model_evaluate(pi_detection_result_t *result,
                             const char *prompt,
                             const char *response,
                             const pi_defense_config_t *config)
{
    double score = 0.0;
    size_t i;
    const char *combined_text = prompt ? prompt : "";
    (void)response;

    for (i = 0; i < s_num_dangerous; i++) {
        if (strstr(combined_text, s_dangerous_patterns[i]))
            score += 0.2;
    }

    memset(result, 0, sizeof(*result));
    result->confidence  = score;
    result->guard_score = score;
    result->severity    = (score > config->guard_threshold) ? PI_SEVERITY_HIGH : PI_SEVERITY_SAFE;
}

double pi_guard_score(const char *text, const char **dangerous_patterns,
                      size_t num_patterns)
{
    double score = 0.0;
    size_t i;
    if (!text) return 0.0;
    for (i = 0; i < num_patterns; i++) {
        if (strstr(text, dangerous_patterns[i])) score += 1.0;
    }
    return score / (double)(num_patterns > 0 ? num_patterns : 1);
}

void pi_enforce_instruction_hierarchy(pi_message_t *messages,
                                      size_t num_messages,
                                      const pi_defense_config_t *config)
{
    size_t i;
    (void)config;
    for (i = 0; i < num_messages; i++) {
        if (messages[i].role == PI_ROLE_SYSTEM)
            messages[i].is_trusted_source = 1;
        else if (messages[i].role == PI_ROLE_USER)
            messages[i].is_trusted_source = 0;
    }
}

int pi_detect_indirect_injection(const pi_message_t *message,
                                 const char *external_data_sources[],
                                 size_t num_sources)
{
    size_t i;
    if (!message || !message->content) return 0;

    for (i = 0; i < num_sources; i++) {
        if (strstr(message->content, external_data_sources[i]))
            return 1;
    }
    return 0;
}

int pi_detect_jailbreak(const char *prompt,
                        const pi_defense_config_t *config,
                        pi_severity_t *severity)
{
    double score = 0.0;
    size_t i;
    (void)config;

    if (!prompt) { if (severity) *severity = PI_SEVERITY_SAFE; return 0; }

    for (i = 0; i < s_num_dangerous; i++) {
        if (strstr(prompt, s_dangerous_patterns[i])) score += 0.3;
    }

    if (severity) {
        if (score > 0.8) *severity = PI_SEVERITY_HIGH;
        else *severity = (score > 0.4) ? PI_SEVERITY_MEDIUM : PI_SEVERITY_SAFE;
    }
    return (score > 0.4) ? 1 : 0;
}

int pi_detect_prompt_leaking(const char *response,
                             const char *system_prompt,
                             double *leak_score)
{
    double score = 0.0;
    if (!response || !system_prompt) { if (leak_score) *leak_score = 0.0; return 0; }

    if (strstr(response, system_prompt)) score = 1.0;
    else if (strstr(response, "system prompt") || strstr(response, "instructions are"))
        score = 0.5;

    if (leak_score) *leak_score = score;
    return (score > 0.3) ? 1 : 0;
}

int pi_detect_data_exfiltration(const char *response,
                                const char *sensitive_patterns[],
                                size_t num_patterns,
                                double *exfil_score)
{
    double score = 0.0;
    size_t i;
    if (!response) { if (exfil_score) *exfil_score = 0.0; return 0; }

    for (i = 0; i < num_patterns; i++) {
        if (strstr(response, sensitive_patterns[i])) score += 1.0;
    }
    score /= (double)(num_patterns > 0 ? num_patterns : 1);

    if (exfil_score) *exfil_score = score;
    return (score > 0.3) ? 1 : 0;
}

void pi_apply_rlhf_safety(const char *prompt,
                          char *response,
                          size_t response_capacity,
                          const pi_defense_config_t *config)
{
    (void)config;
    if (!prompt || !response) return;
    if (pi_detect_jailbreak(prompt, config, NULL))
        snprintf(response, response_capacity, "I cannot fulfill that request.");
}

void pi_evaluate_alignment(pi_alignment_eval_t *eval,
                           const char *prompt,
                           const char *response)
{
    memset(eval, 0, sizeof(*eval));
    if (!prompt || !response) return;

    if (strstr(response, "I cannot") || strstr(response, "I'm sorry")) {
        eval->refusal_probability = 1.0;
        eval->should_refuse       = 1;
        eval->harmfulness_score   = 0.0;
    } else {
        eval->refusal_probability = 0.1;
        eval->should_refuse       = 0;
        eval->harmfulness_score   = 0.3;
    }
    eval->alignment_score   = 0.8;
    eval->helpfulness_score = 0.7;
    eval->honesty_score     = 0.75;
}

void pi_constraint_check(const char *prompt,
                         const char *response,
                         const char **constraints,
                         size_t num_constraints,
                         int *violations)
{
    size_t i;
    *violations = 0;
    (void)prompt;

    for (i = 0; i < num_constraints; i++) {
        if (response && strstr(response, constraints[i]))
            (*violations)++;
    }
}

int pi_perplexity_check(const char *text,
                        double *perplexity,
                        double *burstiness)
{
    size_t len, i;
    if (!text) { if (perplexity) *perplexity = 0.0; if (burstiness) *burstiness = 0.0; return 0; }

    len = strlen(text);
    if (len < 2) { if (perplexity) *perplexity = 1.0; if (burstiness) *burstiness = 0.0; return 0; }

    *perplexity = 1.0 + 100.0 * (double)len / 65536.0;
    *burstiness = 0.0;
    for (i = 1; i < len; i++)
        if (isalpha((unsigned char)text[i]) && isalpha((unsigned char)text[i - 1]))
            *burstiness += 1.0;
    *burstiness /= (double)(len > 0 ? len : 1);

    return 0;
}

void pi_detect_encoding_obfuscation(const char *text,
                                    int *encoding_flags,
                                    int *suspicion_score)
{
    size_t i;
    *encoding_flags   = 0;
    *suspicion_score  = 0;
    if (!text) return;

    for (i = 0; text[i]; i++) {
        if ((unsigned char)text[i] > 127) (*encoding_flags) |= 1;
        if (text[i] == '\\' && text[i + 1] == 'u')  (*encoding_flags) |= 2;
        if (text[i] == '&' && text[i + 1] == '#')   (*encoding_flags) |= 4;
    }
    *suspicion_score = (int)(*encoding_flags > 0);
}

void pi_context_window_protect(pi_message_t *messages,
                               size_t num_messages,
                               size_t max_length,
                               size_t *truncated_to)
{
    size_t total = 0, i;
    *truncated_to = num_messages;

    for (i = 0; i < num_messages; i++)
        total += messages[i].length;

    while (total > max_length && *truncated_to > 1) {
        total -= messages[*truncated_to - 1].length;
        (*truncated_to)--;
    }
}

int pi_multi_turn_defense(const pi_message_t *conversation,
                          size_t num_turns,
                          int *cumulative_risk,
                          const pi_defense_config_t *config)
{
    size_t i;
    size_t np;
    *cumulative_risk = 0;
    (void)config;

    for (i = 0; i < num_turns; i++) {
        if (conversation[i].role == PI_ROLE_USER && conversation[i].content) {
            for (np = 0; np < s_num_dangerous; np++) {
                if (strstr(conversation[i].content, s_dangerous_patterns[np]))
                    (*cumulative_risk)++;
            }
        }
    }
    return *cumulative_risk;
}

const char *pi_attack_type_name(pi_attack_type_t type)
{
    switch (type) {
        case PI_DIRECT_INJECTION:     return "Direct Prompt Injection";
        case PI_INDIRECT_INJECTION:   return "Indirect Injection";
        case PI_JAILBREAK:            return "Jailbreak";
        case PI_PROMPT_LEAKING:       return "Prompt Leaking";
        case PI_DATA_EXFILTRATION:    return "Data Exfiltration";
        case PI_ROLE_PLAY_BYPASS:     return "Role-Play Bypass";
        case PI_ENCODING_BYPASS:      return "Encoding Bypass";
        case PI_MULTILINGUAL_BYPASS:  return "Multilingual Bypass";
        case PI_CONTEXT_OVERFLOW:     return "Context Overflow";
        case PI_CHAINED_ATTACK:       return "Chained Attack";
        default:                      return "Unknown";
    }
}

const char *pi_defense_type_name(pi_defense_type_t type)
{
    switch (type) {
        case PI_DEFENSE_INSTRUCTION_HIERARCHY: return "Instruction Hierarchy";
        case PI_DEFENSE_OUTPUT_FILTER:         return "Output Filtering";
        case PI_DEFENSE_CONSTRAINT_CHECK:      return "Constraint Checking";
        case PI_DEFENSE_GUARD_MODEL:           return "Guard Model";
        case PI_DEFENSE_RLHF_ALIGNMENT:        return "RLHF Safety Alignment";
        case PI_DEFENSE_SANDWICH_DEFENSE:      return "Sandwich Defense";
        case PI_DEFENSE_INPUT_CANON:           return "Input Canonicalization";
        case PI_DEFENSE_PERPLEXITY_CHECK:      return "Perplexity Check";
        default:                               return "Unknown";
    }
}

const char *pi_severity_name(pi_severity_t severity)
{
    switch (severity) {
        case PI_SEVERITY_SAFE:     return "Safe";
        case PI_SEVERITY_LOW:      return "Low";
        case PI_SEVERITY_MEDIUM:   return "Medium";
        case PI_SEVERITY_HIGH:     return "High";
        case PI_SEVERITY_CRITICAL: return "Critical";
        default:                   return "Unknown";
    }
}
