# API Reference — mini-ai-security

## adversarial_ml.h

### Types

| Type | Description |
|------|-------------|
| `adv_attack_type_t` | FGSM, PGD, C&W L2/Linf, Patch, Physical |
| `adv_defense_type_t` | Training, Distillation, InputTransform, FeatureSqueeze, Ensemble |
| `adv_norm_t` | L1, L2, Linf |
| `adv_tensor_t` | Tensor with data, dims, stride |
| `adv_attack_config_t` | Attack configuration (epsilon, alpha, iterations...) |
| `adv_defense_config_t` | Defense configuration (temperature, ensemble_count...) |
| `adv_gradient_info_t` | Gradient info (gradients, loss, predictions) |
| `adv_model_output_t` | Model output (logits, num_classes, temperature) |

### Functions

| Function | Description |
|----------|-------------|
| `adv_tensor_create(dims)` | Allocate tensor |
| `adv_tensor_free(t)` | Free tensor |
| `adv_tensor_clone(src)` | Deep copy tensor |
| `adv_fgsm_generate(adv, input, grad, eps)` | Generate FGSM adversarial sample |
| `adv_fgsm_targeted(adv, input, grad, eps)` | Targeted FGSM |
| `adv_pgd_generate(adv, input, grads, cfg)` | Generate PGD adversarial sample |
| `adv_pgd_iteration(cur, grad, alpha, norm)` | Single PGD step |
| `adv_clip_perturbation(adv, orig, eps, norm)` | Clip perturbation to ε-ball |
| `adv_cw_loss(logits, target, true, norm, conf, out)` | Compute C&W loss |
| `adv_patch_apply(img, patch, row, col)` | Apply patch to image |
| `adv_patch_generate(patch, images, n, cfg)` | Generate adversarial patch |
| `adv_physical_transform(out, in, rot, scale, bright)` | Physical world transform |
| `adv_physical_robustness_score(orig, trans, norm)` | Robustness score |
| `adv_input_transform_defense(out, in, cfg)` | Input transformation defense |
| `adv_bit_depth_reduce(out, in, bits)` | Bit depth reduction |
| `adv_median_filter(out, in, ksize)` | Median filter |
| `adv_gaussian_noise_defense(out, in, std)` | Gaussian noise injection |
| `adv_random_resize_pad(out, in, min, max)` | Random resize + pad |
| `adv_perturbation_norm(orig, adv, norm)` | Perturbation magnitude |
| `adv_transferability_test(sample, adv, score)` | Transferability metric |
| `adv_distillation_temperature(logit, T)` | Apply temperature scaling |
| `adv_distilled_softmax(out, logits, n, T)` | Distilled softmax |
| `adv_ensemble_predict(pred, outputs, n)` | Ensemble voting |
| `adv_adversarial_training_step(w, clean, adv, cfg, lr, n)` | One training step |
| `adv_detect_adversarial(input, thresh, norm)` | Detect adversarial input |
| `adv_lipschitz_estimate(weights, n, samples)` | Estimate Lipschitz constant |

---

## model_inversion.h

### Types

| Type | Description |
|------|-------------|
| `mi_attack_type_t` | Inversion, Membership, Attribute, Extraction, GradientLeak |
| `mi_defense_type_t` | DP-SGD, Gaussian, Laplace, Clip, PATE, AdvReg |
| `mi_privacy_metric_t` | Epsilon, Delta, Renyi, zCDP |
| `mi_tensor_t` | MI tensor |
| `mi_attack_config_t` | Attack config (epsilon, delta, iterations, shadow models) |
| `mi_defense_config_t` | Defense config (noise_multiplier, clip_norm, teachers) |
| `mi_privacy_budget_t` | Privacy budget tracker (epsilon, delta, violated) |
| `mi_membership_result_t` | Membership inference result |
| `mi_attribute_result_t` | Attribute inference result |
| `mi_inversion_result_t` | Model inversion result (MSE, SSIM) |

### Functions

| Function | Description |
|----------|-------------|
| `mi_tensor_alloc(dims)` | Allocate MI tensor |
| `mi_tensor_free(t)` | Free MI tensor |
| `mi_tensor_clone(src)` | Clone MI tensor |
| `mi_tensor_fill(t, val)` | Fill tensor with value |
| `mi_tensor_norm(t)` | L2 norm |
| `mi_tensor_l1_norm(t)` | L1 norm |
| `mi_model_inversion_attack(result, logits, params, cfg)` | Model inversion attack |
| `mi_inversion_gradient_step(recon, grad, cfg)` | Single inversion step |
| `mi_inversion_loss(r_logits, t_logits, prior)` | Inversion loss function |
| `mi_membership_inference(result, sample, logits, shadow, n, cfg)` | Membership inference |
| `mi_membership_score(logits, label, thresh)` | Membership confidence score |
| `mi_shadow_model_train(params, data, count, pc)` | Train shadow model |
| `mi_attribute_inference(result, pub, sens, outputs, n, cfg)` | Attribute inference |
| `mi_attribute_correlation(a, b)` | Attribute correlation |
| `mi_model_extraction(clone, pc, query_fn, ctx, nq, cfg)` | Model extraction |
| `mi_extraction_generate_query(query, seed, rate)` | Generate extraction query |
| `mi_gradient_leak_attack(recon, grads, params, np, cfg)` | FL gradient leak |
| `mi_gradient_leak_detect(grads, thresh, ref)` | Detect gradient leak |
| `mi_dp_sgd_apply(grads, n, defense)` | Apply DP-SGD |
| `mi_gaussian_mechanism(vals, n, sens, eps, delta)` | Gaussian noise |
| `mi_laplace_mechanism(vals, n, sens, eps)` | Laplace noise |
| `mi_gradient_clipping(grads, n, clip)` | Clip gradients |
| `mi_pate_aggregate(out, votes, teachers, cls, thresh, sigma)` | PATE aggregation |
| `mi_renyi_divergence(p, q, dims, alpha)` | Renyi divergence |
| `mi_check_privacy_budget(budget, incr, cfg)` | Check privacy budget |
| `mi_compute_sensitivity(sens, data, n, radius)` | Compute sensitivity |
| `mi_exact_privacy_loss(budget)` | Exact privacy loss |
| `mi_differential_privacy_audit(result, losses, n, eps)` | DP audit |

---

## prompt_injection.h

### Types

| Type | Description |
|------|-------------|
| `pi_attack_type_t` | Direct/Indirect Injection, Jailbreak, Leaking, Exfiltration... |
| `pi_defense_type_t` | Hierarchy, OutputFilter, Constraint, Guard, RLHF... |
| `pi_severity_t` | Safe, Low, Medium, High, Critical |
| `pi_message_role_t` | System, User, Assistant, Tool, External |
| `pi_message_t` | Message struct with content, role, trust flag |
| `pi_attack_config_t` | Attack configuration |
| `pi_defense_config_t` | Defense configuration |
| `pi_detection_result_t` | Injection detection result |
| `pi_sanitize_result_t` | Input sanitization result |
| `pi_alignment_eval_t` | RLHF alignment evaluation |

### Functions

| Function | Description |
|----------|-------------|
| `pi_message_create(content, role)` | Create message |
| `pi_message_free(msg)` | Free message |
| `pi_detect_injection(result, msgs, n, cfg)` | Detect prompt injection |
| `pi_check_instruction_override(sys, msg, cfg)` | Check override attempt |
| `pi_sanitize_input(result, prompt, cfg)` | Sanitize user input |
| `pi_validate_output(resp, prompt, cfg)` | Validate model output |
| `pi_guard_model_evaluate(result, prompt, resp, cfg)` | Guard model evaluation |
| `pi_guard_score(text, patterns, n)` | Compute guard score |
| `pi_enforce_instruction_hierarchy(msgs, n, cfg)` | Enforce hierarchy |
| `pi_detect_indirect_injection(msg, sources, n)` | Indirect injection detection |
| `pi_detect_jailbreak(prompt, cfg, severity)` | Jailbreak detection |
| `pi_detect_prompt_leaking(resp, sys, score)` | Prompt leak detection |
| `pi_detect_data_exfiltration(resp, patterns, n, score)` | Exfiltration detection |
| `pi_apply_rlhf_safety(prompt, resp, cap, cfg)` | RLHF safety filter |
| `pi_evaluate_alignment(eval, prompt, resp)` | Alignment evaluation |
| `pi_constraint_check(prompt, resp, cons, n, violations)` | Constraint verification |
| `pi_perplexity_check(text, ppl, burst)` | Perplexity/ burstiness check |
| `pi_detect_encoding_obfuscation(text, flags, score)` | Encoding bypass detection |
| `pi_context_window_protect(msgs, n, max, trunc)` | Context window protection |
| `pi_multi_turn_defense(conv, turns, risk, cfg)` | Multi-turn defense |

---

## data_poison.h

### Types

| Type | Description |
|------|-------------|
| `dp_poison_type_t` | Backdoor, CleanLabel, Availability, Targeted, LabelFlip, Collision |
| `dp_defense_type_t` | Sanitization, RobustTrain, Anomaly, DP, Spectral, Trim, KNN, Certified |
| `dp_trigger_type_t` | Pixel, Pattern, Watermark, Semantic, Frequency |
| `dp_sample_t` | Sample with features, label, poison flag, anomaly score |
| `dp_trigger_t` | Trigger pattern data |
| `dp_poison_config_t` | Poison attack config |
| `dp_defense_config_t` | Defense config |
| `dp_poison_result_t` | Poison evaluation result |
| `dp_client_update_t` | FL client gradient update |
| `dp_fl_aggregate_t` | FL aggregation with anomaly scores |

### Functions

| Function | Description |
|----------|-------------|
| `dp_sample_create(dims)` | Create sample |
| `dp_sample_free(s)` | Free sample |
| `dp_sample_clone(src)` | Clone sample |
| `dp_backdoor_inject(samples, n, trigger, cfg)` | Backdoor injection |
| `dp_trigger_generate(trigger, type, rows, cols)` | Generate trigger |
| `dp_trigger_random(trigger)` | Random trigger |
| `dp_trigger_checkerboard(trigger)` | Checkerboard pattern |
| `dp_trigger_watermark(trigger, text)` | Text watermark |
| `dp_trigger_frequency_domain(trigger, freq)` | Frequency domain trigger |
| `dp_trigger_apply(sample, trigger, row, col)` | Apply trigger to sample |
| `dp_clean_label_poison(samples, n, cfg)` | Clean-label poisoning |
| `dp_availability_attack(samples, n, cfg)` | Availability attack |
| `dp_label_flipping(samples, n, target, ratio)` | Label flipping |
| `dp_data_sanitization(samples, n, cfg)` | Data sanitization |
| `dp_detect_poison(sample, cfg, score)` | Poison detection |
| `dp_anomaly_detection(result, samples, n, cfg)` | Anomaly detection |
| `dp_outlier_score(sample, dataset, size)` | Outlier score |
| `dp_robust_training(weights, nw, samples, ns, cfg)` | Robust training |
| `dp_trimmed_loss(grads, n, ratio)` | Trim loss |
| `dp_spectral_signature_defense(result, samples, n, cfg)` | Spectral defense |
| `dp_knn_filter(samples, n, cfg)` | KNN filter |
| `dp_certified_robustness(radius, sample, cfg)` | Certified robustness |
| `dp_fl_malicious_detection(agg, updates, nc, cfg)` | FL malicious detection |
| `dp_fl_secure_aggregate(model, np, updates, nc, cfg)` | FL secure aggregate |
| `dp_fl_byzantine_resilient_agg(model, np, updates, nc, nb)` | Byzantine aggregate |
| `dp_poison_evaluate(result, samples, n, pcfg, dcfg)` | Evaluate poison/defense |
| `dp_poison_effectiveness(result)` | Effectiveness metric |
| `dp_trigger_detected(sample, triggers, n, thresh)` | Trigger detection |

---

## ai_governance.h

### Types

| Type | Description |
|------|-------------|
| `ag_bias_metric_t` | DemParity, EqOdds, EqOpp, DisparateImpact, Calibration, Individual, Counterfactual |
| `ag_xai_method_t` | SHAP, LIME, IntegratedGrad, DeepLift, Saliency, PartialDep, Permutation |
| `ag_audit_type_t` | RedTeam, Safety, Failure, Robustness, Fairness, Transparency, Accountability |
| `ag_content_category_t` | Safe, Hate, Violence, Sexual, SelfHarm, Harassment, Misinfo, Illegal |
| `ag_fairness_sample_t` | Fairness sample |
| `ag_explanation_t` | XAI explanation |
| `ag_model_card_t` | Model card |
| `ag_bias_result_t` | Bias measurement result |
| `ag_audit_result_t` | Audit result |
| `ag_content_safety_t` | Content safety check |
| `ag_model_provenance_t` | Model provenance |

### Functions

| Function | Description |
|----------|-------------|
| `ag_fairness_sample_create(dims)` | Create fairness sample |
| `ag_fairness_sample_free(s)` | Free fairness sample |
| `ag_model_card_create()` | Create model card |
| `ag_model_card_free(card)` | Free model card |
| `ag_model_card_to_json(card, buf, sz)` | Export to JSON |
| `ag_compute_demographic_parity(result, samples, n, ga, gb)` | Demographic parity |
| `ag_compute_equalized_odds(result, samples, tl, pred, n, ga, gb)` | Equalized odds |
| `ag_compute_equal_opportunity(result, samples, tl, pred, n, ga, gb)` | Equal opportunity |
| `ag_compute_disparate_impact(result, samples, pred, n, ga, gb, fav)` | Disparate impact |
| `ag_compute_calibration(result, samples, conf, tl, n, ga, gb)` | Calibration |
| `ag_compute_individual_fairness(result, sa, sb, thresh)` | Individual fairness |
| `ag_explanation_create(nfeats)` | Create explanation |
| `ag_explanation_free(exp)` | Free explanation |
| `ag_compute_shap_values(exp, sample, ns, nse, method)` | Compute SHAP |
| `ag_shap_kernel_explainer(exp, sample, bg, bgs, ns)` | Kernel SHAP |
| `ag_shap_tree_explainer(exp, sample, tree, nt)` | Tree SHAP |
| `ag_compute_lime(exp, sample, np, kw)` | Compute LIME |
| `ag_lime_perturb_sample(pert, orig, nactive)` | LIME perturbation |
| `ag_lime_exponential_kernel(dist, kw)` | LIME kernel |
| `ag_compute_integrated_gradients(exp, sample, baseline, steps)` | Integrated gradients |
| `ag_compute_saliency_map(exp, sample)` | Saliency map |
| `ag_compute_permutation_importance(imp, nf, samples, ns, labels, bs, nr)` | Permutation importance |
| `ag_run_red_team_audit(result, name, prompts, n, expected)` | Red team audit |
| `ag_run_safety_evaluation(result, prompts, n, responses, thresh)` | Safety evaluation |
| `ag_run_failure_mode_analysis(result, cases, n, pred, expected)` | Failure analysis |
| `ag_run_robustness_audit(result, samples, n, mag)` | Robustness audit |
| `ag_run_fairness_audit(result, samples, pred, tl, groups, n)` | Fairness audit |
| `ag_check_content_safety(result, content, thresh)` | Content safety |
| `ag_classify_content(content, confidence)` | Content classification |
| `ag_content_safety_filter(out, in, max, blist, n)` | Safety filter |
| `ag_verify_model_provenance(prov, hash, expected)` | Verify provenance |
| `ag_compute_model_hash(prov, weights, n, data_id)` | Compute model hash |
| `ag_generate_model_card(card, name, ver, use, lim, metrics, names, n)` | Generate model card |
| `ag_responsible_ai_checklist(checklist, n, card)` | RAI checklist |
| `ag_fairness_summary(results, n)` | Fairness summary |
| `ag_compare_models_fairness(a, b, n)` | Compare model fairness |
| `ag_bias_mitigation_rewrite(samples, n, biases, nb)` | Bias mitigation |
| `ag_disaggregated_evaluation(results, samples, n, groups, ng)` | Disaggregated eval |
