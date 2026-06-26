# mini-privacy-compute API Reference

## Overview

mini-privacy-compute is a C99 library implementing **隐私计算 (Privacy-Preserving Computation)** techniques. It provides 5 modules covering differential privacy, federated learning, secure multi-party computation, data anonymization, and privacy-enhancing technologies (PETs).

All modules use plain C99; no external dependencies beyond `<stdlib.h>`, `<math.h>`, and `<string.h>`.

## Module 1: differential_privacy.h

Differential privacy mechanisms and budget management.

| Function | Description |
|---|---|
| `dp_laplace_mechanism()` | Apply Laplace noise to a single value using L1 sensitivity |
| `dp_laplace_vector()` | Batch Laplace noise to a vector |
| `dp_gaussian_mechanism()` | Apply Gaussian noise using L2 sensitivity |
| `dp_gaussian_vector()` | Batch Gaussian noise to a vector |
| `dp_comp_init()` | Initialize sequential composition tracker |
| `dp_comp_sequential()` | Record sequential query (sums epsilon) |
| `dp_comp_parallel_query()` | Record parallel queries (max epsilon) |
| `dp_budget_init()` | Initialize privacy budget with limits |
| `dp_budget_consume()` | Consume budget; returns 0 when exhausted |
| `dp_local_laplace()` | Local DP: user perturbs own data |
| `dp_local_randomize()` | Randomized response for binary values |
| `dp_global_aggregate()` | Aggregate perturbed responses from multiple users |
| `dp_sgd_clip_gradients()` | Clip gradients to max norm (DP-SGD) |
| `dp_sgd_add_noise()` | Add Gaussian noise to gradients |
| `dp_sgd_step()` | Full DP-SGD update step |
| `rappor_init()` | Initialize Google RAPPOR client |
| `rappor_encode()` / `rappor_randomize()` | RAPPOR bloom filter + perturbation |
| `rappor_decode()` | Decode aggregated RAPPOR reports |
| `dp_analyze_risk()` | Analyze privacy-utility tradeoff |
| `dp_advanced_composition()` | Advanced composition theorem |

### Key Types

- `DPConfig` — mechanism config: epsilon, delta, budget tracking
- `DPBudget` — privacy budget with exhaustion detection
- `DPComposition` — sequential/parallel composition tracker
- `RAPPORClient` — RAPPOR randomized response state
- `DPSGDPConfig` — DP-SGD hyperparameters

## Module 2: federated_learn.h

Federated learning with secure aggregation and DP protection.

| Function | Description |
|---|---|
| `fl_server_init()` / `fl_server_free()` | Initialize/free FL server state |
| `fl_server_init_model()` | Set initial global model weights |
| `fl_download_model()` | Server sends model to a client |
| `fl_upload_update()` | Client uploads gradients to server |
| `fedavg_init()` / `fedavg_accumulate()` / `fedavg_apply()` | Federated averaging workflow |
| `secagg_init()` / `secagg_add_update()` / `secagg_finalize()` | Secure aggregation with mask sharing |
| `fl_dp_clip_update()` / `fl_dp_add_noise()` / `fl_dp_protect_update()` | DP protection for FL updates |
| `vfl_party_init()` / `vfl_party_compute()` | Vertical FL per-party computation |
| `hfl_client_train()` | Horizontal FL local training |
| `fl_random_select()` | Random client subset selection |
| `fl_weighted_select()` | Quality-weighted client selection |
| `fl_compute_update_norm()` | Compute L2 norm of update vector |
| `fl_check_convergence()` | Check if model has converged |

### Key Types

- `FLServer` — global server state with model, client list, training config
- `FLClient` — per-client metadata (selection status, contributions)
- `FedAvgState` — weighted sum accumulator for FedAvg
- `SecureAggState` — encrypted aggregation accumulator
- `VFLParty` — vertical FL party with partial features

## Module 3: secure_mpc_comp.h

Secure multi-party computation (SMPC) primitives.

| Function | Description |
|---|---|
| `ss_init()` / `ss_share()` / `ss_reconstruct()` | Additive secret sharing |
| `ss_add()` / `ss_scalar_mul()` | Addition and scalar multiplication on shares |
| `bt_pool_init()` / `bt_pool_generate()` | Beaver triple pool management |
| `bt_multiply()` | Secure multiplication using Beaver triple |
| `spdz_init()` / `spdz_online_add()` / `spdz_online_multiply()` | SPDZ online phase with MAC |
| `gc_init()` / `gc_set_gate()` / `gc_garble()` / `gc_evaluate()` | Garbled circuit construction and evaluation |
| `oram_init()` / `oram_access()` | Oblivious RAM (tree-based) |
| `psi_client_init()` / `psi_server_init()` / `psi_compute_intersection()` | ECDH-style Private Set Intersection |
| `pir_db_init()` / `pir_query()` / `pir_answer()` | Private Information Retrieval |
| `mpc_mod_exp()` / `mpc_mod_inv()` / `mpc_hash_bytes()` | MPC utility functions |

### Key Types

- `SecretSharing` — additive secret sharing over prime field
- `BeaverTriple` / `BeaverTriplePool` — pre-computed multiplication triples
- `SPDZState` — SPDZ online phase with MAC shares
- `GarbledCircuit` — boolean garbled circuit
- `ORAMServer` — oblivious RAM state
- `PSIClient` / `PSIServer` — ECDH-based PSI
- `PIRDatabase` — PIR database with query/answer

## Module 4: anonymization.h

Data anonymization and de-anonymization risk assessment.

| Function | Description |
|---|---|
| `kanon_init_dataset()` / `kanon_add_record()` | Build anonymization dataset |
| `kanon_check()` | Verify k-anonymity (k indistinguishable records) |
| `kanon_generalize()` | Generalize quasi-identifier by level |
| `kanon_suppress_records()` | Probabilistic record suppression |
| `kanon_equivalence_class()` | Get group sizes per equivalence class |
| `ldiversity_check()` | Check l-diversity (l distinct sensitive values) |
| `ldiversity_entropy_l()` | Entropy-based l-diversity |
| `ldiversity_recursive()` | Recursive (c,l)-diversity |
| `ldiversity_enforce()` | Enforce l-diversity via generalization |
| `tclose_check()` | Check t-closeness via EMD |
| `tclose_emd()` | Earth Mover's Distance for distributions |
| `pseud_init()` / `pseud_generate()` / `pseud_verify()` | Pseudonymization with hash-based tokens |
| `deanon_attack_linkage()` | Linkage attack simulation |
| `deanon_attack_netflix()` / `deanon_attack_aol()` | Netflix/AOL-style attack simulation |
| `reid_score_compute()` | Re-identification risk scoring |
| `anon_measure_utility()` | Measure information loss from anonymization |
| `anon_validate_invariants()` | Validate required group invariants |

### Risk Score Fields

- `prosecutor_risk` — risk of identifying a specific known target
- `journalist_risk` — risk of finding any match in population
- `marketer_risk` — risk of linking at least one record
- `uniqueness_score` — fraction of unique quasi-identifier combinations

## Module 5: pet_tools.h

Privacy-Enhancing Technologies orchestrator and toolkit.

| Function | Description |
|---|---|
| `pet_get_descriptor()` / `pet_print_landscape()` | PET landscape overview |
| `odproc_init()` / `odproc_compute_local()` | On-device processing |
| `odproc_minimize_upload()` | Minimize data sent to server |
| `dprep_init()` / `dprep_generate()` / `dprep_verify()` | DP report lifecycle |
| `dprep_serialize()` / `dprep_deserialize()` | Report serialization |
| `enclave_init()` / `enclave_attest()` | TEE enclave abstraction |
| `enclave_load_data()` / `enclave_compute()` | In-enclave computation |
| `enclave_seal()` / `enclave_verify_sealing()` | Sealing for trusted storage |
| `anoncred_init()` / `anoncred_request()` / `anoncred_issue()` | Anonymous credential lifecycle |
| `anoncred_present()` / `anoncred_verify_presentation()` | Selective disclosure |
| `zkidp_init()` / `zkidp_prove()` / `zkidp_verify()` | ZK identity proofs |
| `zkidp_range_proof()` | Range proof (age verification) |
| `vc_create()` / `vc_issue()` / `vc_verify()` | W3C Verifiable Credentials |
| `datamin_init()` / `datamin_collect_purpose()` | Purpose-based data minimization |
| `datamin_apply()` / `datamin_audit()` | Apply/audit minimization |
| `pbd_init()` / `pbd_add_requirement()` | Privacy by Design framework |
| `pbd_map_dataflow()` / `pbd_assess_risk()` | Data flow mapping and risk scoring |
| `pbd_validate_design()` / `pbd_check_gdpr()` | Design validation + GDPR compliance |
| `petorch_init()` / `petorch_enable()` | PET orchestrator |
| `petorch_assess_privacy()` / `petorch_audit_log_event()` | Privacy scoring + audit logging |

### PET Categories

| ID | Name | Maturity | Overhead |
|----|------|----------|----------|
| 0 | On-Device Processing | 4/5 | 1/5 |
| 1 | Differential Privacy | 4/5 | 2/5 |
| 2 | Secure MPC | 3/5 | 4/5 |
| 3 | Federated Learning | 4/5 | 2/5 |
| 4 | Trusted Execution Env | 4/5 | 2/5 |
| 5 | Zero-Knowledge Proofs | 3/5 | 4/5 |
| 6 | Anonymous Credentials | 3/5 | 3/5 |
| 7 | Pseudonymization | 5/5 | 1/5 |
| 8 | Homomorphic Encryption | 2/5 | 5/5 |
| 9 | Data Minimization | 5/5 | 1/5 |
| 10 | Privacy by Design | 5/5 | 1/5 |
