# mini-adv-crypto API Reference

## 1. Zero-Knowledge Proofs (`zk_proof.h`)

### Field Arithmetic

| Function | Description |
|----------|-------------|
| `zk_field_zero(f)` | Set field element to zero |
| `zk_field_one(f)` | Set field element to one |
| `zk_field_add(r, a, b)` | r = a + b |
| `zk_field_mul(r, a, b)` | r = a * b |
| `zk_field_neg(r, a)` | r = -a |
| `zk_field_inv(r, a)` | r = a^(-1) |
| `zk_field_eq(a, b)` | Compare two field elements |
| `zk_field_from_u64(f, val)` | Set field from uint64_t |
| `zk_field_print(label, f)` | Print field element |

### R1CS Constraint System

| Function | Description |
|----------|-------------|
| `zk_r1cs_init(r1cs, num_vars, num_constraints)` | Initialize R1CS with v variables and k constraints |
| `zk_r1cs_add_constraint(r1cs, idx, a, b, c)` | Add constraint: (a*w)(b*w) = (c*w) |
| `zk_r1cs_verify_witness(r1cs, witness)` | Check that witness satisfies all constraints |
| `zk_r1cs_print(r1cs)` | Print the constraint system |

### QAP Polynomials

| Function | Description |
|----------|-------------|
| `zk_qap_from_r1cs(qap, r1cs)` | Convert R1CS to QAP representation |
| `zk_qap_evaluate(qap, x, out_a, out_b, out_c, out_t)` | Evaluate QAP at point x |
| `zk_qap_verify_division(qap, witness, h)` | Verify QAP divisibility check |

### Trusted Setup

| Function | Description |
|----------|-------------|
| `zk_trusted_setup(pk, vk, r1cs, info)` | Generate proving and verification keys |
| `zk_setup_toxic_mpc(pk, num_participants)` | MPC ceremony to distribute toxic waste |
| `zk_proving_key_free(pk)` | Zeroize proving key |
| `zk_verification_key_free(vk)` | Zeroize verification key |

### Groth16 Protocol

| Function | Description |
|----------|-------------|
| `zk_groth16_prove(proof, pk, witness, num_pub_inputs)` | Generate Groth16 proof |
| `zk_groth16_verify(proof, vk, pub_inputs, num_inputs)` | Verify Groth16 proof |
| `zk_groth16_print(proof)` | Print proof elements |

### Pinocchio Protocol

| Function | Description |
|----------|-------------|
| `zk_pinocchio_prove(proof, qap, witness, num_io)` | Generate Pinocchio proof |
| `zk_pinocchio_verify(proof, qap, io, num_io)` | Verify Pinocchio proof |

### zk-STARK

| Function | Description |
|----------|-------------|
| `zk_stark_trace_commit(trace, exec_trace, steps, regs)` | Commit execution trace |
| `zk_stark_merkle_root(root, trace)` | Compute Merkle root of trace |
| `zk_stark_fri_verify(trace, queries)` | FRI low-degree test |

---

## 2. Homomorphic Encryption (`homomorphic_enc.h`)

### BigInt Utilities

| Function | Description |
|----------|-------------|
| `he_bigint_zero(a)` | Set to zero |
| `he_bigint_set_u64(a, val)` | Set from uint64_t |
| `he_bigint_add(r, a, b)` | r = a + b |
| `he_bigint_mul(r, a, b)` | r = a * b |
| `he_bigint_mod(r, a, m)` | r = a mod m |
| `he_bigint_mod_exp(r, base, exp, mod)` | r = base^exp mod m |
| `he_bigint_gcd(r, a, b)` | r = gcd(a, b) |
| `he_bigint_lcm(r, a, b)` | r = lcm(a, b) |
| `he_bigint_cmp(a, b)` | Compare: -1, 0, 1 |
| `he_bigint_print(label, a)` | Print big integer |

### Paillier Cryptosystem

| Function | Description |
|----------|-------------|
| `he_paillier_keygen(pub, prv, bits)` | Generate key pair |
| `he_paillier_encrypt(ct, msg, pub)` | Encrypt message |
| `he_paillier_decrypt(msg, ct, prv)` | Decrypt ciphertext |
| `he_paillier_add(r, a, b, pub)` | Homomorphic addition: Dec(r) = Dec(a) + Dec(b) |
| `he_paillier_scalar_mul(r, a, scalar, pub)` | Homomorphic scalar multiply: Dec(r) = Dec(a) * k |
| `he_paillier_zero_test(a, b, pub, prv)` | Test if a and b encrypt same value |
| `he_paillier_print_ct(label, ct)` | Print ciphertext |

### BFV Scheme

| Function | Description |
|----------|-------------|
| `he_bfv_params_init(params, degree, modulus)` | Initialize BFV parameters |
| `he_bfv_keygen(sk, params)` | Generate secret key |
| `he_bfv_encrypt(ct, pt, sk, params)` | Encrypt plaintext |
| `he_bfv_decrypt(pt, ct, sk, params)` | Decrypt ciphertext |
| `he_bfv_add(r, a, b, params)` | Homomorphic addition |
| `he_bfv_mul(r, a, b, params)` | Homomorphic multiplication |
| `he_bfv_noise_budget(ct)` | Query remaining noise budget |
| `he_bfv_relinearize(ct, params)` | Relinearize after multiplication |

---

## 3. Secure MPC (`mpc_proto.h`)

### Shamir Secret Sharing

| Function | Description |
|----------|-------------|
| `mpc_shamir_split(ctx, secret, threshold, total)` | Split secret into n shares, need t to recover |
| `mpc_shamir_reconstruct(secret, ctx, indices, count)` | Reconstruct secret from shares |
| `mpc_shamir_add_share(r, a, b)` | Add two shares (homomorphic) |
| `mpc_shamir_mul_share(r, a, b)` | Multiply two shares (degree increases) |
| `mpc_shamir_print(ctx)` | Print share context |

### Yao Garbled Circuit

| Function | Description |
|----------|-------------|
| `mpc_garble_and_gate(gate, wire_a, wire_b, wire_out)` | Garble an AND gate |
| `mpc_garble_circuit_init(gc, num_gates, num_inputs, num_outputs)` | Initialize garbled circuit |
| `mpc_garble_evaluate_circuit(output, gc, input_keys, num_inputs)` | Evaluate garbled circuit |
| `mpc_garble_encode_input(key, value, wire_id)` | Encode plaintext input into key |
| `mpc_garble_decode_output(value, wire_id)` | Decode circuit output |
| `mpc_garble_print_circuit(gc)` | Print circuit description |

### Oblivious Transfer

| Function | Description |
|----------|-------------|
| `mpc_ot_sender_init(sender)` | Initialize OT sender |
| `mpc_ot_send_messages(sender, m0, m1)` | Prepare two messages |
| `mpc_ot_receiver_choose(receiver, choice, pubkey)` | Receiver chooses 0 or 1 |
| `mpc_ot_receiver_get(msg, receiver)` | Receiver retrieves chosen message |
| `mpc_ot_1_of_2(result, m0, m1, choice)` | Simplified 1-of-2 OT |
| `mpc_ot_print_messages(sender)` | Print OT messages |

### SPDZ Protocol

| Function | Description |
|----------|-------------|
| `mpc_spdz_init(ctx, num_parties, mac_key)` | Initialize SPDZ context |
| `mpc_spdz_share(ctx, party_id, value)` | Create authenticated share |
| `mpc_spdz_reconstruct(result, ctx)` | Reconstruct value with MAC check |
| `mpc_spdz_add(r, a, b)` | Add shares (local) |
| `mpc_spdz_mul(r, a, b, ctx)` | Multiply shares (requires interaction) |
| `mpc_spdz_verify(ctx)` | Verify all MACs |
| `mpc_multi_party_sum(result, inputs, num_parties)` | Privacy-preserving sum |

---

## 4. Post-Quantum Cryptography (`post_quantum.h`)

### Polynomial Operations

| Function | Description |
|----------|-------------|
| `pq_poly_init(p)` | Initialize polynomial |
| `pq_poly_ntt(p)` | Forward NTT transform |
| `pq_poly_invntt(p)` | Inverse NTT transform |
| `pq_poly_add(r, a, b)` | Polynomial addition |
| `pq_poly_sub(r, a, b)` | Polynomial subtraction |
| `pq_poly_mul(r, a, b)` | Polynomial multiplication (schoolbook) |
| `pq_poly_reduce(p)` | Barrett reduction modulo Q |
| `pq_poly_cbd(p, seed, eta)` | Centered Binomial Distribution sampling |

### Kyber KEM (ML-KEM)

| Function | Description |
|----------|-------------|
| `pq_kyber_keygen(pk, sk)` | Generate Kyber key pair |
| `pq_kyber_encaps(ct, shared_secret, pk)` | Encapsulate: produce ciphertext and shared secret |
| `pq_kyber_decaps(shared_secret, ct, sk)` | Decapsulate: recover shared secret |
| `pq_kyber_indcpa_enc(ct, m, pk, coins)` | IND-CPA encryption core |
| `pq_kyber_indcpa_dec(m, ct, sk)` | IND-CPA decryption core |

### Dilithium Signature (ML-DSA)

| Function | Description |
|----------|-------------|
| `pq_dilithium_keygen(pk, sk)` | Generate Dilithium key pair |
| `pq_dilithium_sign(sig, siglen, msg, msglen, sk)` | Sign message |
| `pq_dilithium_verify(sig, msg, msglen, pk)` | Verify signature |
| `pq_dilithium_rej_sampling(y, gamma)` | Rejection sampling for signatures |

### SPHINCS+ (SLH-DSA)

| Function | Description |
|----------|-------------|
| `pq_sphincs_keygen(pk, sk)` | Generate SPHINCS+ key pair |
| `pq_sphincs_sign(sig, msg, msglen, sk)` | Sign message |
| `pq_sphincs_verify(sig, msg, msglen, pk)` | Verify signature |
| `pq_sphincs_ht_sign(sig, sk, idx)` | Hypertree signing |
| `pq_sphincs_ht_verify(sig, pk, idx)` | Hypertree verification |

### Module-LWE/LWR

| Function | Description |
|----------|-------------|
| `pq_mlwe_sample(s, seed)` | Sample small polynomial for MLWE |
| `pq_mlwr_round(r, s)` | Rounding for Module-LWR |
| `pq_mlwe_encrypt(u, v, t, m, coins)` | MLWE encryption demo |

---

## 5. Threshold Signatures (`threshold_sig.h`)

### Shamir Secret Sharing (SSS)

| Function | Description |
|----------|-------------|
| `ts_sss_split(ctx, secret, threshold, total)` | Split secret |
| `ts_sss_reconstruct(secret, shares, num_shares, threshold)` | Reconstruct secret |
| `ts_sss_add_share(r, a, b, prime)` | Additive homomorphism on shares |
| `ts_sss_mul_share(r, a, b, prime)` | Multiplicative homomorphism on shares |
| `ts_sss_lagrange_coeff(coeff, indices, count, target_idx, prime)` | Compute Lagrange coefficient |

### FROST Protocol

| Function | Description |
|----------|-------------|
| `ts_frost_keygen_round1(party, party_id, threshold, num_signers)` | Key generation |
| `ts_frost_sign_round1(nonce, commit, party)` | Round 1: nonce commitment |
| `ts_frost_sign_round2(sig_z, party, nonce, agg_r, challenge, msg, msglen)` | Round 2: signature share |
| `ts_frost_aggregate_nonces(agg_r, commits, count)` | Aggregate nonces |
| `ts_frost_aggregate_sigs(sig, sig_shares, party, count)` | Aggregate signature shares |
| `ts_frost_verify(sig, msg, msglen, group_pubkey)` | Verify threshold signature |

### Distributed Key Generation

| Function | Description |
|----------|-------------|
| `ts_dkg_init(ctx, threshold, total)` | Initialize DKG session |
| `ts_dkg_round1(ctx, party_id)` | Round 1: generate and commit polynomials |
| `ts_dkg_round2(ctx, party_id)` | Round 2: distribute secret shares |
| `ts_dkg_round3(ctx, party_id)` | Round 3: compute group public key |
| `ts_dkg_finalize(group_pk, secret_shares, ctx)` | Finalize DKG |

### Proactive Security

| Function | Description |
|----------|-------------|
| `ts_refresh_share(new_share, old_share, threshold, total, epoch)` | Refresh single share |
| `ts_refresh_proactive(ctx, epoch)` | Refresh all shares (proactive) |
| `ts_refresh_verify(old_ctx, new_ctx, threshold)` | Verify refresh correctness |

---

## Common Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `ZK_MAX_VARS` | 64 | Max R1CS variables |
| `ZK_MAX_CONSTRAINTS` | 128 | Max R1CS constraints |
| `HE_PAILLIER_BITS` | 2048 | Paillier default key size |
| `MPC_MAX_PARTIES` | 32 | Max MPC parties |
| `PQ_KYBER_N` | 256 | Kyber polynomial degree |
| `PQ_KYBER_Q` | 3329 | Kyber modulus |
| `TS_MAX_PARTIES` | 32 | Max threshold parties |
| `TS_SSS_PRIME` | 2147483647 | SSS finite field prime |
