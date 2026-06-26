# Mini Security Crypto Web3

**From-scratch, zero-dependency C implementations** of cryptography, blockchain, Web3, and security concepts. Each module models security primitives and systems at educational fidelity — from hash functions and symmetric/asymmetric encryption to zero-knowledge proofs, smart contract security, and privacy-preserving computation.

## Modules

| Module | Topics | Key References |
|--------|--------|----------------|
| [mini-crypto-basic](mini-crypto-basic/) | Hash (SHA256/MD5), AES/DES, RSA/ECC, digital signature, PKI | NIST FIPS, RFC 5280 |
| [mini-adv-crypto](mini-adv-crypto/) | zk-SNARKs, homomorphic enc, MPC, post-quantum, threshold sig | zk-SNARKs paper, BGV/Paillier |
| [mini-blockchain-core](mini-blockchain-core/) | UTXO/account model, Merkle tree, PoW/PoS, tx pool, P2P net | Bitcoin, Ethereum |
| [mini-defi-crosschain](mini-defi-crosschain/) | AMM (Uniswap), lending, stablecoin, cross-chain bridge, oracle | Uniswap V3, Aave, Chainlink |
| [mini-smart-contract-sec](mini-smart-contract-sec/) | EVM sim, reentrancy, overflow, access control, formal verify | Ethereum Yellow Paper, OpenZeppelin |
| [mini-web-security](mini-web-security/) | XSS/SQLi/CSRF, CSP, OWASP Top 10, input validation, auth | OWASP, MDN Security |
| [mini-binary-security](mini-binary-security/) | Buffer overflow, ROP, ASLR/NX/canary, format string, fuzzing | MIT 6.858, Phrack |
| [mini-cloud-security](mini-cloud-security/) | IAM, KMS, WAF, DDoS, container security, CSPM | AWS Security, GCP Security |
| [mini-ai-security](mini-ai-security/) | Adversarial ML, model inversion, prompt injection, data poisoning | OWASP ML Top 10, NIST AI RMF |
| [mini-trusted-compute](mini-trusted-compute/) | TEE (SGX/TDX), remote attestation, confidential computing | Intel SGX, AMD SEV-SNP |
| [mini-privacy-compute](mini-privacy-compute/) | Differential privacy, federated learning, SMPC, data anonymization | Dwork Differential Privacy, OpenMined |
| [mini-supply-chain-sec](mini-supply-chain-sec/) | SBOM, SLSA, sigstore/cosign, dependency vuln, provenance | SLSA.dev, Sigstore |
| [mini-sec-governance](mini-sec-governance/) | ISO 27001, SOC2, NIST CSF, risk assessment, compliance | ISO 27001, SOC2, NIST CSF |

## Design Philosophy

- **Zero external dependencies** — pure C (C99/C11), only `libc` and `libm`
- **Self-contained modules** — each directory has its own `Makefile`, `include/`, `src/`, `examples/`, `demos/`, `tests/`
- **Security simulation in user-space** — educational models of cryptographic primitives, blockchain consensus, and attack/defense patterns
- **Theory-to-code mapping** — every module includes `docs/` with paper/standard-alignment notes
- **Practical demos** — cryptocurrency node, EVM simulator, exploit/defense demos, zk-SNARK verifier, and more

## Building

Each module is standalone. Navigate to a module directory and run:

```bash
cd mini-crypto-basic
make all    # build everything
make test   # run tests
```

Requires **GCC** and **GNU Make**.

## Project Structure

```
mini-security-crypto-web3/
├── mini-crypto-basic/           # Basic Cryptography
├── mini-adv-crypto/             # Advanced Cryptography
├── mini-blockchain-core/        # Blockchain Core
├── mini-defi-crosschain/        # DeFi & Cross-chain
├── mini-smart-contract-sec/     # Smart Contract Security
├── mini-web-security/           # Web Security
├── mini-binary-security/        # Binary Security
├── mini-cloud-security/         # Cloud Security
├── mini-ai-security/            # AI Security
├── mini-trusted-compute/        # Trusted Computing
├── mini-privacy-compute/        # Privacy Computing
├── mini-supply-chain-sec/       # Supply Chain Security
└── mini-sec-governance/         # Security Governance & Compliance
```

## License

MIT
