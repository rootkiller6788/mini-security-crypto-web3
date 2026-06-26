#ifndef CROSSCHAIN_BRIDGE_H
#define CROSSCHAIN_BRIDGE_H

#include <stdbool.h>
#include <stdint.h>

#define BRIDGE_MAX_VALIDATORS     21
#define BRIDGE_SIG_THRESHOLD_NUM  14
#define BRIDGE_SIG_THRESHOLD_DEN  21
#define BRIDGE_MAX_EVENTS         256
#define BRIDGE_HEADER_SIZE        80
#define BRIDGE_HASH_SIZE          32
#define BRIDGE_ADDR_SIZE          20

typedef enum {
    BRIDGE_LOCK_MINT,
    BRIDGE_BURN_RELEASE,
    BRIDGE_ATOMIC_SWAP
} BridgeModel;

typedef enum {
    BRIDGE_MULTI_SIG,
    BRIDGE_LIGHT_CLIENT,
    BRIDGE_OPTIMISTIC
} BridgeSecurity;

typedef struct {
    uint8_t pubkey[64];
    uint8_t addr[BRIDGE_ADDR_SIZE];
    bool    active;
    uint64_t stake;
} BridgeValidator;

typedef struct {
    uint8_t prev_hash[BRIDGE_HASH_SIZE];
    uint8_t merkle_root[BRIDGE_HASH_SIZE];
    uint8_t state_root[BRIDGE_HASH_SIZE];
    uint64_t height;
    uint64_t timestamp;
    uint32_t nonce;
    uint8_t difficulty[4];
} BridgeBlockHeader;

typedef struct {
    BridgeBlockHeader header;
    uint8_t proof[BRIDGE_HASH_SIZE * 10];
    int proof_length;
} BridgeHeaderProof;

typedef struct {
    uint8_t tx_hash[BRIDGE_HASH_SIZE];
    uint8_t sender[BRIDGE_ADDR_SIZE];
    uint8_t receiver[BRIDGE_ADDR_SIZE];
    uint64_t amount;
    uint64_t source_chain_id;
    uint64_t dest_chain_id;
    uint64_t nonce;
    uint64_t timestamp;
    bool     processed;
    bool     confirmed;
} BridgeEvent;

typedef struct {
    BridgeModel model;
    BridgeSecurity security;
    uint64_t chain_id;
    uint64_t event_count;
    BridgeValidator validators[BRIDGE_MAX_VALIDATORS];
    int     validator_count;
    BridgeEvent events[BRIDGE_MAX_EVENTS];
    uint64_t locked_amount;
    uint64_t minted_amount;
    bool    halted;
} Bridge;

typedef struct {
    uint8_t  hash[BRIDGE_HASH_SIZE];
    uint8_t  signer[BRIDGE_ADDR_SIZE];
    uint8_t  signature[64];
    bool     valid;
} BridgeSignature;

typedef struct {
    uint8_t  data[128];
    uint64_t source_height;
    int      required_signers;
    BridgeSignature sigs[BRIDGE_MAX_VALIDATORS];
    int      sig_count;
} BridgeRelayMessage;

void     bridge_init(Bridge *bridge, BridgeModel model, BridgeSecurity security, uint64_t chain_id);
void     bridge_add_validator(Bridge *bridge, const uint8_t pubkey[64], const uint8_t addr[20], uint64_t stake);
bool     bridge_remove_validator(Bridge *bridge, const uint8_t addr[20]);
bool     bridge_lock(Bridge *bridge, const uint8_t sender[20], const uint8_t receiver[20], uint64_t amount, uint64_t dest_chain);
bool     bridge_mint(Bridge *bridge, const uint8_t receiver[20], uint64_t amount, const BridgeRelayMessage *msg);
bool     bridge_burn(Bridge *bridge, const uint8_t sender[20], uint64_t amount, uint64_t dest_chain);
bool     bridge_release(Bridge *bridge, const uint8_t receiver[20], uint64_t amount, const BridgeRelayMessage *msg);
bool     bridge_verify_header(const Bridge *bridge, const BridgeBlockHeader *header, const BridgeHeaderProof *proof);
bool     bridge_verify_event(const Bridge *bridge, const BridgeEvent *event, const BridgeBlockHeader *header);
int      bridge_collect_signatures(BridgeSignature *sigs, int max_sigs, const BridgeRelayMessage *msg);
bool     bridge_verify_multisig(const Bridge *bridge, const BridgeRelayMessage *msg);
void     bridge_generate_message(BridgeRelayMessage *msg, const BridgeEvent *event, uint64_t height);
bool     bridge_process_event(Bridge *bridge, uint64_t event_id);
uint64_t bridge_get_event_nonce(const Bridge *bridge);
void     bridge_simulate_event(uint8_t tx_hash[32], uint8_t sender[20], uint8_t receiver[20], uint64_t amount, uint64_t dest_chain);
uint32_t bridge_compute_merkle_root(const uint8_t leaves[][BRIDGE_HASH_SIZE], int count, uint8_t root[BRIDGE_HASH_SIZE]);

#endif
