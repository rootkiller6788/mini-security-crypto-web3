#ifndef GOVERNANCE_DAO_H
#define GOVERNANCE_DAO_H

#include <stdbool.h>
#include <stdint.h>

#define DAO_MAX_PROPOSALS        128
#define DAO_MAX_VOTERS           1024
#define DAO_MAX_DELEGATES        256
#define DAO_BPS_DENOM            10000
#define DAO_VOTING_PERIOD        604800
#define DAO_TIMELOCK_DELAY       172800
#define DAO_QUORUM_BPS           4000
#define DAO_PROPOSAL_THRESHOLD_BPS 100

typedef enum {
    DAO_PENDING,
    DAO_ACTIVE,
    DAO_CANCELED,
    DAO_DEFEATED,
    DAO_SUCCEEDED,
    DAO_QUEUED,
    DAO_EXECUTED,
    DAO_EXPIRED,
    DAO_VETOED
} DAOProposalState;

typedef enum {
    DAO_VOTE_AGAINST   = 0,
    DAO_VOTE_FOR       = 1,
    DAO_VOTE_ABSTAIN   = 2
} DAOVoteType;

typedef struct {
    uint8_t  voter_addr[20];
    uint64_t voting_power;
    uint64_t delegated_from;
    bool     has_voted;
    DAOVoteType vote;
} DAOVoter;

typedef struct {
    uint8_t  delegate_addr[20];
    uint8_t  delegator_addr[20];
    uint64_t delegated_power;
    uint64_t expiry;
    bool     active;
} DAODelegation;

typedef struct {
    uint32_t proposal_id;
    uint8_t  proposer[20];
    uint8_t  targets[8][20];
    uint64_t values[8];
    uint8_t  calldatas[8][128];
    uint32_t target_count;
    uint64_t start_time;
    uint64_t end_time;
    uint64_t for_votes;
    uint64_t against_votes;
    uint64_t abstain_votes;
    DAOProposalState state;
    uint64_t execution_time;
    uint8_t  description_hash[32];
    bool     executed;
} DAOProposal;

typedef struct {
    uint64_t total_supply;
    uint64_t quorum_bps;
    uint64_t proposal_threshold_bps;
    uint64_t voting_period;
    uint64_t timelock_delay;
    uint64_t proposal_count;
    DAOProposal proposals[DAO_MAX_PROPOSALS];
    DAOVoter voters[DAO_MAX_VOTERS];
    int      voter_count;
    DAODelegation delegations[DAO_MAX_DELEGATES];
    int      delegation_count;
    uint8_t  timelock_controller[20];
    bool     emergency_mode;
} DAOGovernor;

typedef struct {
    uint64_t voice_credits;
    uint64_t raw_votes;
    uint64_t quadratic_weight;
    uint64_t effective_power;
} DAOQuadraticVote;

typedef struct {
    uint32_t proposal_id;
    uint8_t  voter[20];
    uint64_t voice_credits_spent;
    uint64_t raw_vote_count;
    uint64_t quadratic_result;
    bool     cast;
} DAOQuadraticBallot;

void        governor_init(DAOGovernor *gov, uint64_t total_supply, uint64_t quorum_bps, uint64_t voting_period);
uint32_t    proposal_create(DAOGovernor *gov, const uint8_t proposer[20], const uint8_t targets[][20], const uint64_t *values, const uint8_t calldatas[][128], int target_count, const uint8_t desc_hash[32]);
bool        proposal_cancel(DAOGovernor *gov, uint32_t proposal_id, const uint8_t caller[20]);
bool        proposal_veto(DAOGovernor *gov, uint32_t proposal_id);
bool        vote_cast(DAOGovernor *gov, uint32_t proposal_id, const uint8_t voter[20], uint64_t power, DAOVoteType vote);
DAOVoteType vote_get_result(const DAOGovernor *gov, uint32_t proposal_id);
bool        vote_has_quorum(const DAOGovernor *gov, uint32_t proposal_id);
uint64_t    vote_count_delegated_power(const DAOGovernor *gov, const uint8_t voter[20]);
bool        vote_delegate(DAOGovernor *gov, const uint8_t delegator[20], const uint8_t delegate[20], uint64_t amount, uint64_t expiry);
bool        vote_undelegate(DAOGovernor *gov, const uint8_t delegator[20]);
uint64_t    vote_get_voting_power(const DAOGovernor *gov, const uint8_t addr[20]);
bool        proposal_queue(DAOGovernor *gov, uint32_t proposal_id);
bool        proposal_execute(DAOGovernor *gov, uint32_t proposal_id);
bool        proposal_state_transition(DAOGovernor *gov, uint32_t proposal_id);
void        proposal_process_expired(DAOGovernor *gov, uint64_t current_time);
void        quadratic_vote_init(DAOQuadraticVote *qv, uint64_t voice_credits);
DAOVoteType quadratic_vote_cast(DAOGovernor *gov, uint32_t proposal_id, const uint8_t voter[20], uint64_t voice_credits, DAOVoteType preference);
uint64_t    quadratic_voting_cost(uint64_t vote_count);
uint64_t    quadratic_voting_power(uint64_t voice_credits, uint64_t votes_spent);
uint64_t    time_weighted_voting_power(uint64_t raw_power, uint64_t lock_duration, uint64_t max_lock);
uint64_t    vote_boost_from_lock(uint64_t lock_days, uint64_t max_lock_days);
uint64_t    conviction_voting_weight(uint64_t preference_intensity, uint64_t time_staked);
bool        conviction_threshold_met(uint64_t conviction, uint64_t threshold);

#endif
