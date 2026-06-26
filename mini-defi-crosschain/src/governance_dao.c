#include "governance_dao.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t dao_rand_seed = 0xDA0DA000;

static uint32_t dao_rand(void) {
    dao_rand_seed = dao_rand_seed * 1103515245 + 12345;
    return dao_rand_seed;
}

static uint64_t dao_min64(uint64_t a, uint64_t b) { return a < b ? a : b; }
static uint64_t dao_max64(uint64_t a, uint64_t b) { return a > b ? a : b; }

/*
 * ===================================================================
 * L1: Governor initialization — sets up DAO with configurable
 * quorum, voting period, and timelock delay.
 * ===================================================================
 */
void governor_init(DAOGovernor *gov, uint64_t total_supply,
                   uint64_t quorum_bps, uint64_t voting_period) {
    memset(gov, 0, sizeof(DAOGovernor));
    gov->total_supply = total_supply;
    gov->quorum_bps = quorum_bps > 0 ? quorum_bps : DAO_QUORUM_BPS;
    gov->proposal_threshold_bps = DAO_PROPOSAL_THRESHOLD_BPS;
    gov->voting_period = voting_period > 0 ? voting_period : DAO_VOTING_PERIOD;
    gov->timelock_delay = DAO_TIMELOCK_DELAY;
    gov->proposal_count = 0;
    gov->voter_count = 0;
    gov->delegation_count = 0;
    gov->emergency_mode = false;
}

/*
 * ===================================================================
 * L1: Proposal creation — stores call targets, values, and calldatas.
 * Returns the new proposal ID (1-indexed), or 0 on failure.
 * ===================================================================
 */
uint32_t proposal_create(DAOGovernor *gov, const uint8_t proposer[20],
                          const uint8_t targets[][20], const uint64_t *values,
                          const uint8_t calldatas[][128], int target_count,
                          const uint8_t desc_hash[32]) {
    if (!gov || !proposer || target_count <= 0 || target_count > 8)
        return 0;
    if (gov->proposal_count >= DAO_MAX_PROPOSALS) return 0;

    uint64_t proposer_power = vote_get_voting_power(gov, proposer);
    uint64_t threshold = gov->total_supply * gov->proposal_threshold_bps
                        / DAO_BPS_DENOM;
    if (proposer_power < threshold) return 0;

    uint32_t pid = gov->proposal_count;
    DAOProposal *p = &gov->proposals[pid];

    p->proposal_id = pid;
    memcpy(p->proposer, proposer, 20);
    p->target_count = (uint32_t)target_count;
    if (targets) {
        for (int i = 0; i < target_count && i < 8; i++) {
            memcpy(p->targets[i], targets[i], 20);
            p->values[i] = values ? values[i] : 0;
            if (calldatas) memcpy(p->calldatas[i], calldatas[i], 128);
        }
    }
    p->start_time = dao_rand() + 1000000;
    p->end_time = p->start_time + gov->voting_period;
    p->for_votes = 0;
    p->against_votes = 0;
    p->abstain_votes = 0;
    p->state = DAO_ACTIVE;
    p->executed = false;
    if (desc_hash) memcpy(p->description_hash, desc_hash, 32);

    gov->proposal_count++;
    return pid + 1;
}

bool proposal_cancel(DAOGovernor *gov, uint32_t proposal_id,
                     const uint8_t caller[20]) {
    if (!gov || !caller || proposal_id == 0 || proposal_id > gov->proposal_count)
        return false;

    DAOProposal *p = &gov->proposals[proposal_id - 1];
    if (p->state != DAO_ACTIVE && p->state != DAO_PENDING) return false;
    if (memcmp(p->proposer, caller, 20) != 0) return false;

    p->state = DAO_CANCELED;
    return true;
}

bool proposal_veto(DAOGovernor *gov, uint32_t proposal_id) {
    if (!gov || proposal_id == 0 || proposal_id > gov->proposal_count)
        return false;
    if (!gov->emergency_mode) return false;

    DAOProposal *p = &gov->proposals[proposal_id - 1];
    if (p->state == DAO_EXECUTED) return false;
    p->state = DAO_VETOED;
    return true;
}

/*
 * ===================================================================
 * L2: Vote casting — records a vote with voting power.
 * A voter can only vote once per proposal (re-vote overwrites).
 * ===================================================================
 */
bool vote_cast(DAOGovernor *gov, uint32_t proposal_id,
               const uint8_t voter[20], uint64_t power, DAOVoteType vote) {
    if (!gov || !voter || proposal_id == 0 || proposal_id > gov->proposal_count)
        return false;

    DAOProposal *p = &gov->proposals[proposal_id - 1];
    if (p->state != DAO_ACTIVE) return false;

    /* Check if voter already voted and subtract old vote */
    for (int i = 0; i < gov->voter_count; i++) {
        if (memcmp(gov->voters[i].voter_addr, voter, 20) == 0 &&
            gov->voters[i].has_voted) {
            if (gov->voters[i].vote == DAO_VOTE_FOR)
                p->for_votes -= gov->voters[i].voting_power;
            else if (gov->voters[i].vote == DAO_VOTE_AGAINST)
                p->against_votes -= gov->voters[i].voting_power;
            else
                p->abstain_votes -= gov->voters[i].voting_power;

            gov->voters[i].voting_power = power;
            gov->voters[i].vote = vote;
            goto add_vote;
        }
    }

    /* New voter */
    if (gov->voter_count >= DAO_MAX_VOTERS) return false;
    {
        DAOVoter *v = &gov->voters[gov->voter_count];
        memcpy(v->voter_addr, voter, 20);
        v->voting_power = power;
        v->has_voted = true;
        v->vote = vote;
        v->delegated_from = 0;
        gov->voter_count++;
    }

add_vote:
    if (vote == DAO_VOTE_FOR) p->for_votes += power;
    else if (vote == DAO_VOTE_AGAINST) p->against_votes += power;
    else p->abstain_votes += power;

    return true;
}

DAOVoteType vote_get_result(const DAOGovernor *gov, uint32_t proposal_id) {
    if (!gov || proposal_id == 0 || proposal_id > gov->proposal_count)
        return DAO_VOTE_AGAINST;

    const DAOProposal *p = &gov->proposals[proposal_id - 1];
    if (p->state != DAO_SUCCEEDED && p->state != DAO_QUEUED)
        return DAO_VOTE_AGAINST;

    if (p->for_votes > p->against_votes) return DAO_VOTE_FOR;
    return DAO_VOTE_AGAINST;
}

/*
 * ===================================================================
 * L3: Quorum check — enough participation to legitimize decision.
 *
 * Theorem: Quorum requirement prevents minority capture.
 * Without quorum, a small group could pass proposals without
 * meaningful stakeholder participation.
 * ===================================================================
 */
bool vote_has_quorum(const DAOGovernor *gov, uint32_t proposal_id) {
    if (!gov || proposal_id == 0 || proposal_id > gov->proposal_count)
        return false;

    const DAOProposal *p = &gov->proposals[proposal_id - 1];
    uint64_t total_votes = p->for_votes + p->against_votes + p->abstain_votes;
    uint64_t required = gov->total_supply * gov->quorum_bps / DAO_BPS_DENOM;
    return total_votes >= required;
}

/*
 * ===================================================================
 * L2: Delegation — liquid democracy mechanism
 *
 * Token holders can delegate voting power to representatives.
 * Delegation can be revoked at any time.
 * ===================================================================
 */
bool vote_delegate(DAOGovernor *gov, const uint8_t delegator[20],
                   const uint8_t delegate[20], uint64_t amount,
                   uint64_t expiry) {
    if (!gov || !delegator || !delegate) return false;
    if (gov->delegation_count >= DAO_MAX_DELEGATES) return false;

    for (int i = 0; i < gov->delegation_count; i++) {
        if (gov->delegations[i].active &&
            memcmp(gov->delegations[i].delegator_addr, delegator, 20) == 0) {
            gov->delegations[i].delegated_power = amount;
            gov->delegations[i].expiry = expiry;
            memcpy(gov->delegations[i].delegate_addr, delegate, 20);
            return true;
        }
    }

    DAODelegation *d = &gov->delegations[gov->delegation_count];
    memcpy(d->delegator_addr, delegator, 20);
    memcpy(d->delegate_addr, delegate, 20);
    d->delegated_power = amount;
    d->expiry = expiry;
    d->active = true;
    gov->delegation_count++;
    return true;
}

bool vote_undelegate(DAOGovernor *gov, const uint8_t delegator[20]) {
    if (!gov || !delegator) return false;
    for (int i = 0; i < gov->delegation_count; i++) {
        if (gov->delegations[i].active &&
            memcmp(gov->delegations[i].delegator_addr, delegator, 20) == 0) {
            gov->delegations[i].active = false;
            return true;
        }
    }
    return false;
}

uint64_t vote_get_voting_power(const DAOGovernor *gov, const uint8_t addr[20]) {
    if (!gov || !addr) return 0;

    uint64_t power = 0;
    for (int i = 0; i < gov->delegation_count; i++) {
        if (gov->delegations[i].active &&
            memcmp(gov->delegations[i].delegate_addr, addr, 20) == 0) {
            power += gov->delegations[i].delegated_power;
        }
    }
    return power;
}

uint64_t vote_count_delegated_power(const DAOGovernor *gov,
                                     const uint8_t voter[20]) {
    return vote_get_voting_power(gov, voter);
}

/*
 * ===================================================================
 * L3: Proposal lifecycle — state machine for governance proposals
 *
 * States: PENDING -> ACTIVE -> SUCCEEDED -> QUEUED -> EXECUTED
 *               \-> CANCELED
 *               \-> DEFEATED
 *               \-> EXPIRED (timelock timeout)
 * ===================================================================
 */
bool proposal_queue(DAOGovernor *gov, uint32_t proposal_id) {
    if (!gov || proposal_id == 0 || proposal_id > gov->proposal_count)
        return false;

    DAOProposal *p = &gov->proposals[proposal_id - 1];
    if (p->state != DAO_SUCCEEDED) return false;
    if (!vote_has_quorum(gov, proposal_id)) return false;

    p->state = DAO_QUEUED;
    p->execution_time = p->end_time + gov->timelock_delay;
    return true;
}

bool proposal_execute(DAOGovernor *gov, uint32_t proposal_id) {
    if (!gov || proposal_id == 0 || proposal_id > gov->proposal_count)
        return false;

    DAOProposal *p = &gov->proposals[proposal_id - 1];
    if (p->state != DAO_QUEUED || p->executed) return false;

    uint64_t now = dao_rand() + 3000000;
    if (now < p->execution_time) return false;

    p->executed = true;
    p->state = DAO_EXECUTED;
    return true;
}

bool proposal_state_transition(DAOGovernor *gov, uint32_t proposal_id) {
    if (!gov || proposal_id == 0 || proposal_id > gov->proposal_count)
        return false;

    DAOProposal *p = &gov->proposals[proposal_id - 1];
    uint64_t now = dao_rand() + 2000000;

    if (p->state == DAO_ACTIVE && now >= p->end_time) {
        if (vote_has_quorum(gov, proposal_id) &&
            p->for_votes > p->against_votes) {
            p->state = DAO_SUCCEEDED;
        } else {
            p->state = DAO_DEFEATED;
        }
        return true;
    }

    if (p->state == DAO_PENDING && now >= p->start_time) {
        p->state = DAO_ACTIVE;
        return true;
    }

    return false;
}

void proposal_process_expired(DAOGovernor *gov, uint64_t current_time) {
    if (!gov) return;
    for (uint32_t i = 0; i < gov->proposal_count; i++) {
        DAOProposal *p = &gov->proposals[i];
        if (p->state == DAO_ACTIVE && current_time > p->end_time) {
            proposal_state_transition(gov, i + 1);
        }
        if (p->state == DAO_QUEUED &&
            current_time > p->execution_time + gov->timelock_delay * 2) {
            p->state = DAO_EXPIRED;
        }
    }
}

/*
 * ===================================================================
 * L5: Quadratic Voting — cost of N votes = N^2 voice credits
 *
 * Theorem (Lalley & Weyl 2018): Under Quadratic Voting, the marginal
 * cost of influence equals the marginal social harm, achieving
 * approximate social optimality for public goods funding.
 *
 * Reference: "Radical Markets" — Posner & Weyl (2018)
 * ===================================================================
 */
void quadratic_vote_init(DAOQuadraticVote *qv, uint64_t voice_credits) {
    memset(qv, 0, sizeof(DAOQuadraticVote));
    qv->voice_credits = voice_credits;
}

uint64_t quadratic_voting_cost(uint64_t vote_count) {
    return vote_count * vote_count;
}

uint64_t quadratic_voting_power(uint64_t voice_credits, uint64_t votes_spent) {
    if (voice_credits == 0) return 0;
    uint64_t max_votes = 0;
    while ((max_votes + 1) * (max_votes + 1) <= voice_credits) {
        max_votes++;
    }
    if (votes_spent > max_votes) votes_spent = max_votes;
    return votes_spent;
}

DAOVoteType quadratic_vote_cast(DAOGovernor *gov, uint32_t proposal_id,
                                 const uint8_t voter[20], uint64_t voice_credits,
                                 DAOVoteType preference) {
    if (!gov || !voter || proposal_id == 0 || proposal_id > gov->proposal_count)
        return DAO_VOTE_ABSTAIN;

    DAOProposal *p = &gov->proposals[proposal_id - 1];
    uint64_t qv_power = quadratic_voting_power(voice_credits,
                                                voice_credits / 100 + 1);

    if (preference == DAO_VOTE_FOR)
        p->for_votes += qv_power;
    else if (preference == DAO_VOTE_AGAINST)
        p->against_votes += qv_power;
    else
        p->abstain_votes += qv_power;

    return preference;
}

/*
 * ===================================================================
 * L8: Time-weighted voting — veToken model (Curve Finance)
 *
 * Longer token lock = more voting power. Aligns incentives:
 * long-term stakeholders get more governance influence.
 *
 * Formula: power = raw * (1 + lock/max_lock)
 * Range: 1x to 2x voting power
 * ===================================================================
 */
uint64_t time_weighted_voting_power(uint64_t raw_power, uint64_t lock_duration,
                                     uint64_t max_lock) {
    if (max_lock == 0) return raw_power;
    if (lock_duration > max_lock) lock_duration = max_lock;
    return raw_power + (raw_power * lock_duration) / max_lock;
}

uint64_t vote_boost_from_lock(uint64_t lock_days, uint64_t max_lock_days) {
    if (max_lock_days == 0 || lock_days == 0) return DAO_BPS_DENOM;
    if (lock_days > max_lock_days) lock_days = max_lock_days;
    return DAO_BPS_DENOM + (lock_days * 150 * DAO_BPS_DENOM)
                         / (max_lock_days * 100);
}

/*
 * ===================================================================
 * L9: Conviction Voting — experimental governance (1Hive Gardens)
 *
 * Voting power accumulates as sqrt(time) while preference is staked.
 * Proposals pass when accumulated conviction exceeds threshold.
 * ===================================================================
 */
uint64_t conviction_voting_weight(uint64_t preference_intensity,
                                   uint64_t time_staked) {
    uint64_t sqrt_time = 0;
    while ((sqrt_time + 1) * (sqrt_time + 1) <= time_staked) {
        sqrt_time++;
    }
    return preference_intensity * sqrt_time / 100;
}

bool conviction_threshold_met(uint64_t conviction, uint64_t threshold) {
    return conviction >= threshold;
}