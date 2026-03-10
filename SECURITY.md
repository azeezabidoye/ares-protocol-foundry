# ARES Protocol — Security Analysis

## Overview

This document describes the major attack surfaces of the ARES Protocol treasury system, the defensive mechanisms that address each one, and the residual risks that remain. It is intended as a reference for security reviewers and protocol operators.

---

## Attack Surfaces and Mitigations

### 1. Reentrancy

**Risk.** A malicious contract called as part of a treasury execution could attempt to call `execute()` recursively before the first execution completes. In a naive implementation, this would allow an attacker to drain treasury funds multiple times from a single authorized proposal.

**Defense.** The system applies two independent defenses. First, both the TimelockEngine and ProposalManager update their state to a terminal value (`executed = true`, `state = EXECUTED`) before the external call is ever made. This satisfies the checks-effects-interactions pattern: any reentrant call finds the proposal already executed and reverts. Second, `AresTreasury.execute()` carries OpenZeppelin's `ReentrancyGuard` mutex, which unconditionally reverts any nested call to any `nonReentrant` function in the same transaction. The two defenses are independent — either one alone is sufficient to block the attack.

### 2. Signature Replay

**Risk.** If valid signatures are not consumed after use, an attacker who observes a successful authorization could resubmit those same signatures to authorize a different proposal, or resubmit them on a different chain where the same contracts exist.

**Defense.** Every signature encodes three anti-replay fields: a per-signer nonce (incremented on consumption), a deadline timestamp after which the signature is invalid, and an EIP-712 domain separator that encodes both the contract address and `block.chainid`. Replaying a signature from chain A on chain B produces a different digest, which fails ECDSA recovery. Replaying a used signature on the same chain fails the nonce check. Using a stored signature after its deadline fails the expiry check.

### 3. Double Claims

**Risk.** A contributor who has proven inclusion in a Merkle tree could attempt to call `claim()` multiple times, receiving rewards repeatedly.

**Defense.** The `RewardDistributor` maintains a `claimed[periodId][account]` mapping that is set to `true` before the token transfer executes (CEI pattern). Any subsequent call with the same `(periodId, account)` pair reverts with `"already claimed"`. The claim state is keyed by period rather than globally, which correctly allows a contributor to claim across multiple independent reward periods while still preventing any double-claim within a single period.

### 4. Flash Loan Governance Manipulation

**Risk.** An attacker could borrow a large quantity of governance tokens within a single transaction, gain temporary voting power, and use it to approve a treasury drain before repaying the loan.

**Defense.** The proposal lifecycle requires a minimum delay between commit and reveal (block-level), and all proposals must pass through the timelock (minimum 1 day) before execution. Flash loans are atomic — they are borrowed and repaid within one block. By the time the timelock delay elapses, any borrowed voting weight has long since been repaid. Additionally, the AuthorizationLayer uses a fixed, known signer set rather than token-weighted voting, which makes this class of attack structurally inapplicable to the authorization step.

### 5. Unauthorized Execution

**Risk.** An adversary with no governance role attempts to execute a treasury action directly.

**Defense.** All execution-path functions (`queueExecution`, `execute`) are gated behind OpenZeppelin's `AccessControl` `EXECUTOR_ROLE`. Additionally, `execute()` checks that the proposal exists in `QUEUED` state in the ProposalManager (proving it was legitimately revealed), that it has been authorized by the AuthorizationLayer (proving M-of-N approval), and that the TimelockEngine reports it as executable (proving the delay has elapsed). All four conditions must be simultaneously true.

### 6. Timelock Bypass

**Risk.** An attacker attempts to circumvent the time delay, either by exploiting a logic flaw in the `executableAfter` check, by manipulating block timestamps, or by using reentrancy to execute before the delay elapses.

**Defense.** The `MIN_DELAY` constant is 1 day. Validator timestamp manipulation is limited to approximately 15 seconds on modern chains — several orders of magnitude below the minimum delay. The `markExecuted` function verifies `block.timestamp >= executableAfter` as an explicit require, so timestamp drift cannot bypass it. The reentrancy scenario is addressed separately above.

### 7. Proposal Griefing

**Risk.** An adversary submits a large number of proposals to consume governance attention, bloat storage, or prevent legitimate proposals from being processed.

**Defense.** The ProposalManager enforces a `MAX_ACTIVE_PER_PROPOSER` limit. Once an address has five concurrent active proposals, further commits revert. Proposals can only be cancelled (not withdrawn and resubmitted) once committed, preventing rapid cycling. The guardian role can cancel malicious proposals without waiting for governance, providing a low-latency response to active griefing campaigns.

### 8. Merkle Root Manipulation

**Risk.** A malicious governance action updates the Merkle root to one that contains fraudulent (address, amount) entries, directing rewards to attacker-controlled addresses.

**Defense.** Root updates in `RewardDistributor` are gated behind `ADMIN_ROLE`, which means they require a full governance proposal, M-of-N authorization, and the timelock delay before taking effect. This gives honest observers a 24+ hour window to detect and cancel a fraudulent root update via the guardian.

### 9. Spending Limit Breach

**Risk.** A legitimate but misconfigured proposal, or a governance attack that passes all security layers, attempts to drain the entire treasury in a single transaction.

**Defense.** `AresTreasury` enforces a per-transaction limit (`MAX_SINGLE_TRANSFER = 1,000,000 ether`) and a rolling 24-hour outflow cap (`DAILY_LIMIT = 5,000,000 ether`) enforced by `SpendingLib`. Even a fully authorized proposal cannot move more than these amounts. These constants can only be changed through a contract upgrade, which itself requires governance + timelock.

---

## Remaining Risks and Limitations

**Admin key compromise.** If the admin multisig is compromised, an attacker could update the signer set, lower the authorization threshold, or assign privileged roles. This is mitigated operationally by using hardware wallets, geographic distribution, and a timelock on admin actions. It cannot be fully eliminated in a system that requires governance upgrade capability.

**Signer collusion.** If a majority of the M-of-N signer set colludes, they can authorize any proposal. The timelock delay provides the primary defense — the community has a window to observe suspicious authorizations and respond. The guardian can cancel proposals during this window.

**Off-chain Merkle tree integrity.** The correctness of the reward distribution depends on the off-chain process that builds and publishes the Merkle tree. If the off-chain data is corrupted or manipulated before the root is submitted to governance, the on-chain system cannot detect this. Protocols should publish Merkle tree data publicly and allow community verification before root activation.

**Oracle-free design.** This system contains no price oracles or external data feeds, which eliminates an entire class of oracle manipulation attacks. This is an intentional design constraint.

**No upgradeability.** Contracts are not upgradeable proxies. This eliminates upgrade-related attack vectors but means that bug fixes require deploying new contracts and migrating state. This is a deliberate security tradeoff favoring immutability.
