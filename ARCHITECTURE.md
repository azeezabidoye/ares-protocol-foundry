# ARES Protocol — System Architecture

## Overview

The ARES Protocol treasury system is based on a single principle: no treasury action should be possible with a single point of failure. Each execution path requires four separate requirements to be met: a legitimate proposal, cryptographic authorization, a time delay, and role-gated triggering. If any of these conditions are not met, the execution reverts.

The system is purposely divided into modules rather than being built as a single contract. This separation ensures that a bug in the reward distribution system does not influence the timelock, that a compromised authorization signer cannot directly drain funds, and that the spending restriction logic is enforced in a library that cannot be bypassed through module interaction.

---

## Module Responsibilities

**AresTreasury (core/AresTreasury.sol)** is the orchestrator. It contains no proposal logic, signature verification logic, or queue logic of its own. It delegated to the three modules and ensured proper sequencing. It also owns the spending limit enforcement, which is the only place where the protocol's financial risk caps are reviewed before a transfer occurs. The treasury is the only contract with the TREASURY_ROLE on the other modules, making it the only authorized caller for state-changing operations on them.

**ProposalManager (modules/ProposalManager.sol)** owns the full lifecycle of a treasury proposal, from initial hash commitment through reveal, queuing, execution, and cancellation. It enforces the commit-reveal pattern, which prevents front-running and ensures that a proposer cannot silently change their proposal parameters after submission. It also enforces per-address proposal rate limiting to prevent spam attacks.

**AuthorizationLayer (modules/AuthorizationLayer.sol)** handles all cryptographic verification. It implements EIP-712 structured signing with a per-contract domain separator, per-signer nonces, and signature deadlines. It requires M-of-N threshold approval from a registered signer set before marking a proposal as authorized. All signature operations use OpenZeppelin's ECDSA library, which eliminates signature malleability vulnerabilities present in raw `ecrecover` usage.

**TimelockEngine (modules/TimelockEngine.sol)** is a hash-based execution queue. Proposals enter the queue as 32-byte hashes with an `executableAfter` timestamp. At execution time, the treasury marks the entry as executed before making any external calls, satisfying the checks-effects-interactions pattern. A `ReentrancyGuard` on the treasury provides a second independent barrier. The minimum delay is enforced as a constant (1 day), making timestamp drift attacks economically irrelevant.

**RewardDistributor (modules/RewardDistributor.sol)** manages Merkle-based contributor reward distribution. Rather than storing individual claim entitlements on-chain, only the 32-byte Merkle root is stored. Contributors claim by supplying their leaf data and an inclusion proof. Leaves are double-hashed to prevent second-preimage attacks. Claim state is tracked per (periodId, account) to prevent double claims while allowing multiple independent reward periods.

The ordering within step [5] is critical: both state machines are updated to their terminal state before any external call is made. This means that any reentrant attempt to call `execute()` again will find the proposal already marked as executed and revert immediately.

---

## Security Boundaries

Each module trusts only its own state and the addresses it was initialized with. The AuthorizationLayer does not know whether a proposal was legitimately created — it only verifies signatures. The TimelockEngine does not know whether authorization passed — it only enforces the time delay. The AresTreasury is the single point that verifies all three pre-conditions are satisfied before proceeding.

The guardian role exists at the boundary of speed vs. safety. Guardians can cancel proposals but cannot execute them. This asymmetric power model means that even if the guardian key is compromised, an attacker can only block proposals, not steal funds.

---

## Trust Assumptions

The system assumes the admin multisig is honest but does not assume it is infallible. The timelock delay provides a window for the broader community to observe and react to any governance action, including one that would update the system's own parameters. The signer set for the AuthorizationLayer should be geographically distributed and stored on hardware wallets. The guardian should be a separate key set from the executor to eliminate single-point privilege escalation.
