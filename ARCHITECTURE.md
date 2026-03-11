# ARES Protocol — System Architecture

## Overview

The ARES Protocol treasury system is built around a single principle: no treasury action should be possible through a single point of failure. Every execution path requires four independent conditions to be satisfied — a valid proposal, cryptographic authorization, a time delay, and role-gated triggering. If any one of these conditions is missing, execution reverts.

The system is deliberately split into modules rather than implemented as a monolithic contract. This separation means that a bug in the reward distribution system cannot affect the timelock, a compromised authorization signer cannot directly drain funds, and the spending limit logic is enforced in a library that cannot be bypassed through module interaction.

---

## Module Responsibilities

**AresTreasury (AresTreasury.sol)** is the orchestrator. It holds no proposal logic, no signature verification logic, and no queue logic of its own. It delegates to the three modules and enforces the correct sequencing. It also owns the spending limit enforcement — the only place where the protocol's financial risk caps are checked before a transfer executes. The treasury is the only contract that holds the TREASURY_ROLE on the other modules, meaning it is the sole authorized caller for state-changing operations on them.

**ProposalManager (ProposalManager.sol)** owns the full lifecycle of a treasury proposal, from initial hash commitment through reveal, queuing, execution, and cancellation. It enforces the commit-reveal pattern, which prevents front-running and ensures that a proposer cannot silently change their proposal parameters after submission. It also enforces per-address proposal rate limiting to prevent spam attacks.

**AuthorizationLayer (AuthorizationLayer.sol)** handles all cryptographic verification. It implements EIP-712 structured signing with a per-contract domain separator, per-signer nonces, and signature deadlines. It requires M-of-N threshold approval from a registered signer set before marking a proposal as authorized. All signature operations use OpenZeppelin's ECDSA library, which eliminates signature malleability vulnerabilities present in raw `ecrecover` usage.

**TimelockEngine (TimelockEngine.sol)** is a hash-based execution queue. Proposals enter the queue as 32-byte hashes with an `executableAfter` timestamp. At execution time, the treasury marks the entry as executed before making any external calls, satisfying the checks-effects-interactions pattern. A `ReentrancyGuard` on the treasury provides a second independent barrier. The minimum delay is enforced as a constant (1 day), making timestamp drift attacks economically irrelevant.

**RewardDistributor (RewardDistributor.sol)** manages Merkle-based contributor reward distribution. Rather than storing individual claim entitlements on-chain, only the 32-byte Merkle root is stored. Contributors claim by supplying their leaf data and an inclusion proof. Leaves are double-hashed to prevent second-preimage attacks. Claim state is tracked per (periodId, account) to prevent double claims while allowing multiple independent reward periods.

The ordering within step [5] is critical: both state machines are updated to their terminal state before any external call is made. This means that any reentrant attempt to call `execute()` again will find the proposal already marked as executed and revert immediately.

---

## Security Boundaries

Each module trusts only its own state and the addresses it was initialized with. The `AuthorizationLayer` does not know whether a proposal was legitimately created — it only verifies signatures. The `TimelockEngine` does not know whether authorization passed — it only enforces the time delay. The `AresTreasury` is the single point that verifies all three pre-conditions are satisfied before proceeding.

The guardian role exists at the boundary of speed vs. safety. Guardians can cancel proposals but cannot execute them. This asymmetric power model means that even if the guardian key is compromised, an attacker can only block proposals, not steal funds.

---

## Trust Assumptions

The system assumes the admin multisig is honest but does not assume it is infallible. The timelock delay provides a window for the broader community to observe and react to any governance action, including one that would update the system's own parameters. The signer set for the `AuthorizationLayer` should be geographically distributed and stored on hardware wallets. The guardian should be a separate key set from the executor to eliminate single-point privilege escalation.
