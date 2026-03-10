# ARES Protocol — Treasury Execution System

A modular, attack-resistant smart contract treasury for decentralized protocol governance. Manages $500M+ in treasury assets with a multi-layered security architecture: commit-reveal proposals, EIP-712 multi-sig authorization, time-locked execution, and scalable Merkle reward distribution.

---

## Protocol Purpose

ARES Protocol distributes capital to contributors, liquidity providers, and governance participants through a fully on-chain, trustless execution pipeline. Every treasury action must pass through four independent security checkpoints before funds move.

---

## Project Structure

```
ares-protocol/
├── src/
│   ├── core/
│   │   └── AresTreasury.sol          # Central orchestrator
│   ├── modules/
│   │   ├── ProposalManager.sol       # Proposal lifecycle
│   │   ├── AuthorizationLayer.sol    # EIP-712 multi-sig
│   │   ├── TimelockEngine.sol        # Delayed execution queue
│   │   └── RewardDistributor.sol     # Merkle reward claims
│   ├── interfaces/
│   │   ├── IProposalManager.sol
│   │   ├── IAuthorizationLayer.sol
│   │   ├── ITimelockEngine.sol
│   │   └── IRewardDistributor.sol
│   └── libraries/
│       ├── SignatureLib.sol           # EIP-712 helpers (stateless)
│       └── SpendingLib.sol            # Daily spending limit tracker
├── test/
│   ├── AresProtocol.t.sol            # Full test suite (functional + attacks)
│   └── mocks/
│       ├── MockERC20.sol
│       └── MaliciousReentrant.sol
├── script/
│   └── Deploy.s.sol                  # Foundry deployment script
├── foundry.toml
├── README.md
├── ARCHITECTURE.md
└── SECURITY.md
```

---

## Installation

### Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation) (forge, cast, anvil)
- Git

### Clone and Install

```bash
git clone https://github.com/your-org/ares-protocol
cd ares-protocol

# Install OpenZeppelin Contracts
forge install OpenZeppelin/openzeppelin-contracts --no-commit

# Verify installation
forge build
```

---

## Running Tests

```bash
# Run full test suite
forge test

# Run with verbose output (shows test names and logs)
forge test -vvv

# Run a specific test
forge test --match-test test_FullGovernanceLifecycle -vvv

# Run only attack simulation tests
forge test --match-test test_Attack -vvv

# Run with gas reporting
forge test --gas-report

# Run with increased fuzz iterations
forge test --fuzz-runs 1000
```

Expected output: all tests pass, including 11 negative/attack test cases.

---

## Deployment

### Local (Anvil)

```bash
# Start local node
anvil

# Deploy with default settings
forge script script/Deploy.s.sol --broadcast --rpc-url http://127.0.0.1:8545
```

### Testnet (Sepolia)

```bash
# Copy and configure environment
cp .env.example .env
# Edit .env with your values

source .env

forge script script/Deploy.s.sol \
  --broadcast \
  --rpc-url $SEPOLIA_RPC \
  --private-key $DEPLOYER_KEY \
  --verify \
  --etherscan-api-key $ETHERSCAN_KEY
```

### Environment Variables

| Variable | Description | Example |
|---|---|---|
| `ADMIN_ADDRESS` | Governance multisig | `0xABC...` |
| `GUARDIAN_ADDRESS` | Guardian multisig (cancel-only) | `0xDEF...` |
| `EXECUTOR_ADDRESS` | Executor EOA or contract | `0x123...` |
| `SIGNER_1` / `_2` / `_3` | Authorization signers | `0x456...` |
| `REWARD_TOKEN` | ERC-20 token for rewards | `0x789...` |
| `TIMELOCK_DELAY` | Delay in seconds | `86400` |

---

## Governance Lifecycle (Quick Reference)

```
1. proposalMgr.commitProposal(hash)         → COMMITTED
2. proposalMgr.revealProposal(params, salt)  → QUEUED
3. authLayer.authorizeProposal(hash, sigs)   → authorized = true
4. treasury.queueExecution(hash)             → enters timelock
5. (wait delay period)
6. treasury.execute(hash)                    → EXECUTED
```

---

## Audit Status

This system has not been audited. It is provided as a reference implementation demonstrating secure treasury design patterns. **Do not deploy to production without a professional security audit.**

---

## License

MIT
