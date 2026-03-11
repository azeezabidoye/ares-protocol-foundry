# ARES Protocol — Treasury Execution System

The Project is a modular, attack-resistant smart contract treasury for decentralized protocol governance. Manages $500 million+ in treasury assets using a multi-layered security architecture that includes commit-reveal proposals, EIP-712 multi-sig authorization, time-locked execution, and scalable Merkle reward distribution.

## Protocol Purpose

The ARES Protocol distributes capital to contributors, liquidity providers, and governance participants using a fully on-chain, trustless execution pipeline. Before monies can be transferred, each treasury action must pass through four independent security checkpoints.

---

## Compiling Contracts

```bash
forge build
```

## Running Tests

```bash
forge test -vvv
```

Expected output: all tests pass, including 11 negative/attack test cases.
