// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IProposalManager
/// @notice Interface for the ARES Protocol proposal lifecycle management
interface IProposalManager {
    // ─────────────────────────────────────────────────────────────────────────
    // Enums & Structs
    // ─────────────────────────────────────────────────────────────────────────

    enum ProposalState {
        NONE,        // Does not exist
        COMMITTED,   // Hash committed, details not yet revealed
        QUEUED,      // Revealed and entered into timelock
        EXECUTED,    // Successfully executed
        CANCELLED    // Cancelled by guardian or proposer
    }

    enum ActionType {
        TRANSFER,   // ERC-20 token transfer
        CALL,       // Arbitrary external call
        UPGRADE     // Contract upgrade
    }

    struct Proposal {
        bytes32      proposalHash;
        address      proposer;
        ActionType   actionType;
        address      target;
        bytes        callData;
        uint256      value;
        uint256      commitBlock;
        uint256      revealBlock;
        ProposalState state;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Events
    // ─────────────────────────────────────────────────────────────────────────

    event ProposalCommitted(bytes32 indexed proposalHash, address indexed proposer);
    event ProposalRevealed(bytes32 indexed proposalHash, ActionType actionType);
    event ProposalQueued(bytes32 indexed proposalHash, uint256 executableAfter);
    event ProposalExecuted(bytes32 indexed proposalHash);
    event ProposalCancelled(bytes32 indexed proposalHash, address cancelledBy);

    // ─────────────────────────────────────────────────────────────────────────
    // Functions
    // ─────────────────────────────────────────────────────────────────────────

    function commitProposal(bytes32 proposalHash) external;

    function revealProposal(
        ActionType actionType,
        address    target,
        bytes calldata callData,
        uint256    value,
        bytes32    salt
    ) external returns (bytes32 proposalHash);

    function cancelProposal(bytes32 proposalHash) external;

    function getProposal(bytes32 proposalHash) external view returns (Proposal memory);

    function getProposalState(bytes32 proposalHash) external view returns (ProposalState);
}
