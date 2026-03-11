// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IProposalManager {
    enum ProposalState {
        NONE,
        COMMITTED,
        QUEUED,
        EXECUTED,
        CANCELLED
    }

    enum ActionType {
        TRANSFER,
        CALL,
        UPGRADE
    }

    struct Proposal {
        bytes32 proposalHash;
        address proposer;
        ActionType actionType;
        address target;
        bytes callData;
        uint256 value;
        uint256 commitBlock;
        uint256 revealBlock;
        ProposalState state;
    }

    event ProposalCommitted(bytes32 indexed proposalHash, address indexed proposer);
    event ProposalRevealed(bytes32 indexed proposalHash, ActionType actionType);
    event ProposalQueued(bytes32 indexed proposalHash, uint256 executableAfter);
    event ProposalExecuted(bytes32 indexed proposalHash);
    event ProposalCancelled(bytes32 indexed proposalHash, address cancelledBy);

    function commitProposal(bytes32 proposalHash) external;

    function revealProposal(
        ActionType actionType,
        address target,
        bytes calldata callData,
        uint256 value,
        bytes32 salt
    ) external returns (bytes32 proposalHash);

    function cancelProposal(bytes32 proposalHash) external;

    function getProposal(bytes32 proposalHash) external view returns (Proposal memory);

    function getProposalState(bytes32 proposalHash) external view returns (ProposalState);
}
