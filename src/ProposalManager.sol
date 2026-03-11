// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {AccessControl} from "openzeppelin-contracts/contracts/access/AccessControl.sol";
import {IProposalManager} from "../src/interfaces/IProposalManager.sol";

contract ProposalManager is IProposalManager, AccessControl {
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    bytes32 public constant TREASURY_ROLE = keccak256("TREASURY_ROLE");

    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");

    uint256 public constant MIN_COMMIT_BLOCKS = 1;

    mapping(bytes32 => Proposal) private _proposals;

    mapping(address => uint256) private _activeProposals;

    uint256 public constant MAX_ACTIVE_PER_PROPOSER = 5;

    constructor(address admin, address guardian) {
        require(admin != address(0), "ProposalManager: zero admin");
        require(guardian != address(0), "ProposalManager: zero guardian");

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, guardian);
    }

    function commitProposal(bytes32 proposalHash) external override {
        require(proposalHash != bytes32(0), "ProposalManager: zero hash");
        require(_proposals[proposalHash].state == ProposalState.NONE, "ProposalManager: already exists");
        require(_activeProposals[msg.sender] < MAX_ACTIVE_PER_PROPOSER, "ProposalManager: too many active proposals");

        _proposals[proposalHash] = Proposal({
            proposalHash: proposalHash,
            proposer: msg.sender,
            actionType: ActionType.TRANSFER,
            target: address(0),
            callData: "",
            value: 0,
            commitBlock: block.number,
            revealBlock: 0,
            state: ProposalState.COMMITTED
        });

        _activeProposals[msg.sender]++;

        emit ProposalCommitted(proposalHash, msg.sender);
    }

    function revealProposal(ActionType actionType, address target, bytes calldata callData, uint256 value, bytes32 salt)
        external
        override
        returns (bytes32 proposalHash)
    {
        proposalHash = keccak256(abi.encode(actionType, target, callData, value, salt));

        Proposal storage p = _proposals[proposalHash];
        require(p.state == ProposalState.COMMITTED, "ProposalManager: not committed");
        require(p.proposer == msg.sender, "ProposalManager: not proposer");
        require(block.number >= p.commitBlock + MIN_COMMIT_BLOCKS, "ProposalManager: reveal too soon");
        require(target != address(0), "ProposalManager: zero target");

        p.actionType = actionType;
        p.target = target;
        p.callData = callData;
        p.value = value;
        p.revealBlock = block.number;
        p.state = ProposalState.QUEUED;

        emit ProposalRevealed(proposalHash, actionType);
    }

    function cancelProposal(bytes32 proposalHash) external override {
        Proposal storage p = _proposals[proposalHash];
        require(
            p.state == ProposalState.COMMITTED || p.state == ProposalState.QUEUED, "ProposalManager: not cancellable"
        );

        bool isGuardian = hasRole(GUARDIAN_ROLE, msg.sender);
        bool isProposer = (p.proposer == msg.sender && p.state == ProposalState.COMMITTED);

        require(isGuardian || isProposer, "ProposalManager: not authorized to cancel");

        p.state = ProposalState.CANCELLED;
        _activeProposals[p.proposer]--;

        emit ProposalCancelled(proposalHash, msg.sender);
    }

    function markExecuted(bytes32 proposalHash) external onlyRole(TREASURY_ROLE) {
        Proposal storage p = _proposals[proposalHash];
        require(p.state == ProposalState.QUEUED, "ProposalManager: not queued");

        p.state = ProposalState.EXECUTED;
        _activeProposals[p.proposer]--;

        emit ProposalExecuted(proposalHash);
    }

    function getProposal(bytes32 proposalHash) external view override returns (Proposal memory) {
        return _proposals[proposalHash];
    }

    function getProposalState(bytes32 proposalHash) external view override returns (ProposalState) {
        return _proposals[proposalHash].state;
    }
}
