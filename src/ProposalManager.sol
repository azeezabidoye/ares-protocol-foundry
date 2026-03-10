// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {AccessControl} from "openzeppelin-contracts/contracts/access/AccessControl.sol";
import {IProposalManager} from "../src/interfaces/IProposalManager.sol";

/// @title ProposalManager
/// @notice Manages the full lifecycle of ARES treasury proposals.
///
///         Lifecycle:
///           commit()  → COMMITTED
///           reveal()  → QUEUED     (also notifies TimelockEngine via callback)
///           cancel()  → CANCELLED
///           markExecuted() is called by AresTreasury after successful execution → EXECUTED
///
///         The commit-reveal pattern prevents front-running: the proposer first
///         locks in a hash commitment without revealing call parameters, then
///         reveals after the commit block.
contract ProposalManager is IProposalManager, AccessControl {
    // ─────────────────────────────────────────────────────────────────────────
    // Roles
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice May cancel any proposal (guardian multisig — cannot execute).
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    /// @notice The treasury core contract — the only caller of markExecuted().
    bytes32 public constant TREASURY_ROLE = keccak256("TREASURY_ROLE");

    /// @notice Address allowed to reveal and queue proposals (set to treasury).
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");

    // ─────────────────────────────────────────────────────────────────────────
    // State
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Minimum blocks between commit and reveal to deter spam.
    uint256 public constant MIN_COMMIT_BLOCKS = 1;

    /// @dev proposalHash → Proposal
    mapping(bytes32 => Proposal) private _proposals;

    /// @dev proposer → active proposal count (rate limiting)
    mapping(address => uint256) private _activeProposals;

    /// @notice Maximum concurrent active proposals per address.
    uint256 public constant MAX_ACTIVE_PER_PROPOSER = 5;

    // ─────────────────────────────────────────────────────────────────────────
    // Constructor
    // ─────────────────────────────────────────────────────────────────────────

    constructor(address admin, address guardian) {
        require(admin != address(0), "ProposalManager: zero admin");
        require(guardian != address(0), "ProposalManager: zero guardian");

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, guardian);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // External — Proposer Actions
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Phase 1: commit a hash of the proposal parameters.
    /// @param  proposalHash keccak256(abi.encode(actionType, target, callData, value, salt))
    function commitProposal(bytes32 proposalHash) external override {
        require(proposalHash != bytes32(0), "ProposalManager: zero hash");
        require(
            _proposals[proposalHash].state == ProposalState.NONE,
            "ProposalManager: already exists"
        );
        require(
            _activeProposals[msg.sender] < MAX_ACTIVE_PER_PROPOSER,
            "ProposalManager: too many active proposals"
        );

        _proposals[proposalHash] = Proposal({
            proposalHash: proposalHash,
            proposer: msg.sender,
            actionType: ActionType.TRANSFER, // placeholder until reveal
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

    /// @notice Phase 2: reveal parameters and queue the proposal.
    ///         Verifies the hash matches the committed one.
    /// @return proposalHash The verified proposal hash
    function revealProposal(
        ActionType actionType,
        address target,
        bytes calldata callData,
        uint256 value,
        bytes32 salt
    ) external override returns (bytes32 proposalHash) {
        proposalHash = keccak256(
            abi.encode(actionType, target, callData, value, salt)
        );

        Proposal storage p = _proposals[proposalHash];
        require(
            p.state == ProposalState.COMMITTED,
            "ProposalManager: not committed"
        );
        require(p.proposer == msg.sender, "ProposalManager: not proposer");
        require(
            block.number >= p.commitBlock + MIN_COMMIT_BLOCKS,
            "ProposalManager: reveal too soon"
        );
        require(target != address(0), "ProposalManager: zero target");

        // Write revealed parameters
        p.actionType = actionType;
        p.target = target;
        p.callData = callData;
        p.value = value;
        p.revealBlock = block.number;
        p.state = ProposalState.QUEUED;

        emit ProposalRevealed(proposalHash, actionType);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // External — Guardian / Proposer Cancel
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Cancel a proposal.  Allowed for: guardian (any state), proposer
    ///         (COMMITTED state only before reveal).
    function cancelProposal(bytes32 proposalHash) external override {
        Proposal storage p = _proposals[proposalHash];
        require(
            p.state == ProposalState.COMMITTED ||
                p.state == ProposalState.QUEUED,
            "ProposalManager: not cancellable"
        );

        bool isGuardian = hasRole(GUARDIAN_ROLE, msg.sender);
        bool isProposer = (p.proposer == msg.sender &&
            p.state == ProposalState.COMMITTED);

        require(
            isGuardian || isProposer,
            "ProposalManager: not authorized to cancel"
        );

        p.state = ProposalState.CANCELLED;
        _activeProposals[p.proposer]--;

        emit ProposalCancelled(proposalHash, msg.sender);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // External — Treasury Callback
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Called by AresTreasury after a proposal is successfully executed.
    function markExecuted(
        bytes32 proposalHash
    ) external onlyRole(TREASURY_ROLE) {
        Proposal storage p = _proposals[proposalHash];
        require(p.state == ProposalState.QUEUED, "ProposalManager: not queued");

        p.state = ProposalState.EXECUTED;
        _activeProposals[p.proposer]--;

        emit ProposalExecuted(proposalHash);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // View
    // ─────────────────────────────────────────────────────────────────────────

    function getProposal(
        bytes32 proposalHash
    ) external view override returns (Proposal memory) {
        return _proposals[proposalHash];
    }

    function getProposalState(
        bytes32 proposalHash
    ) external view override returns (ProposalState) {
        return _proposals[proposalHash].state;
    }
}
