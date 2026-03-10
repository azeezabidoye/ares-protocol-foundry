// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {AccessControl} from "openzeppelin-contracts/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "openzeppelin-contracts/contracts/utils/ReentrancyGuard.sol";
import {MerkleProof} from "openzeppelin-contracts/contracts/utils/cryptography/MerkleProof.sol";
import {SafeERC20} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {IRewardDistributor} from "../src/interfaces/IRewardDistributor.sol";

/// @title RewardDistributor
/// @notice Scalable Merkle-proof reward distribution for ARES contributors.
///
///         Design overview:
///         - Off-chain: build a Merkle tree of (address, amount) leaves
///         - On-chain: store only the 32-byte root
///         - Claimers supply their leaf + proof; contract verifies and transfers
///
///         Security properties:
///         ✓ Double-hash of leaves prevents second-preimage attacks
///         ✓ claimed[periodId][account] prevents double-claim within a period
///         ✓ Each period has an independent root — updating a root cannot
///           retroactively invalidate past claims
///         ✓ Root updates require ADMIN_ROLE (goes through governance + timelock)
///         ✓ ReentrancyGuard + CEI pattern around token transfer
contract RewardDistributor is
    IRewardDistributor,
    AccessControl,
    ReentrancyGuard
{
    using SafeERC20 for IERC20;
    using MerkleProof for bytes32[];

    // ─────────────────────────────────────────────────────────────────────────
    // Roles
    // ─────────────────────────────────────────────────────────────────────────

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    // ─────────────────────────────────────────────────────────────────────────
    // State
    // ─────────────────────────────────────────────────────────────────────────

    IERC20 public immutable rewardToken;

    uint256 private _currentPeriod;

    /// @dev periodId → RewardPeriod
    mapping(uint256 => RewardPeriod) private _periods;

    /// @dev periodId → account → claimed
    mapping(uint256 => mapping(address => bool)) private _claimed;

    // ─────────────────────────────────────────────────────────────────────────
    // Constructor
    // ─────────────────────────────────────────────────────────────────────────

    constructor(address admin, address token) {
        require(admin != address(0), "RewardDist: zero admin");
        require(token != address(0), "RewardDist: zero token");

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);

        rewardToken = IERC20(token);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // External — Admin: activate a new reward period
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Activate a new reward period with a Merkle root.
    ///         Called by governance (via AresTreasury) after timelock delay.
    /// @param  merkleRoot   Root of the (address, amount) Merkle tree
    /// @param  totalAmount  Total tokens deposited for this period
    function activatePeriod(
        bytes32 merkleRoot,
        uint256 totalAmount
    ) external onlyRole(ADMIN_ROLE) {
        require(merkleRoot != bytes32(0), "RewardDist: zero root");
        require(totalAmount > 0, "RewardDist: zero amount");

        uint256 periodId = ++_currentPeriod;

        _periods[periodId] = RewardPeriod({
            merkleRoot: merkleRoot,
            totalAmount: totalAmount,
            activatedAt: block.timestamp,
            active: true
        });

        // Caller must have pre-approved this contract to pull the tokens.
        rewardToken.safeTransferFrom(msg.sender, address(this), totalAmount);

        emit PeriodActivated(periodId, merkleRoot, totalAmount);
    }

    /// @notice Update the root for an existing period (governance may correct errors).
    ///         Previous claims under the old root remain valid — no retroactive
    ///         invalidation because claims are keyed by (periodId, account).
    function updateRoot(
        uint256 periodId,
        bytes32 newRoot
    ) external onlyRole(ADMIN_ROLE) {
        require(_periods[periodId].active, "RewardDist: period not active");
        require(newRoot != bytes32(0), "RewardDist: zero root");

        bytes32 oldRoot = _periods[periodId].merkleRoot;
        _periods[periodId].merkleRoot = newRoot;

        emit RootUpdated(periodId, oldRoot, newRoot);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // External — Claim
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Claim contributor rewards for a specific period.
    ///
    ///         The leaf is double-hashed to prevent second-preimage attacks where
    ///         a crafted internal node could be submitted as a valid leaf.
    ///
    /// @param periodId  Reward period identifier
    /// @param account   Recipient address (claimant proves they are in the tree)
    /// @param amount    Token amount for this account in this period
    /// @param proof     Merkle inclusion proof
    function claim(
        uint256 periodId,
        address account,
        uint256 amount,
        bytes32[] calldata proof
    ) external override nonReentrant {
        require(account != address(0), "RewardDist: zero account");
        require(amount > 0, "RewardDist: zero amount");
        require(_periods[periodId].active, "RewardDist: period not active");
        require(!_claimed[periodId][account], "RewardDist: already claimed");

        // Double-hash the leaf: keccak256(keccak256(abi.encodePacked(account, amount)))
        // This matches the standard used by off-chain Merkle tree builders that
        // also double-hash, and prevents second-preimage attacks.
        bytes32 leaf = keccak256(
            bytes.concat(keccak256(abi.encodePacked(account, amount)))
        );

        require(
            MerkleProof.verify(proof, _periods[periodId].merkleRoot, leaf),
            "RewardDist: invalid proof"
        );

        // ── Effects BEFORE interaction (CEI) ──
        _claimed[periodId][account] = true;

        // ── Interaction ──
        rewardToken.safeTransfer(account, amount);

        emit RewardClaimed(periodId, account, amount);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // View
    // ─────────────────────────────────────────────────────────────────────────

    function hasClaimed(
        uint256 periodId,
        address account
    ) external view override returns (bool) {
        return _claimed[periodId][account];
    }

    function getPeriod(
        uint256 periodId
    ) external view override returns (RewardPeriod memory) {
        return _periods[periodId];
    }

    function currentPeriod() external view override returns (uint256) {
        return _currentPeriod;
    }
}
