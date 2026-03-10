// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IRewardDistributor
/// @notice Interface for the Merkle-based contributor reward distribution system
interface IRewardDistributor {
    // ─────────────────────────────────────────────────────────────────────────
    // Structs
    // ─────────────────────────────────────────────────────────────────────────

    struct RewardPeriod {
        bytes32 merkleRoot;
        uint256 totalAmount;
        uint256 activatedAt;
        bool    active;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Events
    // ─────────────────────────────────────────────────────────────────────────

    event RootUpdated(uint256 indexed periodId, bytes32 oldRoot, bytes32 newRoot);
    event RewardClaimed(uint256 indexed periodId, address indexed account, uint256 amount);
    event PeriodActivated(uint256 indexed periodId, bytes32 merkleRoot, uint256 totalAmount);

    // ─────────────────────────────────────────────────────────────────────────
    // Functions
    // ─────────────────────────────────────────────────────────────────────────

    function claim(
        uint256          periodId,
        address          account,
        uint256          amount,
        bytes32[] calldata proof
    ) external;

    function hasClaimed(uint256 periodId, address account) external view returns (bool);

    function getPeriod(uint256 periodId) external view returns (RewardPeriod memory);

    function currentPeriod() external view returns (uint256);
}
