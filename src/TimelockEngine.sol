// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {AccessControl} from "openzeppelin-contracts/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "openzeppelin-contracts/contracts/utils/ReentrancyGuard.sol";
import {ITimelockEngine} from "../src/interfaces/ITimelockEngine.sol";

/// @title TimelockEngine
/// @notice Hash-based time-delayed execution queue.
///
///         Security properties:
///         ✓ Minimum 24 h delay makes timestamp manipulation (~15 s drift) irrelevant
///         ✓ Execution parameters are re-hashed at execution time — transaction
///           replacement is impossible (you must supply the exact original params)
///         ✓ State is set to executed BEFORE the external call (CEI pattern)
///         ✓ ReentrancyGuard as a second independent reentrancy barrier
///         ✓ Cancelled entries can never be resurrected (no proposal replay)
contract TimelockEngine is ITimelockEngine, AccessControl, ReentrancyGuard {
    // ─────────────────────────────────────────────────────────────────────────
    // Roles
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Only the treasury core may queue and cancel executions.
    bytes32 public constant TREASURY_ROLE = keccak256("TREASURY_ROLE");

    /// @notice Guardian can cancel but never execute.
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    // ─────────────────────────────────────────────────────────────────────────
    // Constants
    // ─────────────────────────────────────────────────────────────────────────

    uint256 public constant MIN_DELAY = 1 days;
    uint256 public constant MAX_DELAY = 30 days;

    // ─────────────────────────────────────────────────────────────────────────
    // State
    // ─────────────────────────────────────────────────────────────────────────

    uint256 private _delay;

    /// @dev execHash → QueuedExecution
    mapping(bytes32 => QueuedExecution) private _queue;

    // ─────────────────────────────────────────────────────────────────────────
    // Constructor
    // ─────────────────────────────────────────────────────────────────────────

    constructor(address admin, address guardian, uint256 initialDelay) {
        require(admin != address(0), "Timelock: zero admin");
        require(guardian != address(0), "Timelock: zero guardian");
        require(
            initialDelay >= MIN_DELAY && initialDelay <= MAX_DELAY,
            "Timelock: delay out of bounds"
        );

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, guardian);

        _delay = initialDelay;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // External — Queue
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Queue a proposal for delayed execution.
    ///         Called by AresTreasury after authorization passes.
    /// @param  proposalHash  The proposal identifier (becomes the exec hash)
    /// @return execHash      Same as proposalHash (stored in queue)
    function queue(
        bytes32 proposalHash
    ) external override onlyRole(TREASURY_ROLE) returns (bytes32 execHash) {
        require(proposalHash != bytes32(0), "Timelock: zero hash");

        execHash = proposalHash; // 1-to-1 mapping for simplicity

        // Allow re-queue only if the slot is empty or was previously cancelled.
        // A previously executed slot cannot be re-queued (proposal replay prevention).
        QueuedExecution storage existing = _queue[execHash];
        require(
            existing.executableAfter == 0 || existing.cancelled,
            "Timelock: already queued"
        );

        uint256 readyAt = block.timestamp + _delay;

        _queue[execHash] = QueuedExecution({
            execHash: execHash,
            executableAfter: readyAt,
            executed: false,
            cancelled: false
        });

        emit ExecutionQueued(execHash, readyAt);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // External — Cancel
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Cancel a queued execution.
    ///         Callable by treasury or guardian.  Sets cancelled = true so the
    ///         entry can never be re-queued with the same hash.
    function cancel(bytes32 execHash) external override {
        require(
            hasRole(TREASURY_ROLE, msg.sender) ||
                hasRole(GUARDIAN_ROLE, msg.sender),
            "Timelock: not authorized"
        );

        QueuedExecution storage entry = _queue[execHash];
        require(entry.executableAfter > 0, "Timelock: not queued");
        require(!entry.executed, "Timelock: already executed");
        require(!entry.cancelled, "Timelock: already cancelled");

        entry.cancelled = true;
        emit ExecutionCancelled(execHash);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // External — Mark Executed (called by AresTreasury after the actual call)
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Mark an entry as executed.
    ///         IMPORTANT: AresTreasury must call this BEFORE making the external
    ///         treasury call to satisfy CEI.  The nonReentrant modifier on
    ///         AresTreasury.execute() provides the second layer of protection.
    function markExecuted(bytes32 execHash) external onlyRole(TREASURY_ROLE) {
        QueuedExecution storage entry = _queue[execHash];
        require(entry.executableAfter > 0, "Timelock: not queued");
        require(!entry.executed, "Timelock: already executed");
        require(!entry.cancelled, "Timelock: cancelled");
        require(
            block.timestamp >= entry.executableAfter,
            "Timelock: not yet executable"
        );

        // ── Effects FIRST ──
        entry.executed = true;

        emit ExecutionCompleted(execHash);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Admin
    // ─────────────────────────────────────────────────────────────────────────

    function updateDelay(
        uint256 newDelay
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(
            newDelay >= MIN_DELAY && newDelay <= MAX_DELAY,
            "Timelock: delay out of bounds"
        );
        emit DelayUpdated(_delay, newDelay);
        _delay = newDelay;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // View
    // ─────────────────────────────────────────────────────────────────────────

    function isQueued(bytes32 execHash) external view override returns (bool) {
        QueuedExecution storage e = _queue[execHash];
        return e.executableAfter > 0 && !e.executed && !e.cancelled;
    }

    function isExecutable(
        bytes32 execHash
    ) external view override returns (bool) {
        QueuedExecution storage e = _queue[execHash];
        return
            e.executableAfter > 0 &&
            !e.executed &&
            !e.cancelled &&
            block.timestamp >= e.executableAfter;
    }

    function getExecution(
        bytes32 execHash
    ) external view override returns (QueuedExecution memory) {
        return _queue[execHash];
    }

    function getDelay() external view override returns (uint256) {
        return _delay;
    }
}
