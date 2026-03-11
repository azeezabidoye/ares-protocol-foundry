// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {AccessControl} from "openzeppelin-contracts/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "openzeppelin-contracts/contracts/utils/ReentrancyGuard.sol";
import {ITimelockEngine} from "../src/interfaces/ITimelockEngine.sol";

contract TimelockEngine is ITimelockEngine, AccessControl, ReentrancyGuard {
    bytes32 public constant TREASURY_ROLE = keccak256("TREASURY_ROLE");

    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    uint256 public constant MIN_DELAY = 1 days;
    uint256 public constant MAX_DELAY = 30 days;

    uint256 private _delay;

    mapping(bytes32 => QueuedExecution) private _queue;

    constructor(address admin, address guardian, uint256 initialDelay) {
        require(admin != address(0), "Timelock: zero admin");
        require(guardian != address(0), "Timelock: zero guardian");
        require(initialDelay >= MIN_DELAY && initialDelay <= MAX_DELAY, "Timelock: delay out of bounds");

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, guardian);

        _delay = initialDelay;
    }

    function queue(bytes32 proposalHash) external override onlyRole(TREASURY_ROLE) returns (bytes32 execHash) {
        require(proposalHash != bytes32(0), "Timelock: zero hash");

        execHash = proposalHash;

        QueuedExecution storage existing = _queue[execHash];
        require(existing.executableAfter == 0 || existing.cancelled, "Timelock: already queued");

        uint256 readyAt = block.timestamp + _delay;

        _queue[execHash] =
            QueuedExecution({execHash: execHash, executableAfter: readyAt, executed: false, cancelled: false});

        emit ExecutionQueued(execHash, readyAt);
    }

    function cancel(bytes32 execHash) external override {
        require(hasRole(TREASURY_ROLE, msg.sender) || hasRole(GUARDIAN_ROLE, msg.sender), "Timelock: not authorized");

        QueuedExecution storage entry = _queue[execHash];
        require(entry.executableAfter > 0, "Timelock: not queued");
        require(!entry.executed, "Timelock: already executed");
        require(!entry.cancelled, "Timelock: already cancelled");

        entry.cancelled = true;
        emit ExecutionCancelled(execHash);
    }

    function markExecuted(bytes32 execHash) external onlyRole(TREASURY_ROLE) {
        QueuedExecution storage entry = _queue[execHash];
        require(entry.executableAfter > 0, "Timelock: not queued");
        require(!entry.executed, "Timelock: already executed");
        require(!entry.cancelled, "Timelock: cancelled");
        require(block.timestamp >= entry.executableAfter, "Timelock: not yet executable");

        entry.executed = true;

        emit ExecutionCompleted(execHash);
    }

    function updateDelay(uint256 newDelay) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newDelay >= MIN_DELAY && newDelay <= MAX_DELAY, "Timelock: delay out of bounds");
        emit DelayUpdated(_delay, newDelay);
        _delay = newDelay;
    }

    function isQueued(bytes32 execHash) external view override returns (bool) {
        QueuedExecution storage e = _queue[execHash];
        return e.executableAfter > 0 && !e.executed && !e.cancelled;
    }

    function isExecutable(bytes32 execHash) external view override returns (bool) {
        QueuedExecution storage e = _queue[execHash];
        return e.executableAfter > 0 && !e.executed && !e.cancelled && block.timestamp >= e.executableAfter;
    }

    function getExecution(bytes32 execHash) external view override returns (QueuedExecution memory) {
        return _queue[execHash];
    }

    function getDelay() external view override returns (uint256) {
        return _delay;
    }
}
