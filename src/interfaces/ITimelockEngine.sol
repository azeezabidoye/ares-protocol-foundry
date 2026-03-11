// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ITimelockEngine {
    struct QueuedExecution {
        bytes32 execHash;
        uint256 executableAfter;
        bool executed;
        bool cancelled;
    }

    event ExecutionQueued(bytes32 indexed execHash, uint256 executableAfter);
    event ExecutionCompleted(bytes32 indexed execHash);
    event ExecutionCancelled(bytes32 indexed execHash);
    event DelayUpdated(uint256 oldDelay, uint256 newDelay);

    function queue(bytes32 proposalHash) external returns (bytes32 execHash);

    function cancel(bytes32 execHash) external;

    function markExecuted(bytes32 execHash) external;

    function isQueued(bytes32 execHash) external view returns (bool);

    function isExecutable(bytes32 execHash) external view returns (bool);

    function getExecution(bytes32 execHash) external view returns (QueuedExecution memory);

    function getDelay() external view returns (uint256);
}
