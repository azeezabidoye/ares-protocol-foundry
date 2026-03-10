// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title MaliciousReentrant
/// @notice Simulates a reentrancy attack against AresTreasury.execute().
///
///         When AresTreasury calls attack() during proposal execution, this
///         contract attempts to call execute() again on the treasury.
///         The test asserts that reentrancySucceeded == false after the call.
contract MaliciousReentrant {
    address public immutable treasury;
    bytes32 public targetProposal;
    bool    public reentrancySucceeded;

    constructor(address _treasury) {
        treasury = _treasury;
    }

    function setTargetProposal(bytes32 h) external {
        targetProposal = h;
    }

    /// @notice Called by the treasury during execution.
    ///         Tries to reenter treasury.execute() with the same proposal.
    function attack() external {
        if (targetProposal == bytes32(0)) return;

        (bool success,) = treasury.call(
            abi.encodeWithSignature("execute(bytes32)", targetProposal)
        );

        // success should always be false — ReentrancyGuard blocks the call
        if (success) {
            reentrancySucceeded = true;
        }
    }

    receive() external payable {}
}
