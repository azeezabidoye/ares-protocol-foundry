// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {AccessControl} from "openzeppelin-contracts/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "openzeppelin-contracts/contracts/utils/ReentrancyGuard.sol";
import {SafeERC20} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

import {IProposalManager} from "../interfaces/IProposalManager.sol";
import {IAuthorizationLayer} from "../interfaces/IAuthorizationLayer.sol";
import {ITimelockEngine} from "../interfaces/ITimelockEngine.sol";
import {SpendingLib} from "../libraries/SpendingLib.sol";

contract AresTreasury is AccessControl, ReentrancyGuard {
    using SafeERC20 for IERC20;
    using SpendingLib for SpendingLib.DailyTracker;

    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    uint256 public constant MAX_SINGLE_TRANSFER = 1_000_000 ether;

    /// Rolling 24-hour outflow cap.
    uint256 public constant DAILY_LIMIT = 5_000_000 ether;

    SpendingLib.DailyTracker private _dailyTracker;

    IProposalManager public immutable proposalManager;
    IAuthorizationLayer public immutable authLayer;
    ITimelockEngine public immutable timelockEngine;

    // Events
    event ExecutionQueued(bytes32 indexed proposalHash);
    event ExecutionPerformed(bytes32 indexed proposalHash, bool success);
    event NativeReceived(address indexed sender, uint256 amount);

    // Constructor
    constructor(
        address admin,
        address guardian,
        address executor,
        address _proposalManager,
        address _authLayer,
        address _timelockEngine
    ) {
        require(admin != address(0), "Treasury: zero admin");
        require(guardian != address(0), "Treasury: zero guardian");
        require(
            _proposalManager != address(0),
            "Treasury: zero proposal manager"
        );
        require(_authLayer != address(0), "Treasury: zero auth layer");
        require(_timelockEngine != address(0), "Treasury: zero timelock");

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, guardian);
        _grantRole(EXECUTOR_ROLE, executor);

        proposalManager = IProposalManager(_proposalManager);
        authLayer = IAuthorizationLayer(_authLayer);
        timelockEngine = ITimelockEngine(_timelockEngine);
    }

    // External —> Execution Flow
    function queueExecution(
        bytes32 proposalHash
    ) external onlyRole(EXECUTOR_ROLE) {
        // Verify: proposal is in QUEUED state (revealed)
        require(
            proposalManager.getProposalState(proposalHash) ==
                IProposalManager.ProposalState.QUEUED,
            "Treasury: proposal not queued"
        );
        // Verify: authorization threshold met
        require(
            authLayer.isAuthorized(proposalHash),
            "Treasury: not authorized"
        );

        timelockEngine.queue(proposalHash);

        emit ExecutionQueued(proposalHash);
    }

    //  Must match a timelock-eligible entry
    function execute(
        bytes32 proposalHash
    ) external nonReentrant onlyRole(EXECUTOR_ROLE) {
        // Load proposal parameters
        IProposalManager.Proposal memory p = proposalManager.getProposal(
            proposalHash
        );

        require(
            p.state == IProposalManager.ProposalState.QUEUED,
            "Treasury: proposal not queued"
        );
        require(
            timelockEngine.isExecutable(proposalHash),
            "Treasury: timelock not elapsed"
        );

        // Enforce spending limits for token transfers
        if (p.actionType == IProposalManager.ActionType.TRANSFER) {
            require(
                p.value <= MAX_SINGLE_TRANSFER,
                "Treasury: single transfer limit"
            );
            _dailyTracker.recordSpend(p.value, DAILY_LIMIT);
        }

        // ── Effects BEFORE interactions ──
        // Mark in timelock first — makes reentrant re-entry fail immediately
        timelockEngine.markExecuted(proposalHash);
        // Mark in proposal manager
        // (cast needed because ProposalManager exposes this as a public fn)
        (bool pmSuccess, ) = address(proposalManager).call(
            abi.encodeWithSignature("markExecuted(bytes32)", proposalHash)
        );
        require(pmSuccess, "Treasury: proposal mark failed");

        // ── Interaction ──
        (bool success, bytes memory returnData) = p.target.call{value: p.value}(
            p.callData
        );

        emit ExecutionPerformed(proposalHash, success);

        // Bubble up revert reason on failure
        if (!success) {
            if (returnData.length > 0) {
                assembly {
                    revert(add(32, returnData), mload(returnData))
                }
            }
            revert("Treasury: execution failed");
        }
    }

    // External — Guardian

    // Guardian can cancel any proposal that has not yet executed.
    function emergencyCancel(
        bytes32 proposalHash
    ) external onlyRole(GUARDIAN_ROLE) {
        timelockEngine.cancel(proposalHash);
        proposalManager.cancelProposal(proposalHash);
    }

    // ERC-20 Recovery (admin only — for mistakenly sent tokens)
    function recoverToken(
        address token,
        address to,
        uint256 amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        IERC20(token).safeTransfer(to, amount);
    }

    // Receive ETH
    receive() external payable {
        emit NativeReceived(msg.sender, msg.value);
    }

    // View
    function getDailySpent() external view returns (uint256) {
        return _dailyTracker.spent;
    }
}
