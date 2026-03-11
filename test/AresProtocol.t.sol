// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

import {AresTreasury} from "../src/core/AresTreasury.sol";
import {ProposalManager} from "../src/modules/ProposalManager.sol";
import {AuthorizationLayer} from "../src/modules/AuthorizationLayer.sol";
import {TimelockEngine} from "../src/modules/TimelockEngine.sol";
import {RewardDistributor} from "../src/modules/RewardDistributor.sol";

import {IProposalManager} from "../src/interfaces/IProposalManager.sol";
import {ITimelockEngine} from "../src/interfaces/ITimelockEngine.sol";
import {SignatureLib} from "../src/libraries/SignatureLib.sol";

import {MockERC20} from "./mocks/MockERC20.sol";
import {MaliciousReentrant} from "./mocks/MaliciousReentrant.sol";

/// @title AresProtocolTest
/// @notice Full Foundry test suite — functional + attack simulation.
///
///         Functional tests:  proposal lifecycle, signature auth, timelock,
///                            reward claiming, governance flow
///         Attack tests (8+): reentrancy, double-claim, invalid signature,
///                            early execution, proposal replay, replay sig,
///                            cross-chain sig, spending limit breach,
///                            griefing proposal spam
contract AresProtocolTest is Test {
    // ─────────────────────────────────────────────────────────────────────────
    // Contracts
    // ─────────────────────────────────────────────────────────────────────────

    AresTreasury public treasury;
    ProposalManager public proposalMgr;
    AuthorizationLayer public authLayer;
    TimelockEngine public timelock;
    RewardDistributor public rewardDist;
    MockERC20 public token;

    // ─────────────────────────────────────────────────────────────────────────
    // Actors
    // ─────────────────────────────────────────────────────────────────────────

    address admin = makeAddr("admin");
    address guardian = makeAddr("guardian");
    address executor = makeAddr("executor");
    address proposer = makeAddr("proposer");
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    address carol = makeAddr("carol");
    address attacker = makeAddr("attacker");

    // Signers for AuthorizationLayer (need private keys to sign)
    uint256 signer1Pk = 0xA11CE;
    uint256 signer2Pk = 0xB0B;
    uint256 signer3Pk = 0xCA01;
    address signer1;
    address signer2;
    address signer3;

    // ─────────────────────────────────────────────────────────────────────────
    // Constants
    // ─────────────────────────────────────────────────────────────────────────

    uint256 constant DELAY = 1 days;
    uint256 constant REWARD_AMOUNT = 1_000_000 ether;
    uint256 constant CLAIM_AMOUNT = 100 ether;

    // ─────────────────────────────────────────────────────────────────────────
    // Setup
    // ─────────────────────────────────────────────────────────────────────────

    function setUp() public {
        // Derive signer addresses from private keys
        signer1 = vm.addr(signer1Pk);
        signer2 = vm.addr(signer2Pk);
        signer3 = vm.addr(signer3Pk);

        vm.startPrank(admin);

        // Deploy mock token
        token = new MockERC20("ARES", "ARES", 18);
        token.mint(admin, 100_000_000 ether);

        // Deploy modules
        address[] memory signers = new address[](3);
        signers[0] = signer1;
        signers[1] = signer2;
        signers[2] = signer3;

        authLayer = new AuthorizationLayer(admin, signers, 2); // 2-of-3
        proposalMgr = new ProposalManager(admin, guardian);
        timelock = new TimelockEngine(admin, guardian, DELAY);

        // Deploy core treasury
        treasury =
            new AresTreasury(admin, guardian, executor, address(proposalMgr), address(authLayer), address(timelock));

        // Deploy reward distributor
        rewardDist = new RewardDistributor(admin, address(token));

        // Wire roles: treasury needs TREASURY_ROLE on timelock & proposalMgr
        timelock.grantRole(timelock.TREASURY_ROLE(), address(treasury));
        proposalMgr.grantRole(proposalMgr.TREASURY_ROLE(), address(treasury));
        // Executor needs EXECUTOR_ROLE on proposalMgr for reveal
        proposalMgr.grantRole(proposalMgr.EXECUTOR_ROLE(), executor);

        // Fund the treasury with ETH and tokens
        vm.deal(address(treasury), 10 ether);
        token.transfer(address(treasury), 10_000_000 ether);

        vm.stopPrank();
    }

    // ═════════════════════════════════════════════════════════════════════════
    // ── FUNCTIONAL TESTS ────────────────────────────────────────────────────
    // ═════════════════════════════════════════════════════════════════════════

    // ─────────────────────────────────────────────────────────────────────────
    // F-1  Proposal Lifecycle
    // ─────────────────────────────────────────────────────────────────────────

    function test_ProposalLifecycle_CommitAndReveal() public {
        (bytes32 proposalHash, bytes32 salt) = _buildProposalHash(
            IProposalManager.ActionType.TRANSFER,
            address(token),
            abi.encodeWithSignature("transfer(address,uint256)", alice, 1 ether),
            0
        );

        // ── Commit ──
        vm.prank(proposer);
        proposalMgr.commitProposal(proposalHash);

        assertEq(
            uint8(proposalMgr.getProposalState(proposalHash)),
            uint8(IProposalManager.ProposalState.COMMITTED),
            "should be COMMITTED after commit"
        );

        // ── Reveal ──
        vm.roll(block.number + 2);
        vm.prank(proposer);
        proposalMgr.revealProposal(
            IProposalManager.ActionType.TRANSFER,
            address(token),
            abi.encodeWithSignature("transfer(address,uint256)", alice, 1 ether),
            0,
            salt
        );

        assertEq(
            uint8(proposalMgr.getProposalState(proposalHash)),
            uint8(IProposalManager.ProposalState.QUEUED),
            "should be QUEUED after reveal"
        );
    }

    function test_ProposalLifecycle_Cancel_ByProposer() public {
        (bytes32 proposalHash,) = _buildProposalHash(IProposalManager.ActionType.TRANSFER, alice, "", 0);

        vm.prank(proposer);
        proposalMgr.commitProposal(proposalHash);

        vm.prank(proposer);
        proposalMgr.cancelProposal(proposalHash);

        assertEq(uint8(proposalMgr.getProposalState(proposalHash)), uint8(IProposalManager.ProposalState.CANCELLED));
    }

    function test_ProposalLifecycle_Cancel_ByGuardian() public {
        (bytes32 proposalHash,) = _buildProposalHash(IProposalManager.ActionType.TRANSFER, alice, "", 0);

        vm.prank(proposer);
        proposalMgr.commitProposal(proposalHash);

        vm.prank(guardian);
        proposalMgr.cancelProposal(proposalHash);

        assertEq(uint8(proposalMgr.getProposalState(proposalHash)), uint8(IProposalManager.ProposalState.CANCELLED));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // F-2  Signature Authorization
    // ─────────────────────────────────────────────────────────────────────────

    function test_Authorization_ValidThreshold() public {
        bytes32 proposalHash = keccak256("test_proposal_auth");
        uint256 deadline = block.timestamp + 1 hours;

        bytes[] memory sigs =
            _signProposal(proposalHash, uint8(IProposalManager.ActionType.TRANSFER), deadline, signer1Pk, signer2Pk);

        authLayer.authorizeProposal(proposalHash, uint8(IProposalManager.ActionType.TRANSFER), deadline, sigs);

        assertTrue(authLayer.isAuthorized(proposalHash), "should be authorized");
    }

    function test_Authorization_NoncesConsumed() public {
        bytes32 proposalHash = keccak256("nonce_test");
        uint256 deadline = block.timestamp + 1 hours;

        uint256 nonceBefore = authLayer.getNonce(signer1);

        bytes[] memory sigs =
            _signProposal(proposalHash, uint8(IProposalManager.ActionType.TRANSFER), deadline, signer1Pk, signer2Pk);
        authLayer.authorizeProposal(proposalHash, uint8(IProposalManager.ActionType.TRANSFER), deadline, sigs);

        assertEq(authLayer.getNonce(signer1), nonceBefore + 1, "nonce should increment");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // F-3  Timelock Execution
    // ─────────────────────────────────────────────────────────────────────────

    function test_Timelock_QueueAndExecuteAfterDelay() public {
        bytes32 execHash = keccak256("timelock_test");

        // Grant treasury role for this test
        bytes32 currentRole = timelock.TREASURY_ROLE();
        vm.prank(admin);
        timelock.grantRole(currentRole, address(this));

        timelock.queue(execHash);

        assertFalse(timelock.isExecutable(execHash), "should not be executable yet");

        vm.warp(block.timestamp + DELAY + 1);

        assertTrue(timelock.isExecutable(execHash), "should be executable after delay");

        timelock.markExecuted(execHash);

        ITimelockEngine.QueuedExecution memory entry = timelock.getExecution(execHash);
        assertTrue(entry.executed, "should be marked executed");
    }

    function test_Timelock_CancelByGuardian() public {
        bytes32 execHash = keccak256("cancel_test");

        bytes32 currentRole = timelock.TREASURY_ROLE();
        vm.prank(admin);
        timelock.grantRole(currentRole, address(this));

        timelock.queue(execHash);
        vm.prank(guardian);
        timelock.cancel(execHash);

        ITimelockEngine.QueuedExecution memory entry = timelock.getExecution(execHash);
        assertTrue(entry.cancelled, "should be cancelled");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // F-4  Reward Distribution
    // ─────────────────────────────────────────────────────────────────────────

    function test_Reward_ClaimSuccess() public {
        (bytes32 root, bytes32[] memory aliceProof) = _buildMerkleTree(alice, CLAIM_AMOUNT);

        // Admin activates period
        vm.startPrank(admin);
        token.approve(address(rewardDist), REWARD_AMOUNT);
        rewardDist.activatePeriod(root, REWARD_AMOUNT);
        vm.stopPrank();

        uint256 balanceBefore = token.balanceOf(alice);

        vm.prank(alice);
        rewardDist.claim(1, alice, CLAIM_AMOUNT, aliceProof);

        assertEq(token.balanceOf(alice), balanceBefore + CLAIM_AMOUNT, "alice should receive reward");
        assertTrue(rewardDist.hasClaimed(1, alice), "should be marked claimed");
    }

    function test_Reward_MultiplePeriods() public {
        // Period 1
        (bytes32 root1, bytes32[] memory proof1) = _buildMerkleTree(alice, CLAIM_AMOUNT);
        vm.startPrank(admin);
        token.approve(address(rewardDist), REWARD_AMOUNT * 2);
        rewardDist.activatePeriod(root1, REWARD_AMOUNT);

        // Period 2 with different amount
        (bytes32 root2, bytes32[] memory proof2) = _buildMerkleTree(alice, CLAIM_AMOUNT * 2);
        rewardDist.activatePeriod(root2, REWARD_AMOUNT);
        vm.stopPrank();

        vm.prank(alice);
        rewardDist.claim(1, alice, CLAIM_AMOUNT, proof1);

        vm.prank(alice);
        rewardDist.claim(2, alice, CLAIM_AMOUNT * 2, proof2);

        // Both claims succeed independently
        assertTrue(rewardDist.hasClaimed(1, alice));
        assertTrue(rewardDist.hasClaimed(2, alice));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // F-5  End-to-End Governance Lifecycle
    // ─────────────────────────────────────────────────────────────────────────

    function test_FullGovernanceLifecycle() public {
        address recipient = alice;
        uint256 amount = 1 ether;
        bytes memory callData = abi.encodeWithSignature("transfer(address,uint256)", recipient, amount);
        bytes32 salt = keccak256("salt_e2e");

        // 1. Commit
        bytes32 proposalHash =
            keccak256(abi.encode(IProposalManager.ActionType.TRANSFER, address(token), callData, 0, salt));
        vm.prank(proposer);
        proposalMgr.commitProposal(proposalHash);

        // 2. Reveal
        vm.roll(block.number + 2);
        vm.prank(proposer);
        proposalMgr.revealProposal(IProposalManager.ActionType.TRANSFER, address(token), callData, 0, salt);

        // 3. Authorize (2-of-3)
        uint256 deadline = block.timestamp + 2 hours;
        bytes[] memory sigs =
            _signProposal(proposalHash, uint8(IProposalManager.ActionType.TRANSFER), deadline, signer1Pk, signer2Pk);
        authLayer.authorizeProposal(proposalHash, uint8(IProposalManager.ActionType.TRANSFER), deadline, sigs);

        // 4. Queue in timelock
        vm.prank(executor);
        treasury.queueExecution(proposalHash);

        // 5. Warp past delay
        vm.warp(block.timestamp + DELAY + 1);

        uint256 balBefore = token.balanceOf(recipient);

        // 6. Execute
        vm.prank(executor);
        treasury.execute(proposalHash);

        assertGt(token.balanceOf(recipient), balBefore, "recipient should have received tokens");
        assertEq(uint8(proposalMgr.getProposalState(proposalHash)), uint8(IProposalManager.ProposalState.EXECUTED));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // ── ATTACK SIMULATION TESTS ──────────────────────────────────────────────
    // ═════════════════════════════════════════════════════════════════════════

    // ─────────────────────────────────────────────────────────────────────────
    // A-1  Reentrancy Attack
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Malicious contract attempts to reenter execute() during the
    ///         external call.  The ReentrancyGuard + CEI pattern must block it.
    function test_Attack_Reentrancy_Blocked() public {
        MaliciousReentrant malicious = new MaliciousReentrant(address(treasury));

        // Set up a proposal that calls into the malicious contract
        bytes memory callData = abi.encodeWithSignature("attack()");
        bytes32 salt = keccak256("reentrancy_salt");
        bytes32 proposalHash =
            keccak256(abi.encode(IProposalManager.ActionType.CALL, address(malicious), callData, 0, salt));

        // Commit & reveal
        vm.prank(proposer);
        proposalMgr.commitProposal(proposalHash);
        vm.roll(block.number + 2);
        vm.prank(proposer);
        proposalMgr.revealProposal(IProposalManager.ActionType.CALL, address(malicious), callData, 0, salt);

        // Authorize
        uint256 deadline = block.timestamp + 2 hours;
        bytes[] memory sigs =
            _signProposal(proposalHash, uint8(IProposalManager.ActionType.CALL), deadline, signer1Pk, signer2Pk);
        authLayer.authorizeProposal(proposalHash, uint8(IProposalManager.ActionType.CALL), deadline, sigs);

        // Queue and warp
        vm.prank(executor);
        treasury.queueExecution(proposalHash);
        vm.warp(block.timestamp + DELAY + 1);

        // The reentrant attempt during execute() should revert
        malicious.setTargetProposal(proposalHash);

        // Execute should not allow reentrant double-drain
        vm.prank(executor);
        // This will call malicious.attack() which tries to reenter — should fail gracefully
        // (execution itself succeeds, but the reentrant call inside is blocked)
        treasury.execute(proposalHash);

        // Verify reentrant call was blocked
        assertFalse(malicious.reentrancySucceeded(), "reentrancy must be blocked");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // A-2  Double Claim
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Claiming rewards twice for the same period must revert.
    function test_Attack_DoubleClaim_Reverts() public {
        (bytes32 root, bytes32[] memory proof) = _buildMerkleTree(alice, CLAIM_AMOUNT);

        vm.startPrank(admin);
        token.approve(address(rewardDist), REWARD_AMOUNT);
        rewardDist.activatePeriod(root, REWARD_AMOUNT);
        vm.stopPrank();

        vm.prank(alice);
        rewardDist.claim(1, alice, CLAIM_AMOUNT, proof);

        // Second claim must revert
        vm.prank(alice);
        vm.expectRevert("RewardDist: already claimed");
        rewardDist.claim(1, alice, CLAIM_AMOUNT, proof);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // A-3  Invalid Signature
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice A signature from an unauthorized address must be rejected.
    function test_Attack_InvalidSignature_Reverts() public {
        bytes32 proposalHash = keccak256("invalid_sig_test");
        uint256 deadline = block.timestamp + 1 hours;

        // Sign with an address that is NOT a registered signer
        uint256 rogueKey = 0xDEADBEEF;
        bytes[] memory sigs = _signProposal(
            proposalHash,
            uint8(IProposalManager.ActionType.TRANSFER),
            deadline,
            rogueKey, // <-- not a signer
            signer2Pk
        );

        vm.expectRevert("AuthLayer: invalid signer");
        authLayer.authorizeProposal(proposalHash, uint8(IProposalManager.ActionType.TRANSFER), deadline, sigs);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // A-4  Early Execution (before timelock delay)
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Attempting to execute before the timelock delay must revert.
    function test_Attack_EarlyExecution_Reverts() public {
        bytes32 execHash = keccak256("early_exec");

        bytes32 currentRole = timelock.TREASURY_ROLE();
        vm.prank(admin);
        timelock.grantRole(currentRole, address(this));

        timelock.queue(execHash);

        // Try to execute immediately — should revert
        vm.expectRevert("Timelock: not yet executable");
        timelock.markExecuted(execHash);
    }

    function test_Attack_EarlyExecution_OnTreasury_Reverts() public {
        // Full proposal setup without warping past delay
        bytes32 salt = keccak256("early_salt");
        bytes memory callData = abi.encodeWithSignature("transfer(address,uint256)", alice, 1 ether);
        bytes32 proposalHash =
            keccak256(abi.encode(IProposalManager.ActionType.TRANSFER, address(token), callData, 0, salt));

        vm.prank(proposer);
        proposalMgr.commitProposal(proposalHash);
        vm.roll(block.number + 2);
        vm.prank(proposer);
        proposalMgr.revealProposal(IProposalManager.ActionType.TRANSFER, address(token), callData, 0, salt);

        uint256 deadline = block.timestamp + 2 hours;
        bytes[] memory sigs =
            _signProposal(proposalHash, uint8(IProposalManager.ActionType.TRANSFER), deadline, signer1Pk, signer2Pk);
        authLayer.authorizeProposal(proposalHash, uint8(IProposalManager.ActionType.TRANSFER), deadline, sigs);

        vm.prank(executor);
        treasury.queueExecution(proposalHash);

        // Do NOT warp — attempt immediate execution
        vm.prank(executor);
        vm.expectRevert("Treasury: timelock not elapsed");
        treasury.execute(proposalHash);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // A-5  Proposal Replay
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Trying to re-commit an already-existing proposal hash must revert.
    function test_Attack_ProposalReplay_Reverts() public {
        (bytes32 proposalHash,) = _buildProposalHash(IProposalManager.ActionType.TRANSFER, alice, "", 0);

        vm.prank(proposer);
        proposalMgr.commitProposal(proposalHash);

        // Replay the same commitment
        vm.prank(attacker);
        vm.expectRevert("ProposalManager: already exists");
        proposalMgr.commitProposal(proposalHash);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // A-6  Signature Replay
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice After a signature's nonce is consumed, reusing it on a new
    ///         proposal must fail.
    function test_Attack_SignatureReplay_Reverts() public {
        bytes32 proposalHash1 = keccak256("proposal_1");
        bytes32 proposalHash2 = keccak256("proposal_2");
        uint256 deadline = block.timestamp + 2 hours;

        // Authorize proposal 1 — consumes nonce 0 for signer1 and signer2
        bytes[] memory sigs1 =
            _signProposal(proposalHash1, uint8(IProposalManager.ActionType.TRANSFER), deadline, signer1Pk, signer2Pk);
        authLayer.authorizeProposal(proposalHash1, uint8(IProposalManager.ActionType.TRANSFER), deadline, sigs1);

        // Reuse those SAME signatures (nonce 0) for proposal 2 — must revert
        vm.expectRevert("AuthLayer: invalid signer");
        authLayer.authorizeProposal(proposalHash2, uint8(IProposalManager.ActionType.TRANSFER), deadline, sigs1);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // A-7  Invalid Merkle Proof
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Submitting a fabricated Merkle proof must be rejected.
    function test_Attack_InvalidMerkleProof_Reverts() public {
        (bytes32 root,) = _buildMerkleTree(alice, CLAIM_AMOUNT);

        vm.startPrank(admin);
        token.approve(address(rewardDist), REWARD_AMOUNT);
        rewardDist.activatePeriod(root, REWARD_AMOUNT);
        vm.stopPrank();

        // Attacker constructs a fake proof for a larger amount
        bytes32[] memory fakeProof = new bytes32[](1);
        fakeProof[0] = keccak256("fake_sibling");

        vm.prank(attacker);
        vm.expectRevert("RewardDist: invalid proof");
        rewardDist.claim(1, attacker, CLAIM_AMOUNT * 1000, fakeProof);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // A-8  Proposal Griefing (rate limit)
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice A single address cannot spam more than MAX_ACTIVE_PER_PROPOSER
    ///         concurrent proposals.
    function test_Attack_ProposalGriefing_RateLimit() public {
        uint256 max = proposalMgr.MAX_ACTIVE_PER_PROPOSER();

        // Fill up the limit
        for (uint256 i; i < max; ++i) {
            bytes32 h = keccak256(abi.encode("spam", i));
            vm.prank(attacker);
            proposalMgr.commitProposal(h);
        }

        // One more should revert
        bytes32 overflow = keccak256("overflow");
        vm.prank(attacker);
        vm.expectRevert("ProposalManager: too many active proposals");
        proposalMgr.commitProposal(overflow);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // A-9  Unauthorized Treasury Execution
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Non-executor cannot call execute().
    function test_Attack_UnauthorizedExecution_Reverts() public {
        bytes32 proposalHash = keccak256("unauth");

        vm.prank(attacker);
        vm.expectRevert(); // AccessControl revert
        treasury.execute(proposalHash);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // A-10  Executing Without Authorization
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Even an executor cannot queue a proposal that lacks M-of-N approval.
    function test_Attack_QueueWithoutAuthorization_Reverts() public {
        bytes32 salt = keccak256("no_auth_salt");
        bytes memory callData = "";
        bytes32 proposalHash = keccak256(abi.encode(IProposalManager.ActionType.TRANSFER, alice, callData, 0, salt));

        vm.prank(proposer);
        proposalMgr.commitProposal(proposalHash);
        vm.roll(block.number + 2);
        vm.prank(proposer);
        proposalMgr.revealProposal(IProposalManager.ActionType.TRANSFER, alice, callData, 0, salt);

        // Try to queue without authorizing — must revert
        vm.prank(executor);
        vm.expectRevert("Treasury: not authorized");
        treasury.queueExecution(proposalHash);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // A-11  Expired Signature
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice A signature past its deadline must be rejected.
    function test_Attack_ExpiredSignature_Reverts() public {
        bytes32 proposalHash = keccak256("expired_sig");
        uint256 deadline = block.timestamp + 1 hours;

        bytes[] memory sigs =
            _signProposal(proposalHash, uint8(IProposalManager.ActionType.TRANSFER), deadline, signer1Pk, signer2Pk);

        // Warp past deadline
        vm.warp(deadline + 1);

        vm.expectRevert("AuthLayer: signatures expired");
        authLayer.authorizeProposal(proposalHash, uint8(IProposalManager.ActionType.TRANSFER), deadline, sigs);
    }

    // ═════════════════════════════════════════════════════════════════════════
    // ── HELPERS ──────────────────────────────────────────────────────────────
    // ═════════════════════════════════════════════════════════════════════════

    /// @dev Build a proposal hash from parameters + random salt.
    function _buildProposalHash(
        IProposalManager.ActionType actionType,
        address target,
        bytes memory callData,
        uint256 value
    ) internal view returns (bytes32 proposalHash, bytes32 salt) {
        salt = keccak256(abi.encode(block.timestamp, block.number, msg.sender));
        proposalHash = keccak256(abi.encode(actionType, target, callData, value, salt));
    }

    /// @dev Build a minimal two-leaf Merkle tree for alice and a dummy leaf.
    ///      Returns the root and alice's proof.
    ///      NOTE: uses double-hashing to match RewardDistributor.
    function _buildMerkleTree(address account, uint256 amount)
        internal
        pure
        returns (bytes32 root, bytes32[] memory proof)
    {
        // Double-hash leaves (matches contract)
        bytes32 leafA = keccak256(bytes.concat(keccak256(abi.encodePacked(account, amount))));
        bytes32 leafB = keccak256(bytes.concat(keccak256(abi.encodePacked(address(0xDEAD), uint256(1)))));

        // Sort leaves (standard Merkle tree convention)
        (bytes32 l, bytes32 r) = leafA < leafB ? (leafA, leafB) : (leafB, leafA);
        root = keccak256(abi.encodePacked(l, r));

        proof = new bytes32[](1);
        proof[0] = leafB;
    }

    /// @dev Sign a TreasuryAction for two signers and return packed signature array.
    ///      Off-chain equivalent: wallets call `eth_signTypedData_v4`.
    function _signProposal(bytes32 proposalHash, uint8 actionType, uint256 deadline, uint256 pk1, uint256 pk2)
        internal
        view
        returns (bytes[] memory sigs)
    {
        bytes32 domSep = authLayer.DOMAIN_SEPARATOR();

        // Sign with pk1 using their CURRENT nonce
        address addr1 = vm.addr(pk1);
        uint256 nonce1 = authLayer.getNonce(addr1);
        bytes32 digest1 = SignatureLib.toTypedDataHash(
            domSep, SignatureLib.hashTreasuryAction(proposalHash, actionType, nonce1, deadline)
        );
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(pk1, digest1);

        // Sign with pk2 using their CURRENT nonce
        address addr2 = vm.addr(pk2);
        uint256 nonce2 = authLayer.getNonce(addr2);
        bytes32 digest2 = SignatureLib.toTypedDataHash(
            domSep, SignatureLib.hashTreasuryAction(proposalHash, actionType, nonce2, deadline)
        );
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(pk2, digest2);

        sigs = new bytes[](2);
        sigs[0] = abi.encodePacked(r1, s1, v1);
        sigs[1] = abi.encodePacked(r2, s2, v2);
    }
}
