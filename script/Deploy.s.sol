// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";

import {AresTreasury} from "../src/AresTreasury.sol";
import {ProposalManager} from "../src/ProposalManager.sol";
import {AuthorizationLayer} from "../src/AuthorizationLayer.sol";
import {TimelockEngine} from "../src/TimelockEngine.sol";
import {RewardDistributor} from "../src/RewardDistributor.sol";

/// @title Deploy
/// @notice Foundry deployment script for the ARES Protocol treasury system.
///
/// Usage (local Anvil):
///   forge script script/Deploy.s.sol --broadcast --rpc-url http://127.0.0.1:8545
///
/// Usage (testnet, e.g. Sepolia):
///   forge script script/Deploy.s.sol \
///     --broadcast \
///     --rpc-url $SEPOLIA_RPC \
///     --private-key $DEPLOYER_KEY \
///     --verify \
///     --etherscan-api-key $ETHERSCAN_KEY
///
/// Environment variables (set in .env):
///   ADMIN_ADDRESS     - governance / admin multisig
///   GUARDIAN_ADDRESS  - guardian multisig (cancel-only)
///   EXECUTOR_ADDRESS  - executor EOA or contract
///   SIGNER_1 … _3    - authorization layer signers
///   REWARD_TOKEN      - ERC-20 token address for reward distribution
///   TIMELOCK_DELAY    - delay in seconds (e.g. 86400 = 1 day)
contract Deploy is Script {
    // ─────────────────────────────────────────────────────────────────────────
    // Deployed Addresses (populated during run)
    // ─────────────────────────────────────────────────────────────────────────

    AresTreasury public treasury;
    ProposalManager public proposalMgr;
    AuthorizationLayer public authLayer;
    TimelockEngine public timelockEngine;
    RewardDistributor public rewardDist;

    // ─────────────────────────────────────────────────────────────────────────
    // run()
    // ─────────────────────────────────────────────────────────────────────────

    function run() external {
        // ── Read configuration ──
        address admin = vm.envOr("ADMIN_ADDRESS", msg.sender);
        address guardian = vm.envOr("GUARDIAN_ADDRESS", msg.sender);
        address executor = vm.envOr("EXECUTOR_ADDRESS", msg.sender);
        address rewardToken = vm.envOr("REWARD_TOKEN", address(0));
        uint256 delay = vm.envOr("TIMELOCK_DELAY", uint256(1 days));

        // Authorization signers — default to deployer for local testing
        address[] memory signers = new address[](3);
        signers[0] = vm.envOr("SIGNER_1", msg.sender);
        signers[1] = vm.envOr("SIGNER_2", msg.sender);
        signers[2] = vm.envOr("SIGNER_3", msg.sender);

        console2.log("=== ARES Protocol Deployment ===");
        console2.log("Admin   :", admin);
        console2.log("Guardian:", guardian);
        console2.log("Executor:", executor);
        console2.log("Delay   :", delay);

        vm.startBroadcast();

        // ── 1. Authorization Layer ──
        authLayer = new AuthorizationLayer(admin, signers, 2);
        console2.log("AuthorizationLayer  :", address(authLayer));

        // ── 2. Proposal Manager ──
        proposalMgr = new ProposalManager(admin, guardian);
        console2.log("ProposalManager     :", address(proposalMgr));

        // ── 3. Timelock Engine ──
        timelockEngine = new TimelockEngine(admin, guardian, delay);
        console2.log("TimelockEngine      :", address(timelockEngine));

        // ── 4. Reward Distributor (skip if no token provided) ──
        if (rewardToken != address(0)) {
            rewardDist = new RewardDistributor(admin, rewardToken);
            console2.log("RewardDistributor   :", address(rewardDist));
        }

        // ── 5. Core Treasury ──
        treasury = new AresTreasury(
            admin,
            guardian,
            executor,
            address(proposalMgr),
            address(authLayer),
            address(timelockEngine)
        );
        console2.log("AresTreasury        :", address(treasury));

        // ── 6. Wire roles ──
        timelockEngine.grantRole(
            timelockEngine.TREASURY_ROLE(),
            address(treasury)
        );
        proposalMgr.grantRole(proposalMgr.TREASURY_ROLE(), address(treasury));
        proposalMgr.grantRole(proposalMgr.EXECUTOR_ROLE(), executor);

        vm.stopBroadcast();

        console2.log("=== Deployment Complete ===");
        _printSummary();
    }

    function _printSummary() internal view {
        console2.log("");
        console2.log("Contract Addresses:");
        console2.log("  AresTreasury      :", address(treasury));
        console2.log("  ProposalManager   :", address(proposalMgr));
        console2.log("  AuthLayer         :", address(authLayer));
        console2.log("  TimelockEngine    :", address(timelockEngine));
        if (address(rewardDist) != address(0)) {
            console2.log("  RewardDistributor :", address(rewardDist));
        }
    }
}
