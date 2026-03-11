// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {AccessControl} from "openzeppelin-contracts/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "openzeppelin-contracts/contracts/utils/ReentrancyGuard.sol";
import {MerkleProof} from "openzeppelin-contracts/contracts/utils/cryptography/MerkleProof.sol";
import {SafeERC20} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {IRewardDistributor} from "../src/interfaces/IRewardDistributor.sol";

contract RewardDistributor is IRewardDistributor, AccessControl, ReentrancyGuard {
    using SafeERC20 for IERC20;
    using MerkleProof for bytes32[];

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    IERC20 public immutable rewardToken;

    uint256 private _currentPeriod;

    mapping(uint256 => RewardPeriod) private _periods;

    mapping(uint256 => mapping(address => bool)) private _claimed;

    constructor(address admin, address token) {
        require(admin != address(0), "RewardDist: zero admin");
        require(token != address(0), "RewardDist: zero token");

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);

        rewardToken = IERC20(token);
    }

    function activatePeriod(bytes32 merkleRoot, uint256 totalAmount) external onlyRole(ADMIN_ROLE) {
        require(merkleRoot != bytes32(0), "RewardDist: zero root");
        require(totalAmount > 0, "RewardDist: zero amount");

        uint256 periodId = ++_currentPeriod;

        _periods[periodId] = RewardPeriod({
            merkleRoot: merkleRoot, totalAmount: totalAmount, activatedAt: block.timestamp, active: true
        });

        rewardToken.safeTransferFrom(msg.sender, address(this), totalAmount);

        emit PeriodActivated(periodId, merkleRoot, totalAmount);
    }

    function updateRoot(uint256 periodId, bytes32 newRoot) external onlyRole(ADMIN_ROLE) {
        require(_periods[periodId].active, "RewardDist: period not active");
        require(newRoot != bytes32(0), "RewardDist: zero root");

        bytes32 oldRoot = _periods[periodId].merkleRoot;
        _periods[periodId].merkleRoot = newRoot;

        emit RootUpdated(periodId, oldRoot, newRoot);
    }

    function claim(uint256 periodId, address account, uint256 amount, bytes32[] calldata proof)
        external
        override
        nonReentrant
    {
        require(account != address(0), "RewardDist: zero account");
        require(amount > 0, "RewardDist: zero amount");
        require(_periods[periodId].active, "RewardDist: period not active");
        require(!_claimed[periodId][account], "RewardDist: already claimed");

        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encodePacked(account, amount))));

        require(MerkleProof.verify(proof, _periods[periodId].merkleRoot, leaf), "RewardDist: invalid proof");

        _claimed[periodId][account] = true;

        rewardToken.safeTransfer(account, amount);

        emit RewardClaimed(periodId, account, amount);
    }

    function hasClaimed(uint256 periodId, address account) external view override returns (bool) {
        return _claimed[periodId][account];
    }

    function getPeriod(uint256 periodId) external view override returns (RewardPeriod memory) {
        return _periods[periodId];
    }

    function currentPeriod() external view override returns (uint256) {
        return _currentPeriod;
    }
}
