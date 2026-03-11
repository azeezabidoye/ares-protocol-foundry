// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IAuthorizationLayer {
    struct AuthorizationRequest {
        bytes32 proposalHash;
        uint8 actionType;
        uint256 nonce;
        uint256 deadline;
    }

    event SignerAdded(address indexed signer);
    event SignerRemoved(address indexed signer);
    event ProposalAuthorized(bytes32 indexed proposalHash, address indexed signer);
    event ThresholdUpdated(uint256 oldThreshold, uint256 newThreshold);

    function authorizeProposal(
        bytes32 proposalHash,
        uint8 actionType,
        uint256 deadline,
        bytes[] calldata signatures
    ) external;

    function isAuthorized(bytes32 proposalHash) external view returns (bool);

    function getNonce(address signer) external view returns (uint256);

    function isSigner(address account) external view returns (bool);

    function getSignerCount() external view returns (uint256);

    function getThreshold() external view returns (uint256);
}
