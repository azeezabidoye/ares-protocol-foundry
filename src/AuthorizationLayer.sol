// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {AccessControl} from "openzeppelin-contracts/contracts/access/AccessControl.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {IAuthorizationLayer} from "../src/interfaces/IAuthorizationLayer.sol";
import {SignatureLib} from "../src/libraries/SignatureLib.sol";

contract AuthorizationLayer is IAuthorizationLayer, AccessControl {
    using ECDSA for bytes32;

    bytes32 public constant SIGNER_ROLE = keccak256("SIGNER_ROLE");
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    bytes32 public immutable DOMAIN_SEPARATOR;

    uint256 private _threshold;

    uint256 private _signerCount;

    mapping(address => uint256) private _nonces;

    mapping(bytes32 => bool) private _authorized;

    mapping(bytes32 => mapping(address => bool)) private _hasSigned;

    constructor(address admin, address[] memory signers, uint256 threshold) {
        require(admin != address(0), "AuthLayer: zero admin");
        require(signers.length >= threshold, "AuthLayer: threshold too high");
        require(threshold > 0, "AuthLayer: zero threshold");

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);

        for (uint256 i; i < signers.length; ++i) {
            require(signers[i] != address(0), "AuthLayer: zero signer");
            _grantRole(SIGNER_ROLE, signers[i]);
        }
        _signerCount = signers.length;
        _threshold = threshold;

        DOMAIN_SEPARATOR = SignatureLib.buildDomainSeparator("AresProtocol", "1", address(this));
    }

    function authorizeProposal(bytes32 proposalHash, uint8 actionType, uint256 deadline, bytes[] calldata signatures)
        external
        override
    {
        require(!_authorized[proposalHash], "AuthLayer: already authorized");
        require(block.timestamp <= deadline, "AuthLayer: signatures expired");
        require(signatures.length >= _threshold, "AuthLayer: insufficient signatures");

        address[] memory validated = new address[](signatures.length);
        uint256 validCount;

        for (uint256 i; i < signatures.length; ++i) {
            bytes32 digest0 = SignatureLib.toTypedDataHash(
                DOMAIN_SEPARATOR, SignatureLib.hashTreasuryAction(proposalHash, actionType, 0, deadline)
            );

            address candidate = ECDSA.recover(digest0, signatures[i]);
            if (!hasRole(SIGNER_ROLE, candidate) || candidate == address(0)) {
                revert("AuthLayer: invalid signer");
            }

            bytes32 realDigest = SignatureLib.toTypedDataHash(
                DOMAIN_SEPARATOR,
                SignatureLib.hashTreasuryAction(proposalHash, actionType, _nonces[candidate], deadline)
            );
            address recovered = ECDSA.recover(realDigest, signatures[i]);
            require(recovered == candidate, "AuthLayer: nonce mismatch");
            require(!_hasSigned[proposalHash][candidate], "AuthLayer: duplicate signer");

            validated[validCount++] = candidate;
            _hasSigned[proposalHash][candidate] = true;
        }

        require(validCount >= _threshold, "AuthLayer: threshold not met");

        for (uint256 i; i < validCount; ++i) {
            _nonces[validated[i]]++;
            emit ProposalAuthorized(proposalHash, validated[i]);
        }

        _authorized[proposalHash] = true;
    }

    function addSigner(address signer) external onlyRole(ADMIN_ROLE) {
        require(signer != address(0), "AuthLayer: zero signer");
        require(!hasRole(SIGNER_ROLE, signer), "AuthLayer: already signer");
        _grantRole(SIGNER_ROLE, signer);
        _signerCount++;
        emit SignerAdded(signer);
    }

    function removeSigner(address signer) external onlyRole(ADMIN_ROLE) {
        require(hasRole(SIGNER_ROLE, signer), "AuthLayer: not signer");
        require(_signerCount - 1 >= _threshold, "AuthLayer: would break threshold");
        _revokeRole(SIGNER_ROLE, signer);
        _signerCount--;
        emit SignerRemoved(signer);
    }

    function updateThreshold(uint256 newThreshold) external onlyRole(ADMIN_ROLE) {
        require(newThreshold > 0, "AuthLayer: zero threshold");
        require(newThreshold <= _signerCount, "AuthLayer: threshold too high");
        emit ThresholdUpdated(_threshold, newThreshold);
        _threshold = newThreshold;
    }

    function isAuthorized(bytes32 proposalHash) external view override returns (bool) {
        return _authorized[proposalHash];
    }

    function getNonce(address signer) external view override returns (uint256) {
        return _nonces[signer];
    }

    function isSigner(address account) external view override returns (bool) {
        return hasRole(SIGNER_ROLE, account);
    }

    function getSignerCount() external view override returns (uint256) {
        return _signerCount;
    }

    function getThreshold() external view override returns (uint256) {
        return _threshold;
    }
}
