// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {AccessControl} from "openzeppelin-contracts/contracts/access/AccessControl.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {IAuthorizationLayer} from "../interfaces/IAuthorizationLayer.sol";
import {SignatureLib} from "../libraries/SignatureLib.sol";

contract AuthorizationLayer is IAuthorizationLayer, AccessControl {
    using ECDSA for bytes32;

    bytes32 public constant SIGNER_ROLE = keccak256("SIGNER_ROLE");
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    // State
    /// @notice EIP-712 domain separator — computed once at deployment.
    bytes32 public immutable DOMAIN_SEPARATOR;

    /// @notice Number of valid signatures required to authorize a proposal.
    uint256 private _threshold;

    /// @notice Current number of registered signers.
    uint256 private _signerCount;

    /// @dev signer → current nonce
    mapping(address => uint256) private _nonces;

    /// @dev proposalHash → authorized
    mapping(bytes32 => bool) private _authorized;

    /// @dev proposalHash → signer → has signed (prevents double-counting within one batch)
    mapping(bytes32 => mapping(address => bool)) private _hasSigned;

    // ─────────────────────────────────────────────────────────────────────────
    // Constructor
    // ─────────────────────────────────────────────────────────────────────────

    /// @param admin      Governance address that can add/remove signers
    /// @param signers    Initial set of authorized signers
    /// @param threshold  Minimum signatures required (must be ≤ signers.length)
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

        // Build the domain separator — chains chainId and this address into every
        // signature, making replay on another chain or contract impossible.
        DOMAIN_SEPARATOR = SignatureLib.buildDomainSeparator(
            "AresProtocol",
            "1",
            address(this)
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // External — Authorization
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Submit M-of-N signatures to authorize a queued proposal.
    ///
    ///         Each signature must:
    ///         - Come from a distinct registered signer
    ///         - Cover the correct (proposalHash, actionType, nonce, deadline) struct
    ///         - Not have expired (deadline > block.timestamp)
    ///
    ///         Nonces are consumed atomically: if any signature fails, the whole
    ///         call reverts and no nonces are advanced.
    ///
    /// @param proposalHash  Hash of the proposal being approved
    /// @param actionType    Action category (mirrors IProposalManager.ActionType)
    /// @param deadline      Unix timestamp after which signatures are invalid
    /// @param signatures    Packed (r,s,v) signatures — one per signer
    function authorizeProposal(
        bytes32 proposalHash,
        uint8 actionType,
        uint256 deadline,
        bytes[] calldata signatures
    ) external override {
        require(!_authorized[proposalHash], "AuthLayer: already authorized");
        require(block.timestamp <= deadline, "AuthLayer: signatures expired");
        require(
            signatures.length >= _threshold,
            "AuthLayer: insufficient signatures"
        );

        // Collect signers whose nonces will be consumed — we validate all before
        // mutating any state (checks-effects-interactions at the batch level).
        address[] memory validated = new address[](signatures.length);
        uint256 validCount;

        for (uint256 i; i < signatures.length; ++i) {
            uint256 expectedNonce = _nonces[address(0)]; // placeholder — resolved per signer below
            // Decode the signer from the signature to look up their nonce
            bytes32 structHash = SignatureLib.hashTreasuryAction(
                proposalHash,
                actionType,
                0, // nonce is encoded per-signer; see note below
                deadline
            );

            // We encode the signer's *current* nonce into the digest so that
            // each signer's signature is bound to a specific use-count.
            // The off-chain tool must fetch getNonce(signer) before signing.
            //
            // Step 1: recover address with nonce = 0 to find candidate signer
            bytes32 digest0 = SignatureLib.toTypedDataHash(
                DOMAIN_SEPARATOR,
                SignatureLib.hashTreasuryAction(
                    proposalHash,
                    actionType,
                    0,
                    deadline
                )
            );

            // Try to recover — then validate against their actual nonce
            address candidate = ECDSA.recover(digest0, signatures[i]);
            if (!hasRole(SIGNER_ROLE, candidate) || candidate == address(0)) {
                revert("AuthLayer: invalid signer");
            }

            // Re-derive digest with the signer's real nonce
            bytes32 realDigest = SignatureLib.toTypedDataHash(
                DOMAIN_SEPARATOR,
                SignatureLib.hashTreasuryAction(
                    proposalHash,
                    actionType,
                    _nonces[candidate],
                    deadline
                )
            );
            address recovered = ECDSA.recover(realDigest, signatures[i]);
            require(recovered == candidate, "AuthLayer: nonce mismatch");
            require(
                !_hasSigned[proposalHash][candidate],
                "AuthLayer: duplicate signer"
            );

            validated[validCount++] = candidate;
            _hasSigned[proposalHash][candidate] = true;
        }

        require(validCount >= _threshold, "AuthLayer: threshold not met");

        // All checks passed — now mutate state (consume nonces)
        for (uint256 i; i < validCount; ++i) {
            _nonces[validated[i]]++;
            emit ProposalAuthorized(proposalHash, validated[i]);
        }

        _authorized[proposalHash] = true;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // External — Admin (signer management)
    // ─────────────────────────────────────────────────────────────────────────

    function addSigner(address signer) external onlyRole(ADMIN_ROLE) {
        require(signer != address(0), "AuthLayer: zero signer");
        require(!hasRole(SIGNER_ROLE, signer), "AuthLayer: already signer");
        _grantRole(SIGNER_ROLE, signer);
        _signerCount++;
        emit SignerAdded(signer);
    }

    function removeSigner(address signer) external onlyRole(ADMIN_ROLE) {
        require(hasRole(SIGNER_ROLE, signer), "AuthLayer: not signer");
        require(
            _signerCount - 1 >= _threshold,
            "AuthLayer: would break threshold"
        );
        _revokeRole(SIGNER_ROLE, signer);
        _signerCount--;
        emit SignerRemoved(signer);
    }

    function updateThreshold(
        uint256 newThreshold
    ) external onlyRole(ADMIN_ROLE) {
        require(newThreshold > 0, "AuthLayer: zero threshold");
        require(newThreshold <= _signerCount, "AuthLayer: threshold too high");
        emit ThresholdUpdated(_threshold, newThreshold);
        _threshold = newThreshold;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // View
    // ─────────────────────────────────────────────────────────────────────────

    function isAuthorized(
        bytes32 proposalHash
    ) external view override returns (bool) {
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
