// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title SignatureLib
/// @notice Pure library for EIP-712 domain separation and struct hashing.
///         Contains no state — safe to import in any module.
library SignatureLib {
    // ─────────────────────────────────────────────────────────────────────────
    // Type Hashes  (keccak256 of the EIP-712 type string)
    // ─────────────────────────────────────────────────────────────────────────

    bytes32 internal constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    bytes32 internal constant TREASURY_ACTION_TYPEHASH = keccak256(
        "TreasuryAction(bytes32 proposalHash,uint8 actionType,uint256 nonce,uint256 deadline)"
    );

    // ─────────────────────────────────────────────────────────────────────────
    // Domain Separator
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Compute the EIP-712 domain separator.
    /// @dev    Should be called once at deployment and cached.  Re-computing
    ///         per call would work but wastes gas.
    /// @param  name              Human-readable protocol name
    /// @param  version           Contract version string
    /// @param  verifyingContract Address of the authorizing contract
    function buildDomainSeparator(
        string memory name,
        string memory version,
        address verifyingContract
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                block.chainid,       // Prevents cross-chain replay
                verifyingContract    // Prevents cross-contract replay
            )
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Struct Hashing
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Hash a TreasuryAction struct according to EIP-712.
    function hashTreasuryAction(
        bytes32 proposalHash,
        uint8   actionType,
        uint256 nonce,
        uint256 deadline
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                TREASURY_ACTION_TYPEHASH,
                proposalHash,
                actionType,
                nonce,
                deadline
            )
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Digest
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Produce the final EIP-712 digest that a signer should sign.
    /// @param  domainSeparator Pre-computed domain separator
    /// @param  structHash       Output of hashTreasuryAction()
    function toTypedDataHash(
        bytes32 domainSeparator,
        bytes32 structHash
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }
}
