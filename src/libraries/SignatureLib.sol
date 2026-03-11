// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library SignatureLib {
    bytes32 internal constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    bytes32 internal constant TREASURY_ACTION_TYPEHASH =
        keccak256("TreasuryAction(bytes32 proposalHash,uint8 actionType,uint256 nonce,uint256 deadline)");

    function buildDomainSeparator(string memory name, string memory version, address verifyingContract)
        internal
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                block.chainid,
                verifyingContract
            )
        );
    }

    function hashTreasuryAction(bytes32 proposalHash, uint8 actionType, uint256 nonce, uint256 deadline)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(TREASURY_ACTION_TYPEHASH, proposalHash, actionType, nonce, deadline));
    }

    function toTypedDataHash(bytes32 domainSeparator, bytes32 structHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }
}
