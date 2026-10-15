// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title MetorahManifestV1
 * @notice Cross-language canonical SHA-256 encoding reference for issue #25.
 * @dev NOT a proof of the source chain and NOT the legacy claim contract's
 *      active proof algorithm. Issue #26 must integrate a safe verifier.
 *      Fixed-width integers are big endian under Solidity abi.encodePacked.
 *      Tree siblings retain LEFT/RIGHT position and odd nodes duplicate last.
 */
library MetorahManifestV1 {
    struct Header {
        bytes32 sourceGenesis;
        bytes32 finalizedBlockHash;
        uint64 finalizedBlockNumber;
        bytes32 finalizedStateRoot;
        bytes32 sourceContract;
        bytes32 sourceCodeHash;
        bytes32 migrationId;
        bytes32 assetId;
        uint64 destinationChainId;
        address destinationContract;
        uint8 entitlementKind;
        uint8 decimals;
        uint32 historicalHolderCount;
        uint32 activeHolderCount;
        uint128 totalUnits;
    }

    struct Entry {
        uint32 leafIndex;
        uint32 historicalIndex;
        bytes32 sourceAccount;
        address beneficiary;
        uint128 units;
        uint64 bindingNonce;
    }

    function headerHash(Header memory h) internal pure returns (bytes32) {
        require(h.sourceGenesis != bytes32(0) && h.finalizedBlockHash != bytes32(0), "missing chain");
        require(h.finalizedBlockNumber > 0 && h.finalizedStateRoot != bytes32(0), "missing finality");
        require(h.sourceContract != bytes32(0) && h.sourceCodeHash != bytes32(0), "missing source");
        require(h.migrationId != bytes32(0) && h.assetId != bytes32(0), "missing migration");
        require(h.destinationChainId > 0 && h.destinationContract != address(0), "missing destination");
        require(h.entitlementKind == 1 && h.decimals <= 18, "unsupported entitlement");
        require(
            h.activeHolderCount > 0 &&
            h.activeHolderCount <= h.historicalHolderCount &&
            h.totalUnits > 0,
            "invalid holder totals"
        );

        bytes memory first = abi.encodePacked(
            "METORAH_HEADER_V1", bytes1(0),
            h.sourceGenesis, h.finalizedBlockHash, h.finalizedBlockNumber,
            h.finalizedStateRoot, h.sourceContract, h.sourceCodeHash,
            h.migrationId, h.assetId
        );
        bytes memory second = abi.encodePacked(
            h.destinationChainId, h.destinationContract, h.entitlementKind,
            h.decimals, h.historicalHolderCount, h.activeHolderCount, h.totalUnits
        );
        return sha256(bytes.concat(first, second));
    }

    function leafHash(bytes32 h, Entry memory e) internal pure returns (bytes32) {
        require(h != bytes32(0) && e.sourceAccount != bytes32(0), "invalid leaf source");
        require(e.beneficiary != address(0) && e.units > 0 && e.bindingNonce > 0, "invalid leaf rights");
        return sha256(abi.encodePacked(
            "METORAH_LEAF_V1", bytes1(0), h,
            e.leafIndex, e.historicalIndex, e.sourceAccount,
            e.beneficiary, e.units, e.bindingNonce
        ));
    }

    function nodeHash(bytes32 left, bytes32 right) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(
            "METORAH_NODE_V1", bytes1(0), left, right
        ));
    }

    function manifestDigest(bytes32 h, bytes32 root) internal pure returns (bytes32) {
        require(h != bytes32(0) && root != bytes32(0), "missing commitment");
        return sha256(abi.encodePacked(
            "METORAH_MANIFEST_V1", bytes1(0), h, root
        ));
    }

    function verifyProof(
        bytes32 h,
        Entry memory e,
        bytes32[] memory siblings,
        bytes32 root,
        uint32 leafCount
    ) internal pure returns (bool) {
        if (leafCount == 0 || e.leafIndex >= leafCount || root == bytes32(0)) return false;
        uint256 expectedDepth = 0;
        uint256 count = leafCount;
        while (count > 1) {
            count = count / 2 + count % 2;
            ++expectedDepth;
        }
        if (siblings.length != expectedDepth) return false;
        bytes32 current = leafHash(h, e);
        uint256 index = e.leafIndex;
        count = leafCount;
        for (uint256 i = 0; i < siblings.length; ++i) {
            bytes32 sibling = siblings[i];
            if ((index ^ 1) >= count && sibling != current) return false;
            current = (index & 1) == 1
                ? nodeHash(sibling, current) : nodeHash(current, sibling);
            index /= 2;
            count = count / 2 + count % 2;
        }
        return current == root;
    }
}

/**
 * @notice Pure development harness exposing the Solidity implementation for
 *         Foundry/parity regression tests; NOT a trustless root commitment.
 */
contract MetorahManifestV1Harness {
    function hashHeader(MetorahManifestV1.Header calldata header) external pure returns (bytes32) {
        return MetorahManifestV1.headerHash(header);
    }

    function hashLeaf(bytes32 headerDigest, MetorahManifestV1.Entry calldata entry)
        external pure returns (bytes32)
    {
        return MetorahManifestV1.leafHash(headerDigest, entry);
    }

    function hashNode(bytes32 left, bytes32 right) external pure returns (bytes32) {
        return MetorahManifestV1.nodeHash(left, right);
    }

    function hashManifest(bytes32 headerDigest, bytes32 root) external pure returns (bytes32) {
        return MetorahManifestV1.manifestDigest(headerDigest, root);
    }

    function verify(
        bytes32 headerDigest,
        MetorahManifestV1.Entry calldata entry,
        bytes32[] calldata siblings,
        bytes32 root,
        uint32 leafCount
    ) external pure returns (bool) {
        return MetorahManifestV1.verifyProof(headerDigest, entry, siblings, root, leafCount);
    }
}
