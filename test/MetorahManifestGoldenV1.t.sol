// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MetorahManifestV1, MetorahManifestV1Harness} from "../src/MetorahManifestV1.sol";

/**
 * Four-language golden proof vectors for issue #26.
 * The account IDs, chain IDs, blocks and funds are SYNTHETIC.
 * No test here verifies Portaldot finality, source state or asset backing.
 */
contract MetorahManifestGoldenV1Test {
    MetorahManifestV1Harness private verifier;

    function setUp() public {
        verifier = new MetorahManifestV1Harness();
    }

    function _header(uint32 n) internal pure returns (MetorahManifestV1.Header memory h) {
        h.sourceGenesis = 0x1111111111111111111111111111111111111111111111111111111111111111;
        h.finalizedBlockHash = 0x2222222222222222222222222222222222222222222222222222222222222222;
        h.finalizedBlockNumber = 12345;
        h.finalizedStateRoot = 0x3333333333333333333333333333333333333333333333333333333333333333;
        h.sourceContract = 0x4444444444444444444444444444444444444444444444444444444444444444;
        h.sourceCodeHash = 0x5555555555555555555555555555555555555555555555555555555555555555;
        h.migrationId = 0x6666666666666666666666666666666666666666666666666666666666666666;
        h.assetId = 0x7777777777777777777777777777777777777777777777777777777777777777;
        h.destinationChainId = 31337;
        h.destinationContract = address(uint160(0x8888888888888888888888888888888888888888));
        h.entitlementKind = 1;
        h.decimals = 12;
        h.historicalHolderCount = n + (n - 1) / 8 + 1;
        h.activeHolderCount = n;
        uint128 total;
        for (uint256 i; i < n; ++i) {
            total += uint128((i + 1) * (i + 11));
        }
        h.totalUnits = total;
    }

    function _entry(uint32 i) internal pure returns (MetorahManifestV1.Entry memory e) {
        e.leafIndex = i;
        e.historicalIndex = i + i / 8;
        e.sourceAccount = bytes32(uint256(i) + 1);
        e.beneficiary = address(uint160(uint256(i) + 1001));
        e.units = uint128((uint256(i) + 1) * (uint256(i) + 11));
        e.bindingNonce = uint64(1 + i % 3);
    }

    function _expected(uint32 n)
        internal pure returns (bytes32 header, bytes32 first, bytes32 last, bytes32 root, bytes32 manifest)
    {
        if (n == 1) {
            return (
                0x8cbce6e2540f466f2f38fd605d2c9757ac16039ca19ac1a09b02c8713cf2505e,
                0x6045087ba0351018ff064f34336da6bd33b0020c288e023b7af9fd9416a3988c,
                0x6045087ba0351018ff064f34336da6bd33b0020c288e023b7af9fd9416a3988c,
                0x6045087ba0351018ff064f34336da6bd33b0020c288e023b7af9fd9416a3988c,
                0x811f69011a8346c026df8eded7697f23f4c3dd3bfba6a1c34ed9c4d71a332e39
            );
        }
        if (n == 2) {
            return (
                0x39c8118a4a072632f2c7c51fceae5d6a1be0609a816d9bf96108a9660a8c9e95,
                0x1df90df03ebac540f97a41701cad5c4b03c592c141161918e5f37dbb0f7ee1da,
                0x5afcd211415492eb73f2d9982bf85cb06d704bb117e5fb20c90c2d541b260942,
                0x9921a12392018914ca5f46f8bf0783cfa99a733b08ce6805ba3cf0c8349b43e5,
                0xb5b2667a831fd38efabb70ce900b375df4438744a80c89cf7d17132883a6371d
            );
        }
        if (n == 3) {
            return (
                0x1495c975e592002f4d8a3148032074071c6c18faf06bb55f6b87499859e6de45,
                0xdc14e916adc5387729a7ee2f0b69677ff11116367bd9c01d1fb5d3e9d4fc1fe3,
                0xe2c918394cdbd29d03adafa8b82295d5f768fbcc0514ad83c2a506fdcc1beaf1,
                0x15fc7eda49f59fae49474ac00e43b0b256403db0669a8fd616b49a486c7f91d8,
                0x99033e12ada957cffb521cf23f3e568eb2a5e6a6ec741bfb4769bf6a9b1d57a8
            );
        }
        if (n == 257) {
            return (
                0xe70c3fb5a228b922cd0870eb3faa43cf5458ca55e76c09d65485eb5e9f693939,
                0x74bf5db0794e8ecddd251c9f5e036ad50c99da444fcdf293c1918abc6f3fbf3e,
                0x746f1162ebc98d318e60077aff20be72be725d705c0f80033fb5e630c4ea90cc,
                0x43bf015333a2537273fd72f750179f27cf6d8869f8f7a488e240f5419e526061,
                0x42d131ab1f6a35b13a998e97194e7ea0718cf3a06bd78a7b6bc34698536ec632
            );
        }
        revert("not a golden fixture");
    }

    // Compute the exact bottom-up tree while retaining first/last proofs.
    // Adjacency is POSITIONAL, and unmatched nodes duplicate themselves.
    function _tree(uint32 n, bytes32 hd)
        internal view returns (bytes32 root, bytes32 first, bytes32 last, bytes32[] memory proofFirst, bytes32[] memory proofLast)
    {
        bytes32[] memory layer = new bytes32[](n);
        for (uint32 i; i < n; ++i) {
            layer[i] = verifier.hashLeaf(hd, _entry(i));
        }
        first = layer[0];
        last = layer[n - 1];
        uint256 depth;
        uint256 size = n;
        while (size > 1) {
            size = size / 2 + size % 2;
            ++depth;
        }
        proofFirst = new bytes32[](depth);
        proofLast = new bytes32[](depth);
        size = n;
        uint256 firstIndex;
        uint256 lastIndex = n - 1;
        for (uint256 d; d < depth; ++d) {
            proofFirst[d] = layer[firstIndex ^ 1 < size ? firstIndex ^ 1 : firstIndex];
            uint256 pair = lastIndex ^ 1;
            proofLast[d] = layer[pair < size ? pair : lastIndex];
            uint256 next = size / 2 + size % 2;
            for (uint256 i; i < next; ++i) {
                uint256 leftIndex = 2 * i;
                bytes32 left = layer[leftIndex];
                bytes32 right = leftIndex + 1 < size ? layer[leftIndex + 1] : left;
                layer[i] = verifier.hashNode(left, right);
            }
            firstIndex /= 2;
            lastIndex /= 2;
            size = next;
        }
        root = layer[0];
    }

    function testGoldenVectorsOneTwoThreeAndLarge() public {
        uint32[4] memory sizes = [uint32(1), uint32(2), uint32(3), uint32(257)];
        for (uint256 i; i < sizes.length; ++i) {
            uint32 n = sizes[i];
            MetorahManifestV1.Header memory header = _header(n);
            (
                bytes32 expectedHeader,
                bytes32 expectedFirst,
                bytes32 expectedLast,
                bytes32 expectedRoot,
                bytes32 expectedManifest
            ) = _expected(n);
            bytes32 hd = verifier.hashHeader(header);
            assert(hd == expectedHeader);
            (bytes32 root, bytes32 first, bytes32 last, bytes32[] memory p0, bytes32[] memory pn) = _tree(n, hd);
            assert(first == expectedFirst);
            assert(last == expectedLast);
            assert(root == expectedRoot);
            assert(verifier.hashManifest(hd, root) == expectedManifest);
            assert(verifier.verify(hd, _entry(0), p0, root, n));
            assert(verifier.verify(hd, _entry(n - 1), pn, root, n));
            if (n == 3 || n == 257) {
                assert(pn[0] == last);
            }
        }
    }

    function testRejectTamperedBeneficiarySourceIndexOrAmount() public {
        uint32 n = 3;
        bytes32 hd = verifier.hashHeader(_header(n));
        (bytes32 root, , , bytes32[] memory p0, ) = _tree(n, hd);
        MetorahManifestV1.Entry memory e = _entry(0);
        e.beneficiary = address(uint160(424242));
        assert(!verifier.verify(hd, e, p0, root, n));
        e = _entry(0); e.sourceAccount = bytes32(uint256(999));
        assert(!verifier.verify(hd, e, p0, root, n));
        e = _entry(0); e.units += 1;
        assert(!verifier.verify(hd, e, p0, root, n));
        e = _entry(0); e.leafIndex = 1;
        assert(!verifier.verify(hd, e, p0, root, n));
        e = _entry(0); e.bindingNonce += 1;
        assert(!verifier.verify(hd, e, p0, root, n));
    }

    function testRejectCrossChainDestinationAndMigrationReplay() public {
        MetorahManifestV1.Header memory h = _header(2);
        bytes32 hd = verifier.hashHeader(h);
        (bytes32 root, , , bytes32[] memory p0, ) = _tree(2, hd);
        h.migrationId = bytes32(uint256(999));
        assert(!verifier.verify(verifier.hashHeader(h), _entry(0), p0, root, 2));
        h = _header(2); h.destinationChainId = 1;
        assert(!verifier.verify(verifier.hashHeader(h), _entry(0), p0, root, 2));
        h = _header(2); h.destinationContract = address(uint160(424242));
        assert(!verifier.verify(verifier.hashHeader(h), _entry(0), p0, root, 2));
        h = _header(2); h.sourceGenesis = bytes32(uint256(1));
        assert(!verifier.verify(verifier.hashHeader(h), _entry(0), p0, root, 2));
    }

    function testForgedOddLeafSiblingIsRejected() public {
        uint32 n = 257;
        bytes32 hd = verifier.hashHeader(_header(n));
        (bytes32 root, , , , bytes32[] memory proof) = _tree(n, hd);
        proof[0] = bytes32(uint256(0xBAD));
        assert(!verifier.verify(hd, _entry(n - 1), proof, root, n));
    }

    function testIncompleteOrExtraProofIsRejected() public {
        uint32 n = 2;
        bytes32 hd = verifier.hashHeader(_header(n));
        (bytes32 root, , , , bytes32[] memory path) = _tree(n, hd);
        bytes32[] memory empty = new bytes32[](0);
        bytes32[] memory extra = new bytes32[](2);
        extra[0] = path[0]; extra[1] = path[0];
        assert(!verifier.verify(hd, _entry(1), empty, root, n));
        assert(!verifier.verify(hd, _entry(1), extra, root, n));
    }
}
